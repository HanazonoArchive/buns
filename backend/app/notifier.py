"""Notifications: when something breaks, tell the people responsible.

Every event becomes a Notification row, which the in-app bell shows. It is
then delivered to each enabled channel that subscribes to the event and whose
severity threshold it meets: email (SMTP), Discord, Slack, Telegram or a
generic JSON webhook. Email channels can also copy the target's owner.

Messages carry only what someone needs to act: what happened, where, how
severe, and a link back to buns. Evidence, payloads and responses stay in
the platform; text that came from tools passes through the sanitiser.
"""

from __future__ import annotations

import re
import smtplib
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from .config import settings
from .db import session_scope
from .models import SEVERITIES, Channel, Delivery, Finding, Notification, Scan, Target
from .sanitize import Sanitizer

_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # critical=0 ... info=4
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="notify")
_lock = threading.Lock()

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}
SEV_COLOR = {"critical": 0x9B1C31, "high": 0xC4511A, "medium": 0xA87A12, "low": 0x2F6F8F, "info": 0x6B7280}
EVENT_LABEL = {
    "finding.detected": "Serious finding detected",
    "scan.analysed": "Scan analysed",
    "scan.failed": "Scan failed",
    "finding.confirmed": "Finding confirmed",
    "report.generated": "Report generated",
}


class ChannelError(ValueError):
    pass


def meets(severity: str, minimum: str) -> bool:
    """True when severity is at least as serious as minimum. Events with no
    severity (scan failed, report generated) always pass."""
    if not severity:
        return True
    return _RANK.get(severity, 9) <= _RANK.get(minimum, 4)


@dataclass
class Message:
    event: str
    title: str
    body: str
    severity: str = ""
    link: str = ""
    facts: list[tuple[str, str]] = field(default_factory=list)
    target_id: int | None = None
    scan_id: int | None = None
    finding_id: int | None = None
    owner_email: str = ""


def _clean(text: str, limit: int = 300) -> str:
    return Sanitizer(max_chars=limit).clean(text or "").strip()


def _path(url: str) -> str:
    p = urlsplit(url)
    return (p.path or "/") + (f"?{p.query}" if p.query else "")


def _link(path: str) -> str:
    return f"{settings.public_url}{path}"


# -- message builders --------------------------------------------------------

def finding_detected(f: Finding) -> Message:
    sev = f.ai_severity or f.tool_severity
    return Message(
        event="finding.detected",
        severity=sev,
        title=f"{SEV_LABEL[sev]}: {_clean(f.title, 120)}",
        body=(f"Automated analysis rated this {SEV_LABEL[sev].lower()} on {f.target.name}. "
              "It has not been verified yet; an assessor should review the evidence."),
        link=_link(f"/findings/{f.id}"),
        facts=[("Target", f.target.name), ("Endpoint", f"{f.method} {_clean(_path(f.url), 120)}"),
               ("Category", f.owasp or f.category)]
              + ([("CVSS", f"{f.ai_cvss_score:.1f}")] if f.ai_cvss_score is not None else []),
        target_id=f.target_id, scan_id=f.scan_id, finding_id=f.id, owner_email=f.target.owner_email,
    )


def scan_analysed(scan: Scan, findings: list[Finding]) -> Message:
    """Summary of a finished scan. Findings first reported by this scan are
    "new"; the rest were already known and keep their earlier decisions."""
    new = [f for f in findings if f.scan_id == scan.id]
    known = len(findings) - len(new)
    counts = {s: 0 for s in SEVERITIES}
    for f in new:
        counts[f.effective_severity] = counts.get(f.effective_severity, 0) + 1
    worst = next((s for s in SEVERITIES if counts[s]), "")
    parts = [f"{counts[s]} {SEV_LABEL[s].lower()}" for s in SEVERITIES if counts[s]]
    summary = ", ".join(parts) if parts else "none"
    title = f"Scan {scan.id} on {scan.target.name}: {len(new)} new finding(s)"
    if known:
        title += f", {known} seen before"
    body = (f"Analysis finished. Suggested ratings of the new findings: {summary}. "
            "Nothing is confirmed until an assessor reviews it.") if new else (
            "No new findings. Everything this scan reported was already known; earlier decisions are kept.")
    facts = [("Target", scan.target.name), ("New", str(len(new)))]
    if known:
        facts.append(("Seen before", str(known)))
    if new:
        facts.append(("Breakdown", summary))
    return Message(
        event="scan.analysed",
        severity=worst,
        title=title,
        body=body,
        link=_link(f"/findings?scan={scan.id}&status=pending" if new else f"/findings?scan={scan.id}&status="),
        facts=facts,
        target_id=scan.target_id, scan_id=scan.id, owner_email=scan.target.owner_email,
    )


def scan_failed(scan: Scan) -> Message:
    reason = (scan.error or "unknown error").splitlines()[0]
    return Message(
        event="scan.failed",
        title=f"Scan {scan.id} on {scan.target.name} failed",
        body=f"The scan stopped before finishing: {_clean(reason, 200)}",
        link=_link(f"/scans/{scan.id}"),
        facts=[("Target", scan.target.name), ("Phase", scan.phase)],
        target_id=scan.target_id, scan_id=scan.id, owner_email=scan.target.owner_email,
    )


def finding_confirmed(f: Finding) -> Message:
    sev = f.final_severity or f.effective_severity
    return Message(
        event="finding.confirmed",
        severity=sev,
        title=f"Confirmed {SEV_LABEL[sev].lower()}: {_clean(f.title, 120)}",
        body=(f"{f.reviewer} verified this vulnerability on {f.target.name} against the HTTP evidence. "
              "Fix guidance is attached to the finding in buns."),
        link=_link(f"/findings/{f.id}"),
        facts=[("Target", f.target.name), ("Endpoint", f"{f.method} {_clean(_path(f.url), 120)}"),
               ("Verified by", f.reviewer)]
              + ([("Note", _clean(f.review_note, 200))] if f.review_note else []),
        target_id=f.target_id, scan_id=f.scan_id, finding_id=f.id, owner_email=f.target.owner_email,
    )


def report_generated(target: Target, report_id: int, count: int, prepared_by: str) -> Message:
    return Message(
        event="report.generated",
        title=f"Security report ready for {target.name}",
        body=f"{prepared_by} generated a report with {count} confirmed finding(s).",
        link=_link(f"/api/reports/{report_id}/download"),
        facts=[("Target", target.name), ("Confirmed findings", str(count)), ("Prepared by", prepared_by)],
        target_id=target.id, owner_email=target.owner_email,
    )


def test_message(channel: Channel) -> Message:
    return Message(
        event="test",
        severity="",
        title="Test notification from buns",
        body=f"The channel '{channel.name}' is set up correctly. Real alerts will look like this.",
        link=_link("/settings"),
        facts=[("Channel", channel.name), ("Type", channel.kind)],
    )


# -- formatting per channel kind ---------------------------------------------

def _text(msg: Message) -> str:
    lines = [msg.title, "", msg.body, ""]
    lines += [f"{k}: {v}" for k, v in msg.facts]
    if msg.link:
        lines += ["", msg.link]
    return "\n".join(lines)


def discord_payload(msg: Message) -> dict[str, Any]:
    embed: dict[str, Any] = {
        "title": msg.title[:256],
        "description": msg.body[:2000],
        "color": SEV_COLOR.get(msg.severity, 0x2346B0),
        "fields": [{"name": k, "value": v[:1000] or "-", "inline": len(v) < 40} for k, v in msg.facts][:10],
        "footer": {"text": f"buns · {EVENT_LABEL.get(msg.event, msg.event)}"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if msg.link.startswith("http"):
        embed["url"] = msg.link
    return {"username": "buns", "embeds": [embed]}


def slack_payload(msg: Message) -> dict[str, Any]:
    fields = [{"type": "mrkdwn", "text": f"*{k}*\n{v}"} for k, v in msg.facts][:10]
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": msg.title[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": msg.body}},
    ]
    if fields:
        blocks.append({"type": "section", "fields": fields})
    if msg.link:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"<{msg.link}|Open in buns>"}]})
    return {"text": msg.title, "blocks": blocks}


def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def telegram_payload(msg: Message, chat_id: str) -> dict[str, Any]:
    lines = [f"<b>{_html_escape(msg.title)}</b>", "", _html_escape(msg.body), ""]
    lines += [f"<b>{_html_escape(k)}:</b> {_html_escape(v)}" for k, v in msg.facts]
    if msg.link:
        lines += ["", f'<a href="{_html_escape(msg.link)}">Open in buns</a>']
    return {"chat_id": chat_id, "text": "\n".join(lines), "parse_mode": "HTML", "disable_web_page_preview": True}


def webhook_payload(msg: Message) -> dict[str, Any]:
    return {
        "event": msg.event,
        "severity": msg.severity or None,
        "title": msg.title,
        "body": msg.body,
        "link": msg.link,
        "facts": dict(msg.facts),
        "target_id": msg.target_id,
        "scan_id": msg.scan_id,
        "finding_id": msg.finding_id,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "source": "buns",
    }


def email_message(msg: Message, recipients: list[str]) -> EmailMessage:
    em = EmailMessage()
    prefix = f"[buns] [{SEV_LABEL[msg.severity]}] " if msg.severity else "[buns] "
    em["Subject"] = prefix + msg.title
    em["From"] = settings.smtp_from or settings.smtp_user
    em["To"] = ", ".join(recipients)
    em.set_content(_text(msg) + "\n\n-- \nSent by buns, AI-assisted security assessment.\n")
    color = "#%06x" % SEV_COLOR.get(msg.severity, 0x2346B0)
    rows = "".join(
        f'<tr><td style="padding:4px 12px 4px 0;color:#5c6776">{_html_escape(k)}</td>'
        f'<td style="padding:4px 0">{_html_escape(v)}</td></tr>' for k, v in msg.facts
    )
    button = (f'<p><a href="{_html_escape(msg.link)}" style="display:inline-block;background:#2346b0;color:#fff;'
              f'padding:8px 14px;border-radius:6px;text-decoration:none">Open in buns</a></p>') if msg.link else ""
    em.add_alternative(
        f'<div style="font-family:Arial,sans-serif;font-size:14px;color:#1b2330;max-width:560px">'
        f'<div style="border-left:4px solid {color};padding-left:12px">'
        f'<h2 style="font-size:18px;margin:0 0 8px">{_html_escape(msg.title)}</h2>'
        f'<p>{_html_escape(msg.body)}</p></div><table style="margin:12px 0">{rows}</table>{button}'
        f'<p style="color:#8a93a3;font-size:12px">Sent by buns, AI-assisted security assessment.</p></div>',
        subtype="html",
    )
    return em


# -- transport (module-level so tests can replace them) -----------------------

def http_post(url: str, payload: dict[str, Any]) -> None:
    with httpx.Client(timeout=15) as client:
        resp = client.post(url, json=payload)
    if resp.status_code >= 300:
        raise ChannelError(f"HTTP {resp.status_code}: {resp.text[:200]}")


def smtp_send(em: EmailMessage) -> None:
    if not settings.smtp_host:
        raise ChannelError("SMTP_HOST is not set, so email cannot be sent. Add the SMTP_* settings to .env.")
    if settings.smtp_security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20,
                                                context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
    try:
        if settings.smtp_security == "starttls":
            server.starttls(context=ssl.create_default_context())
        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password)
        server.send_message(em)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def deliver(channel: Channel, msg: Message) -> None:
    """Send one message through one channel. Raises ChannelError on failure."""
    cfg = channel.config or {}
    try:
        if channel.kind == "discord":
            http_post(cfg["url"], discord_payload(msg))
        elif channel.kind == "slack":
            http_post(cfg["url"], slack_payload(msg))
        elif channel.kind == "webhook":
            http_post(cfg["url"], webhook_payload(msg))
        elif channel.kind == "telegram":
            http_post(f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage",
                      telegram_payload(msg, str(cfg["chat_id"])))
        elif channel.kind == "email":
            recipients = list(cfg.get("to") or [])
            if channel.notify_owner and msg.owner_email and msg.owner_email not in recipients:
                recipients.append(msg.owner_email)
            if not recipients:
                raise ChannelError("No recipients: add an address or set the target's owner email.")
            smtp_send(email_message(msg, recipients))
        else:
            raise ChannelError(f"Unknown channel type '{channel.kind}'.")
    except ChannelError:
        raise
    except KeyError as exc:
        raise ChannelError(f"Channel is missing the '{exc.args[0]}' setting.") from exc
    except (httpx.HTTPError, smtplib.SMTPException, OSError) as exc:
        raise ChannelError(f"{type(exc).__name__}: {exc}") from exc


# -- configuration validation -------------------------------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SECRET_KEYS = ("url", "bot_token")


def validate_config(kind: str, cfg: dict[str, Any]) -> dict[str, Any]:
    if kind in ("discord", "slack", "webhook"):
        url = str(cfg.get("url", "")).strip()
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ChannelError("Enter the full webhook URL, starting with https://.")
        if kind == "discord" and parts.netloc not in ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"):
            raise ChannelError("A Discord webhook URL starts with https://discord.com/api/webhooks/.")
        if kind == "slack" and parts.netloc != "hooks.slack.com":
            raise ChannelError("A Slack webhook URL starts with https://hooks.slack.com/.")
        return {"url": url}
    if kind == "telegram":
        token = str(cfg.get("bot_token", "")).strip()
        chat = str(cfg.get("chat_id", "")).strip()
        if not re.fullmatch(r"\d+:[A-Za-z0-9_-]{20,}", token):
            raise ChannelError("The bot token looks like 123456789:ABC... (from @BotFather).")
        if not re.fullmatch(r"-?\d+|@[A-Za-z0-9_]{4,}", chat):
            raise ChannelError("The chat ID is a number such as 123456789, or @channelname.")
        return {"bot_token": token, "chat_id": chat}
    if kind == "email":
        raw = cfg.get("to") or []
        if isinstance(raw, str):
            raw = re.split(r"[,;\s]+", raw)
        to = [a.strip() for a in raw if a and a.strip()]
        bad = [a for a in to if not _EMAIL_RE.match(a)]
        if bad:
            raise ChannelError(f"Not an email address: {', '.join(bad)}")
        return {"to": to}
    raise ChannelError(f"Unknown channel type '{kind}'.")


def mask(value: str) -> str:
    if len(value) <= 12:
        return "••••"
    return value[: min(28, len(value) // 2)] + "••••" + value[-4:]


def public_config(kind: str, cfg: dict[str, Any]) -> dict[str, Any]:
    out = dict(cfg or {})
    for key in SECRET_KEYS:
        if out.get(key):
            out[key] = mask(str(out[key]))
    return out


def merge_config(kind: str, old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Keep stored secrets when the client sends back the masked value."""
    merged = dict(new)
    for key in SECRET_KEYS:
        if key in old and (not merged.get(key) or "••••" in str(merged.get(key))):
            merged[key] = old[key]
    return validate_config(kind, merged)


# -- emitting ----------------------------------------------------------------

def _channels_for(db, msg: Message) -> list[Channel]:
    chans = db.scalars(select(Channel).where(Channel.enabled.is_(True)))
    return [
        c for c in chans
        if msg.event in (c.events or [])
        and meets(msg.severity, c.min_severity)
        and (c.target_id is None or c.target_id == msg.target_id)
    ]


def emit(msg: Message) -> int:
    """Store the notification and queue deliveries. Returns the notification id."""
    with session_scope() as db:
        n = Notification(event=msg.event, severity=msg.severity, title=msg.title[:300], body=msg.body,
                         link=msg.link, target_id=msg.target_id, scan_id=msg.scan_id, finding_id=msg.finding_id)
        db.add(n)
        db.flush()
        jobs = []
        for c in _channels_for(db, msg):
            d = Delivery(notification_id=n.id, channel_id=c.id, channel_name=c.name, kind=c.kind)
            db.add(d)
            db.flush()
            jobs.append((d.id, c.id))
        nid = n.id
    for delivery_id, channel_id in jobs:
        _pool.submit(_run_delivery, delivery_id, channel_id, msg)
    return nid


def _run_delivery(delivery_id: int, channel_id: int, msg: Message) -> None:
    with session_scope() as db:
        channel = db.get(Channel, channel_id)
        if channel is None:
            return
        db.expunge(channel)
    status, error = "sent", ""
    try:
        deliver(channel, msg)
    except ChannelError as exc:
        status, error = "failed", str(exc)[:1000]
    except Exception as exc:  # pragma: no cover - defensive
        status, error = "failed", f"{type(exc).__name__}: {exc}"[:1000]
    with session_scope() as db:
        d = db.get(Delivery, delivery_id)
        if d:
            d.status, d.error = status, error
        c = db.get(Channel, channel_id)
        if c:
            c.last_status, c.last_error = status, error
            c.last_sent_at = datetime.now(timezone.utc)


def safe_emit(build, *args) -> None:
    """Run a hook, or emit a ready Message, without ever breaking the caller
    (scans, reviews). Hooks that emit by themselves return None."""
    try:
        msg = build if isinstance(build, Message) else build(*args)
        if isinstance(msg, Message):
            emit(msg)
    except Exception:  # pragma: no cover - notifications must not break scans
        import logging

        logging.getLogger("buns.notify").exception("notification failed")


# -- hooks called from the rest of the platform --------------------------------

def on_analysis_done(finding_id: int) -> None:
    """Called after a finding is analysed: alert on serious ones, and send the
    scan summary once the last finding of the scan is done."""
    outbox: list[Message] = []
    with _lock, session_scope() as db:
        f = db.get(Finding, finding_id)
        if f is None:
            return
        already = db.scalar(select(Notification.id).where(
            Notification.finding_id == f.id, Notification.event == "finding.detected").limit(1))
        if f.ai_status == "done" and already is None and (f.ai_severity or f.tool_severity) in ("critical", "high"):
            outbox.append(finding_detected(f))
        scan = f.scan
        pending = db.scalar(
            select(Finding.id).where(Finding.scan_id == scan.id, Finding.ai_status.in_(("pending", "running"))).limit(1)
        )
        if pending is None and scan.status == "completed" and not scan.analysis_notified:
            scan.analysis_notified = True
            outbox.append(scan_analysed(scan, _scan_findings(db, scan.id)))
    for msg in outbox:
        safe_emit(msg)


def on_scan_without_findings(scan_id: int) -> None:
    """Summary for a scan with nothing new to analyse."""
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        scan.analysis_notified = True
        msg = scan_analysed(scan, _scan_findings(db, scan_id))
    emit(msg)


def _scan_findings(db, scan_id: int) -> list[Finding]:
    from .models import FindingScan

    return list(db.scalars(select(Finding).join(FindingScan, FindingScan.finding_id == Finding.id)
                           .where(FindingScan.scan_id == scan_id)))


def on_scan_failed(scan_id: int) -> None:
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        msg = scan_failed(scan)
    emit(msg)
