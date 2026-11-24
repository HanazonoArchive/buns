"""Scan orchestration: reconnaissance -> scanning -> AI queue.

Runs in a background thread per scan. Progress and a human-readable log are
written back to the Scan row so the frontend can poll them. If ZAP is not
reachable the scan still runs the cURL probes and records why ZAP was
skipped, so the platform degrades instead of failing outright.
"""

from __future__ import annotations

import threading
import traceback
from datetime import datetime, timezone

from sqlalchemy import select

from .db import session_scope
from .models import Endpoint, Finding, FindingScan, Scan
from .taxonomy import ZAP_ACTIVE_SCANNERS
from .tools import curl, probes
from .tools.drafts import make_fingerprint
from .tools.normalize import dedupe, normalize_zap_alerts
from .tools.zap import ZapClient, ZapError

_scans: dict[int, threading.Thread] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class _Progress:
    """Writes log lines and progress percentages to the scan row."""

    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self._lines: list[str] = []

    def log(self, message: str) -> None:
        stamp = _now().strftime("%H:%M:%S")
        self._lines.append(f"[{stamp}] {message}")
        with session_scope() as db:
            scan = db.get(Scan, self.scan_id)
            if scan:
                scan.log = "\n".join(self._lines[-400:])

    def set(self, phase: str | None = None, progress: int | None = None) -> None:
        with session_scope() as db:
            scan = db.get(Scan, self.scan_id)
            if not scan:
                return
            if phase is not None:
                scan.phase = phase
            if progress is not None:
                scan.progress = max(scan.progress, min(int(progress), 100))


def recover_interrupted() -> None:
    """Mark scans left running by a previous process as failed."""
    from sqlalchemy import select

    with session_scope() as db:
        for scan in db.scalars(select(Scan).where(Scan.status.in_(("queued", "running")))):
            scan.status = "failed"
            scan.phase = "failed"
            scan.error = "The server restarted while this scan was running."
            scan.finished_at = _now()
        for f in db.scalars(select(Finding).where(Finding.ai_status == "running")):
            f.ai_status = "pending"
        for f in db.scalars(select(Finding).where(Finding.remediation_status == "running")):
            f.remediation_status = "failed"


def start_scan(scan_id: int) -> None:
    thread = threading.Thread(target=_run, args=(scan_id,), daemon=True, name=f"scan-{scan_id}")
    _scans[scan_id] = thread
    thread.start()


def _run(scan_id: int) -> None:
    prog = _Progress(scan_id)
    try:
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            target = scan.target
            ctx = {
                "base_url": target.base_url,
                "in_scope": list(target.in_scope),
                "out_of_scope": list(target.out_of_scope),
                "categories": list(scan.categories),
                "active_scan": scan.active_scan,
                "ajax_spider": scan.ajax_spider,
                "test_email": target.test_email,
                "test_password": target.test_password,
            }
            scan.status = "running"
            scan.started_at = _now()
        prog.log(f"Scan started against {ctx['base_url']}")
        prog.log(f"Categories: {', '.join(ctx['categories']) or '(none)'}")

        endpoints: list[tuple[str, str, int]] = []
        drafts = []

        drafts += _recon_and_zap(ctx, prog, endpoints)
        drafts += _curl_probes(ctx, prog, endpoints)

        drafts = dedupe(drafts)
        prog.set(phase="storing", progress=95)
        finding_ids = _store(scan_id, drafts, endpoints, prog)

        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            scan.status = "completed"
            scan.phase = "completed"
            scan.progress = 100
            scan.finished_at = _now()
        prog.log(f"Scan complete: {len(drafts)} findings, {len(endpoints)} endpoints recorded.")
        from . import audit, notifier

        audit.system(
            "scan.complete",
            f"Scan #{scan_id} of {ctx['base_url']} completed: {len(drafts)} finding(s), {len(endpoints)} endpoint(s)",
            detail={"scan_id": scan_id, "findings": len(drafts), "endpoints": len(endpoints)},
        )

        if finding_ids:
            from .ai import engine

            engine.queue_analysis(finding_ids)
            prog.log(f"Queued {len(finding_ids)} findings for analysis ({engine.model_name()}).")
        else:
            notifier.safe_emit(notifier.on_scan_without_findings, scan_id)
    except Exception as exc:  # pragma: no cover - top-level guard
        prog.log(f"Scan failed: {exc}")
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.phase = "failed"
                scan.error = f"{exc}\n{traceback.format_exc()}"
                scan.finished_at = _now()
        from . import audit, notifier

        audit.system("scan.failed", f"Scan #{scan_id} failed: {exc}", detail={"scan_id": scan_id})
        notifier.safe_emit(notifier.on_scan_failed, scan_id)
    finally:
        _scans.pop(scan_id, None)


def _recon_and_zap(ctx, prog, endpoints) -> list:
    from . import scope

    prog.set(phase="recon", progress=5)
    client = ZapClient()
    try:
        version = client.version()
    except ZapError as exc:
        prog.log(f"ZAP unavailable ({exc}). Continuing with cURL probes only.")
        client.close()
        return []

    prog.log(f"Connected to OWASP ZAP {version}")
    try:
        includes, excludes = scope.zap_regexes(ctx["base_url"], ctx["in_scope"], ctx["out_of_scope"])
        context = f"buns-scan-{prog.scan_id}"
        context_id = client.setup_context(context, includes, excludes)
        prog.log(f"ZAP context scoped: {len(includes)} include / {len(excludes)} exclude rules")

        client.access(ctx["base_url"])
        prog.set(phase="spider", progress=12)
        found = client.spider(
            ctx["base_url"], context,
            on_progress=lambda p: prog.set(progress=12 + p * 0.18),
        )
        prog.log(f"Spider mapped {len(found)} URLs")
        for url in found:
            if scope.is_allowed(url, ctx["base_url"], ctx["in_scope"], ctx["out_of_scope"]):
                endpoints.append(("GET", url, None))

        seeded = _seed_zap(client, ctx)
        if seeded:
            prog.log(f"Sent {seeded} API requests through ZAP so the active scan covers the JSON endpoints")

        if ctx["ajax_spider"]:
            prog.set(phase="ajax-spider", progress=32)
            n = client.ajax_spider(ctx["base_url"], context)
            prog.log(f"AJAX spider found {n} results")

        prog.set(phase="passive-scan", progress=38)
        client.wait_passive()
        prog.log("Passive scan backlog drained")

        if ctx["active_scan"]:
            scanner_ids: list[int] = []
            for cat in ctx["categories"]:
                scanner_ids += ZAP_ACTIVE_SCANNERS.get(cat, [])
            if scanner_ids:
                enabled = client.make_policy("buns-policy", sorted(set(scanner_ids)))
                prog.log(f"Active-scan policy enabled {len(enabled)} rules for selected categories")
                prog.set(phase="active-scan", progress=45)
                client.active_scan(
                    ctx["base_url"], context_id, "buns-policy",
                    on_progress=lambda p: prog.set(progress=45 + p * 0.35),
                )
                prog.log("Active scan finished")
                client.wait_passive()
            else:
                prog.log("No active-scan rules map to the selected categories; passive only.")

        prog.set(phase="collecting", progress=82)
        alerts = client.alerts(ctx["base_url"])
        in_scope_alerts = [
            a for a in alerts
            if scope.is_allowed(a.get("url", ""), ctx["base_url"], ctx["in_scope"], ctx["out_of_scope"])
        ]
        prog.log(f"ZAP reported {len(alerts)} alerts, {len(in_scope_alerts)} within scope")
        drafts = normalize_zap_alerts(in_scope_alerts)
        _attach_zap_messages(client, drafts, prog)
        return drafts
    finally:
        client.close()


def _attach_zap_messages(client, drafts, prog) -> None:
    """ZAP's alert list carries no HTTP exchange; fetch it from the history."""
    missing = 0
    for d in drafts:
        if d.request_raw or not d.message_id:
            continue
        try:
            msg = client.message(d.message_id)
        except ZapError:
            missing += 1
            continue
        d.request_raw = (msg.get("requestHeader") or "") + (msg.get("requestBody") or "")
        d.response_raw = (msg.get("responseHeader") or "") + (msg.get("responseBody") or "")[:200_000]
    if missing:
        prog.log(f"Could not load the HTTP exchange for {missing} ZAP finding(s)")


# Juice Shop is an Angular single-page app: the classic spider sees the HTML
# shell and static files but not the JSON API the app calls. These requests
# put the API routes (with their parameters) into ZAP's site tree so the
# active scan has something to attack. All are read-only or a failed login.
ZAP_SEEDS: tuple[tuple[str, str, str], ...] = (
    ("GET", "/rest/products/search?q=apple", ""),
    ("POST", "/rest/user/login", '{"email":"seed@example.test","password":"not-a-real-password"}'),
    ("GET", "/api/Products/1", ""),
    ("GET", "/rest/user/whoami", ""),
    ("GET", "/rest/track-order/5267-f9cd5882f54c75a3", ""),
)


def _seed_zap(client, ctx) -> int:
    from urllib.parse import urlsplit

    from . import scope

    host = urlsplit(ctx["base_url"]).netloc
    sent = 0
    for method, path, body in ZAP_SEEDS:
        url = ctx["base_url"].rstrip("/") + path
        if not scope.is_allowed(url, ctx["base_url"], ctx["in_scope"], ctx["out_of_scope"]):
            continue
        headers = [f"{method} {url} HTTP/1.1", f"Host: {host}", "Accept: application/json"]
        if body:
            headers += ["Content-Type: application/json", f"Content-Length: {len(body.encode())}"]
        try:
            client.send_raw("\r\n".join(headers) + "\r\n\r\n" + body)
            sent += 1
        except ZapError:
            continue
    return sent


def _curl_probes(ctx, prog, endpoints) -> list:
    if not curl.available():
        prog.log("curl binary not found; skipping cURL probes.")
        return []
    prog.set(phase="curl-probes", progress=85)
    pctx = probes.ProbeContext(
        base_url=ctx["base_url"],
        in_scope=ctx["in_scope"],
        out_of_scope=ctx["out_of_scope"],
        test_email=ctx["test_email"],
        test_password=ctx["test_password"],
        log=prog.log,
        endpoints=endpoints,
    )
    drafts = probes.run_probes(pctx, ctx["categories"])
    prog.log(f"cURL probes produced {len(drafts)} findings")
    return drafts


def _store(scan_id: int, drafts, endpoints, prog) -> list[int]:
    """Save endpoints and findings; return the ids of findings that are new.

    A finding the target already has (same fingerprint) is not stored again:
    the existing one is linked to this scan, so its review decision, analysis
    and alerts carry over to the re-scan.
    """
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        seen_urls: set[tuple[str, str]] = set()
        for method, url, status in endpoints:
            if (method, url) in seen_urls:
                continue
            seen_urls.add((method, url))
            db.add(Endpoint(
                scan_id=scan.id, method=method, url=url, status_code=status,
                source="zap-spider" if status is None else "curl",
            ))

        known = {
            f.fingerprint: f
            for f in db.scalars(select(Finding).where(Finding.target_id == scan.target_id, Finding.fingerprint != ""))
        }
        rows: list[Finding] = []
        recurring = 0
        linked: set[int] = set()
        for d in drafts:
            fp = d.fingerprint()
            existing = known.get(fp)
            if existing is not None:
                if existing.id in linked:
                    continue
                linked.add(existing.id)
                recurring += 1
                existing.times_seen = (existing.times_seen or 1) + 1
                existing.last_seen_scan_id = scan.id
                urls = list(dict.fromkeys([*(existing.affected_urls or []), *(d.affected_urls or [d.url])]))
                existing.affected_urls = urls[:200]
                existing.occurrences = max(existing.occurrences or 1, d.occurrences)
                db.add(FindingScan(finding_id=existing.id, scan_id=scan.id))
                continue
            f = Finding(
                scan_id=scan.id,
                target_id=scan.target_id,
                source=d.source,
                tool_rule_id=d.rule_id,
                title=d.title[:300],
                description=d.description,
                category=d.category,
                owasp=d.owasp,
                wstg=d.wstg,
                cwe_id=d.cwe_id,
                method=d.method,
                url=d.url,
                param=d.param,
                attack=d.attack,
                evidence=d.evidence,
                request_raw=d.request_raw,
                response_raw=d.response_raw,
                tool_severity=d.severity,
                tool_confidence=d.confidence,
                occurrences=d.occurrences,
                affected_urls=d.affected_urls or [d.url],
                ai_status="pending",
                fingerprint=fp,
                times_seen=1,
                last_seen_scan_id=scan.id,
            )
            known[fp] = f
            rows.append(f)
        db.add_all(rows)
        db.flush()
        for f in rows:
            linked.add(f.id)
            db.add(FindingScan(finding_id=f.id, scan_id=scan.id))
        new_ids = [r.id for r in rows]
    # Logged after the transaction above has committed: prog.log writes to
    # the scan row in its own session, and SQLite allows one writer at a time.
    if recurring:
        prog.log(f"{len(new_ids)} new finding(s); {recurring} already known from earlier scans "
                 "(their decisions and analysis are kept)")
    return new_ids


def fingerprint_of(f: Finding) -> str:
    """Fingerprint for a stored finding (used to backfill older databases)."""
    from urllib.parse import urlsplit

    site_wide = f.source == "zap" and not f.attack
    path = "" if site_wide else urlsplit(f.url).path
    if f.tool_rule_id == "curl:stack-trace":
        path = "/api/<unknown route>"
    return make_fingerprint(f.source, f.tool_rule_id, f.method, path, f.param)


def merge_duplicate_findings() -> int:
    """Backfill fingerprints and merge findings duplicated by earlier re-scans.

    For each target and fingerprint one finding is kept: the one with a review
    decision if any, otherwise the oldest. The others' scans, URLs and alerts
    move to it before they are deleted. Returns the number of rows merged.
    """
    from .models import Notification

    merged = 0
    with session_scope() as db:
        rows = list(db.scalars(select(Finding).order_by(Finding.id)))
        if not rows:
            return 0
        links = {(fs.finding_id, fs.scan_id) for fs in db.scalars(select(FindingScan))}
        groups: dict[tuple[int, str], list[Finding]] = {}
        for f in rows:
            if not f.fingerprint:
                f.fingerprint = fingerprint_of(f)
            if (f.id, f.scan_id) not in links:
                db.add(FindingScan(finding_id=f.id, scan_id=f.scan_id))
                links.add((f.id, f.scan_id))
            if f.last_seen_scan_id is None:
                f.last_seen_scan_id = f.scan_id
            groups.setdefault((f.target_id, f.fingerprint), []).append(f)
        db.flush()

        for group in groups.values():
            if len(group) < 2:
                continue
            decided = [f for f in group if f.status != "pending"]
            keep = (decided or group)[0]
            scan_ids = {sid for (fid, sid) in links if fid in {f.id for f in group}}
            for f in group:
                if f is keep:
                    continue
                db.query(Notification).filter(Notification.finding_id == f.id).update(
                    {Notification.finding_id: keep.id}, synchronize_session=False)
                keep.affected_urls = list(dict.fromkeys([*(keep.affected_urls or []), *(f.affected_urls or [])]))[:200]
                db.delete(f)
                merged += 1
            db.flush()
            for sid in scan_ids:
                if (keep.id, sid) not in links:
                    db.add(FindingScan(finding_id=keep.id, scan_id=sid))
                    links.add((keep.id, sid))
            keep.scan_id = min(scan_ids)
            keep.last_seen_scan_id = max(scan_ids)
            keep.times_seen = len(scan_ids)
    return merged
