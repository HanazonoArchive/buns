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

from .db import session_scope
from .models import Endpoint, Finding, Scan
from .taxonomy import ZAP_ACTIVE_SCANNERS
from .tools import curl, probes
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
                scan.progress = max(scan.progress, min(progress, 100))


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
        if finding_ids:
            from .ai import engine

            engine.queue_analysis(finding_ids)
            prog.log(f"Queued {len(finding_ids)} findings for analysis ({engine.model_name()}).")
    except Exception as exc:  # pragma: no cover - top-level guard
        prog.log(f"Scan failed: {exc}")
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.phase = "failed"
                scan.error = f"{exc}\n{traceback.format_exc()}"
                scan.finished_at = _now()
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
        return normalize_zap_alerts(in_scope_alerts)
    finally:
        client.close()


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
        rows = []
        for d in drafts:
            rows.append(Finding(
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
                ai_status="pending",
            ))
        db.add_all(rows)
        db.flush()
        return [r.id for r in rows]
