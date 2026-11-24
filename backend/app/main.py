from __future__ import annotations

import shlex
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import scanner, scope
from .ai import engine
from .config import settings
from .db import get_db, init_db
from .models import CATEGORIES, SEVERITIES, Endpoint, Finding, Report, Scan, Target
from .schemas import (
    DashboardOut,
    FindingDetail,
    FindingSummary,
    HealthOut,
    ReportIn,
    ReportOut,
    ReviewIn,
    ScanDetail,
    ScanIn,
    ScanOut,
    ScopeCheckIn,
    ScopeCheckOut,
    TargetIn,
    TargetOut,
    TargetPatch,
)
from .seed import seed_default_target
from .tools import curl
from .tools.zap import ZapClient, ZapError


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    seed_default_target()
    scanner.recover_interrupted()
    yield


app = FastAPI(title="buns", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

Db = Depends(get_db)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get(db: Session, model, obj_id: int, label: str):
    obj = db.get(model, obj_id)
    if obj is None:
        raise HTTPException(404, f"{label} {obj_id} not found")
    return obj


# -- health ----------------------------------------------------------------

@app.get("/api/health", response_model=HealthOut)
def health() -> HealthOut:
    client = ZapClient(timeout=3)
    try:
        zap = f"ZAP {client.version()}"
    except ZapError:
        zap = "unreachable"
    finally:
        client.close()
    return HealthOut(
        status="ok",
        zap=zap,
        curl=curl.available(),
        ai_mode=settings.ai_mode,
        ai_model=engine.model_name(),
        allowed_hosts=settings.allowed_hosts,
    )


# -- targets ---------------------------------------------------------------

def _target_out(db: Session, t: Target) -> TargetOut:
    out = TargetOut.model_validate(t)
    out.has_test_password = bool(t.test_password)
    out.scan_count = db.scalar(select(func.count(Scan.id)).where(Scan.target_id == t.id)) or 0
    out.finding_count = db.scalar(select(func.count(Finding.id)).where(Finding.target_id == t.id)) or 0
    return out


@app.get("/api/targets", response_model=list[TargetOut])
def list_targets(db: Session = Db):
    return [_target_out(db, t) for t in db.scalars(select(Target).order_by(Target.id))]


@app.post("/api/targets", response_model=TargetOut, status_code=201)
def create_target(body: TargetIn, db: Session = Db):
    try:
        base = scope.validate_target_url(body.base_url)
    except scope.ScopeError as exc:
        raise HTTPException(422, str(exc)) from exc
    t = Target(
        name=body.name.strip(),
        base_url=base,
        authorization_notes=body.authorization_notes.strip(),
        in_scope=scope.normalise_prefixes(body.in_scope),
        out_of_scope=scope.normalise_prefixes(body.out_of_scope),
        test_email=body.test_email.strip(),
        test_password=body.test_password,
    )
    db.add(t)
    db.commit()
    return _target_out(db, t)


@app.get("/api/targets/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Db):
    return _target_out(db, _get(db, Target, target_id, "Target"))


@app.patch("/api/targets/{target_id}", response_model=TargetOut)
def update_target(target_id: int, body: TargetPatch, db: Session = Db):
    t = _get(db, Target, target_id, "Target")
    data = body.model_dump(exclude_none=True)
    for key in ("in_scope", "out_of_scope"):
        if key in data:
            data[key] = scope.normalise_prefixes(data[key])
    for key, value in data.items():
        setattr(t, key, value)
    db.commit()
    return _target_out(db, t)


@app.delete("/api/targets/{target_id}", status_code=204)
def delete_target(target_id: int, db: Session = Db):
    t = _get(db, Target, target_id, "Target")
    if any(s.status in ("queued", "running") for s in t.scans):
        raise HTTPException(409, "A scan is still running for this target.")
    db.delete(t)
    db.commit()


@app.post("/api/targets/{target_id}/scope-check", response_model=ScopeCheckOut)
def scope_check(target_id: int, body: ScopeCheckIn, db: Session = Db):
    t = _get(db, Target, target_id, "Target")
    try:
        scope.check(body.url, t.base_url, t.in_scope, t.out_of_scope)
    except scope.ScopeError as exc:
        return ScopeCheckOut(allowed=False, reason=str(exc))
    return ScopeCheckOut(allowed=True, reason="Inside the registered scope.")


# -- scans -----------------------------------------------------------------

def _scan_out(db: Session, s: Scan, cls=ScanOut):
    out = cls.model_validate(s)
    out.target_name = s.target.name
    out.finding_count = db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == s.id)) or 0
    out.endpoint_count = db.scalar(select(func.count(Endpoint.id)).where(Endpoint.scan_id == s.id)) or 0
    return out


@app.post("/api/targets/{target_id}/scans", response_model=ScanOut, status_code=201)
def create_scan(target_id: int, body: ScanIn, db: Session = Db):
    t = _get(db, Target, target_id, "Target")
    # Re-validate the stored URL: the allow-list may have changed since registration.
    try:
        scope.validate_target_url(t.base_url)
    except scope.ScopeError as exc:
        raise HTTPException(422, str(exc)) from exc
    if any(s.status in ("queued", "running") for s in t.scans):
        raise HTTPException(409, "A scan is already running for this target.")
    s = Scan(
        target_id=t.id,
        categories=body.categories,
        active_scan=body.active_scan,
        ajax_spider=body.ajax_spider,
    )
    db.add(s)
    db.commit()
    scanner.start_scan(s.id)
    return _scan_out(db, s)


@app.get("/api/scans", response_model=list[ScanOut])
def list_scans(target_id: int | None = None, limit: int = Query(50, le=200), db: Session = Db):
    q = select(Scan).order_by(Scan.id.desc()).limit(limit)
    if target_id is not None:
        q = q.where(Scan.target_id == target_id)
    return [_scan_out(db, s) for s in db.scalars(q)]


@app.get("/api/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Db):
    s = _get(db, Scan, scan_id, "Scan")
    out = _scan_out(db, s, ScanDetail)
    out.endpoints = sorted(s.endpoints, key=lambda e: (e.url, e.method))
    return out


# -- findings --------------------------------------------------------------

_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


@app.get("/api/findings", response_model=list[FindingSummary])
def list_findings(
    target_id: int | None = None,
    scan_id: int | None = None,
    status: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    db: Session = Db,
):
    q = select(Finding)
    if target_id is not None:
        q = q.where(Finding.target_id == target_id)
    if scan_id is not None:
        q = q.where(Finding.scan_id == scan_id)
    if status:
        q = q.where(Finding.status == status)
    if category:
        q = q.where(Finding.category == category)
    rows = list(db.scalars(q))
    if severity:
        rows = [f for f in rows if f.effective_severity == severity]
    rows.sort(key=lambda f: (_SEV_ORDER.get(f.effective_severity, 9), f.status != "pending", -f.id))
    return rows


def _curl_repro(f: Finding) -> str:
    """Rebuild a cURL command that reproduces the request, with secrets as variables."""
    if not f.request_raw:
        return ""
    head, _, body = f.request_raw.replace("\r\n", "\n").partition("\n\n")
    lines = head.split("\n")[1:]
    parts = ["curl", "-i", "-X", f.method, shlex.quote(f.url)]
    for line in lines:
        if ":" not in line:
            continue
        name, value = (x.strip() for x in line.split(":", 1))
        low = name.lower()
        if low in ("host", "content-length", "user-agent", "accept-encoding", "connection"):
            continue
        if low == "authorization":
            value = "Bearer $TOKEN"
        elif low == "cookie":
            value = "$COOKIE"
        parts += ["-H", shlex.quote(f"{name}: {value}")]
    if body.strip():
        parts += ["--data-raw", shlex.quote(body.strip())]
    return " ".join(parts)


def _finding_detail(f: Finding) -> FindingDetail:
    out = FindingDetail.model_validate(f)
    out.curl_command = _curl_repro(f)
    return out


@app.get("/api/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, db: Session = Db):
    return _finding_detail(_get(db, Finding, finding_id, "Finding"))


@app.post("/api/findings/{finding_id}/review", response_model=FindingDetail)
def review_finding(finding_id: int, body: ReviewIn, db: Session = Db):
    f = _get(db, Finding, finding_id, "Finding")
    if body.decision == "reset":
        f.status, f.final_severity, f.reviewer, f.review_note, f.reviewed_at = "pending", "", "", "", None
    else:
        if not body.reviewer.strip():
            raise HTTPException(422, "Enter the assessor's name before recording a decision.")
        if body.decision == "confirm":
            sev = body.severity or f.ai_severity or f.tool_severity
            changed = sev != (f.ai_severity or f.tool_severity)
            if changed and not body.note.strip():
                raise HTTPException(422, "Explain why the severity differs from the suggested rating.")
            f.status, f.final_severity = "confirmed", sev
        else:
            if not body.note.strip():
                raise HTTPException(422, "Record why this finding is a false positive.")
            f.status, f.final_severity = "rejected", ""
        f.reviewer = body.reviewer.strip()
        f.review_note = body.note.strip()
        f.reviewed_at = _now()
    db.commit()
    if f.status == "confirmed" and f.remediation_status in ("none", "failed"):
        engine.queue_remediation(f.id)
    return _finding_detail(f)


@app.post("/api/findings/{finding_id}/analyze", response_model=FindingDetail)
def reanalyze(finding_id: int, db: Session = Db):
    f = _get(db, Finding, finding_id, "Finding")
    engine.queue_analysis([f.id])
    f.ai_status = "pending"
    db.commit()
    return _finding_detail(f)


@app.post("/api/findings/{finding_id}/remediation", response_model=FindingDetail)
def regenerate_remediation(finding_id: int, db: Session = Db):
    f = _get(db, Finding, finding_id, "Finding")
    if f.status != "confirmed":
        raise HTTPException(409, "Remediation is generated for confirmed findings only.")
    engine.queue_remediation(f.id)
    f.remediation_status = "running"
    db.commit()
    return _finding_detail(f)


@app.post("/api/scans/{scan_id}/analyze-pending")
def analyze_pending(scan_id: int, db: Session = Db):
    _get(db, Scan, scan_id, "Scan")
    ids = list(db.scalars(select(Finding.id).where(
        Finding.scan_id == scan_id, Finding.ai_status.in_(("pending", "failed"))
    )))
    return {"queued": engine.queue_analysis(ids)}


# -- dashboard -------------------------------------------------------------

@app.get("/api/dashboard", response_model=DashboardOut)
def dashboard(target_id: int | None = None, db: Session = Db):
    fq = select(Finding)
    sq = select(Scan).order_by(Scan.id.desc())
    if target_id is not None:
        fq = fq.where(Finding.target_id == target_id)
        sq = sq.where(Scan.target_id == target_id)
    findings = list(db.scalars(fq))
    scans = list(db.scalars(sq))

    status = Counter(f.status for f in findings)
    sev_conf = {s: 0 for s in SEVERITIES}
    sev_open = {s: 0 for s in SEVERITIES}
    by_cat = {c: {"pending": 0, "confirmed": 0, "rejected": 0} for c in CATEGORIES}
    for f in findings:
        sev = f.effective_severity
        if f.status == "confirmed":
            sev_conf[sev] = sev_conf.get(sev, 0) + 1
        elif f.status == "pending":
            sev_open[sev] = sev_open.get(sev, 0) + 1
        by_cat.setdefault(f.category, {"pending": 0, "confirmed": 0, "rejected": 0})[f.status] += 1

    return DashboardOut(
        targets=db.scalar(select(func.count(Target.id))) or 0,
        scans=len(scans),
        scans_running=sum(1 for s in scans if s.status in ("queued", "running")),
        findings=len(findings),
        pending=status.get("pending", 0),
        confirmed=status.get("confirmed", 0),
        rejected=status.get("rejected", 0),
        ai_done=sum(1 for f in findings if f.ai_status == "done"),
        severity_confirmed=sev_conf,
        severity_open=sev_open,
        by_category=by_cat,
        recent_scans=[_scan_out(db, s) for s in scans[:6]],
        redactions=engine.redaction_totals(findings),
        ai_mode=settings.ai_mode,
    )


# -- reports ---------------------------------------------------------------

@app.post("/api/targets/{target_id}/reports", response_model=ReportOut, status_code=201)
def create_report(target_id: int, body: ReportIn, db: Session = Db):
    from .report import build_report

    t = _get(db, Target, target_id, "Target")
    confirmed = list(db.scalars(
        select(Finding).where(Finding.target_id == t.id, Finding.status == "confirmed")
    ))
    if not confirmed:
        raise HTTPException(409, "Confirm at least one finding before generating a report.")
    report_dir = settings.data_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = _now().strftime("%Y%m%d-%H%M%S")
    filename = f"buns-report-target{t.id}-{stamp}.pdf"
    build_report(db, t, body.prepared_by.strip(), report_dir / filename)
    r = Report(target_id=t.id, filename=filename, findings_count=len(confirmed), prepared_by=body.prepared_by.strip())
    db.add(r)
    db.commit()
    return r


@app.get("/api/reports", response_model=list[ReportOut])
def list_reports(target_id: int | None = None, db: Session = Db):
    q = select(Report).order_by(Report.id.desc())
    if target_id is not None:
        q = q.where(Report.target_id == target_id)
    return list(db.scalars(q))


@app.get("/api/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Db):
    r = _get(db, Report, report_id, "Report")
    path = settings.data_dir / "reports" / r.filename
    if not path.is_file():
        raise HTTPException(410, "The report file is no longer on disk.")
    return FileResponse(path, media_type="application/pdf", filename=r.filename)


# -- frontend --------------------------------------------------------------

_static = Path(__file__).resolve().parent.parent / "static"
if _static.is_dir():
    app.mount("/assets", StaticFiles(directory=_static / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404)
        candidate = (_static / path).resolve()
        if path and candidate.is_file() and _static in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(_static / "index.html")
