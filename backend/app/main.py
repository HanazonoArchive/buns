from __future__ import annotations

import shlex
import time as _time
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from . import audit, auth, notifier, scanner, scope
from .ai import engine
from .config import settings
from .db import get_db, init_db
from .models import (
    CATEGORIES,
    SEVERITIES,
    AuditLog,
    Channel,
    Endpoint,
    Finding,
    FindingScan,
    Notification,
    Report,
    Scan,
    Target,
    User,
)
from .schemas import (
    AuditOut,
    ChangePasswordIn,
    ChannelIn,
    ChannelOut,
    ChannelPatch,
    DashboardOut,
    FindingDetail,
    FindingSummary,
    HealthOut,
    LoginIn,
    MarkReadIn,
    MeOut,
    NotificationOut,
    NotificationSummary,
    ReportIn,
    ReportOut,
    ResetPasswordIn,
    ReviewIn,
    ScanDetail,
    ScanIn,
    ScanOut,
    ScopeCheckIn,
    ScopeCheckOut,
    TargetIn,
    TargetOut,
    TargetPatch,
    TestResult,
    UserIn,
    UserOut,
    UserPatch,
)
from .seed import seed_default_target
from .tools import curl
from .tools.zap import ZapClient, ZapError


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    if auth.seed_superadmin():
        audit.system("auth.seed", f"Created the superadmin account {auth.SUPERADMIN_EMAIL}; its password must be changed at first sign-in")
    seed_default_target()
    scanner.recover_interrupted()
    scanner.merge_duplicate_findings()
    yield


app = FastAPI(title="buns", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Db = Depends(get_db)


# -- authentication and roles ----------------------------------------------

# Reachable without signing in.
PUBLIC = {("POST", "/api/auth/login"), ("POST", "/api/auth/logout"), ("GET", "/api/health")}
# Allowed while the password still has to be changed.
PASSWORD_CHANGE_OK = {"/api/auth/me", "/api/auth/change-password", "/api/auth/logout"}
# Writes a viewer may make (they only affect the viewer's own view).
VIEWER_WRITES = {"/api/notifications/read", "/api/auth/change-password", "/api/auth/logout"}
SUPERADMIN_ONLY = ("/api/users", "/api/audit")


def me(request: Request) -> auth.Actor | None:
    return getattr(request.state, "user", None)


def ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _deny(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


@app.middleware("http")
async def require_sign_in(request: Request, call_next):
    path, method = request.url.path, request.method
    if not path.startswith("/api/") or (method, path) in PUBLIC or method == "OPTIONS":
        return await call_next(request)
    actor = await run_in_threadpool(auth.actor_for_token, request.cookies.get(auth.COOKIE))
    if actor is None:
        return _deny(401, "Sign in to continue.")
    request.state.user = actor
    if actor.must_change_password and path not in PASSWORD_CHANGE_OK:
        return _deny(403, "Change your password before continuing.")
    if path.startswith(SUPERADMIN_ONLY) and not actor.is_superadmin:
        return _deny(403, "Only the superadmin can do this.")
    writes = method not in ("GET", "HEAD")
    if writes and actor.role == "viewer" and path not in VIEWER_WRITES:
        return _deny(403, "Your role (Viewer) can look but not change anything.")
    started = _time.perf_counter()
    response = await call_next(request)
    if writes:
        await run_in_threadpool(
            audit.request, actor, method=method, path=path, status=response.status_code,
            duration_ms=int((_time.perf_counter() - started) * 1000), ip=ip(request),
        )
    return response


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(auth.COOKIE, token, httponly=True, samesite="lax", path="/",
                        max_age=int(auth.SESSION_MAX.total_seconds()), secure=settings.public_url.startswith("https://"))


def _me_out(a: auth.Actor) -> MeOut:
    return MeOut(id=a.id, email=a.email, name=a.name, role=a.role, custom_id=a.custom_id,
                 must_change_password=a.must_change_password)


@app.post("/api/auth/login", response_model=MeOut)
def login(body: LoginIn, request: Request, response: Response):
    email = body.email.strip().lower()
    wait = auth.locked_out(email)
    if wait:
        audit.anonymous("auth.locked", f"Sign-in blocked for {email}: too many failed attempts", email=email, ip=ip(request))
        raise HTTPException(429, f"Too many failed attempts. Try again in {max(1, wait // 60)} minute(s).")
    user = auth.authenticate(email, body.password)
    if user is None:
        auth.note_failure(email)
        audit.anonymous("auth.login_failed", f"Failed sign-in for {email}", email=email, ip=ip(request))
        raise HTTPException(401, "Incorrect email or password.")
    if not user.active:
        audit.anonymous("auth.login_disabled", f"Sign-in refused for disabled account {email}", email=email, ip=ip(request))
        raise HTTPException(403, "This account is disabled. Ask the superadmin to enable it.")
    auth.clear_failures(email)
    token = auth.start_session(user.id, ip(request), request.headers.get("user-agent", ""))
    _set_cookie(response, token)
    actor = auth.actor_for_token(token)
    audit.event(actor, "auth.login", f"{actor.name} signed in", ip=ip(request))
    return _me_out(actor)


@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    token = request.cookies.get(auth.COOKIE)
    actor = auth.actor_for_token(token)
    auth.end_session(token)
    response.delete_cookie(auth.COOKIE, path="/")
    if actor:
        audit.event(actor, "auth.logout", f"{actor.name} signed out", ip=ip(request))


@app.get("/api/auth/me", response_model=MeOut)
def whoami(request: Request):
    return _me_out(me(request))


@app.post("/api/auth/change-password", response_model=MeOut)
def change_password(body: ChangePasswordIn, request: Request, db: Session = Db):
    actor = me(request)
    u = db.get(User, actor.id)
    if not auth.verify_password(body.current_password, u.password_hash):
        audit.event(actor, "auth.password_change_failed", "Password change refused: wrong current password", ip=ip(request))
        raise HTTPException(422, "The current password is not correct.")
    try:
        auth.check_new_password(body.new_password, email=u.email, current=body.current_password)
    except auth.AuthError as exc:
        raise HTTPException(422, str(exc)) from exc
    u.password_hash = auth.hash_password(body.new_password)
    u.must_change_password = False
    db.commit()
    # Sign out every other browser using the old password.
    auth.end_all_sessions(u.id, keep_token=request.cookies.get(auth.COOKIE))
    audit.event(actor, "auth.password_change", f"{u.name} changed their password", ip=ip(request))
    return _me_out(auth.actor_for_token(request.cookies.get(auth.COOKIE)))


# -- user management (superadmin) -------------------------------------------

def _check_email(db: Session, email: str, exclude: int | None = None) -> str:
    email = email.strip().lower()
    if not auth.EMAIL_RE.match(email):
        raise HTTPException(422, f"'{email}' is not a valid email address.")
    q = select(User.id).where(User.email == email)
    if exclude is not None:
        q = q.where(User.id != exclude)
    if db.scalar(q):
        raise HTTPException(409, f"An account with {email} already exists.")
    return email


@app.get("/api/users", response_model=list[UserOut])
def list_users(db: Session = Db):
    return list(db.scalars(select(User).order_by(User.role != "superadmin", User.name)))


@app.post("/api/users", response_model=UserOut, status_code=201)
def create_user(body: UserIn, request: Request, db: Session = Db):
    email = _check_email(db, body.email)
    try:
        auth.check_new_password(body.password, email=email)
    except auth.AuthError as exc:
        raise HTTPException(422, f"Temporary password: {exc}") from exc
    u = User(email=email, name=body.name.strip(), role=body.role, custom_id=body.custom_id.strip(),
             password_hash=auth.hash_password(body.password), must_change_password=True)
    db.add(u)
    db.commit()
    audit.event(me(request), "user.create",
                f"Created {auth.ROLE_LABEL[u.role]} account for {u.name} <{u.email}>" + (f" (ID {u.custom_id})" if u.custom_id else ""),
                ip=ip(request), detail={"user_id": u.id, "role": u.role, "custom_id": u.custom_id or None})
    return u


@app.patch("/api/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserPatch, request: Request, db: Session = Db):
    u = _get(db, User, user_id, "User")
    data = body.model_dump(exclude_unset=True)
    if u.role == "superadmin" and ({"role", "active"} & set(data)):
        raise HTTPException(409, "The superadmin's role and status cannot be changed.")
    changes = []
    for key, value in data.items():
        if isinstance(value, str):
            value = value.strip()
        if getattr(u, key) != value:
            changes.append(f"{key}: {getattr(u, key)!r} -> {value!r}")
            setattr(u, key, value)
    db.commit()
    if data.get("active") is False:
        auth.end_all_sessions(u.id)
    if changes:
        audit.event(me(request), "user.update", f"Updated {u.name} <{u.email}>: " + "; ".join(changes),
                    ip=ip(request), detail={"user_id": u.id, "changes": changes})
    return u


@app.post("/api/users/{user_id}/reset-password", response_model=UserOut)
def reset_password(user_id: int, body: ResetPasswordIn, request: Request, db: Session = Db):
    u = _get(db, User, user_id, "User")
    try:
        auth.check_new_password(body.password, email=u.email)
    except auth.AuthError as exc:
        raise HTTPException(422, f"Temporary password: {exc}") from exc
    u.password_hash = auth.hash_password(body.password)
    u.must_change_password = True
    db.commit()
    auth.end_all_sessions(u.id, keep_token=request.cookies.get(auth.COOKIE) if u.id == me(request).id else None)
    audit.event(me(request), "user.reset_password", f"Reset the password of {u.name} <{u.email}>; they must change it at next sign-in",
                ip=ip(request), detail={"user_id": u.id})
    return u


@app.delete("/api/users/{user_id}", status_code=204)
def delete_user(user_id: int, request: Request, db: Session = Db):
    u = _get(db, User, user_id, "User")
    if u.role == "superadmin":
        raise HTTPException(409, "The superadmin account cannot be deleted.")
    label = f"{u.name} <{u.email}>"
    db.delete(u)
    db.commit()
    audit.event(me(request), "user.delete", f"Deleted the account of {label}", ip=ip(request), detail={"user_id": user_id})


# -- audit log (superadmin) -------------------------------------------------

def _audit_query(kind: str | None, q: str | None, actor: str | None):
    stmt = select(AuditLog).order_by(AuditLog.id.desc())
    if kind:
        stmt = stmt.where(AuditLog.kind == kind)
    if actor:
        stmt = stmt.where(AuditLog.actor_email == actor)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(AuditLog.message.ilike(like) | AuditLog.action.ilike(like) | AuditLog.actor_email.ilike(like)
                          | AuditLog.path.ilike(like))
    return stmt


@app.get("/api/audit", response_model=list[AuditOut])
def list_audit(kind: str | None = None, q: str | None = None, actor: str | None = None,
               before: int | None = None, limit: int = Query(200, le=1000), db: Session = Db):
    stmt = _audit_query(kind, q, actor)
    if before:
        stmt = stmt.where(AuditLog.id < before)
    return list(db.scalars(stmt.limit(limit)))


def raw_line(e: AuditLog) -> str:
    ts = e.created_at.strftime("%Y-%m-%d %H:%M:%S")
    who = e.actor_email or e.actor_name or "-"
    role = f"[{e.actor_role}]" if e.actor_role else ""
    tail = f" {e.status} {e.duration_ms}ms" if e.kind == "request" else ""
    where = f" from {e.ip}" if e.ip else ""
    text = f"{e.method} {e.path}{tail}" if e.kind == "request" else e.message
    return f"{ts}  {e.kind.upper():7}  {e.action:24}  {who}{role}{where}  {text}"


@app.get("/api/audit/export", response_class=PlainTextResponse)
def export_audit(request: Request, kind: str | None = None, q: str | None = None, actor: str | None = None,
                 db: Session = Db):
    rows = list(db.scalars(_audit_query(kind, q, actor).limit(50000)))
    audit.event(me(request), "audit.export", f"Downloaded {len(rows)} log entries", ip=ip(request))
    stamp = _now().strftime("%Y%m%d-%H%M%S")
    return PlainTextResponse("\n".join(raw_line(e) for e in reversed(rows)) + "\n",
                             headers={"Content-Disposition": f'attachment; filename="buns-audit-{stamp}.log"'})


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


def _owner_email(value: str) -> str:
    value = (value or "").strip()
    if value and not notifier._EMAIL_RE.match(value):
        raise HTTPException(422, f"'{value}' is not a valid email address for the owner.")
    return value


@app.get("/api/targets", response_model=list[TargetOut])
def list_targets(db: Session = Db):
    return [_target_out(db, t) for t in db.scalars(select(Target).order_by(Target.id))]


@app.post("/api/targets", response_model=TargetOut, status_code=201)
def create_target(body: TargetIn, request: Request, db: Session = Db):
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
        owner_name=body.owner_name.strip(),
        owner_email=_owner_email(body.owner_email),
    )
    db.add(t)
    db.commit()
    audit.event(me(request), "target.create", f"Registered target '{t.name}' ({t.base_url})", ip=ip(request),
                detail={"target_id": t.id, "in_scope": t.in_scope, "out_of_scope": t.out_of_scope})
    return _target_out(db, t)


@app.get("/api/targets/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Db):
    return _target_out(db, _get(db, Target, target_id, "Target"))


@app.patch("/api/targets/{target_id}", response_model=TargetOut)
def update_target(target_id: int, body: TargetPatch, request: Request, db: Session = Db):
    t = _get(db, Target, target_id, "Target")
    data = body.model_dump(exclude_none=True)
    for key in ("in_scope", "out_of_scope"):
        if key in data:
            data[key] = scope.normalise_prefixes(data[key])
    if "owner_email" in data:
        data["owner_email"] = _owner_email(data["owner_email"])
    for key, value in data.items():
        setattr(t, key, value)
    db.commit()
    audit.event(me(request), "target.update", f"Updated target '{t.name}': {', '.join(sorted(data)) or 'nothing'}",
                ip=ip(request), detail={"target_id": t.id, "fields": sorted(k for k in data if k != "test_password")})
    return _target_out(db, t)


@app.delete("/api/targets/{target_id}", status_code=204)
def delete_target(target_id: int, request: Request, db: Session = Db):
    t = _get(db, Target, target_id, "Target")
    if any(s.status in ("queued", "running") for s in t.scans):
        raise HTTPException(409, "A scan is still running for this target.")
    name = t.name
    db.delete(t)
    db.commit()
    audit.event(me(request), "target.delete", f"Deleted target '{name}' with its scans and findings",
                ip=ip(request), detail={"target_id": target_id})


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
    out.finding_count = db.scalar(select(func.count()).select_from(FindingScan).where(FindingScan.scan_id == s.id)) or 0
    out.new_finding_count = db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == s.id)) or 0
    out.endpoint_count = db.scalar(select(func.count(Endpoint.id)).where(Endpoint.scan_id == s.id)) or 0
    return out


@app.post("/api/targets/{target_id}/scans", response_model=ScanOut, status_code=201)
def create_scan(target_id: int, body: ScanIn, request: Request, db: Session = Db):
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
    audit.event(me(request), "scan.start", f"Started scan {s.id} on '{t.name}' ({t.base_url})", ip=ip(request),
                detail={"scan_id": s.id, "target_id": t.id, "categories": s.categories,
                        "active_scan": s.active_scan, "ajax_spider": s.ajax_spider})
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
        q = q.join(FindingScan, FindingScan.finding_id == Finding.id).where(FindingScan.scan_id == scan_id)
    if status:
        q = q.where(Finding.status == status)
    if category:
        q = q.where(Finding.category == category)
    rows = list(db.scalars(q))
    if severity:
        rows = [f for f in rows if f.effective_severity == severity]
    rows.sort(key=lambda f: (_SEV_ORDER.get(f.effective_severity, 9), f.status != "pending", -f.id))
    latest = _latest_scans(db, {f.target_id for f in rows})
    out = []
    for f in rows:
        item = FindingSummary.model_validate(f)
        item.not_in_latest_scan = _missing_from_latest(f, latest.get(f.target_id))
        out.append(item)
    return out


def _latest_scans(db: Session, target_ids: set[int]) -> dict[int, Scan]:
    """Most recent completed scan per target."""
    latest: dict[int, Scan] = {}
    if not target_ids:
        return latest
    for s in db.scalars(select(Scan).where(Scan.target_id.in_(target_ids), Scan.status == "completed").order_by(Scan.id)):
        latest[s.target_id] = s
    return latest


def _missing_from_latest(f: Finding, latest: Scan | None) -> int | None:
    """Id of the latest scan if it covered this finding's category but did not
    report it again (it may have been fixed), else None."""
    if latest is None or (f.last_seen_scan_id or f.scan_id) >= latest.id:
        return None
    return latest.id if f.category in (latest.categories or []) else None


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


def _finding_detail(f: Finding, db: Session | None = None) -> FindingDetail:
    out = FindingDetail.model_validate(f)
    out.curl_command = _curl_repro(f)
    if db is not None:
        out.seen_in_scans = sorted(db.scalars(select(FindingScan.scan_id).where(FindingScan.finding_id == f.id)))
        out.not_in_latest_scan = _missing_from_latest(f, _latest_scans(db, {f.target_id}).get(f.target_id))
    return out


@app.get("/api/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, db: Session = Db):
    return _finding_detail(_get(db, Finding, finding_id, "Finding"), db)


@app.post("/api/findings/{finding_id}/review", response_model=FindingDetail)
def review_finding(finding_id: int, body: ReviewIn, request: Request, db: Session = Db):
    f = _get(db, Finding, finding_id, "Finding")
    actor = me(request)
    # Decisions are recorded under the signed-in account, not a typed name.
    reviewer = (actor.name if actor else body.reviewer).strip()
    if body.decision == "reset":
        f.status, f.final_severity, f.reviewer, f.review_note, f.reviewed_at = "pending", "", "", "", None
    else:
        if not reviewer:
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
        f.reviewer = reviewer
        f.review_note = body.note.strip()
        f.reviewed_at = _now()
    db.commit()
    if f.status == "confirmed" and f.remediation_status in ("none", "failed"):
        engine.queue_remediation(f.id)
    if body.decision == "confirm":
        notifier.safe_emit(notifier.finding_confirmed, f)
    verb = {"confirm": f"Confirmed as {f.final_severity}", "reject": "Rejected as a false positive",
            "reset": "Reopened"}[body.decision]
    audit.event(actor, f"finding.{body.decision}", f"{verb}: BUNS-{f.id:03d} {f.title}", ip=ip(request),
                detail={"finding_id": f.id, "severity": f.final_severity or None, "note": f.review_note or None})
    return _finding_detail(f)


@app.post("/api/findings/{finding_id}/analyze", response_model=FindingDetail)
def reanalyze(finding_id: int, request: Request, db: Session = Db):
    f = _get(db, Finding, finding_id, "Finding")
    # Save the new state before queueing: a fast worker could otherwise
    # finish first and have its result overwritten with "pending".
    f.ai_status = "pending"
    db.commit()
    engine.queue_analysis([f.id])
    audit.event(me(request), "finding.reanalyse", f"Re-ran analysis for BUNS-{f.id:03d}", ip=ip(request),
                detail={"finding_id": f.id})
    return _finding_detail(f)


@app.post("/api/findings/{finding_id}/remediation", response_model=FindingDetail)
def regenerate_remediation(finding_id: int, request: Request, db: Session = Db):
    f = _get(db, Finding, finding_id, "Finding")
    if f.status != "confirmed":
        raise HTTPException(409, "Remediation is generated for confirmed findings only.")
    f.remediation_status = "running"
    db.commit()
    engine.queue_remediation(f.id)
    audit.event(me(request), "finding.remediation", f"Regenerated remediation for BUNS-{f.id:03d}", ip=ip(request),
                detail={"finding_id": f.id})
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
def create_report(target_id: int, body: ReportIn, request: Request, db: Session = Db):
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
    notifier.safe_emit(notifier.report_generated, t, r.id, r.findings_count, r.prepared_by)
    audit.event(me(request), "report.generate", f"Generated report {filename} for '{t.name}' ({len(confirmed)} findings)",
                ip=ip(request), detail={"report_id": r.id, "target_id": t.id, "prepared_by": r.prepared_by})
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


# -- notifications ---------------------------------------------------------

@app.get("/api/notifications", response_model=list[NotificationOut])
def list_notifications(unread: bool = False, finding_id: int | None = None, limit: int = Query(50, le=200),
                       db: Session = Db):
    q = select(Notification).order_by(Notification.id.desc()).limit(limit)
    if unread:
        q = q.where(Notification.read.is_(False))
    if finding_id is not None:
        q = q.where(Notification.finding_id == finding_id)
    return list(db.scalars(q))


@app.get("/api/notifications/summary", response_model=NotificationSummary)
def notification_summary(db: Session = Db):
    return NotificationSummary(
        unread=db.scalar(select(func.count(Notification.id)).where(Notification.read.is_(False))) or 0,
        latest_id=db.scalar(select(func.max(Notification.id))) or 0,
        email_configured=bool(settings.smtp_host),
    )


@app.post("/api/notifications/read", status_code=204)
def mark_read(body: MarkReadIn, db: Session = Db):
    q = select(Notification).where(Notification.read.is_(False))
    if not body.all:
        if not body.ids:
            return
        q = q.where(Notification.id.in_(body.ids))
    for n in db.scalars(q):
        n.read = True
    db.commit()


def _channel_out(c: Channel) -> ChannelOut:
    out = ChannelOut.model_validate(c)
    out.config = notifier.public_config(c.kind, c.config)
    return out


@app.get("/api/channels", response_model=list[ChannelOut])
def list_channels(db: Session = Db):
    return [_channel_out(c) for c in db.scalars(select(Channel).order_by(Channel.id))]


@app.post("/api/channels", response_model=ChannelOut, status_code=201)
def create_channel(body: ChannelIn, request: Request, db: Session = Db):
    try:
        cfg = notifier.validate_config(body.kind, body.config)
    except notifier.ChannelError as exc:
        raise HTTPException(422, str(exc)) from exc
    if body.kind == "email" and not cfg["to"] and not body.notify_owner:
        raise HTTPException(422, "Add at least one address, or turn on emailing the target's owner.")
    if body.target_id is not None:
        _get(db, Target, body.target_id, "Target")
    c = Channel(name=body.name.strip(), kind=body.kind, config=cfg, events=list(dict.fromkeys(body.events)),
                min_severity=body.min_severity, target_id=body.target_id, notify_owner=body.notify_owner,
                enabled=body.enabled)
    db.add(c)
    db.commit()
    audit.event(me(request), "channel.create", f"Added {c.kind} alert channel '{c.name}'", ip=ip(request),
                detail={"channel_id": c.id, "events": c.events, "min_severity": c.min_severity})
    return _channel_out(c)


@app.patch("/api/channels/{channel_id}", response_model=ChannelOut)
def update_channel(channel_id: int, body: ChannelPatch, request: Request, db: Session = Db):
    c = _get(db, Channel, channel_id, "Channel")
    data = body.model_dump(exclude_unset=True)
    if "config" in data:
        try:
            data["config"] = notifier.merge_config(c.kind, c.config, data["config"] or {})
        except notifier.ChannelError as exc:
            raise HTTPException(422, str(exc)) from exc
    if "events" in data:
        data["events"] = list(dict.fromkeys(data["events"] or []))
    for key, value in data.items():
        setattr(c, key, value)
    db.commit()
    audit.event(me(request), "channel.update", f"Updated alert channel '{c.name}': {', '.join(sorted(data))}",
                ip=ip(request), detail={"channel_id": c.id, "fields": sorted(data)})
    return _channel_out(c)


@app.delete("/api/channels/{channel_id}", status_code=204)
def delete_channel(channel_id: int, request: Request, db: Session = Db):
    c = _get(db, Channel, channel_id, "Channel")
    name = c.name
    db.delete(c)
    db.commit()
    audit.event(me(request), "channel.delete", f"Removed alert channel '{name}'", ip=ip(request),
                detail={"channel_id": channel_id})


@app.post("/api/channels/{channel_id}/test", response_model=TestResult)
def test_channel(channel_id: int, request: Request, db: Session = Db):
    c = _get(db, Channel, channel_id, "Channel")
    msg = notifier.test_message(c)
    if c.kind == "email" and c.notify_owner:
        msg.owner_email = next((t.owner_email for t in db.scalars(select(Target)) if t.owner_email), "")
    try:
        notifier.deliver(c, msg)
    except notifier.ChannelError as exc:
        c.last_status, c.last_error = "failed", str(exc)
        db.commit()
        audit.event(me(request), "channel.test", f"Test message to '{c.name}' failed: {exc}", ip=ip(request),
                    detail={"channel_id": c.id, "ok": False})
        return TestResult(ok=False, error=str(exc))
    c.last_status, c.last_error, c.last_sent_at = "sent", "", _now()
    db.commit()
    audit.event(me(request), "channel.test", f"Sent a test message to '{c.name}'", ip=ip(request),
                detail={"channel_id": c.id, "ok": True})
    return TestResult(ok=True)


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
        # index.html names the current asset files; never serve a stale copy.
        return FileResponse(_static / "index.html", headers={"Cache-Control": "no-cache"})
