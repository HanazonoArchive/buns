"""Audit log: who did what, when, from where.

Three kinds of entry:
- event: a meaningful action by a person (signed in, started a scan,
  confirmed a finding, created an account...), with a readable message.
- request: every API call that changed something, recorded by middleware
  (method, path, status, duration). Request bodies are never stored, so
  passwords and tokens cannot end up in the log.
- system: things the platform did on its own (scan finished or failed).
"""

from __future__ import annotations

import logging
from typing import Any

from .db import session_scope
from .models import AuditLog

log = logging.getLogger("buns.audit")


def _write(**fields: Any) -> None:
    try:
        with session_scope() as db:
            db.add(AuditLog(**fields))
    except Exception:  # pragma: no cover - auditing must never break a request
        log.exception("could not write audit entry")


def event(actor, action: str, message: str, *, ip: str = "", detail: dict | None = None) -> None:
    _write(
        kind="event", action=action, message=message, ip=ip, detail=detail or {},
        actor_id=getattr(actor, "id", None), actor_email=getattr(actor, "email", "") or "",
        actor_name=getattr(actor, "name", "") or "", actor_role=getattr(actor, "role", "") or "",
    )


def anonymous(action: str, message: str, *, email: str = "", ip: str = "", detail: dict | None = None) -> None:
    """An event without a signed-in actor, such as a failed sign-in."""
    _write(kind="event", action=action, message=message, ip=ip, detail=detail or {}, actor_email=email)


def system(action: str, message: str, *, detail: dict | None = None) -> None:
    _write(kind="system", action=action, message=message, detail=detail or {}, actor_name="buns")


def request(actor, *, method: str, path: str, status: int, duration_ms: int, ip: str) -> None:
    _write(
        kind="request", action="http", message=f"{method} {path} -> {status}",
        method=method, path=path[:300], status=status, duration_ms=duration_ms, ip=ip,
        actor_id=getattr(actor, "id", None), actor_email=getattr(actor, "email", "") or "",
        actor_name=getattr(actor, "name", "") or "", actor_role=getattr(actor, "role", "") or "",
    )
