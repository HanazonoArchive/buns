"""Accounts, sessions and roles.

Roles
- superadmin: the built-in sadmin@buns.com. Everything, plus managing
  accounts and reading the audit log.
- assessor: registers targets, runs scans, reviews findings, generates
  reports and manages alert channels.
- viewer: read-only.

Passwords are hashed with scrypt (standard library). A session is a random
token in an HttpOnly cookie; only its SHA-256 is stored, so a copy of the
database cannot be used to sign in.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from .db import session_scope
from .models import AuthSession, User

SUPERADMIN_EMAIL = "sadmin@buns.com"
SUPERADMIN_DEFAULT_PASSWORD = "buns"
COOKIE = "buns_session"
SESSION_IDLE = timedelta(hours=12)
SESSION_MAX = timedelta(days=7)
MIN_PASSWORD = 8
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ROLE_LABEL = {"superadmin": "Superadmin", "assessor": "Assessor", "viewer": "Viewer"}


class AuthError(ValueError):
    pass


@dataclass(frozen=True)
class Actor:
    """The signed-in user, detached from any database session."""

    id: int
    email: str
    name: str
    role: str
    custom_id: str
    must_change_password: bool

    @property
    def is_superadmin(self) -> bool:
        return self.role == "superadmin"


def _actor(u: User) -> Actor:
    return Actor(u.id, u.email, u.name, u.role, u.custom_id, u.must_change_password)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# -- passwords -----------------------------------------------------------------

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(bytes.fromhex(digest)))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calc.hex(), digest)


def check_new_password(password: str, *, email: str, current: str | None = None) -> None:
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"Use at least {MIN_PASSWORD} characters.")
    if password.lower() in (SUPERADMIN_DEFAULT_PASSWORD, email.lower(), "password", "12345678"):
        raise AuthError("That password is too easy to guess.")
    if current is not None and password == current:
        raise AuthError("Choose a password different from the current one.")


# -- sign-in throttling --------------------------------------------------------

_fail_lock = threading.Lock()
_failures: dict[str, list[float]] = {}
MAX_FAILURES = 5
WINDOW_S = 10 * 60


def locked_out(email: str) -> int:
    """Seconds until sign-in is allowed again, or 0."""
    now = time.monotonic()
    with _fail_lock:
        recent = [t for t in _failures.get(email.lower(), []) if now - t < WINDOW_S]
        _failures[email.lower()] = recent
        if len(recent) >= MAX_FAILURES:
            return int(WINDOW_S - (now - recent[0])) + 1
    return 0


def note_failure(email: str) -> None:
    with _fail_lock:
        _failures.setdefault(email.lower(), []).append(time.monotonic())


def clear_failures(email: str) -> None:
    with _fail_lock:
        _failures.pop(email.lower(), None)


# -- sessions --------------------------------------------------------------------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def authenticate(email: str, password: str) -> User | None:
    with session_scope() as db:
        u = db.scalar(select(User).where(User.email == email.strip().lower()))
        if u is None:
            # Spend the same time as a real check so timing does not reveal accounts.
            verify_password(password, "scrypt$16384$8$1$00$00")
            return None
        if not verify_password(password, u.password_hash):
            return None
        db.expunge(u)
        return u


def start_session(user_id: int, ip: str, user_agent: str) -> str:
    token = secrets.token_urlsafe(32)
    with session_scope() as db:
        db.add(AuthSession(token_hash=_hash_token(token), user_id=user_id, ip=ip[:64], user_agent=user_agent[:300]))
        u = db.get(User, user_id)
        u.last_login_at = _now()
    return token


def actor_for_token(token: str | None) -> Actor | None:
    if not token:
        return None
    with session_scope() as db:
        s = db.scalar(select(AuthSession).where(AuthSession.token_hash == _hash_token(token)))
        if s is None:
            return None
        now = _now()
        if now - _aware(s.last_seen_at) > SESSION_IDLE or now - _aware(s.created_at) > SESSION_MAX:
            db.delete(s)
            return None
        u = db.get(User, s.user_id)
        if u is None or not u.active:
            db.delete(s)
            return None
        if now - _aware(s.last_seen_at) > timedelta(minutes=5):
            s.last_seen_at = now
        return _actor(u)


def end_session(token: str | None) -> None:
    if token:
        with session_scope() as db:
            db.execute(delete(AuthSession).where(AuthSession.token_hash == _hash_token(token)))


def end_all_sessions(user_id: int, keep_token: str | None = None) -> None:
    with session_scope() as db:
        q = delete(AuthSession).where(AuthSession.user_id == user_id)
        if keep_token:
            q = q.where(AuthSession.token_hash != _hash_token(keep_token))
        db.execute(q)


# -- the built-in superadmin -----------------------------------------------------

def seed_superadmin() -> bool:
    """Create sadmin@buns.com with password "buns" if it does not exist.
    The password must be changed at first sign-in."""
    with session_scope() as db:
        if db.scalar(select(User.id).where(User.email == SUPERADMIN_EMAIL)):
            return False
        db.add(User(
            email=SUPERADMIN_EMAIL, name="Super Admin", role="superadmin",
            password_hash=hash_password(SUPERADMIN_DEFAULT_PASSWORD), must_change_password=True,
        ))
    return True
