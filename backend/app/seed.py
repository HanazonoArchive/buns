"""Register the lab target from the proposal on first start."""

from __future__ import annotations

import os

from sqlalchemy import func, select

from .db import session_scope
from .models import Target

AUTHORIZATION = (
    "OWASP Juice Shop, a deliberately insecure application published under the MIT License "
    "by Bjorn Kimminich, Jannik Hollenbach and Timo Pagel for security training and tool "
    "testing. Runs as a local Docker container on the assessor's machine. Testing is limited "
    "to this container; no public, university or third-party systems are in scope. "
    "Non-destructive testing only, no DoS."
)


def seed_default_target() -> None:
    url = os.getenv("BUNS_SEED_TARGET", "").strip()
    if not url:
        return
    with session_scope() as db:
        if db.scalar(select(func.count(Target.id))):
            return
        db.add(Target(
            name="OWASP Juice Shop (local lab)",
            base_url=url.rstrip("/"),
            authorization_notes=AUTHORIZATION,
            in_scope=[],
            # Websocket noise and the chatbot add nothing to the four categories.
            out_of_scope=["/socket.io/", "/rest/chatbot/"],
            test_email=os.getenv("BUNS_SEED_TEST_EMAIL", "jim@juice-sh.op"),
            test_password=os.getenv("BUNS_SEED_TEST_PASSWORD", "ncc-1701"),
        ))
