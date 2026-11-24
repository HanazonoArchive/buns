"""Sanitisation applied to anything that leaves the system for the AI API.

The goal is to send only the *shape* of an HTTP exchange plus vulnerability
metadata. Secrets and personal data are replaced with typed placeholders so
the model can still reason about them ("a JWT was returned") without ever
seeing the value.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
)

_HEADER_RE = re.compile(
    r"^(?P<name>" + "|".join(re.escape(h) for h in SENSITIVE_HEADERS) + r")(?P<sep>\s*:\s*)(?P<value>.*)$",
    re.IGNORECASE | re.MULTILINE,
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_BEARER_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# "password": "x", password=x, "passwd":'x', pwd=x ...
_PASSWORD_JSON_RE = re.compile(
    r'(?P<key>"(?:password|passwd|pwd|pass|secret|token|apikey|api_key|answer|totpSecret)")\s*:\s*"(?:[^"\\]|\\.)*"',
    re.IGNORECASE,
)
_PASSWORD_FORM_RE = re.compile(
    r"(?P<key>\b(?:password|passwd|pwd|pass|secret|token|api_key|apikey)=)[^&\s]*",
    re.IGNORECASE,
)
_HASH_RE = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.IGNORECASE)
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LOOPBACK_PREFIXES = ("127.", "0.0.0.0")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


@dataclass
class Sanitizer:
    max_chars: int = 4000
    counts: Counter[str] = field(default_factory=Counter)

    def clean(self, text: str | None) -> str:
        if not text:
            return ""
        out = text

        def header(m: re.Match[str]) -> str:
            self.counts["header"] += 1
            return f"{m.group('name')}{m.group('sep')}[REDACTED]"

        out = _HEADER_RE.sub(header, out)

        def sub(pattern: re.Pattern[str], label: str, repl: str):
            nonlocal out

            def _r(m: re.Match[str]) -> str:
                self.counts[label] += 1
                return repl if "\\g<" not in repl else m.expand(repl)

            out = pattern.sub(_r, out)

        sub(_JWT_RE, "jwt", "[JWT]")
        sub(_BEARER_RE, "token", "[TOKEN]")
        sub(_PASSWORD_JSON_RE, "secret_field", r'\g<key>:"[REDACTED]"')
        sub(_PASSWORD_FORM_RE, "secret_field", r"\g<key>[REDACTED]")
        sub(_EMAIL_RE, "email", "[EMAIL]")
        sub(_HASH_RE, "hash", "[HASH]")

        def card(m: re.Match[str]) -> str:
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 16 and _luhn_ok(digits):
                self.counts["card"] += 1
                return "[CARD]"
            return m.group(0)

        out = _CARD_RE.sub(card, out)

        def ip(m: re.Match[str]) -> str:
            value = m.group(0)
            if value.startswith(_LOOPBACK_PREFIXES):
                return value
            self.counts["ip"] += 1
            return "[IP]"

        out = _IPV4_RE.sub(ip, out)

        if len(out) > self.max_chars:
            self.counts["truncated"] += 1
            out = out[: self.max_chars] + f"\n[... truncated {len(out) - self.max_chars} chars]"
        return out

    def report(self) -> dict[str, int]:
        return dict(self.counts)


def sanitize(text: str | None, max_chars: int = 4000) -> tuple[str, dict[str, int]]:
    s = Sanitizer(max_chars=max_chars)
    cleaned = s.clean(text)
    return cleaned, s.report()
