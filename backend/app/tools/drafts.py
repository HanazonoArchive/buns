from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class FindingDraft:
    """Tool-agnostic finding, before it is stored and analysed."""

    source: str  # "zap" | "curl"
    rule_id: str
    title: str
    description: str
    category: str
    owasp: str
    wstg: str
    cwe_id: int | None
    method: str
    url: str
    severity: str
    confidence: str = ""
    param: str = ""
    attack: str = ""
    evidence: str = ""
    request_raw: str = ""
    response_raw: str = ""
    occurrences: int = 1
    # Curl header checks overlap with ZAP passive rules; drop them when ZAP
    # produced a finding with the same CWE.
    yields_to_zap: bool = False
    # Other CWEs ZAP may use for the same issue.
    zap_cwes: tuple[int, ...] = ()
    affected_urls: list[str] = field(default_factory=list)
    # ZAP history id of the representative alert, used to fetch the exchange.
    message_id: str = ""
    # Path used in the fingerprint. "" for site-wide (passive) ZAP findings,
    # which are one finding however many URLs they appear on.
    group_path: str | None = None

    def fingerprint(self) -> str:
        path = self.group_path if self.group_path is not None else urlsplit(self.url).path
        return make_fingerprint(self.source, self.rule_id, self.method, path, self.param)


def make_fingerprint(source: str, rule_id: str, method: str, path: str, param: str) -> str:
    """Stable identity of a finding within a target."""
    # "" means site-wide; otherwise ignore a trailing slash ("/ftp" == "/ftp/").
    norm_path = (path.rstrip("/") or "/") if path else ""
    return "|".join((source, rule_id, (method or "GET").upper(), norm_path, param or ""))
