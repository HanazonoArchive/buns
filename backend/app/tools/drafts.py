from __future__ import annotations

from dataclasses import dataclass, field


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
