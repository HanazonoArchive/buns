from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import CATEGORIES

Severity = Literal["critical", "high", "medium", "low", "info"]
Category = Literal["authentication", "access_control", "injection", "info_disclosure"]


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# -- targets ---------------------------------------------------------------

class TargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    base_url: str = Field(min_length=1, max_length=500)
    authorization_notes: str = Field(min_length=10, max_length=4000)
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    test_email: str = ""
    test_password: str = ""


class TargetPatch(BaseModel):
    name: str | None = None
    authorization_notes: str | None = None
    in_scope: list[str] | None = None
    out_of_scope: list[str] | None = None
    test_email: str | None = None
    test_password: str | None = None


class TargetOut(_Out):
    id: int
    name: str
    base_url: str
    authorization_notes: str
    in_scope: list[str]
    out_of_scope: list[str]
    test_email: str
    has_test_password: bool = False
    created_at: datetime
    scan_count: int = 0
    finding_count: int = 0


class ScopeCheckIn(BaseModel):
    url: str


class ScopeCheckOut(BaseModel):
    allowed: bool
    reason: str


# -- scans -----------------------------------------------------------------

class ScanIn(BaseModel):
    categories: list[Category] = Field(default_factory=lambda: list(CATEGORIES))
    active_scan: bool = True
    ajax_spider: bool = False

    @field_validator("categories")
    @classmethod
    def _non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Pick at least one assessment category.")
        return list(dict.fromkeys(v))


class ScanOut(_Out):
    id: int
    target_id: int
    target_name: str = ""
    status: str
    phase: str
    progress: int
    categories: list[str]
    active_scan: bool
    ajax_spider: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    finding_count: int = 0
    endpoint_count: int = 0


class EndpointOut(_Out):
    id: int
    method: str
    url: str
    status_code: int | None
    source: str


class ScanDetail(ScanOut):
    log: str
    error: str
    endpoints: list[EndpointOut] = Field(default_factory=list)


# -- findings --------------------------------------------------------------

class FindingSummary(_Out):
    id: int
    scan_id: int
    target_id: int
    source: str
    title: str
    category: str
    owasp: str
    cwe_id: int | None
    method: str
    url: str
    param: str
    tool_severity: str
    ai_status: str
    ai_severity: str
    ai_cvss_score: float | None
    status: str
    final_severity: str
    effective_severity: str
    occurrences: int
    created_at: datetime


class FindingDetail(FindingSummary):
    tool_rule_id: str
    description: str
    wstg: str
    attack: str
    evidence: str
    request_raw: str
    response_raw: str
    tool_confidence: str
    ai_model: str
    ai_summary: str
    ai_impact: str
    ai_rationale: str
    ai_false_positive_hint: str
    ai_cvss_vector: str
    ai_error: str
    ai_payload: dict[str, Any] | None
    ai_redactions: dict[str, int] | None
    remediation_status: str
    remediation: dict[str, Any] | None
    remediation_model: str
    reviewer: str
    review_note: str
    reviewed_at: datetime | None
    curl_command: str = ""


class ReviewIn(BaseModel):
    decision: Literal["confirm", "reject", "reset"]
    severity: Severity | None = None
    reviewer: str = Field(default="", max_length=120)
    note: str = Field(default="", max_length=4000)


# -- dashboard and reports -------------------------------------------------

class DashboardOut(BaseModel):
    targets: int
    scans: int
    scans_running: int
    findings: int
    pending: int
    confirmed: int
    rejected: int
    ai_done: int
    severity_confirmed: dict[str, int]
    severity_open: dict[str, int]
    by_category: dict[str, dict[str, int]]
    recent_scans: list[ScanOut]
    redactions: dict[str, int]
    ai_mode: str


class ReportIn(BaseModel):
    prepared_by: str = Field(min_length=1, max_length=120)


class ReportOut(_Out):
    id: int
    target_id: int
    filename: str
    findings_count: int
    prepared_by: str
    created_at: datetime


class HealthOut(BaseModel):
    status: str
    zap: str
    curl: bool
    ai_mode: str
    ai_model: str
    allowed_hosts: list[str]
