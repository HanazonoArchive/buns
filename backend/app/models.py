from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


SEVERITIES = ("critical", "high", "medium", "low", "info")
CATEGORIES = ("authentication", "access_control", "injection", "info_disclosure")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    base_url: Mapped[str] = mapped_column(String(500))
    authorization_notes: Mapped[str] = mapped_column(Text, default="")
    # Path prefixes (e.g. "/rest/") that may be tested. Empty list = whole origin.
    in_scope: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Path prefixes that must never be requested, even if in scope.
    out_of_scope: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Optional synthetic test account used for access-control checks.
    test_email: Mapped[str] = mapped_column(String(200), default="")
    test_password: Mapped[str] = mapped_column(String(200), default="")
    # Who is responsible for the system: told when something breaks.
    owner_name: Mapped[str] = mapped_column(String(120), default="")
    owner_email: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scans: Mapped[list[Scan]] = relationship(
        back_populates="target", cascade="all, delete-orphan", order_by="Scan.id.desc()"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed
    phase: Mapped[str] = mapped_column(String(40), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    active_scan: Mapped[bool] = mapped_column(default=True)
    ajax_spider: Mapped[bool] = mapped_column(default=False)
    log: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    # Set once the "analysis finished" notification has been sent.
    analysis_notified: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")
    endpoints: Mapped[list[Endpoint]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    method: Mapped[str] = mapped_column(String(10), default="GET")
    url: Mapped[str] = mapped_column(String(1000))
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String(30))  # zap-spider | zap-history | curl

    scan: Mapped[Scan] = relationship(back_populates="endpoints")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))

    # What the tool reported
    source: Mapped[str] = mapped_column(String(20))  # zap | curl
    tool_rule_id: Mapped[str] = mapped_column(String(40), default="")
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(30))  # one of CATEGORIES
    owasp: Mapped[str] = mapped_column(String(60), default="")  # e.g. "A03:2021 Injection"
    wstg: Mapped[str] = mapped_column(String(40), default="")
    cwe_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    method: Mapped[str] = mapped_column(String(10), default="GET")
    url: Mapped[str] = mapped_column(String(1000))
    param: Mapped[str] = mapped_column(String(200), default="")
    attack: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    request_raw: Mapped[str] = mapped_column(Text, default="")
    response_raw: Mapped[str] = mapped_column(Text, default="")
    tool_severity: Mapped[str] = mapped_column(String(10), default="info")
    tool_confidence: Mapped[str] = mapped_column(String(20), default="")
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    affected_urls: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Identity across scans: the same rule on the same endpoint and parameter
    # of the same target is the same finding. scan_id is the first scan that
    # reported it; finding_scans records every scan that has seen it since.
    fingerprint: Mapped[str] = mapped_column(String(400), default="", index=True)
    times_seen: Mapped[int] = mapped_column(Integer, default=1)
    last_seen_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # AI function 1: interpretation and risk scoring
    ai_status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|running|done|failed
    ai_model: Mapped[str] = mapped_column(String(60), default="")
    ai_summary: Mapped[str] = mapped_column(Text, default="")
    ai_impact: Mapped[str] = mapped_column(Text, default="")
    ai_rationale: Mapped[str] = mapped_column(Text, default="")
    ai_severity: Mapped[str] = mapped_column(String(10), default="")
    ai_cvss_vector: Mapped[str] = mapped_column(String(80), default="")
    ai_cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ai_false_positive_hint: Mapped[str] = mapped_column(Text, default="")
    ai_error: Mapped[str] = mapped_column(Text, default="")
    # Exactly what left the system for the AI call, after sanitisation.
    ai_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    ai_redactions: Mapped[dict[str, int] | None] = mapped_column(JSON, nullable=True)

    # AI function 2: remediation
    remediation_status: Mapped[str] = mapped_column(String(20), default="none")  # none|running|done|failed
    remediation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    remediation_model: Mapped[str] = mapped_column(String(60), default="")

    # Human verification
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|confirmed|rejected
    final_severity: Mapped[str] = mapped_column(String(10), default="")
    reviewer: Mapped[str] = mapped_column(String(120), default="")
    review_note: Mapped[str] = mapped_column(Text, default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    target: Mapped[Target] = relationship()

    @property
    def target_name(self) -> str:
        return self.target.name if self.target else ""

    @property
    def effective_severity(self) -> str:
        return self.final_severity or self.ai_severity or self.tool_severity


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    filename: Mapped[str] = mapped_column(String(200))
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    prepared_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    target: Mapped[Target] = relationship()


NOTIFY_EVENTS = (
    "finding.detected",   # analysis rated a new finding critical or high
    "scan.analysed",      # every finding of a scan has been analysed
    "scan.failed",
    "finding.confirmed",  # an assessor confirmed a finding
    "report.generated",
)
CHANNEL_KINDS = ("email", "discord", "slack", "telegram", "webhook")


class Channel(Base):
    """Somewhere notifications are delivered, besides the in-app bell."""

    __tablename__ = "channels"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(20))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    events: Mapped[list[str]] = mapped_column(JSON, default=list)
    min_severity: Mapped[str] = mapped_column(String(10), default="high")
    # None = every target.
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=True)
    notify_owner: Mapped[bool] = mapped_column(default=False)
    enabled: Mapped[bool] = mapped_column(default=True)
    last_status: Mapped[str] = mapped_column(String(20), default="")
    last_error: Mapped[str] = mapped_column(Text, default="")
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    event: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10), default="")
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text, default="")
    link: Mapped[str] = mapped_column(String(300), default="")
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    read: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    deliveries: Mapped[list[Delivery]] = relationship(
        back_populates="notification", cascade="all, delete-orphan", order_by="Delivery.id"
    )


class Delivery(Base):
    __tablename__ = "deliveries"

    id: Mapped[int] = mapped_column(primary_key=True)
    notification_id: Mapped[int] = mapped_column(ForeignKey("notifications.id", ondelete="CASCADE"))
    channel_id: Mapped[int | None] = mapped_column(ForeignKey("channels.id", ondelete="SET NULL"), nullable=True)
    channel_name: Mapped[str] = mapped_column(String(120), default="")
    kind: Mapped[str] = mapped_column(String(20), default="")
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|sent|failed
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    notification: Mapped[Notification] = relationship(back_populates="deliveries")


class FindingScan(Base):
    """Which scans reported a finding (a finding can be seen by many scans)."""

    __tablename__ = "finding_scans"

    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True, index=True)
