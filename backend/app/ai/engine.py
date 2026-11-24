"""The two AI functions from the proposal.

1. ``analyse_finding``: interpretation and risk scoring.
2. ``remediate_finding``: remediation guidance for a confirmed finding.

Both build a payload from the finding, pass every free-text field through the
sanitiser, record exactly what was sent, call DeepSeek (or the offline rules
engine) and validate the reply before it touches the database. The CVSS score
is always computed locally from the vector.
"""

from __future__ import annotations

import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .. import cvss
from ..config import settings
from ..db import session_scope
from ..models import Finding
from ..sanitize import Sanitizer
from . import offline, prompts
from .client import AIError, DeepSeekClient

OFFLINE_MODEL = "offline-rules"

_pool = ThreadPoolExecutor(max_workers=max(1, settings.ai_concurrency), thread_name_prefix="ai")
_inflight: set[tuple[str, int]] = set()
_lock = threading.Lock()


def model_name() -> str:
    return settings.deepseek_model if settings.ai_mode == "deepseek" else OFFLINE_MODEL


# -- payloads --------------------------------------------------------------

def _evidence_window(raw: str, needle: str, size: int) -> str:
    """Keep the part of a response around the evidence string."""
    if not raw:
        return ""
    head, sep, body = raw.replace("\r\n", "\n").partition("\n\n")
    if not needle or needle not in body or len(body) <= size:
        return head + sep + body[:size]
    i = body.index(needle)
    start = max(0, i - size // 2)
    return head + sep + ("[...]" if start else "") + body[start : start + size]


def analysis_payload(f: Finding) -> tuple[dict[str, Any], dict[str, int]]:
    s = Sanitizer(max_chars=2500)
    payload = {
        "tool": f.source,
        "rule": f.tool_rule_id,
        "title": f.title,
        "tool_description": s.clean(f.description),
        "category": f.category,
        "owasp": f.owasp,
        "wstg": f.wstg,
        "cwe": f.cwe_id,
        "method": f.method,
        "url": s.clean(f.url),
        "parameter": s.clean(f.param),
        "attack": s.clean(f.attack),
        "evidence": s.clean(f.evidence),
        "tool_severity": f.tool_severity,
        "tool_confidence": f.tool_confidence,
        "seen_on_urls": f.occurrences,
        "request": s.clean(f.request_raw),
        "response": s.clean(_evidence_window(f.response_raw, f.evidence, 1800)),
        "stack": "Node.js / Express (OWASP Juice Shop)",
    }
    return payload, s.report()


def remediation_payload(f: Finding) -> tuple[dict[str, Any], dict[str, int]]:
    s = Sanitizer(max_chars=1500)
    payload = {
        "title": f.title,
        "cwe": f.cwe_id,
        "owasp": f.owasp,
        "category": f.category,
        "method": f.method,
        "endpoint": s.clean(f.url),
        "parameter": s.clean(f.param),
        "attack": s.clean(f.attack),
        "evidence": s.clean(f.evidence),
        "confirmed_severity": f.effective_severity,
        "assessor_note": s.clean(f.review_note),
        "analysis_summary": s.clean(f.ai_summary),
        "stack": "Node.js 20, Express 4, Sequelize with SQLite, Angular frontend",
    }
    return payload, s.report()


# -- validation ------------------------------------------------------------

def _text(data: dict, key: str, limit: int = 2000) -> str:
    value = data.get(key, "")
    return str(value).strip()[:limit] if value is not None else ""


def validate_analysis(data: dict) -> dict[str, Any]:
    summary = _text(data, "summary")
    if not summary:
        raise AIError("Analysis is missing 'summary'.")
    vector_raw = _text(data, "cvss_vector", 120)
    try:
        vector = cvss.normalise(vector_raw)
        score = cvss.base_score(vector)
    except cvss.CvssError as exc:
        raise AIError(f"Model returned an invalid CVSS vector '{vector_raw}': {exc}") from exc
    return {
        "summary": summary,
        "impact": _text(data, "impact"),
        "rationale": _text(data, "false_positive_assessment"),
        "confidence": _text(data, "confidence", 10).lower() or "medium",
        "vector": vector,
        "score": score,
        "severity": cvss.severity_for(score),
    }


def validate_remediation(data: dict) -> dict[str, Any]:
    steps = data.get("steps") or []
    if isinstance(steps, str):
        steps = [line.strip("-* ").strip() for line in steps.splitlines() if line.strip()]
    steps = [str(s).strip() for s in steps if str(s).strip()][:12]
    if not steps:
        raise AIError("Remediation has no steps.")
    refs = data.get("references") or []
    if isinstance(refs, str):
        refs = [refs]
    return {
        "root_cause": _text(data, "root_cause", 800),
        "steps": steps,
        "code_language": _text(data, "code_language", 30) or "javascript",
        "code_example": _text(data, "code_example", 6000),
        "verification": _text(data, "verification", 600),
        "references": [str(r)[:200] for r in refs][:8],
    }


# -- calls -----------------------------------------------------------------

def _call(kind: str, payload: dict) -> dict:
    if settings.ai_mode != "deepseek":
        return offline.analyse(payload) if kind == "analysis" else offline.remediate(payload)
    client = DeepSeekClient()
    try:
        if kind == "analysis":
            return client.complete_json(prompts.ANALYSIS_SYSTEM, prompts.analysis_user(payload), max_tokens=3000)
        # Steps plus a full code example: the longest reply, so the largest budget.
        return client.complete_json(prompts.REMEDIATION_SYSTEM, prompts.remediation_user(payload), max_tokens=6000)
    finally:
        client.close()


def analyse_finding(finding_id: int) -> None:
    try:
        _analyse_finding(finding_id)
    finally:
        from .. import notifier

        notifier.safe_emit(notifier.on_analysis_done, finding_id)


def _analyse_finding(finding_id: int) -> None:
    with session_scope() as db:
        f = db.get(Finding, finding_id)
        if f is None:
            return
        payload, redactions = analysis_payload(f)
        f.ai_status = "running"
        f.ai_error = ""
        f.ai_payload = payload
        f.ai_redactions = redactions
    try:
        result = validate_analysis(_call("analysis", payload))
    except Exception as exc:
        with session_scope() as db:
            f = db.get(Finding, finding_id)
            if f:
                f.ai_status = "failed"
                f.ai_error = str(exc)[:1000]
        return
    with session_scope() as db:
        f = db.get(Finding, finding_id)
        if f is None:
            return
        f.ai_status = "done"
        f.ai_model = model_name()
        f.ai_summary = result["summary"]
        f.ai_impact = result["impact"]
        f.ai_rationale = result["rationale"]
        f.ai_false_positive_hint = result["confidence"]
        f.ai_cvss_vector = result["vector"]
        f.ai_cvss_score = result["score"]
        f.ai_severity = result["severity"]


def remediate_finding(finding_id: int) -> None:
    with session_scope() as db:
        f = db.get(Finding, finding_id)
        if f is None:
            return
        payload, _ = remediation_payload(f)
        f.remediation_status = "running"
    try:
        result = validate_remediation(_call("remediation", payload))
    except Exception as exc:
        with session_scope() as db:
            f = db.get(Finding, finding_id)
            if f:
                f.remediation_status = "failed"
                f.remediation = {"error": str(exc)[:1000]}
        return
    with session_scope() as db:
        f = db.get(Finding, finding_id)
        if f:
            f.remediation_status = "done"
            f.remediation = result
            f.remediation_model = model_name()


# -- queue -----------------------------------------------------------------

def _submit(kind: str, finding_id: int, fn) -> bool:
    key = (kind, finding_id)
    with _lock:
        if key in _inflight:
            return False
        _inflight.add(key)

    def run():
        try:
            fn(finding_id)
        finally:
            with _lock:
                _inflight.discard(key)

    _pool.submit(run)
    return True


def queue_analysis(finding_ids: list[int]) -> int:
    return sum(_submit("analysis", fid, analyse_finding) for fid in finding_ids)


def queue_remediation(finding_id: int) -> bool:
    return _submit("remediation", finding_id, remediate_finding)


def redaction_totals(findings: list[Finding]) -> dict[str, int]:
    total: Counter[str] = Counter()
    for f in findings:
        total.update(f.ai_redactions or {})
    return dict(total)

