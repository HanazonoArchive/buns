"""Turn raw ZAP alerts into tool-agnostic finding drafts."""

from __future__ import annotations

import html
import re
from collections import defaultdict
from urllib.parse import urlsplit

from ..taxonomy import ZAP_RISK, classify
from .drafts import FindingDraft


def _int_or_none(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _clean(text: str | None) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text).strip()


def _group_key(a: dict) -> tuple:
    rule = a.get("pluginId") or a.get("alertRef") or a.get("alert")
    if a.get("attack"):
        # Active findings: each injectable endpoint/parameter is its own issue.
        path = urlsplit(a.get("url", "")).path
        return (rule, path, a.get("param", ""))
    # Passive findings (missing headers, CORS, comments...) describe one
    # site-wide misconfiguration seen on many URLs: review it once.
    return (rule, "", a.get("param", ""))


def normalize_zap_alerts(alerts: list[dict]) -> list[FindingDraft]:
    """Group ZAP alerts into reviewable findings and keep the richest instance."""
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for a in alerts:
        grouped[_group_key(a)].append(a)

    drafts: list[FindingDraft] = []
    for _key, group in grouped.items():
        a = max(group, key=lambda x: len(x.get("evidence", "")) + len(x.get("attack", "")))
        cwe = _int_or_none(a.get("cweid"))
        if cwe in (-1, 0):
            cwe = None
        category, owasp, wstg = classify(cwe)
        severity = ZAP_RISK.get(str(a.get("risk") if str(a.get("risk", "")).isdigit() else ""), None)
        if severity is None:
            severity = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}.get(
                a.get("risk", "Informational"), "info"
            )

        req = (a.get("request-header", "") or "") + (a.get("request-body", "") or "")
        resp = (a.get("response-header", "") or "") + (a.get("response-body", "") or "")

        drafts.append(FindingDraft(
            source="zap",
            rule_id=f"zap:{a.get('pluginId', '')}",
            title=_clean(a.get("name") or a.get("alert")),
            description=_clean(a.get("description")),
            category=category,
            owasp=owasp,
            wstg=wstg,
            cwe_id=cwe,
            method=(a.get("method") or "GET"),
            url=a.get("url", ""),
            severity=severity,
            confidence=a.get("confidence", ""),
            param=a.get("param", ""),
            attack=a.get("attack", ""),
            evidence=a.get("evidence", ""),
            request_raw=req,
            response_raw=resp,
            occurrences=len(group),
            affected_urls=sorted({x.get("url", "") for x in group if x.get("url")})[:200],
            message_id=str(a.get("messageId") or ""),
            group_path=_group_key(a)[1],
        ))
    return drafts


def _endpoint_key(d: FindingDraft) -> tuple:
    return (d.cwe_id, d.method.upper(), urlsplit(d.url).path, d.param)


def dedupe(drafts: list[FindingDraft]) -> list[FindingDraft]:
    """Remove findings two tools reported for the same issue.

    - A cURL header check yields to the equivalent ZAP passive rule.
    - A ZAP alert on the same CWE, endpoint and parameter as a cURL probe
      yields to the probe, whose evidence shows the exploit working; the
      probe notes that ZAP agreed.
    """
    curl_by_endpoint = {_endpoint_key(d): d for d in drafts if d.source == "curl" and d.cwe_id}
    merged: list[FindingDraft] = []
    for d in drafts:
        twin = curl_by_endpoint.get(_endpoint_key(d)) if d.source == "zap" else None
        if twin is not None:
            twin.description += f" OWASP ZAP reported the same issue independently ({d.title}, rule {d.rule_id})."
            continue
        merged.append(d)
    drafts = merged
    zap_cwes = {d.cwe_id for d in drafts if d.source == "zap" and d.cwe_id is not None}
    kept: list[FindingDraft] = []
    for d in drafts:
        if d.source == "curl" and d.yields_to_zap and ({d.cwe_id, *d.zap_cwes} & zap_cwes):
            continue
        kept.append(d)
    return kept
