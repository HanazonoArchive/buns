"""Turn raw ZAP alerts into tool-agnostic finding drafts."""

from __future__ import annotations

import html
import re
from collections import defaultdict

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


def normalize_zap_alerts(alerts: list[dict]) -> list[FindingDraft]:
    """Group ZAP alerts by (rule, url, param) and keep the richest instance."""
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for a in alerts:
        key = (a.get("pluginId") or a.get("alertRef") or a.get("alert"), a.get("url"), a.get("param", ""))
        grouped[key].append(a)

    drafts: list[FindingDraft] = []
    for (_rule, _url, _param), group in grouped.items():
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
        ))
    return drafts


def dedupe(drafts: list[FindingDraft]) -> list[FindingDraft]:
    """Drop cURL header findings already reported by a ZAP passive rule."""
    zap_cwes = {d.cwe_id for d in drafts if d.source == "zap" and d.cwe_id is not None}
    kept: list[FindingDraft] = []
    for d in drafts:
        if d.source == "curl" and d.yields_to_zap and d.cwe_id in zap_cwes:
            continue
        kept.append(d)
    return kept
