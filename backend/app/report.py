"""PDF security assessment report (ReportLab).

Only findings a human confirmed are reported as vulnerabilities. Rejected
findings are listed in an appendix with the assessor's reason so the reader
can see what was dismissed and why.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import SEVERITIES, Finding, Scan, Target
from .sanitize import Sanitizer
from .taxonomy import CATEGORY_LABELS

INK = colors.HexColor("#16181d")
MUTED = colors.HexColor("#5b616e")
RULE = colors.HexColor("#d9d6cf")
PAPER = colors.HexColor("#f4f2ed")

SEV_COLOR = {
    "critical": colors.HexColor("#8f1d1d"),
    "high": colors.HexColor("#c2410c"),
    "medium": colors.HexColor("#b7791f"),
    "low": colors.HexColor("#2f6f8f"),
    "info": colors.HexColor("#6b7280"),
}
SEV_LABEL = {s: s.capitalize() if s != "info" else "Informational" for s in SEVERITIES}

_base = dict(fontName="Helvetica", textColor=INK, leading=13.5, fontSize=9.6, alignment=TA_LEFT)
S = {
    "body": ParagraphStyle("body", **_base, spaceAfter=6),
    "small": ParagraphStyle("small", **{**_base, "fontSize": 8.2, "leading": 11, "textColor": MUTED}),
    "h1": ParagraphStyle("h1", **{**_base, "fontName": "Helvetica-Bold", "fontSize": 17, "leading": 22, "spaceAfter": 10, "spaceBefore": 4}),
    "h2": ParagraphStyle("h2", **{**_base, "fontName": "Helvetica-Bold", "fontSize": 12.5, "leading": 16, "spaceAfter": 6, "spaceBefore": 12}),
    "h3": ParagraphStyle("h3", **{**_base, "fontName": "Helvetica-Bold", "fontSize": 9.6, "leading": 13, "spaceAfter": 3, "spaceBefore": 8}),
    "label": ParagraphStyle("label", **{**_base, "fontName": "Helvetica-Bold", "fontSize": 7.6, "leading": 10, "textColor": MUTED}),
    "cell": ParagraphStyle("cell", **{**_base, "fontSize": 8.6, "leading": 11.2}),
    "cellb": ParagraphStyle("cellb", **{**_base, "fontName": "Helvetica-Bold", "fontSize": 8.6, "leading": 11.2}),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=7.4, leading=9.4, textColor=INK),
    "bullet": ParagraphStyle("bullet", **{**_base, "leftIndent": 14, "bulletIndent": 2, "spaceAfter": 3}),
    "cover_title": ParagraphStyle("ct", **{**_base, "fontName": "Helvetica-Bold", "fontSize": 28, "leading": 33}),
    "cover_sub": ParagraphStyle("cs", **{**_base, "fontSize": 13, "leading": 18, "textColor": MUTED}),
}

_NON_LATIN = re.compile(r"[^\x09\x0a\x0d\x20-\x7e\xa0-\xff]")


def _latin(text: str) -> str:
    """Built-in PDF fonts are Latin-1 only; replace anything else visibly."""
    text = (text or "").replace("—", "-").replace("–", "-").replace("’", "'")
    text = text.replace("“", '"').replace("”", '"').replace("…", "...")
    return _NON_LATIN.sub("?", text)


def P(text: str, style: str = "body") -> Paragraph:
    return Paragraph(escape(_latin(text)).replace("\n", "<br/>"), S[style])


def Praw(markup: str, style: str = "body") -> Paragraph:
    return Paragraph(markup, S[style])


def _n(count: int, singular: str, plural: str | None = None) -> str:
    """'1 finding', '3 findings'; with verbs: _n(1, 'was', 'were') -> '1 was'."""
    if plural is None:
        plural = singular + "s"
    return f"{count} {singular if count == 1 else plural}"


def fid(f: Finding) -> str:
    return f"BUNS-{f.id:03d}"


def _wrap_mono(text: str, width: int = 104, max_lines: int = 40) -> str:
    out: list[str] = []
    for line in _latin(text).replace("\r\n", "\n").split("\n"):
        while len(line) > width:
            out.append(line[:width])
            line = "  " + line[width:]
        out.append(line)
    if len(out) > max_lines:
        out = out[:max_lines] + [f"[... {len(out) - max_lines} more lines in the platform]"]
    return "\n".join(out)


def _inline(text: str) -> str:
    """Escape for ReportLab, turning `backticked` fragments into monospace."""
    parts = _latin(text or "").split("`")
    return "".join(f'<font face="Courier">{escape(p)}</font>' if i % 2 else escape(p) for i, p in enumerate(parts))


def code_box(text: str, max_lines: int = 40) -> Table:
    pre = Preformatted(_wrap_mono(text, max_lines=max_lines), S["mono"])
    t = Table([[pre]], colWidths=[170 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PAPER),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def _grid(rows, widths, header=True, zebra=False) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [("LINEBELOW", (0, 0), (-1, 0), 0.9, INK)]
    if zebra:
        for r in range(1, len(rows)):
            if r % 2 == 0:
                style.append(("BACKGROUND", (0, r), (-1, r), PAPER))
    t.setStyle(TableStyle(style))
    return t


def _sev_chip(sev: str) -> Paragraph:
    c = SEV_COLOR.get(sev, MUTED).hexval().replace("0x", "#")
    return Praw(f'<font color="{c}"><b>{SEV_LABEL.get(sev, sev)}</b></font>', "cell")


def severity_chart(counts: dict[str, int]) -> Drawing:
    w, row_h, label_w = 170 * mm, 15, 70
    d = Drawing(w, row_h * len(SEVERITIES) + 4)
    top = max(counts.values()) if any(counts.values()) else 1
    bar_w = w - label_w - 30
    for i, sev in enumerate(SEVERITIES):
        y = d.height - (i + 1) * row_h
        d.add(String(0, y + 4, SEV_LABEL[sev], fontName="Helvetica", fontSize=8, fillColor=INK))
        d.add(Rect(label_w, y + 2, bar_w, row_h - 6, fillColor=PAPER, strokeColor=None))
        n = counts.get(sev, 0)
        if n:
            d.add(Rect(label_w, y + 2, bar_w * n / top, row_h - 6, fillColor=SEV_COLOR[sev], strokeColor=None))
        d.add(String(label_w + bar_w + 6, y + 4, str(n), fontName="Helvetica-Bold", fontSize=8, fillColor=INK))
    return d


class _Doc(SimpleDocTemplate):
    def __init__(self, path: Path, target: Target, generated: str):
        super().__init__(
            str(path), pagesize=A4,
            leftMargin=20 * mm, rightMargin=20 * mm, topMargin=20 * mm, bottomMargin=18 * mm,
            title=f"Security assessment - {target.name}", author="buns", subject="Web application security assessment",
        )
        self.target = target
        self.generated = generated

    def afterPage(self):
        c = self.canv
        page = c.getPageNumber()
        if page == 1:
            return
        c.saveState()
        c.setStrokeColor(RULE)
        c.setLineWidth(0.5)
        c.line(20 * mm, A4[1] - 13 * mm, A4[0] - 20 * mm, A4[1] - 13 * mm)
        c.setFont("Helvetica", 7.5)
        c.setFillColor(MUTED)
        c.drawString(20 * mm, A4[1] - 11 * mm, _latin(f"{self.target.name}  /  Security assessment report"))
        c.drawRightString(A4[0] - 20 * mm, A4[1] - 11 * mm, "CONFIDENTIAL - LAB USE")
        c.drawString(20 * mm, 10 * mm, f"Generated {self.generated} by buns")
        c.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {page}")
        c.restoreState()


def _clean(text: str, limit: int = 2400) -> str:
    return Sanitizer(max_chars=limit).clean(text)


def build_report(db: Session, target: Target, prepared_by: str, path: Path) -> Path:
    findings = list(db.scalars(select(Finding).where(Finding.target_id == target.id)))
    order = {s: i for i, s in enumerate(SEVERITIES)}
    confirmed = sorted(
        (f for f in findings if f.status == "confirmed"),
        key=lambda f: (order.get(f.final_severity, 9), -(f.ai_cvss_score or 0), f.id),
    )
    rejected = [f for f in findings if f.status == "rejected"]
    pending = [f for f in findings if f.status == "pending"]
    scans = list(db.scalars(select(Scan).where(Scan.target_id == target.id).order_by(Scan.id)))
    done_scans = [s for s in scans if s.status == "completed"]

    now = datetime.now(timezone.utc)
    generated = now.strftime("%d %b %Y %H:%M UTC")
    doc = _Doc(path, target, generated)
    story: list = []

    # -- cover --
    story += [Spacer(1, 55 * mm), P("Web Application Security Assessment", "cover_title"), Spacer(1, 4 * mm),
              P(target.name, "cover_sub"), Spacer(1, 18 * mm)]
    period = ""
    if done_scans:
        first = min(s.started_at or s.created_at for s in done_scans)
        last = max(s.finished_at or s.created_at for s in done_scans)
        period = f"{first:%d %b %Y} to {last:%d %b %Y}" if first.date() != last.date() else f"{first:%d %b %Y}"
    meta = [
        ("Target", target.base_url),
        ("Assessment period", period or "-"),
        ("Prepared by", prepared_by),
        ("Report date", now.strftime("%d %B %Y")),
        ("Method", "OWASP ZAP and cURL, AI-assisted triage, human-verified findings"),
        ("Classification", "Confidential. Lab environment only."),
    ]
    t = Table([[P(k.upper(), "label"), P(v, "body")] for k, v in meta], colWidths=[42 * mm, 128 * mm])
    t.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, 0), 1.2, INK), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 6),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story += [t, PageBreak()]

    # -- 1. executive summary --
    sev_counts = Counter(f.final_severity for f in confirmed)
    story.append(P("1. Executive summary", "h1"))
    worst = next((s for s in SEVERITIES if sev_counts.get(s)), None)
    intro = (
        f"The assessment of {target.name} ({target.base_url}) produced {_n(len(findings), 'candidate finding')} "
        f"from automated tooling across {_n(len(done_scans), 'completed scan')}. Each candidate was reviewed by "
        f"an assessor against its raw HTTP evidence: {_n(len(confirmed), 'was', 'were')} confirmed as "
        f"vulnerabilities and {_n(len(rejected), 'was', 'were')} rejected as false positives"
        + (f"; {_n(len(pending), 'was', 'were')} still awaiting review when this report was generated." if pending else ".")
    )
    story.append(P(intro))
    if worst in ("critical", "high"):
        n_ch = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
        story.append(P(
            f"{_n(n_ch, 'finding is', 'findings are')} rated High or Critical. These allow an unauthenticated or low-privileged "
            "user to reach data or functions they should not, and should be fixed before any other work on "
            "this application."
        ))
    story += [Spacer(1, 3 * mm), P("Confirmed findings by severity", "h3"), severity_chart(sev_counts), Spacer(1, 4 * mm)]

    cat_rows = [[P("Assessment category", "label"), P("Confirmed", "label"), P("Rejected", "label"), P("Highest severity", "label")]]
    for cat, label in CATEGORY_LABELS.items():
        in_cat = [f for f in confirmed if f.category == cat]
        rej = sum(1 for f in rejected if f.category == cat)
        top = min((order[f.final_severity] for f in in_cat), default=None)
        cat_rows.append([P(label, "cell"), P(str(len(in_cat)), "cell"), P(str(rej), "cell"),
                         _sev_chip(SEVERITIES[top]) if top is not None else P("-", "cell")])
    story.append(_grid(cat_rows, [80 * mm, 25 * mm, 25 * mm, 40 * mm]))

    # -- 2. scope and method --
    story += [CondPageBreak(80 * mm), P("2. Scope and methodology", "h1"), P("Authorisation", "h2"),
              P(target.authorization_notes), P("Scope", "h2")]
    scope_rows = [[P("Origin", "label"), P(target.base_url, "cell")],
                  [P("In scope", "label"), P(", ".join(target.in_scope) or "All paths on the origin", "cell")],
                  [P("Excluded", "label"), P(", ".join(target.out_of_scope) or "None", "cell")]]
    story.append(_grid(scope_rows, [30 * mm, 140 * mm], header=False))
    story += [Spacer(1, 2 * mm), P(
        "Every request made by the platform, whether sent by cURL or handed to ZAP, was checked against these "
        "rules before it left the system. ZAP ran inside a context restricted to the same include and exclude "
        "patterns, and alerts outside the scope were discarded.", "small")]
    story.append(P("Approach", "h2"))
    story.append(P(
        "Test cases follow the OWASP Web Security Testing Guide v4.2 and findings are classified against the "
        "OWASP Top 10 (2021). The assessment covered four categories: authentication, access control, input "
        "validation and injection, and information disclosure."))
    steps = [
        "Reconnaissance: ZAP spider and cURL header, robots.txt and error-handling checks map routes and server behaviour.",
        "Scanning: ZAP passive scan on all traffic, then an active scan with a policy limited to the selected categories. Targeted cURL probes cover login, registration, object-level access and search.",
        "AI triage: each candidate is sanitised (tokens, cookies, credentials, emails and hashes removed) and sent to the language model, which explains it, judges false-positive likelihood and proposes a CVSS v3.1 vector. The platform computes the score from the vector.",
        "Human verification: an assessor compares the explanation with the raw request and response, then confirms, rejects or re-rates each finding. Nothing reaches this report without that decision.",
        "Remediation: confirmed findings receive fix steps and a code example for the Node.js/Express stack.",
    ]
    for s in steps:
        story.append(Paragraph(escape(s), S["bullet"], bulletText="•"))
    ai_models = sorted({f.ai_model for f in findings if f.ai_model})
    red = Counter()
    for f in findings:
        red.update(f.ai_redactions or {})
    if ai_models:
        note = f"Model(s) used for triage: {', '.join(ai_models)}."
        if "offline-rules" in ai_models:
            note += (" 'offline-rules' marks findings analysed by the platform's built-in rules engine "
                     "because no AI API key was configured; those explanations are templates, not model output.")
        if red:
            parts = ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in red.most_common())
            note += f" Values redacted before any AI call: {parts}."
        story.append(P(note, "small"))
    story.append(P("Limitations", "h2"))
    story.append(P(
        "Testing was non-destructive and limited to a single local instance. Automated tools do not find most "
        "business-logic flaws; the absence of a finding in a category is not proof that the category is free of "
        "vulnerabilities."))

    # -- 3. findings overview --
    story += [CondPageBreak(90 * mm), P("3. Findings overview", "h1")]
    rows = [[P("ID", "label"), P("Finding", "label"), P("Severity", "label"), P("CVSS", "label"), P("OWASP", "label")]]
    for f in confirmed:
        rows.append([P(fid(f), "cellb"), P(f.title, "cell"), _sev_chip(f.final_severity),
                     P(f"{f.ai_cvss_score:.1f}" if f.ai_cvss_score is not None else "-", "cell"),
                     P(f.owasp.split(" ", 1)[0] if f.owasp else "-", "cell")])
    story.append(_grid(rows, [22 * mm, 88 * mm, 25 * mm, 13 * mm, 22 * mm], zebra=True))

    # -- 4. details --
    story += [PageBreak(), P("4. Detailed findings", "h1")]
    for i, f in enumerate(confirmed):
        if i:
            story.append(CondPageBreak(120 * mm))
        story += _finding_block(f)

    # -- appendix --
    if rejected:
        story += [PageBreak(), P("Appendix A. Rejected candidates", "h1"), P(
            "Tool results the assessor reviewed and judged to be false positives or not applicable. They are "
            "listed so the reader can check the reasoning.", "small"), Spacer(1, 2 * mm)]
        rows = [[P("Candidate", "label"), P("Endpoint", "label"), P("Reason", "label"), P("Reviewer", "label")]]
        for f in sorted(rejected, key=lambda x: x.id):
            rows.append([P(f"{fid(f)}  {f.title}", "cell"), P(_short_url(f.url), "cell"),
                         P(f.review_note, "cell"), P(f.reviewer, "cell")])
        story.append(_grid(rows, [52 * mm, 40 * mm, 58 * mm, 20 * mm], zebra=True))

    doc.build(story)
    return path


def _short_url(url: str) -> str:
    from urllib.parse import urlsplit

    p = urlsplit(url)
    s = (p.path or "/") + (f"?{p.query}" if p.query else "") + (f"#{p.fragment}" if p.fragment else "")
    return s if len(s) <= 70 else s[:67] + "..."


def _finding_block(f: Finding) -> list:
    sev = f.final_severity
    color = SEV_COLOR.get(sev, MUTED)
    head = Table([[Praw(f'<font color="white"><b>{fid(f)}</b></font>', "cell"),
                   Praw(f'<font color="white"><b>{escape(_latin(f.title))}</b></font>', "cell"),
                   Praw(f'<font color="white"><b>{SEV_LABEL[sev].upper()}</b></font>', "cell")]],
                 colWidths=[22 * mm, 118 * mm, 30 * mm])
    head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                              ("ALIGN", (2, 0), (2, 0), "RIGHT")]))

    suggested = f.ai_severity or f.tool_severity
    sev_text = SEV_LABEL[sev] + ("" if suggested == sev else f" (suggested: {SEV_LABEL.get(suggested, suggested)})")
    cvss = f"{f.ai_cvss_score:.1f}  {f.ai_cvss_vector}" if f.ai_cvss_score is not None else "-"
    meta = [
        ("Endpoint", f"{f.method} {_short_url(f.url)}" + (f"  (parameter: {f.param})" if f.param else "")
         + (f"\nand {len(f.affected_urls) - 1} more URL(s), e.g. "
            + ", ".join(_short_url(u) for u in f.affected_urls[1:4]) if len(f.affected_urls or []) > 1 else "")),
        ("Severity", sev_text),
        ("CVSS v3.1", cvss),
        ("Classification", " / ".join(x for x in (f.owasp, f.wstg, f"CWE-{f.cwe_id}" if f.cwe_id else "") if x)),
        ("Detected by", ("OWASP ZAP" if f.source == "zap" else "cURL probe") + f" ({f.tool_rule_id})"),
        ("Verified by", f"{f.reviewer}, {f.reviewed_at:%d %b %Y}" if f.reviewed_at else f.reviewer),
    ]
    mt = _grid([[P(k.upper(), "label"), P(v, "cell")] for k, v in meta], [30 * mm, 140 * mm], header=False)

    out: list = [KeepTogether([head, Spacer(1, 2 * mm), mt])]
    out.append(P("Description", "h3"))
    out.append(P(f.ai_summary or f.description or "-"))
    if f.ai_impact:
        out += [P("Impact", "h3"), P(f.ai_impact)]
    if f.review_note:
        out += [P("Assessor note", "h3"), P(f.review_note)]

    out.append(P("Evidence", "h3"))
    if f.attack or f.evidence:
        bits = []
        if f.attack:
            bits.append(f"<b>Payload:</b> <font face='Courier'>{escape(_latin(_clean(f.attack, 300)))}</font>")
        if f.evidence:
            bits.append(f"<b>Matched:</b> <font face='Courier'>{escape(_latin(_clean(f.evidence, 400)))}</font>")
        out.append(Praw("<br/>".join(bits), "cell"))
        out.append(Spacer(1, 2 * mm))
    if f.request_raw:
        out += [KeepTogether([P("REQUEST", "label"), code_box(_clean(f.request_raw, 1600), 18)]), Spacer(1, 2 * mm)]
    if f.response_raw:
        out += [KeepTogether([P("RESPONSE (excerpt)", "label"), code_box(_clean(f.response_raw, 1600), 22)])]
    out.append(P("Secrets, tokens and email addresses in the evidence are masked.", "small"))

    rem = f.remediation or {}
    if rem.get("steps"):
        out.append(P("Remediation", "h3"))
        if rem.get("root_cause"):
            out.append(Praw(f"<b>Root cause.</b> {_inline(rem['root_cause'])}"))
        paras = []
        for n, step in enumerate(rem["steps"], 1):
            if isinstance(step, dict):
                title, detail = step.get("title", ""), step.get("detail", "")
            else:
                title, detail = "", str(step)
            text = (f"<b>{_inline(title)}.</b> " if title else "") + _inline(detail)
            paras.append(Paragraph(text, S["bullet"], bulletText=f"{n}."))
        # Keep the label with the first step so it never sits alone at a page foot.
        out.append(KeepTogether([P("FIX STEPS", "label"), paras[0]]))
        out += paras[1:]
        if rem.get("code_example") and not rem["code_example"].startswith("// No generic"):
            out += [Spacer(1, 1 * mm), KeepTogether([
                P(f"EXAMPLE ({rem.get('code_language', 'code').upper()})", "label"),
                code_box(rem["code_example"], 45)])]
        if rem.get("verification"):
            out += [Spacer(1, 2 * mm), Praw(f"<b>Verify.</b> {_inline(rem['verification'])}")]
        if rem.get("references"):
            out.append(Praw("<b>References.</b> " + "; ".join(escape(_latin(r)) for r in rem["references"])))
    out.append(Spacer(1, 6 * mm))
    return out
