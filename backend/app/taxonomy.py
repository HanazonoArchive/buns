"""Mapping between tool output and the frameworks named in the proposal:
OWASP Top 10 (2021) and the OWASP Web Security Testing Guide (v4.2)."""

from __future__ import annotations

OWASP_2021 = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

CATEGORY_LABELS = {
    "authentication": "Authentication and login security",
    "access_control": "Access control and authorization",
    "injection": "Input validation and injection",
    "info_disclosure": "Information disclosure",
}

# CWE -> (assessment category, OWASP key, WSTG id)
_CWE_MAP: dict[int, tuple[str, str, str]] = {
    89: ("injection", "A03", "WSTG-INPV-05"),
    79: ("injection", "A03", "WSTG-INPV-01"),
    80: ("injection", "A03", "WSTG-INPV-01"),
    77: ("injection", "A03", "WSTG-INPV-12"),
    78: ("injection", "A03", "WSTG-INPV-12"),
    94: ("injection", "A03", "WSTG-INPV-11"),
    97: ("injection", "A03", "WSTG-INPV-08"),
    113: ("injection", "A03", "WSTG-INPV-15"),
    943: ("injection", "A03", "WSTG-INPV-05"),
    22: ("access_control", "A01", "WSTG-ATHZ-01"),
    284: ("access_control", "A01", "WSTG-ATHZ-02"),
    285: ("access_control", "A01", "WSTG-ATHZ-02"),
    639: ("access_control", "A01", "WSTG-ATHZ-04"),
    352: ("access_control", "A01", "WSTG-SESS-05"),
    1021: ("access_control", "A05", "WSTG-CLNT-09"),
    264: ("access_control", "A05", "WSTG-CLNT-07"),  # ZAP uses 264 for CORS misconfiguration
    942: ("access_control", "A05", "WSTG-CLNT-07"),
    287: ("authentication", "A07", "WSTG-ATHN-04"),
    307: ("authentication", "A07", "WSTG-ATHN-03"),
    521: ("authentication", "A07", "WSTG-ATHN-07"),
    522: ("authentication", "A07", "WSTG-ATHN-01"),
    523: ("authentication", "A07", "WSTG-ATHN-01"),
    614: ("authentication", "A05", "WSTG-SESS-02"),
    1004: ("authentication", "A05", "WSTG-SESS-02"),
    1275: ("authentication", "A05", "WSTG-SESS-02"),
    384: ("authentication", "A07", "WSTG-SESS-03"),
    200: ("info_disclosure", "A01", "WSTG-INFO-05"),
    209: ("info_disclosure", "A05", "WSTG-ERRH-01"),
    497: ("info_disclosure", "A05", "WSTG-INFO-02"),
    548: ("info_disclosure", "A05", "WSTG-CONF-04"),
    530: ("info_disclosure", "A05", "WSTG-CONF-04"),
    538: ("info_disclosure", "A05", "WSTG-CONF-04"),
    540: ("info_disclosure", "A05", "WSTG-INFO-05"),
    615: ("info_disclosure", "A05", "WSTG-INFO-05"),
    693: ("info_disclosure", "A05", "WSTG-CONF-12"),
    16: ("info_disclosure", "A05", "WSTG-CONF-07"),
    319: ("info_disclosure", "A02", "WSTG-CRYP-03"),
    829: ("info_disclosure", "A08", "WSTG-CONF-04"),
    1104: ("info_disclosure", "A06", "WSTG-INFO-08"),
    345: ("info_disclosure", "A08", "WSTG-CONF-04"),
}

# ZAP scanner ids per assessment category, used to build a restricted
# active-scan policy so only the categories chosen in the scan form run.
ZAP_ACTIVE_SCANNERS: dict[str, list[int]] = {
    "injection": [40018, 40019, 40020, 40021, 40022, 40024, 40012, 40014, 40016, 40017, 90019, 90020, 40003, 90021],
    "access_control": [6, 7],
    # ZAP has few active rules for login logic; the authentication category
    # is covered mainly by the controlled cURL probes in tools/probes.py,
    # plus ZAP's passive cookie/session rules which always run.
    "authentication": [],
    "info_disclosure": [0, 10045, 10095, 40028, 40032, 40034, 40035],
}


def classify(cwe_id: int | None, fallback: str = "info_disclosure") -> tuple[str, str, str]:
    """Return (category, OWASP label, WSTG id) for a CWE."""
    if cwe_id is not None and cwe_id in _CWE_MAP:
        cat, owasp, wstg = _CWE_MAP[cwe_id]
        return cat, OWASP_2021[owasp], wstg
    owasp_default = {
        "injection": "A03",
        "access_control": "A01",
        "authentication": "A07",
        "info_disclosure": "A05",
    }[fallback]
    return fallback, OWASP_2021[owasp_default], ""


ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
