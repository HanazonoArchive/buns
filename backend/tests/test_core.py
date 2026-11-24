import json

import httpx
import pytest

from app import cvss, scope
from app.ai import offline
from app.ai.client import AIError, DeepSeekClient
from app.ai.engine import analysis_payload, validate_analysis, validate_remediation
from app.models import Finding
from app.sanitize import sanitize
from app.tools.normalize import dedupe, normalize_zap_alerts

ALLOWED = ["localhost", "127.0.0.1", "juice-shop"]
BASE = "http://localhost:3000"


# -- scope -----------------------------------------------------------------

class TestScope:
    def test_registration_rejects_public_hosts(self):
        for url in ("http://example.com", "https://university.edu.ph", "http://10.0.0.5:3000"):
            with pytest.raises(scope.ScopeError):
                scope.validate_target_url(url, ALLOWED)

    def test_registration_rejects_non_http_and_credentials(self):
        for url in ("ftp://localhost", "file:///etc/passwd", "http://user:pw@localhost:3000"):
            with pytest.raises(scope.ScopeError):
                scope.validate_target_url(url, ALLOWED)

    def test_registration_normalises(self):
        assert scope.validate_target_url("http://LOCALHOST:3000/some/path", ALLOWED) == BASE
        assert scope.validate_target_url("http://localhost:80", ALLOWED) == "http://localhost"

    def test_other_port_on_same_host_is_out(self):
        with pytest.raises(scope.ScopeError, match="outside the target origin"):
            scope.check("http://localhost:8080/", BASE, [], [], ALLOWED)

    def test_in_and_out_prefixes(self):
        ins, outs = ["/rest/", "/api/"], ["/rest/admin/"]
        scope.check(f"{BASE}/rest/products/search?q=a", BASE, ins, outs, ALLOWED)
        with pytest.raises(scope.ScopeError, match="out-of-scope"):
            scope.check(f"{BASE}/rest/admin/application-version", BASE, ins, outs, ALLOWED)
        with pytest.raises(scope.ScopeError, match="not under any in-scope"):
            scope.check(f"{BASE}/ftp/", BASE, ins, outs, ALLOWED)

    def test_hash_routes(self):
        scope.check(f"{BASE}/#/administration", BASE, ["/#/administration"], [], ALLOWED)

    def test_redirect_to_other_host_is_blocked(self):
        with pytest.raises(scope.ScopeError):
            scope.check("http://evil.test/", BASE, [], [], ALLOWED)

    def test_zap_regexes(self):
        inc, exc = scope.zap_regexes(BASE, ["/rest/"], ["/socket.io/"])
        assert inc == [r"http://localhost:3000/rest/.*"]
        assert exc == [r"http://localhost:3000/socket\.io/.*"]


# -- sanitiser ---------------------------------------------------------------

class TestSanitize:
    RAW = (
        "POST /rest/user/login HTTP/1.1\r\n"
        "Host: localhost:3000\r\n"
        "Authorization: Bearer abcdefghijklmnop.qrstuv\r\n"
        "Cookie: token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlc2ln; language=en\r\n\r\n"
        '{"email":"jim@juice-sh.op","password":"ncc-1701"}'
    )

    def test_strips_secrets(self):
        out, counts = sanitize(self.RAW)
        assert "ncc-1701" not in out
        assert "jim@juice-sh.op" not in out
        assert "abcdefghijklmnop" not in out
        assert "eyJhbGciOiJIUzI1NiJ9" not in out
        assert "Authorization: [REDACTED]" in out
        assert '"password":"[REDACTED]"' in out
        assert counts["header"] == 2 and counts["email"] == 1

    def test_keeps_structure(self):
        out, _ = sanitize(self.RAW)
        assert out.startswith("POST /rest/user/login HTTP/1.1")
        assert "Host: localhost:3000" in out

    def test_jwt_in_body(self):
        out, counts = sanitize('{"token":"eyJ0eXAiOiJKV1QifQ.eyJkYXRhIjp7fX0.abcdefghij"}')
        assert "eyJ0eXAi" not in out and counts

    def test_card_numbers_need_luhn(self):
        out, _ = sanitize("card 4111 1111 1111 1111 order 1234567890123")
        assert "[CARD]" in out and "1234567890123" in out

    def test_password_hashes_and_ips(self):
        out, _ = sanitize("hash 0192023a7bbd73250516f069df18b500 from 192.168.4.20 via 127.0.0.1")
        assert "[HASH]" in out and "[IP]" in out and "127.0.0.1" in out

    def test_truncates(self):
        out, counts = sanitize("a" * 5000, max_chars=100)
        assert len(out) < 200 and counts["truncated"] == 1


# -- CVSS --------------------------------------------------------------------

@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
])
def test_cvss_reference_scores(vector, score):
    assert cvss.base_score(vector) == score


def test_cvss_rejects_garbage():
    for bad in ("", "CVSS:3.1/AV:N", "AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8"):
        with pytest.raises(cvss.CvssError):
            cvss.base_score(bad)


def test_cvss_bands():
    assert [cvss.severity_for(s) for s in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0)] == [
        "info", "low", "medium", "medium", "high", "high", "critical"]


# -- normalisation -----------------------------------------------------------

def _alert(**kw):
    a = {"pluginId": "40018", "name": "SQL Injection", "risk": "High", "confidence": "Medium",
         "cweid": "89", "url": f"{BASE}/rest/products/search?q=x", "param": "q", "attack": "'",
         "evidence": "SQLITE_ERROR", "method": "GET", "description": "<p>SQL injection may be possible.</p>"}
    a.update(kw)
    return a


def test_normalize_groups_and_classifies():
    drafts = normalize_zap_alerts([_alert(), _alert(evidence="SQLITE_ERROR: near"), _alert(param="other")])
    assert len(drafts) == 2
    d = next(x for x in drafts if x.param == "q")
    assert d.occurrences == 2 and d.evidence == "SQLITE_ERROR: near"
    assert d.category == "injection" and d.owasp.startswith("A03") and d.wstg == "WSTG-INPV-05"
    assert d.severity == "high" and d.description == "SQL injection may be possible."


def test_zap_exchange_is_fetched_by_message_id():
    from app.scanner import _attach_zap_messages

    class FakeZap:
        def message(self, mid):
            assert mid == "42"
            return {"requestHeader": "GET / HTTP/1.1\r\n\r\n", "requestBody": "",
                    "responseHeader": "HTTP/1.1 200 OK\r\n\r\n", "responseBody": "<html>"}

    drafts = normalize_zap_alerts([_alert(messageId="42")])
    _attach_zap_messages(FakeZap(), drafts, type("P", (), {"log": lambda self, m: None})())
    assert drafts[0].request_raw.startswith("GET / HTTP/1.1") and drafts[0].response_raw.endswith("<html>")


def test_passive_alerts_group_site_wide():
    alerts = [_alert(pluginId="10038", name="CSP Header Not Set", cweid="693", risk="Medium", attack="", param="",
                     url=f"{BASE}/page{i}") for i in range(40)]
    drafts = normalize_zap_alerts(alerts)
    assert len(drafts) == 1
    assert drafts[0].occurrences == 40 and len(drafts[0].affected_urls) == 40


def test_active_alerts_group_per_endpoint():
    alerts = [_alert(url=f"{BASE}/rest/products/search?q={i}") for i in range(5)] + [_alert(url=f"{BASE}/rest/user/login", param="email")]
    assert len(normalize_zap_alerts(alerts)) == 2


def test_dedupe_cors_against_zap_cross_domain():
    from app.tools.drafts import FindingDraft

    zap = normalize_zap_alerts([_alert(pluginId="10098", name="Cross-Domain Misconfiguration", cweid="264", risk="Medium", attack="")])
    cors = FindingDraft(source="curl", rule_id="curl:cors-wildcard", title="CORS", description="", category="access_control",
                        owasp="", wstg="", cwe_id=942, method="GET", url=BASE, severity="medium", yields_to_zap=True, zap_cwes=(264,))
    assert [d.source for d in dedupe(zap + [cors])] == ["zap"]


def test_zap_alert_on_same_endpoint_merges_into_curl_probe():
    from app.tools.drafts import FindingDraft

    zap = normalize_zap_alerts([_alert(url=f"{BASE}/rest/user/login", param="email", method="POST")])
    probe = FindingDraft(source="curl", rule_id="curl:login-sqli-bypass", title="Login bypass", description="Token issued.",
                         category="authentication", owasp="", wstg="", cwe_id=89, method="POST",
                         url=f"{BASE}/rest/user/login", severity="critical", param="email")
    out = dedupe(zap + [probe])
    assert [d.source for d in out] == ["curl"] and "ZAP reported the same issue" in out[0].description


def test_offline_keeps_informational_alerts_informational():
    result = validate_analysis(offline.analyse({"tool_severity": "info", "cwe": None, "title": "Modern Web Application"}))
    assert result["severity"] == "info"


def test_dedupe_prefers_zap_for_headers():
    from app.tools.drafts import FindingDraft

    zap = normalize_zap_alerts([_alert(pluginId="10038", name="CSP Header Not Set", cweid="693", risk="Medium")])
    curl_d = FindingDraft(source="curl", rule_id="curl:header-csp", title="CSP", description="", category="info_disclosure",
                          owasp="", wstg="", cwe_id=693, method="GET", url=BASE, severity="medium", yields_to_zap=True)
    assert [d.source for d in dedupe(zap + [curl_d])] == ["zap"]
    assert [d.source for d in dedupe([curl_d])] == ["curl"]


# -- AI layer ------------------------------------------------------------------

def _finding(**kw) -> Finding:
    base = dict(id=1, source="curl", tool_rule_id="curl:login-sqli-bypass", title="Login bypass", description="",
                category="authentication", owasp="A03:2021 Injection", wstg="WSTG-INPV-05", cwe_id=89,
                method="POST", url=f"{BASE}/rest/user/login", param="email", attack="' OR 1=1--",
                evidence='"token": [JWT issued]', request_raw=TestSanitize.RAW,
                response_raw='HTTP/1.1 200 OK\r\nSet-Cookie: token=abc123456789\r\n\r\n{"authentication":{"token":"eyJ0eXAiOiJKV1QifQ.eyJkYXRhIjp7fX0.abcdefghij","umail":"admin@juice-sh.op"}}',
                tool_severity="critical", tool_confidence="High", review_note="", ai_summary="", final_severity="",
                ai_severity="")
    base.update(kw)
    return Finding(**base)


def test_analysis_payload_contains_no_secrets():
    payload, redactions = analysis_payload(_finding())
    blob = json.dumps(payload)
    for secret in ("ncc-1701", "jim@juice-sh.op", "admin@juice-sh.op", "abc123456789", "eyJ0eXAi", "abcdefghijklmnop"):
        assert secret not in blob, secret
    assert redactions["header"] >= 3
    assert payload["attack"] == "' OR 1=1--"


def test_offline_analysis_is_valid():
    payload, _ = analysis_payload(_finding())
    result = validate_analysis(offline.analyse(payload))
    assert result["score"] == 9.1 and result["severity"] == "critical"
    assert "email" in result["summary"]


def test_offline_remediation_is_valid():
    rem = validate_remediation(offline.remediate({"cwe": 639}))
    assert rem["steps"] and "UserId" in rem["code_example"]


def test_validate_analysis_rejects_bad_vector():
    with pytest.raises(AIError):
        validate_analysis({"summary": "x", "cvss_vector": "9.8 critical"})


def test_validate_remediation_accepts_string_steps():
    rem = validate_remediation({"steps": "- one\n- two", "references": "CWE-89"})
    assert rem["steps"] == ["one", "two"] and rem["references"] == ["CWE-89"]


def test_deepseek_client_request_and_fenced_json():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        content = '```json\n{"summary": "s", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}\n```'
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    client = DeepSeekClient(api_key="sk-test", base_url="https://api.test", model="deepseek-chat",
                            transport=httpx.MockTransport(handler))
    out = client.complete_json("sys", "user")
    assert out["summary"] == "s"
    assert seen["auth"] == "Bearer sk-test"
    assert seen["body"]["response_format"] == {"type": "json_object"}
    assert validate_analysis(out)["score"] == 7.5


def test_deepseek_client_auth_error_is_not_retried():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(401, json={"error": "bad key"})

    client = DeepSeekClient(api_key="sk-bad", transport=httpx.MockTransport(handler))
    with pytest.raises(AIError, match="401"):
        client.complete_json("s", "u")
    assert len(calls) == 1


def test_deepseek_cut_off_reply_is_retried_with_a_bigger_budget(monkeypatch):
    """A reasoning model can spend the whole budget thinking and return no answer."""
    monkeypatch.setattr("app.ai.client.time.sleep", lambda s: None)
    budgets = []

    def handler(request):
        body = json.loads(request.content)
        budgets.append(body["max_tokens"])
        if len(budgets) == 1:
            return httpx.Response(200, json={"choices": [{"message": {"content": ""}, "finish_reason": "length"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"root_cause": "r", "steps": ["a"]}'},
                                                       "finish_reason": "stop"}]})

    client = DeepSeekClient(api_key="sk-test", transport=httpx.MockTransport(handler))
    assert client.complete_json("s", "u", max_tokens=1000)["root_cause"] == "r"
    assert budgets == [1000, 2000]


def test_deepseek_empty_reply_error_says_what_happened(monkeypatch):
    monkeypatch.setattr("app.ai.client.time.sleep", lambda s: None)

    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": ""}, "finish_reason": "length"}]})

    client = DeepSeekClient(api_key="sk-test", transport=httpx.MockTransport(handler))
    with pytest.raises(AIError, match="cut off at the token limit"):
        client.complete_json("s", "u", max_tokens=1000)
