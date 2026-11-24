"""End-to-end: register target, scan with real curl, AI triage, review, report."""

import time

import pytest
from fastapi.testclient import TestClient

from app.tools import probes


def _wait(fn, timeout=30.0, every=0.2):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = fn()
        if value:
            return value
        time.sleep(every)
    raise AssertionError("timed out")


@pytest.fixture(scope="module")
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


def test_probes_against_fake_juice_shop(juice):
    log = []
    ctx = probes.ProbeContext(base_url=juice.url, in_scope=[], out_of_scope=[], test_email="jim@juice-sh.op",
                              test_password="ncc-1701", log=log.append, endpoints=[])
    drafts = probes.run_probes(ctx, ["info_disclosure", "injection", "authentication", "access_control"])
    rules = {d.rule_id for d in drafts}
    assert {
        "curl:header-csp", "curl:cors-wildcard", "curl:robots", "curl:dir-listing", "curl:stack-trace",
        "curl:search-sqli-error", "curl:login-sqli-bypass", "curl:login-no-throttle",
        "curl:weak-password-policy", "curl:users-any-session", "curl:basket-idor",
    } <= rules, rules
    idor = next(d for d in drafts if d.rule_id == "curl:basket-idor")
    assert "GET /rest/basket/3 HTTP/1.1" in idor.request_raw and '"id": 3' in idor.response_raw
    listing = next(d for d in drafts if d.rule_id == "curl:dir-listing")
    assert "package.json.bak" in listing.description  # survived the short-body case
    assert len(ctx.endpoints) >= 15


def test_probes_respect_scope(juice):
    log = []
    ctx = probes.ProbeContext(base_url=juice.url, in_scope=["/rest/"], out_of_scope=["/rest/user/"],
                              log=log.append, endpoints=[])
    drafts = probes.run_probes(ctx, ["authentication", "info_disclosure"])
    assert not drafts
    assert any("skip  POST /rest/user/login" in line for line in log)
    assert all("/rest/" in url and "/rest/user/" not in url for _, url, _ in ctx.endpoints)


def test_rejects_unauthorised_target(client):
    r = client.post("/api/targets", json={"name": "x", "base_url": "https://www.google.com",
                                          "authorization_notes": "no authorisation at all"})
    assert r.status_code == 422 and "not on the authorised list" in r.json()["detail"]


def test_full_assessment_flow(client, juice):
    r = client.post("/api/targets", json={
        "name": "Fake Juice Shop", "base_url": juice.url + "/",
        "authorization_notes": "Test double of OWASP Juice Shop (MIT) running in-process.",
        "in_scope": [], "out_of_scope": ["/socket.io"],
        "test_email": "jim@juice-sh.op", "test_password": "ncc-1701",
    })
    assert r.status_code == 201, r.text
    target = r.json()
    assert target["base_url"] == juice.url and target["has_test_password"] and "test_password" not in target

    chk = client.post(f"/api/targets/{target['id']}/scope-check", json={"url": juice.url + "/socket.io/x"}).json()
    assert chk == {"allowed": False, "reason": chk["reason"]} and "out-of-scope" in chk["reason"]

    r = client.post(f"/api/targets/{target['id']}/scans", json={"categories": ["injection", "authentication", "access_control", "info_disclosure"]})
    assert r.status_code == 201
    scan_id = r.json()["id"]
    assert client.post(f"/api/targets/{target['id']}/scans", json={}).status_code in (201, 409)

    scan = _wait(lambda: (s := client.get(f"/api/scans/{scan_id}").json())["status"] in ("completed", "failed") and s)
    assert scan["status"] == "completed", scan["log"]
    assert "ZAP unavailable" in scan["log"] and scan["finding_count"] >= 10 and scan["endpoints"]

    findings = _wait(lambda: (fs := client.get(f"/api/findings?scan_id={scan_id}").json())
                     and all(f["ai_status"] == "done" for f in fs) and fs)
    assert findings[0]["effective_severity"] == "critical"  # sorted by severity

    sqli = next(f for f in findings if f["title"].startswith("Login bypass"))
    detail = client.get(f"/api/findings/{sqli['id']}").json()
    assert detail["ai_model"] == "offline-rules" and detail["ai_cvss_score"] == 9.1
    assert "ncc-1701" not in str(detail["ai_payload"]) and detail["ai_redactions"]
    assert detail["curl_command"].startswith("curl -i -X POST")

    # Decisions need a reviewer, and a reason when they deviate from the suggestion.
    assert client.post(f"/api/findings/{sqli['id']}/review", json={"decision": "confirm"}).status_code == 422
    r = client.post(f"/api/findings/{sqli['id']}/review", json={"decision": "confirm", "severity": "high", "reviewer": "Morales"})
    assert r.status_code == 422 and "Explain" in r.json()["detail"]
    r = client.post(f"/api/findings/{sqli['id']}/review", json={"decision": "confirm", "reviewer": "Morales",
                                                                "note": "Reproduced with cURL; token returned for admin."})
    assert r.json()["status"] == "confirmed" and r.json()["final_severity"] == "critical"

    idor = next(f for f in findings if "basket" in f["title"])
    client.post(f"/api/findings/{idor['id']}/review", json={"decision": "confirm", "reviewer": "Morales"})

    robots = next(f for f in findings if "robots" in f["title"])
    assert client.post(f"/api/findings/{robots['id']}/review", json={"decision": "reject", "reviewer": "Morales"}).status_code == 422
    client.post(f"/api/findings/{robots['id']}/review", json={"decision": "reject", "reviewer": "Morales",
                                                               "note": "robots.txt is public by design; /ftp is reported separately."})

    rem = _wait(lambda: (d := client.get(f"/api/findings/{idor['id']}").json())["remediation_status"] == "done" and d)
    assert rem["remediation"]["steps"] and "UserId" in rem["remediation"]["code_example"]
    assert client.post(f"/api/findings/{robots['id']}/remediation").status_code == 409

    dash = client.get(f"/api/dashboard?target_id={target['id']}").json()
    assert dash["confirmed"] == 2 and dash["rejected"] == 1 and dash["severity_confirmed"]["critical"] == 1
    assert dash["by_category"]["access_control"]["confirmed"] == 1 and dash["redactions"]

    _wait(lambda: client.get(f"/api/findings/{sqli['id']}").json()["remediation_status"] == "done")
    r = client.post(f"/api/targets/{target['id']}/reports", json={"prepared_by": "Agsoy, Alves, Morales"})
    assert r.status_code == 201, r.text
    report = r.json()
    assert report["findings_count"] == 2
    pdf = client.get(f"/api/reports/{report['id']}/download")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and len(pdf.content) > 5000
    assert b"jim@juice-sh.op" not in pdf.content and b"ncc-1701" not in pdf.content


def test_report_needs_confirmed_findings(client):
    t = client.post("/api/targets", json={"name": "Empty", "base_url": "http://localhost:3999",
                                          "authorization_notes": "Local test target, nothing confirmed."}).json()
    assert client.post(f"/api/targets/{t['id']}/reports", json={"prepared_by": "x"}).status_code == 409
