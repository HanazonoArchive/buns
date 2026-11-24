"""The notifier: when a glass breaks, the right people hear about it."""

import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app import notifier
from app.models import Channel, Finding, Target


def _wait(fn, timeout=30.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.2)
    raise AssertionError("timed out")


# -- unit ------------------------------------------------------------------

def test_severity_threshold():
    assert notifier.meets("critical", "high")
    assert notifier.meets("high", "high")
    assert not notifier.meets("medium", "high")
    assert notifier.meets("", "critical")  # events without severity always pass


@pytest.mark.parametrize("kind,cfg,ok", [
    ("discord", {"url": "https://discord.com/api/webhooks/1/abc"}, True),
    ("discord", {"url": "https://evil.test/api/webhooks/1/abc"}, False),
    ("slack", {"url": "https://hooks.slack.com/services/T/B/x"}, True),
    ("slack", {"url": "http://localhost/hook"}, False),
    ("webhook", {"url": "https://example.test/hook"}, True),
    ("webhook", {"url": "not a url"}, False),
    ("telegram", {"bot_token": "123456789:" + "A" * 35, "chat_id": "-1001234"}, True),
    ("telegram", {"bot_token": "nope", "chat_id": "1"}, False),
    ("email", {"to": "a@b.test, c@d.test"}, True),
    ("email", {"to": ["not-an-email"]}, False),
])
def test_validate_config(kind, cfg, ok):
    if ok:
        notifier.validate_config(kind, cfg)
    else:
        with pytest.raises(notifier.ChannelError):
            notifier.validate_config(kind, cfg)


def test_secrets_are_masked_and_kept_on_update():
    url = "https://discord.com/api/webhooks/123456789/very-secret-token-value"
    shown = notifier.public_config("discord", {"url": url})["url"]
    assert "very-secret-token" not in shown and "••••" in shown
    assert notifier.merge_config("discord", {"url": url}, {"url": shown}) == {"url": url}
    new = "https://discord.com/api/webhooks/9/other"
    assert notifier.merge_config("discord", {"url": url}, {"url": new}) == {"url": new}


def _finding() -> Finding:
    t = Target(id=1, name="Juice Shop", base_url="http://localhost:3000", owner_email="owner@lab.test")
    return Finding(
        id=7, scan_id=1, target_id=1, target=t, source="curl", title="Login bypass with SQL injection",
        category="authentication", owasp="A03:2021 Injection", method="POST",
        url="http://localhost:3000/rest/user/login", tool_severity="critical", ai_severity="critical",
        ai_cvss_score=9.1, request_raw='{"email":"jim@juice-sh.op","password":"ncc-1701"}',
        response_raw='{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2ln"}',
        evidence="token issued", attack="' OR 1=1--",
    )


def test_messages_carry_no_evidence():
    msg = notifier.finding_detected(_finding())
    blobs = [json.dumps(notifier.discord_payload(msg)), json.dumps(notifier.slack_payload(msg)),
             json.dumps(notifier.webhook_payload(msg)), json.dumps(notifier.telegram_payload(msg, "1")),
             notifier.email_message(msg, ["a@b.test"]).as_string()]
    for blob in blobs:
        for secret in ("ncc-1701", "jim@juice-sh.op", "eyJhbGci", "OR 1=1"):
            assert secret not in blob, secret
        assert "/findings/7" in blob


def test_discord_embed_shape():
    payload = notifier.discord_payload(notifier.finding_detected(_finding()))
    embed = payload["embeds"][0]
    assert embed["color"] == notifier.SEV_COLOR["critical"]
    assert embed["title"].startswith("Critical:")
    assert {f["name"] for f in embed["fields"]} >= {"Target", "Endpoint", "CVSS"}


def test_email_copies_owner(monkeypatch):
    sent = []
    monkeypatch.setattr(notifier, "smtp_send", lambda em: sent.append(em))
    ch = Channel(name="Owner", kind="email", config={"to": ["lead@lab.test"]}, notify_owner=True)
    notifier.deliver(ch, notifier.finding_detected(_finding()))
    assert sent[0]["To"] == "lead@lab.test, owner@lab.test"
    assert sent[0]["Subject"].startswith("[buns] [Critical]")


def test_email_without_smtp_explains_itself():
    ch = Channel(name="x", kind="email", config={"to": ["a@b.test"]})
    with pytest.raises(notifier.ChannelError, match="SMTP_HOST"):
        notifier.deliver(ch, notifier.test_message(ch))


# -- flow --------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


def test_glass_breaks_mother_is_told(client, juice, monkeypatch):
    posts: list[tuple[str, dict]] = []
    emails = []
    lock = threading.Lock()

    def fake_post(url, payload):
        with lock:
            posts.append((url, payload))
        if "broken" in url:
            raise notifier.ChannelError("HTTP 404: unknown webhook")

    monkeypatch.setattr(notifier, "http_post", fake_post)
    monkeypatch.setattr(notifier, "smtp_send", lambda em: emails.append(em))

    t = client.post("/api/targets", json={
        "name": "Notify lab", "base_url": juice.url, "authorization_notes": "Stand-in for Juice Shop (MIT).",
        "test_email": "jim@juice-sh.op", "test_password": "ncc-1701",
        "owner_name": "Mother", "owner_email": "mother@lab.test",
    }).json()
    assert t["owner_email"] == "mother@lab.test"
    bad = client.post("/api/targets", json={"name": "x", "base_url": juice.url, "authorization_notes": "0123456789x",
                                            "owner_email": "not-an-email"})
    assert bad.status_code == 422

    def channel(**kw):
        r = client.post("/api/channels", json={"target_id": t["id"], **kw})
        assert r.status_code == 201, r.text
        return r.json()

    discord = channel(name="Team Discord", kind="discord", config={"url": "https://discord.com/api/webhooks/1/secret-token-abc"},
                      events=["finding.detected", "scan.analysed", "finding.confirmed", "report.generated"], min_severity="high")
    assert "secret-token" not in discord["config"]["url"]
    channel(name="Owner email", kind="email", config={"to": ""}, notify_owner=True,
            events=["finding.confirmed"], min_severity="critical")
    channel(name="Broken hook", kind="webhook", config={"url": "https://example.test/broken"},
            events=["scan.analysed"], min_severity="info")
    assert client.post("/api/channels", json={"name": "x", "kind": "discord", "config": {"url": "https://evil.test/x"}}).status_code == 422

    scan = client.post(f"/api/targets/{t['id']}/scans", json={}).json()

    def summary_sent():
        rows = client.get("/api/notifications?limit=200").json()
        return [n for n in rows if n["scan_id"] == scan["id"] and n["event"] == "scan.analysed"]

    summary = _wait(summary_sent)
    assert len(summary) == 1, "the scan summary must be sent exactly once"
    detected = [n for n in client.get("/api/notifications?limit=200").json()
                if n["scan_id"] == scan["id"] and n["event"] == "finding.detected"]
    assert detected and all(n["severity"] in ("critical", "high") for n in detected)

    _wait(lambda: all(d["status"] != "queued" for n in client.get("/api/notifications?limit=200").json()
                      for d in n["deliveries"]))
    rows = {n["id"]: n for n in client.get("/api/notifications?limit=200").json()}
    s = rows[summary[0]["id"]]
    statuses = {d["channel_name"]: d["status"] for d in s["deliveries"]}
    assert statuses == {"Team Discord": "sent", "Broken hook": "failed"}
    broken = next(d for d in s["deliveries"] if d["channel_name"] == "Broken hook")
    assert "404" in broken["error"]

    discord_posts = [p for u, p in posts if "discord.com" in u]
    assert len(discord_posts) == len(detected) + 1
    assert all("ncc-1701" not in json.dumps(p) for p in discord_posts)

    # Confirming a critical finding tells the owner by email.
    crit = next(f for f in client.get(f"/api/findings?scan_id={scan['id']}").json() if f["effective_severity"] == "critical")
    client.post(f"/api/findings/{crit['id']}/review", json={"decision": "confirm", "reviewer": "Morales"})
    _wait(lambda: emails)
    assert "mother@lab.test" in emails[0]["To"] and "Confirmed critical" in emails[0]["Subject"]

    # Re-running analysis must not alert again.
    before = len([n for n in client.get("/api/notifications?limit=200").json() if n["event"] == "finding.detected"])
    client.post(f"/api/findings/{crit['id']}/analyze")
    _wait(lambda: client.get(f"/api/findings/{crit['id']}").json()["ai_status"] == "done")
    time.sleep(0.5)
    after = len([n for n in client.get("/api/notifications?limit=200").json() if n["event"] == "finding.detected"])
    assert after == before

    r = client.post(f"/api/targets/{t['id']}/reports", json={"prepared_by": "Agsoy"})
    assert r.status_code == 201
    _wait(lambda: any(n["event"] == "report.generated" for n in client.get("/api/notifications").json()))

    summ = client.get("/api/notifications/summary").json()
    assert summ["unread"] > 0 and summ["email_configured"] is False
    client.post("/api/notifications/read", json={"all": True})
    assert client.get("/api/notifications/summary").json()["unread"] == 0

    # Test button and channel listing.
    assert client.post(f"/api/channels/{discord['id']}/test").json() == {"ok": True, "error": ""}
    listed = {c["name"]: c for c in client.get("/api/channels").json()}
    assert listed["Broken hook"]["last_status"] == "failed"
    upd = client.patch(f"/api/channels/{discord['id']}", json={"config": {"url": discord["config"]["url"]}, "enabled": False})
    assert upd.status_code == 200 and upd.json()["enabled"] is False


def test_missing_columns_are_added_to_old_databases():
    from sqlalchemy import inspect, text

    from app.db import _add_missing_columns, engine, init_db

    init_db()
    with engine.begin() as conn:
        conn.execute(text('ALTER TABLE targets DROP COLUMN owner_email'))
    engine.dispose()
    assert "owner_email" not in {c["name"] for c in inspect(engine).get_columns("targets")}
    _add_missing_columns()
    assert "owner_email" in {c["name"] for c in inspect(engine).get_columns("targets")}


def test_reanalysis_never_gets_stuck(client, juice):
    if not client.get("/api/findings").json():
        t = client.post("/api/targets", json={"name": "Race", "base_url": juice.url,
                                              "authorization_notes": "Stand-in for Juice Shop (MIT)."}).json()
        scan = client.post(f"/api/targets/{t['id']}/scans", json={"categories": ["injection"]}).json()
        _wait(lambda: client.get(f"/api/scans/{scan['id']}").json()["status"] == "completed")
    f = client.get("/api/findings").json()[0]
    for _ in range(15):
        client.post(f"/api/findings/{f['id']}/analyze")
        _wait(lambda: client.get(f"/api/findings/{f['id']}").json()["ai_status"] == "done", timeout=10)
