"""Re-scanning a target must not duplicate its findings."""

import time

import pytest
from conftest import sign_in
from fastapi.testclient import TestClient


def _wait(fn, timeout=30.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.2)
    raise AssertionError("timed out")


@pytest.fixture(scope="module")
def client():
    from app.main import app

    with TestClient(app) as c:
        sign_in(c)
        yield c


def _scan(client, target_id):
    scan = client.post(f"/api/targets/{target_id}/scans", json={}).json()
    _wait(lambda: client.get(f"/api/scans/{scan['id']}").json()["status"] == "completed")
    _wait(lambda: all(f["ai_status"] == "done" for f in client.get(f"/api/findings?scan_id={scan['id']}").json()))
    return scan["id"]


def test_rescan_keeps_one_finding_per_issue(client, juice):
    t = client.post("/api/targets", json={
        "name": "Rescan lab", "base_url": juice.url, "authorization_notes": "Stand-in for Juice Shop (MIT).",
        "test_email": "jim@juice-sh.op", "test_password": "ncc-1701",
    }).json()

    first = _scan(client, t["id"])
    after_first = client.get(f"/api/findings?target_id={t['id']}").json()
    assert after_first and all(f["times_seen"] == 1 for f in after_first)

    # Decide on two findings before re-scanning.
    robots = next(f for f in after_first if "robots" in f["title"])
    sqli = next(f for f in after_first if f["title"].startswith("Login bypass"))
    client.post(f"/api/findings/{robots['id']}/review", json={"decision": "reject", "reviewer": "Morales", "note": "Public by design."})
    client.post(f"/api/findings/{sqli['id']}/review", json={"decision": "confirm", "reviewer": "Morales"})

    second = _scan(client, t["id"])
    after_second = client.get(f"/api/findings?target_id={t['id']}").json()

    # Same set of findings, no duplicates.
    assert len(after_second) == len(after_first)
    assert {f["id"] for f in after_second} == {f["id"] for f in after_first}
    assert all(f["times_seen"] == 2 and f["last_seen_scan_id"] == second for f in after_second)

    # Decisions survive the re-scan; the false positive does not come back as new.
    by_id = {f["id"]: f for f in after_second}
    assert by_id[robots["id"]]["status"] == "rejected"
    assert by_id[sqli["id"]]["status"] == "confirmed"

    # Both scans list the findings they reported.
    assert len(client.get(f"/api/findings?scan_id={first}").json()) == len(after_first)
    assert len(client.get(f"/api/findings?scan_id={second}").json()) == len(after_first)
    scan2 = client.get(f"/api/scans/{second}").json()
    assert scan2["finding_count"] == len(after_first) and scan2["new_finding_count"] == 0
    assert "already known" in scan2["log"]

    detail = client.get(f"/api/findings/{sqli['id']}").json()
    assert detail["seen_in_scans"] == [first, second]

    # The second scan's summary says nothing new was found.
    summary = _wait(lambda: [n for n in client.get("/api/notifications?limit=200").json()
                             if n["scan_id"] == second and n["event"] == "scan.analysed"])
    assert len(summary) == 1
    assert "0 new finding" in summary[0]["title"] and "seen before" in summary[0]["title"]

    # No second "serious finding detected" alert for already-known findings.
    detected = [n for n in client.get("/api/notifications?limit=200").json()
                if n["event"] == "finding.detected" and n["finding_id"] == sqli["id"]]
    assert len(detected) == 1


def test_finding_missing_from_latest_scan_is_flagged(client, juice):
    from app.db import session_scope
    from app.models import Finding

    t = client.post("/api/targets", json={"name": "Retest lab", "base_url": juice.url,
                                          "authorization_notes": "Stand-in for Juice Shop (MIT)."}).json()
    _scan(client, t["id"])
    target_findings = client.get(f"/api/findings?target_id={t['id']}").json()
    victim = target_findings[0]
    # Pretend the issue was fixed: change its identity so the next scan
    # cannot match it.
    with session_scope() as db:
        db.get(Finding, victim["id"]).fingerprint = "fixed|issue"
    latest = _scan(client, t["id"])
    rows = {f["id"]: f for f in client.get(f"/api/findings?target_id={t['id']}").json()}
    assert rows[victim["id"]]["not_in_latest_scan"] == latest
    assert all(f["not_in_latest_scan"] is None for fid, f in rows.items() if f["last_seen_scan_id"] == latest)


def test_existing_duplicates_are_merged(client, juice):
    from sqlalchemy import select

    from app.db import session_scope
    from app.models import Finding, FindingScan, Notification
    from app.scanner import merge_duplicate_findings

    t = client.post("/api/targets", json={"name": "Old duplicates", "base_url": juice.url,
                                          "authorization_notes": "Stand-in for Juice Shop (MIT)."}).json()
    s1 = _scan(client, t["id"])
    s2 = _scan(client, t["id"])
    original = client.get(f"/api/findings?target_id={t['id']}").json()

    # Recreate what older versions stored: a copy of every finding per scan,
    # without fingerprints, plus an alert on one of the copies.
    with session_scope() as db:
        copies = []
        for f in db.scalars(select(Finding).where(Finding.target_id == t["id"])):
            f.fingerprint = ""
            cols = {c.name: getattr(f, c.name) for c in Finding.__table__.columns if c.name != "id"}
            cols.update(scan_id=s2, status="pending", fingerprint="", last_seen_scan_id=None)
            copies.append(Finding(**cols))
        db.add_all(copies)
        db.flush()
        db.add(Notification(event="finding.detected", title="old alert", finding_id=copies[0].id, target_id=t["id"]))
        for c in copies:
            db.add(FindingScan(finding_id=c.id, scan_id=s2))
    assert len(client.get(f"/api/findings?target_id={t['id']}").json()) == 2 * len(original)

    client.post(f"/api/findings/{original[0]['id']}/review", json={"decision": "reject", "reviewer": "x", "note": "fp"})
    merged = merge_duplicate_findings()
    assert merged >= len(original)

    rows = client.get(f"/api/findings?target_id={t['id']}").json()
    assert len(rows) == len(original)
    kept = next(f for f in rows if f["id"] == original[0]["id"])
    assert kept["status"] == "rejected" and kept["times_seen"] == 2
    assert client.get(f"/api/findings/{kept['id']}").json()["seen_in_scans"] == [s1, s2]
    alerts = [n for n in client.get("/api/notifications?limit=200").json() if n["title"] == "old alert"]
    assert alerts and alerts[0]["finding_id"] in {f["id"] for f in rows}
    assert merge_duplicate_findings() == 0  # idempotent
