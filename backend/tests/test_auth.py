"""Accounts, roles, the forced password change and the audit log."""

import pytest
from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, sign_in
from fastapi.testclient import TestClient

from app import auth
from app.main import app


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        sign_in(c)
        yield c


def _client():
    return TestClient(app)


def test_everything_needs_a_session():
    with _client() as c:
        assert c.get("/api/health").status_code == 200
        for path in ("/api/targets", "/api/findings", "/api/auth/me", "/api/users", "/api/audit"):
            assert c.get(path).status_code == 401, path
        assert c.post("/api/targets", json={"name": "x", "base_url": "http://localhost:1"}).status_code == 401


def test_wrong_password_is_refused_and_logged(admin):
    with _client() as c:
        r = c.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": "nope"})
        assert r.status_code == 401 and "Incorrect" in r.json()["detail"]
    auth.clear_failures(ADMIN_EMAIL)
    log = admin.get("/api/audit", params={"q": "auth.login_failed"}).json()
    assert log and log[0]["actor_email"] == ADMIN_EMAIL and "nope" not in str(log[0])


def test_superadmin_creates_accounts_that_must_change_password(admin):
    r = admin.post("/api/users", json={"name": "Jay Mark Agsoy", "email": "Jay@School.edu", "role": "assessor",
                                       "custom_id": "2022-00417", "password": "temporary-1"})
    assert r.status_code == 201, r.text
    u = r.json()
    assert u["email"] == "jay@school.edu" and u["must_change_password"] and u["custom_id"] == "2022-00417"
    assert "password_hash" not in u and "temporary-1" not in str(u) and "temporary-1" not in str(admin.get("/api/audit").json())

    # Duplicate email, the superadmin role, and weak temporary passwords are refused.
    assert admin.post("/api/users", json={"name": "x", "email": "jay@school.edu", "password": "temporary-2"}).status_code == 409
    assert admin.post("/api/users", json={"name": "x", "email": "y@b.c", "role": "superadmin", "password": "temporary-2"}).status_code == 422
    assert admin.post("/api/users", json={"name": "x", "email": "y@b.c", "password": "short"}).status_code == 422

    with _client() as c:
        me = sign_in(c, "jay@school.edu", "temporary-1")
        assert me["must_change_password"] and me["role"] == "assessor" and me["name"] == "Jay Mark Agsoy"
        # Nothing but the password change works until it is done.
        assert c.get("/api/targets").status_code == 403
        bad = c.post("/api/auth/change-password", json={"current_password": "temporary-1", "new_password": "temporary-1"})
        assert bad.status_code == 422
        ok = c.post("/api/auth/change-password", json={"current_password": "temporary-1", "new_password": "jay-secret-99"})
        assert ok.status_code == 200 and not ok.json()["must_change_password"]
        assert c.get("/api/targets").status_code == 200

        # An assessor tests and reviews but cannot manage accounts or read the log.
        assert c.get("/api/users").status_code == 403
        assert c.get("/api/audit").status_code == 403
        assert c.post("/api/users", json={"name": "z", "email": "z@z.z", "password": "temporary-9"}).status_code == 403
        r = c.post("/api/targets", json={"name": "Jay's lab", "base_url": "http://localhost:3999", "authorization_notes": "Jay owns this local lab."})
        assert r.status_code == 201, r.text
        c.delete(f"/api/targets/{r.json()['id']}")

    log = admin.get("/api/audit", params={"actor": "jay@school.edu"}).json()
    actions = {e["action"] for e in log}
    assert {"auth.login", "auth.password_change", "target.create", "target.delete"} <= actions
    assert any(e["kind"] == "request" and e["path"] == "/api/targets" and e["status"] == 201 for e in log)


def test_viewer_is_read_only(admin):
    admin.post("/api/users", json={"name": "Prof Viewer", "email": "prof@school.edu", "role": "viewer", "password": "temporary-3"})
    with _client() as c:
        sign_in(c, "prof@school.edu", "temporary-3")
        c.post("/api/auth/change-password", json={"current_password": "temporary-3", "new_password": "prof-reads-only"})
        assert c.get("/api/findings").status_code == 200
        r = c.post("/api/targets", json={"name": "nope", "base_url": "http://localhost:3998", "authorization_notes": "Should be refused anyway."})
        assert r.status_code == 403 and "Viewer" in r.json()["detail"]
        assert c.post("/api/notifications/read", json={}).status_code != 403


def test_role_change_disable_reset_and_delete(admin):
    uid = admin.post("/api/users", json={"name": "Morales", "email": "morales@school.edu", "password": "temporary-4"}).json()["id"]
    with _client() as c:
        sign_in(c, "morales@school.edu", "temporary-4")
        c.post("/api/auth/change-password", json={"current_password": "temporary-4", "new_password": "morales-pass-1"})

        # Role changes take effect on the next request, without signing in again.
        r = admin.patch(f"/api/users/{uid}", json={"role": "viewer", "custom_id": "EMP-7"})
        assert r.json()["role"] == "viewer" and r.json()["custom_id"] == "EMP-7"
        assert c.get("/api/auth/me").json()["role"] == "viewer"

        # Disabling ends the session.
        admin.patch(f"/api/users/{uid}", json={"active": False})
        assert c.get("/api/auth/me").status_code == 401
    with _client() as c:
        assert c.post("/api/auth/login", json={"email": "morales@school.edu", "password": "morales-pass-1"}).status_code == 403

    admin.patch(f"/api/users/{uid}", json={"active": True})
    assert admin.post(f"/api/users/{uid}/reset-password", json={"password": "temporary-5"}).json()["must_change_password"]
    with _client() as c:
        assert sign_in(c, "morales@school.edu", "temporary-5")["must_change_password"]

    assert admin.delete(f"/api/users/{uid}").status_code == 204
    assert all(u["id"] != uid for u in admin.get("/api/users").json())


def test_superadmin_is_protected(admin):
    sid = next(u["id"] for u in admin.get("/api/users").json() if u["role"] == "superadmin")
    assert admin.patch(f"/api/users/{sid}", json={"role": "viewer"}).status_code == 409
    assert admin.patch(f"/api/users/{sid}", json={"active": False}).status_code == 409
    assert admin.delete(f"/api/users/{sid}").status_code == 409


def test_repeated_failures_lock_the_account_for_a_while(admin):
    admin.post("/api/users", json={"name": "Locked", "email": "locked@school.edu", "password": "temporary-6"})
    with _client() as c:
        for _ in range(auth.MAX_FAILURES):
            assert c.post("/api/auth/login", json={"email": "locked@school.edu", "password": "wrong"}).status_code == 401
        r = c.post("/api/auth/login", json={"email": "locked@school.edu", "password": "temporary-6"})
        assert r.status_code == 429
    auth.clear_failures("locked@school.edu")


def test_logout_ends_the_session():
    with _client() as c:
        sign_in(c)
        assert c.get("/api/auth/me").status_code == 200
        assert c.post("/api/auth/logout").status_code == 204
        assert c.get("/api/auth/me").status_code == 401


def test_audit_export_is_raw_text(admin):
    r = admin.get("/api/audit/export")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    lines = r.text.strip().splitlines()
    assert any("auth.login" in line and ADMIN_EMAIL in line for line in lines)
    assert ADMIN_PASSWORD not in r.text
