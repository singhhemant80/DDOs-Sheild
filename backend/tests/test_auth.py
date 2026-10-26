import pyotp
from sqlalchemy import select

from app.models import LoginAttempt, Role, User
from tests.conftest import PASSWORD, login, make_user


def test_login_and_me(client):
    make_user("alice", Role.NOC_OPERATOR)
    t = login(client, "ALICE")  # usernames are case-insensitive
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {t['access_token']}"})
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "alice" and body["role"] == "noc_operator"
    assert "mitigation_approve" in body["permissions"] and "manage_users" not in body["permissions"]
    assert "password_hash" not in body and "mfa_secret_enc" not in body


def test_wrong_password_and_unknown_user_look_identical(client, db):
    make_user("bob", Role.READ_ONLY)
    a = client.post("/api/v1/auth/login", json={"username": "bob", "password": "nope"})
    b = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "nope"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()
    reasons = {r.reason for r in db.execute(select(LoginAttempt)).scalars()}
    assert reasons == {"bad_password", "unknown_user"}


def test_lockout_after_repeated_failures(client, db):
    make_user("carol", Role.READ_ONLY)
    for _ in range(5):
        assert client.post("/api/v1/auth/login", json={"username": "carol", "password": "x"}).status_code == 401
    # Correct password is now refused while locked.
    assert client.post("/api/v1/auth/login", json={"username": "carol", "password": PASSWORD}).status_code == 401
    u = db.execute(select(User).where(User.username == "carol")).scalar_one()
    assert u.locked_until is not None


def test_login_rate_limit(client):
    for _ in range(20):
        client.post("/api/v1/auth/login", json={"username": "x", "password": "y"})
    r = client.post("/api/v1/auth/login", json={"username": "x", "password": "y"})
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_refresh_rotation_and_logout(client):
    make_user("dave", Role.READ_ONLY)
    t = login(client, "dave")
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert r.status_code == 200
    t2 = r.json()
    # Old refresh token no longer works.
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]}).status_code == 401
    h = {"Authorization": f"Bearer {t2['access_token']}"}
    assert client.post("/api/v1/auth/logout", headers=h).status_code == 204
    # Access token is dead immediately because its session was revoked.
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t2["refresh_token"]}).status_code == 401


def test_disabling_user_kills_existing_tokens(client, admin):
    make_user("erin", Role.READ_ONLY)
    t = login(client, "erin")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    uid = client.get("/api/v1/auth/me", headers=h).json()["id"]
    assert client.patch(f"/api/v1/users/{uid}", json={"is_active": False}, headers=admin).status_code == 200
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_role_demotion_applies_immediately(client, admin):
    make_user("frank", Role.NETWORK_ENGINEER)
    h = {"Authorization": f"Bearer {login(client, 'frank')['access_token']}"}
    uid = client.get("/api/v1/auth/me", headers=h).json()["id"]
    client.patch(f"/api/v1/users/{uid}", json={"role": "read_only"}, headers=admin)
    # Role change revokes sessions, so the old token is rejected outright.
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_password_policy_and_change(client):
    make_user("gina", Role.READ_ONLY)
    t = login(client, "gina")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    weak = client.post("/api/v1/auth/password", json={"current_password": PASSWORD, "new_password": "short"}, headers=h)
    assert weak.status_code == 422
    ok = client.post("/api/v1/auth/password",
                     json={"current_password": PASSWORD, "new_password": "Another-Strong-Pass-77"}, headers=h)
    assert ok.status_code == 204
    login(client, "gina", "Another-Strong-Pass-77")


def test_mfa_enrolment_and_login(client):
    make_user("hank", Role.ADMIN)
    t = login(client, "hank")
    h = {"Authorization": f"Bearer {t['access_token']}"}
    setup = client.post("/api/v1/auth/mfa/setup", headers=h).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    totp = pyotp.TOTP(setup["secret"])
    assert client.post("/api/v1/auth/mfa/enable", json={"code": "000000"}, headers=h).status_code == 400
    r = client.post("/api/v1/auth/mfa/enable", json={"code": totp.now()}, headers=h)
    assert r.status_code == 200 and r.json()["mfa_verified"] is True
    # Old non-MFA session was revoked.
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401

    no_code = client.post("/api/v1/auth/login", json={"username": "hank", "password": PASSWORD})
    assert no_code.status_code == 401 and no_code.json()["detail"] == "mfa_required"
    bad = client.post("/api/v1/auth/login", json={"username": "hank", "password": PASSWORD, "totp_code": "123456"})
    assert bad.status_code == 401
    good = login(client, "hank", totp_code=totp.now())
    assert good["mfa_verified"] is True


def test_require_mfa_for_admin_setting(client, admin):
    assert client.put("/api/v1/settings/require_mfa_for_admin", json={"value": True}, headers=admin).status_code == 200
    # The same (non-MFA) admin session is now refused for admin-only actions...
    assert client.get("/api/v1/users", headers=admin).status_code == 403
    # ...but can still read and reach MFA enrolment.
    assert client.get("/api/v1/prefixes", headers=admin).status_code == 200
    assert client.post("/api/v1/auth/mfa/setup", headers=admin).status_code == 200


def test_session_listing_and_revocation(client):
    make_user("ivy", Role.READ_ONLY)
    a = login(client, "ivy")
    b = login(client, "ivy")
    ha = {"Authorization": f"Bearer {a['access_token']}"}
    hb = {"Authorization": f"Bearer {b['access_token']}"}
    sessions = client.get("/api/v1/auth/sessions", headers=ha).json()
    assert len(sessions) == 2 and sum(s["current"] for s in sessions) == 1
    other = next(s for s in sessions if not s["current"])
    assert client.delete(f"/api/v1/auth/sessions/{other['id']}", headers=ha).status_code == 204
    assert client.get("/api/v1/auth/me", headers=hb).status_code == 401
