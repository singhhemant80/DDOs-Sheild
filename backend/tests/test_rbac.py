import re

import pytest

from app.models import Role
from app.rbac import ROLE_PERMISSIONS, Perm

PUBLIC = {("GET", "/api/v1/health"), ("POST", "/api/v1/auth/login"), ("POST", "/api/v1/auth/refresh")}


def _operations(client):
    spec = client.app.openapi()
    for path, ops in spec["paths"].items():
        for method in ops:
            yield method.upper(), path


def test_every_non_public_endpoint_requires_auth(client):
    """Acceptance: no unauthenticated endpoint can change configuration or reach mitigation."""
    checked = 0
    for method, path in _operations(client):
        if (method, path) in PUBLIC:
            continue
        url = re.sub(r"\{[^}]+\}", "1", path)
        if "{session_id}" in path or "{user_id}" in path:
            url = re.sub(r"\{[^}]+\}", "00000000-0000-0000-0000-000000000000", path)
        r = client.request(method, url, json={})
        assert r.status_code == 401, f"{method} {path} returned {r.status_code} without a token"
        checked += 1
    assert checked >= 40


def test_garbage_and_forged_tokens_rejected(client):
    import jwt
    forged = jwt.encode({"sub": "x", "sid": "y", "typ": "access", "iss": "crapplet-shield", "exp": 9999999999},
                        "not-the-key-not-the-key-not-the-key-123", algorithm="HS256")
    for tok in ("garbage", forged):
        assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_permission_hierarchy():
    r, n, e, a = (ROLE_PERMISSIONS[x] for x in (Role.READ_ONLY, Role.NOC_OPERATOR, Role.NETWORK_ENGINEER, Role.ADMIN))
    assert r < n < e < a
    assert Perm.AUTOMATION_STOP in n and Perm.AUTOMATION_ENABLE not in n
    assert Perm.CONFIG_NETWORK not in n


@pytest.mark.parametrize("role,expect", [
    (Role.READ_ONLY, 403), (Role.NOC_OPERATOR, 403), (Role.NETWORK_ENGINEER, 201), (Role.ADMIN, 201)])
def test_prefix_creation_by_role(client, as_role, role, expect):
    r = client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24"}, headers=as_role(role))
    assert r.status_code == expect, r.text


def test_noc_can_stop_but_not_enable_automation(client, as_role):
    noc = as_role(Role.NOC_OPERATOR)
    assert client.post("/api/v1/system/emergency-stop", headers=noc).status_code == 200
    assert client.post("/api/v1/system/automation?enabled=true", headers=noc).status_code == 403


def test_guarded_settings_not_editable_directly(client, admin):
    assert client.put("/api/v1/settings/automation_enabled", json={"value": True}, headers=admin).status_code == 409
    assert client.put("/api/v1/settings/global_max_rtbh_routes", json={"value": "lots"}, headers=admin).status_code == 422
    assert client.put("/api/v1/settings/global_max_rtbh_routes", json={"value": 20}, headers=admin).status_code == 200


def test_only_admin_manages_users(client, as_role):
    for role in (Role.READ_ONLY, Role.NOC_OPERATOR, Role.NETWORK_ENGINEER):
        assert client.get("/api/v1/users", headers=as_role(role)).status_code == 403


def test_last_admin_cannot_be_demoted(client, admin):
    me = client.get("/api/v1/auth/me", headers=admin).json()
    r = client.patch(f"/api/v1/users/{me['id']}", json={"role": "read_only"}, headers=admin)
    assert r.status_code == 409
