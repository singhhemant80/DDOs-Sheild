"""Prefixes, eligibility, customers, routers, upstream RTBH policy."""
from sqlalchemy import select

from app.models import AuditLog

EVIDENCE = {"ownership_verified": True, "ownership_evidence": "RIPE route object 163.5.191.0/24 AS154950; ROA valid"}


def _prefix(client, h, prefix="163.5.191.0/24", **kw):
    r = client.post("/api/v1/prefixes", json={"prefix": prefix, **kw}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------- prefixes
def test_prefix_defaults_are_safe(client, engineer):
    p = _prefix(client, engineer)
    assert p["rtbh_allowed"] is p["steering_allowed"] is p["filtering_allowed"] is False
    assert p["min_mitigation_prefix_len"] == 32  # host routes only


def test_overlapping_prefix_rejected(client, engineer):
    _prefix(client, engineer, "163.52.252.0/23")
    r = client.post("/api/v1/prefixes", json={"prefix": "163.52.253.0/24"}, headers=engineer)
    assert r.status_code == 409 and "overlaps" in r.json()["detail"]


def test_bogon_and_host_bits_rejected(client, engineer):
    assert client.post("/api/v1/prefixes", json={"prefix": "10.1.0.0/16"}, headers=engineer).status_code == 422
    assert client.post("/api/v1/prefixes", json={"prefix": "163.5.191.1/24"}, headers=engineer).status_code == 422


def test_mitigation_flags_require_verified_ownership(client, engineer):
    r = client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24", "rtbh_allowed": True}, headers=engineer)
    assert r.status_code == 422
    p = _prefix(client, engineer, rtbh_allowed=True, **EVIDENCE)
    assert p["rtbh_allowed"] and p["authorized_at"] and p["authorized_by_id"]
    # Can't strip ownership while flags remain on.
    r = client.patch(f"/api/v1/prefixes/{p['id']}", json={"ownership_verified": False}, headers=engineer)
    assert r.status_code == 422


def test_min_mitigation_len_bounds(client, engineer):
    r = client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24", "min_mitigation_prefix_len": 16},
                    headers=engineer)
    assert r.status_code == 422


# ---------------------------------------------------------------- eligibility (acceptance)
def test_eligibility_unprotected_destination_is_never_eligible(client, engineer):
    _prefix(client, engineer, rtbh_allowed=True, filtering_allowed=True, **EVIDENCE)
    e = client.get("/api/v1/prefixes/eligibility", params={"target": "77.107.95.10"}, headers=engineer).json()
    assert e["protected_prefix"] is None
    assert not (e["rtbh_allowed"] or e["steering_allowed"] or e["filtering_allowed"])


def test_eligibility_host_vs_whole_prefix(client, engineer):
    _prefix(client, engineer, rtbh_allowed=True, **EVIDENCE)
    host = client.get("/api/v1/prefixes/eligibility", params={"target": "163.5.191.20"}, headers=engineer).json()
    assert host["rtbh_allowed"] and host["within_scope_limit"] and host["target"] == "163.5.191.20/32"
    whole = client.get("/api/v1/prefixes/eligibility", params={"target": "163.5.191.0/24"}, headers=engineer).json()
    assert not whole["rtbh_allowed"] and not whole["within_scope_limit"]


def test_eligibility_respects_disabled_prefix_and_customer_opt_out(client, engineer):
    p = _prefix(client, engineer, rtbh_allowed=True, **EVIDENCE)
    r = client.post("/api/v1/customers/ips", json={"address": "163.5.191.50", "customer_ref": "C-1001",
                                                   "service_type": "vps", "rtbh_opt_out": True}, headers=engineer)
    assert r.status_code == 201
    e = client.get("/api/v1/prefixes/eligibility", params={"target": "163.5.191.50"}, headers=engineer).json()
    assert not e["rtbh_allowed"] and e["customer"]["customer_ref"] == "C-1001"
    client.patch(f"/api/v1/prefixes/{p['id']}", json={"enabled": False}, headers=engineer)
    e = client.get("/api/v1/prefixes/eligibility", params={"target": "163.5.191.20"}, headers=engineer).json()
    assert not e["rtbh_allowed"]


# ---------------------------------------------------------------- customers
def test_customer_ip_must_be_inside_a_protected_prefix(client, engineer):
    _prefix(client, engineer)
    bad = client.post("/api/v1/customers/ips", json={"address": "8.8.8.8", "customer_ref": "X",
                                                     "service_type": "vps"}, headers=engineer)
    assert bad.status_code == 422
    ok = client.post("/api/v1/customers/ips", json={"address": "163.5.191.7", "customer_ref": "C-1",
                                                    "service_type": "vps", "proxmox_vmid": 1207}, headers=engineer)
    assert ok.status_code == 201 and ok.json()["address"] == "163.5.191.7/32"
    dup = client.post("/api/v1/customers/ips", json={"address": "163.5.191.7", "customer_ref": "C-2",
                                                     "service_type": "vps"}, headers=engineer)
    assert dup.status_code == 409


def test_prefix_with_customers_cannot_be_deleted(client, engineer):
    p = _prefix(client, engineer)
    client.post("/api/v1/customers/ips", json={"address": "163.5.191.7", "customer_ref": "C-1",
                                               "service_type": "vps"}, headers=engineer)
    assert client.delete(f"/api/v1/prefixes/{p['id']}", headers=engineer).status_code == 409


# ---------------------------------------------------------------- routers & secrets
def test_router_secret_is_write_only(client, engineer, db):
    r = client.post("/api/v1/routers", json={"name": "edge-r1", "model": "ccr2004", "mgmt_address": "10.255.0.1",
                                             "api_username": "shield-ro", "api_password": "s3cret-router-pw"},
                    headers=engineer)
    assert r.status_code == 201
    body = r.json()
    assert body["has_api_password"] is True and body["access_mode"] == "read_only" and body["dry_run"] is True
    assert "s3cret-router-pw" not in r.text and "api_password_enc" not in body
    row = db.execute(select(AuditLog).where(AuditLog.action == "router.create")).scalar_one()
    assert row.after["api_password_enc"] == "[set]"
    assert "s3cret" not in str(row.after)


def test_read_write_router_requires_verified_tls(client, engineer):
    r = client.post("/api/v1/routers", json={"name": "lab", "model": "ccr2116", "mgmt_address": "10.255.0.9",
                                             "access_mode": "read_write", "verify_tls": False}, headers=engineer)
    assert r.status_code == 422
    r = client.post("/api/v1/routers", json={"name": "lab", "model": "ccr2116", "mgmt_address": "10.255.0.9"},
                    headers=engineer)
    rid = r.json()["id"]
    assert client.patch(f"/api/v1/routers/{rid}", json={"dry_run": False}, headers=engineer).status_code == 422


# ---------------------------------------------------------------- upstream RTBH policy
def _upstream(client, h):
    r = client.post("/api/v1/upstreams", json={"name": "Upstream-A", "asn": 174, "capacity_mbps": 10000}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_rtbh_policy_lifecycle(client, engineer):
    uid = _upstream(client, engineer)
    base = f"/api/v1/upstreams/{uid}/rtbh-policy"
    r = client.put(base, json={"communities": ["174:666", "no-export"], "max_routes": 20}, headers=engineer)
    assert r.status_code == 200 and r.json()["communities"] == ["174:666", "65535:65281"]
    assert client.post(f"{base}/enable", headers=engineer).status_code == 409        # not verified
    assert client.post(f"{base}/verify", headers=engineer).status_code == 422        # no documentation_ref
    client.put(base, json={"communities": ["174:666"], "documentation_ref": "https://provider/rtbh.pdf"},
               headers=engineer)
    assert client.post(f"{base}/verify", headers=engineer).status_code == 200
    r = client.post(f"{base}/enable", headers=engineer)
    assert r.status_code == 200 and r.json()["enabled"] is True
    # Any edit disables the policy and clears verification.
    r = client.put(base, json={"communities": ["174:9999"], "documentation_ref": "x"}, headers=engineer)
    assert r.json()["enabled"] is False and r.json()["verified_at"] is None


def test_rtbh_policy_validation(client, engineer):
    uid = _upstream(client, engineer)
    base = f"/api/v1/upstreams/{uid}/rtbh-policy"
    assert client.put(base, json={"communities": ["174:666666"]}, headers=engineer).status_code == 422
    assert client.put(base, json={"min_prefix_len": 32, "max_prefix_len": 24}, headers=engineer).status_code == 422


def test_bgp_neighbor_asn_must_match_upstream(client, engineer):
    uid = _upstream(client, engineer)
    r = client.post("/api/v1/bgp/neighbors", json={"name": "r1-a", "upstream_id": uid, "purpose": "transit",
                                                   "local_asn": 154950, "remote_asn": 6939,
                                                   "neighbor_address": "198.51.100.1"}, headers=engineer)
    assert r.status_code == 422
    r = client.post("/api/v1/bgp/neighbors", json={"name": "shield-r1", "purpose": "transit", "local_asn": 154950,
                                                   "remote_asn": 154950, "neighbor_address": "10.255.0.1",
                                                   "managed_by_shield": True, "max_prefix_out": 10}, headers=engineer)
    assert r.status_code == 422  # Shield never manages transit sessions
