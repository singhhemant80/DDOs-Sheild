"""Router status API: state, events, test connection, certificate pinning, live BGP."""
import hashlib

import pytest

from app.mikrotik.poller import MikroTikPoller
from app.models import Role
from app.mikrotik.simulator import RouterOSSimulator
from tests.test_mikrotik_poller import HAVE_REDIS, R, Clock

pytestmark = pytest.mark.skipif(not HAVE_REDIS, reason="Redis not available")
PW = "Test-Password-123"


@pytest.fixture
def tls_sim():
    s = RouterOSSimulator(host="127.0.0.3", tls=True).start()
    yield s
    s.stop()


def create(client, hdr, sim, **kw):
    body = {"name": "edge-r1", "model": "ccr2004", "mgmt_address": sim.host, "api_port": sim.port,
            "api_username": "shield-ro", "api_password": PW, **kw}
    r = client.post("/api/v1/routers", json=body, headers=hdr)
    assert r.status_code == 201, r.text
    return r.json()


def test_untrusted_certificate_then_pin(client, engineer, tls_sim):
    rt = create(client, engineer, tls_sim)
    res = client.post(f"/api/v1/routers/{rt['id']}/test", headers=engineer).json()
    assert not res["ok"] and res["kind"] == "tls_untrusted"
    fp = hashlib.sha256(tls_sim.cert_der).hexdigest().upper()
    colon = ":".join(fp[i:i + 2] for i in range(0, 64, 2))
    assert res["presented_fingerprint"] == colon
    assert not [c for c in tls_sim.commands if c[0] == "/login"]      # no credentials sent

    cert = client.post(f"/api/v1/routers/{rt['id']}/certificate", headers=engineer).json()
    assert cert["fingerprint"] == colon and cert["self_signed"] and cert["matches_pin"] is None

    r = client.patch(f"/api/v1/routers/{rt['id']}", json={"tls_fingerprint": fp.lower()}, headers=engineer)
    assert r.status_code == 200 and r.json()["tls_fingerprint"] == colon
    res = client.post(f"/api/v1/routers/{rt['id']}/test", headers=engineer).json()
    assert res["ok"] and res["tls"] == "pinned"
    assert res["system"]["identity"] == "edge-r1"
    assert res["permissions"]["write_policies"] == []
    assert "api_password" not in str(res) and PW not in str(res)

    assert client.patch(f"/api/v1/routers/{rt['id']}", json={"tls_fingerprint": "zz"}, headers=engineer).status_code == 422
    r = client.patch(f"/api/v1/routers/{rt['id']}", json={"tls_fingerprint": ""}, headers=engineer)
    assert r.json()["tls_fingerprint"] is None

    from app.db import session_factory
    from app.models import AuditLog
    with session_factory()() as db:
        assert db.query(AuditLog).filter(AuditLog.action == "router.test").count() == 2


def test_full_account_is_flagged(client, engineer, tls_sim):
    tls_sim.users["admin"] = "Admin-Password-1"
    rt = create(client, engineer, tls_sim, api_username="admin", api_password="Admin-Password-1", verify_tls=False)
    res = client.post(f"/api/v1/routers/{rt['id']}/test", headers=engineer).json()
    assert res["ok"] and res["tls"] == "none"
    codes = {c["code"]: c for c in res["checks"]}
    assert "perm_write" in codes and codes["perm_write"]["level"] == "error"
    assert "tls_unverified" in codes


def test_state_events_and_bgp_after_poll(client, engineer, as_role, tls_sim):
    rt = create(client, engineer, tls_sim, verify_tls=False)
    client.post("/api/v1/bgp/neighbors", json={"name": "upstream-a", "router_id": rt["id"], "purpose": "transit",
                                               "local_asn": 154950, "remote_asn": 174,
                                               "neighbor_address": "198.51.100.1"}, headers=engineer)
    client.post("/api/v1/bgp/neighbors", json={"name": "old-peer", "router_id": rt["id"], "purpose": "transit",
                                               "local_asn": 154950, "remote_asn": 3356,
                                               "neighbor_address": "203.0.113.1"}, headers=engineer)
    p = MikroTikPoller(rds=R, clock=Clock(), ch_insert=lambda rows: None)
    p.reload()
    p.poll(p.routers[rt["id"]], "full")
    tls_sim.update("/routing/bgp/session", {"name": "upstream-a-1"}, established="false")
    p.poll(p.routers[rt["id"]], "bgp")

    viewer = as_role(Role.READ_ONLY)
    st = client.get(f"/api/v1/routers/{rt['id']}/state", headers=viewer).json()
    assert st["ok"] and st["identity"] == "edge-r1" and st["interfaces"] and st["checks"]
    assert client.get("/api/v1/routers/states", headers=viewer).json()[0]["router_id"] == rt["id"]
    ev = client.get("/api/v1/routers/events", headers=viewer).json()
    assert ev[0]["kind"] == "bgp_down" and ev[0]["router"] == "edge-r1"
    assert client.get(f"/api/v1/routers/{rt['id']}/events", headers=viewer).json()[0]["kind"] == "bgp_down"

    sessions = {s["remote_address"]: s for s in client.get("/api/v1/bgp/sessions", headers=viewer).json()}
    assert sessions["198.51.100.1"]["in_inventory"] and not sessions["198.51.100.1"]["established"]
    assert not sessions["10.255.0.10"]["in_inventory"]                 # on the router, not in Shield
    assert sessions["203.0.113.1"]["missing_on_router"]               # in Shield, not on the router

    # Viewers cannot trigger connections.
    assert client.post(f"/api/v1/routers/{rt['id']}/test", headers=viewer).status_code == 403
    assert client.post(f"/api/v1/routers/{rt['id']}/certificate", headers=viewer).status_code == 403


def test_interfaces_deduplicated_by_source(client, engineer):
    import json
    import time
    now = int(time.time())
    base = {"agent": "10.0.0.1", "if_name": "sfp-sfpplus1", "in_bps": 1, "out_bps": 1, "ts": now, "provenance": "measured"}
    R.hset("shield:ifaces", mapping={
        "10.0.0.1|7": json.dumps({**base, "if_index": 7, "source": "snmp", "in_bps": 5}),
        "10.0.0.1|sfp-sfpplus1": json.dumps({**base, "if_index": 99, "source": "routeros", "in_bps": 9}),
    })
    from app import telemetry as tm
    tm.reset_clients()
    rows = [r for r in tm.interfaces() if r["agent"] == "10.0.0.1"]
    assert len(rows) == 1 and rows[0]["source"] == "routeros"
