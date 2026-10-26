"""Phase 8 acceptance: production sessions, canary acceptance runs, the safety interlock and
rollback, against real FRR routers on loopback.

Exit criterion: acceptance tests prove unrelated prefixes are unaffected.
"""
import json
import os
import shutil
import time
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
import redis
from sqlalchemy import select, text

from app import telemetry as tm
from app.api.bgp import receive_filter
from app.db import session_factory
from app.mitigation import acceptance as acc
from app.mitigation.controller import Controller
from app.mitigation.frr import FrrSpeaker
from app.models import AcceptanceRun, ActionState, BgpNeighbor, MitigationAction, Role, Router, RouterState
from tests.conftest import login, make_user
from tests.test_frr_staging import BGPD, start_bgpd, stop_bgpd, vtysh

R = redis.Redis.from_url(os.environ["SHIELD_REDIS_URL"], decode_responses=True)
_HAVE_FRR = os.path.exists(BGPD) and shutil.which("vtysh") and os.geteuid() == 0
if os.environ.get("SHIELD_REQUIRE_FRR") and not _HAVE_FRR:
    raise RuntimeError("SHIELD_REQUIRE_FRR is set but FRR (bgpd, vtysh) or root is missing")
pytestmark = pytest.mark.skipif(not _HAVE_FRR, reason="needs FRR (bgpd, vtysh) and root")

SHIELD, LAB, PROD = "127.0.0.51", "127.0.0.50", "127.0.0.52"
SHIELD_AS, LAB_AS, PROD_AS = 65010, 65020, 65030
LAB_PORT, PROD_PORT = 11279, 11280
PS_SHIELD, PS_LAB, PS_PROD = "shieldt8", "labt8", "prodt8"
API = "/api/v1"
UNRELATED, CANARY, NEW = "163.5.191.30/32", "163.5.191.250/32", "163.5.191.31/32"
EVIDENCE = {"ownership_verified": True, "ownership_evidence": "lab"}


@pytest.fixture(scope="module", autouse=True)
def daemons():
    start_bgpd(PS_LAB, LAB, LAB_PORT)
    start_bgpd(PS_PROD, PROD, PROD_PORT)
    yield
    for ps in (PS_SHIELD, PS_LAB, PS_PROD):
        stop_bgpd(ps)


@pytest.fixture(autouse=True)
def shield_bgpd(daemons):
    tm.reset_clients()
    R.flushdb()
    os.environ["SHIELD_FRR_PATHSPACE"] = PS_SHIELD
    start_bgpd(PS_SHIELD, SHIELD, 0)
    yield
    os.environ.pop("SHIELD_FRR_PATHSPACE", None)
    R.flushdb()


def routes(ps) -> set[str]:
    return set((json.loads(vtysh(ps, "show bgp ipv4 unicast json") or "{}").get("routes") or {}))


def wait(fn, timeout=30, every=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    return fn()


def ctl():
    return Controller(rds=R, speaker=FrrSpeaker(session_factory(), R, pathspace=PS_SHIELD))


def mfa_admin(client):
    make_user("mfaadmin", Role.ADMIN)
    h = {"Authorization": f"Bearer {login(client, 'mfaadmin')['access_token']}"}
    secret = client.post(f"{API}/auth/mfa/setup", headers=h).json()["secret"]
    assert client.post(f"{API}/auth/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=h).status_code == 200
    time.sleep(1)
    tok = login(client, "mfaadmin", totp_code=pyotp.TOTP(secret).now())
    assert tok["mfa_verified"]
    return {"Authorization": f"Bearer {tok['access_token']}"}


def configure_router(ps, me, my_as):
    with session_factory()() as db:
        lines = [ln.strip() for ln in receive_filter(db, "frr").splitlines() if ln.strip() and not ln.startswith("!")]
    vtysh(ps, *lines, configure=True)
    vtysh(ps, f"router bgp {my_as}", f"bgp router-id {me}", "no bgp default ipv4-unicast",
          f"neighbor {SHIELD} remote-as {SHIELD_AS}", f"neighbor {SHIELD} passive", f"neighbor {SHIELD} update-source {me}",
          "address-family ipv4 unicast", f"neighbor {SHIELD} activate", f"neighbor {SHIELD} route-map FROM-SHIELD in",
          f"neighbor {SHIELD} route-map TO-SHIELD out", "exit-address-family", configure=True)


def established(addr):
    return FrrSpeaker(session_factory(), R, pathspace=PS_SHIELD).peer_state(addr) == "Established"


@pytest.fixture
def lab(client, engineer, admin):
    """Staging session to the lab router with one unrelated blackhole active; a production session
    to a second router, recorded but not yet in use."""
    assert client.post(f"{API}/prefixes", json={"prefix": "163.5.191.0/24", "rtbh_allowed": True, **EVIDENCE},
                       headers=engineer).status_code == 201
    for k, v in (("internal_blackhole_community", "65535:666"), ("bgp_router_id", SHIELD), ("bgp_speaker", "frr")):
        assert client.put(f"{API}/settings/{k}", json={"value": v}, headers=admin).status_code == 200
    ids = {}
    for name, addr, asn, port, env in (("to-lab", LAB, LAB_AS, LAB_PORT, "staging"), ("to-prod", PROD, PROD_AS, PROD_PORT, "production")):
        r = client.post(f"{API}/bgp/neighbors", json={
            "name": name, "purpose": "rtbh_signal", "local_asn": SHIELD_AS, "remote_asn": asn, "neighbor_address": addr,
            "local_address": SHIELD, "remote_port": port, "managed_by_shield": True, "max_prefix_out": 20,
            "environment": env}, headers=engineer)
        assert r.status_code == 201, r.text
        ids[name] = r.json()["id"]
    configure_router(PS_LAB, LAB, LAB_AS)
    configure_router(PS_PROD, PROD, PROD_AS)
    vtysh(PS_LAB, f"clear bgp {SHIELD}")
    vtysh(PS_PROD, f"clear bgp {SHIELD}")
    c = ctl()
    c.reconcile()
    assert wait(lambda: established(LAB))
    c.publish_status()
    blackhole(client, engineer, "163.5.191.30", c)
    assert wait(lambda: UNRELATED in routes(PS_LAB))
    return {"ids": ids, "c": c}


def blackhole(client, h, target, c):
    r = client.post(f"{API}/mitigation/actions", json={"target": target, "strategy": "rtbh_internal"},
                    headers={**h, "Idempotency-Key": uuid.uuid4().hex})
    assert r.status_code == 201, r.text
    aid = r.json()["actions"][0]["id"]
    assert client.post(f"{API}/mitigation/actions/{aid}/approve", headers=h).status_code == 200
    c.tick()
    with session_factory()() as db:
        a = db.get(MitigationAction, uuid.UUID(aid))
        assert a.state == ActionState.ACTIVE, a.error
    return aid


def run_acceptance(client, h, c, target="163.5.191.250", timeout=60):
    r = client.post(f"{API}/bgp/acceptance", json={"peer": "internal", "target": target, "confirm_unused": True}, headers=h)
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    seen_on_prod = False
    end = time.time() + timeout
    while time.time() < end:
        c.tick()
        seen_on_prod |= CANARY in routes(PS_PROD)
        run = client.get(f"{API}/bgp/acceptance/{rid}", headers=h).json()
        if run["status"] in ("passed", "failed"):
            return run, seen_on_prod
        time.sleep(0.5)
    return client.get(f"{API}/bgp/acceptance/{rid}", headers=h).json(), seen_on_prod


# ---------------------------------------------------------------- the gate
def test_production_switch_requires_mfa_admin(client, admin, engineer, as_role, lab):
    assert client.post(f"{API}/system/production?enabled=true", headers=admin).status_code == 403      # no MFA
    assert client.post(f"{API}/system/production?enabled=true", headers=engineer).status_code == 403   # not admin
    assert client.put(f"{API}/settings/bgp_production_enabled", json={"value": True}, headers=admin).status_code == 409
    mfa = mfa_admin(client)
    assert client.post(f"{API}/system/production?enabled=true", headers=mfa).status_code == 200
    noc = as_role(Role.NOC_OPERATOR)
    r = client.post(f"{API}/system/production?enabled=false", headers=noc)                            # anyone can stop
    assert r.status_code == 200 and r.json()["withdrawn"] == 1


# ---------------------------------------------------------------- the exit criterion
def test_acceptance_run_changes_nothing_but_the_canary(client, engineer, lab):
    c = lab["c"]
    lab_before = routes(PS_LAB)
    assert lab_before == {UNRELATED}
    assert client.post(f"{API}/system/production?enabled=true", headers=mfa_admin(client)).status_code == 200
    c.reconcile()
    assert wait(lambda: established(PROD))
    c.publish_status()
    time.sleep(2)
    # The production router gets nothing while unaccepted, not even the existing blackhole.
    assert routes(PS_PROD) == set()
    # Ordinary blackholes over the peer are refused until the run passes.
    r = client.post(f"{API}/mitigation/preview", json={"target": "163.5.191.31", "strategy": "rtbh_internal"}, headers=engineer).json()
    assert r["blocked"] and any("acceptance run" in ch["message"] for ch in r["checks"] if ch["level"] == "block")

    run, seen = run_acceptance(client, engineer, c)
    assert run["status"] == "passed", run
    assert seen, "the canary never reached the production router"
    steps = [s["step"] for s in run["steps"]]
    assert steps[:3] == ["baseline", "announcing", "verifying"] and steps[-1] == "withdrawing"
    # Unrelated prefixes unaffected: the lab router has exactly what it had, before and after.
    assert routes(PS_LAB) == lab_before
    assert CANARY not in routes(PS_PROD)
    with session_factory()() as db:
        assert db.get(BgpNeighbor, lab["ids"]["to-prod"]).acceptance_passed_at is not None
    # Accepted: the production router now gets the peer's authorised routes, and new ones.
    assert wait(lambda: routes(PS_PROD) == {UNRELATED}, 20)
    blackhole(client, engineer, "163.5.191.31", c)
    assert wait(lambda: routes(PS_PROD) == {UNRELATED, NEW} and routes(PS_LAB) == {UNRELATED, NEW}, 20)


def test_acceptance_fails_cleanly_when_production_router_is_down(client, engineer, lab, monkeypatch):
    c = lab["c"]
    monkeypatch.setitem(acc.STEP_TIMEOUT, "announcing", timedelta(seconds=4))
    vtysh(PS_PROD, f"router bgp {PROD_AS}", f"neighbor {SHIELD} shutdown", configure=True)
    assert client.post(f"{API}/system/production?enabled=true", headers=mfa_admin(client)).status_code == 200
    c.reconcile()
    c.publish_status()
    run, _ = run_acceptance(client, engineer, c, timeout=40)
    assert run["status"] == "failed" and "did not complete" in run["error"], run
    for _ in range(6):                         # let the controller withdraw the canary
        c.next_try.clear()
        c.tick()
    assert CANARY not in vtysh(PS_SHIELD, "show ip prefix-list SHIELD4-int")
    assert routes(PS_LAB) == {UNRELATED}
    with session_factory()() as db:
        assert db.get(BgpNeighbor, lab["ids"]["to-prod"]).acceptance_passed_at is None
    vtysh(PS_PROD, f"router bgp {PROD_AS}", f"no neighbor {SHIELD} shutdown", configure=True)


def test_router_check_fails_if_another_protected_route_changes(client, engineer, lab):
    """With a router Shield reads (MikroTik, here its stored state), the run also compares the
    router's own routes for protected prefixes before and during the canary."""
    c = lab["c"]
    with session_factory()() as db, db.begin():
        r = Router(name="edge-x", model="ccr2004", mgmt_address="10.9.9.9", enabled=True)
        db.add(r)
        db.flush()
        base = [{"dst": "163.5.191.0/24", "gateway": "sfp-sfpplus3", "blackhole": False, "table": "main"}]
        db.add(RouterState(router_id=r.id, polled_at=datetime.now(UTC), ok=True, routes={"items": base, "at": datetime.now(UTC).isoformat()}))
        rid = r.id
    assert client.post(f"{API}/system/production?enabled=true", headers=mfa_admin(client)).status_code == 200
    c.reconcile()
    assert wait(lambda: established(PROD))
    c.publish_status()
    rr = client.post(f"{API}/bgp/acceptance", json={"peer": "internal", "target": "163.5.191.250", "confirm_unused": True}, headers=engineer)
    assert rr.status_code == 201, rr.text
    run_id = rr.json()["id"]
    for _ in range(20):
        c.tick()
        if client.get(f"{API}/bgp/acceptance/{run_id}", headers=engineer).json()["step"] == "router_check":
            break
        time.sleep(0.5)
    # The router "reports" the canary AND an unrelated change (a protected route now points elsewhere).
    later = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    with session_factory()() as db, db.begin():
        st = db.get(RouterState, rid)
        st.routes = {"at": later, "items": [{"dst": "163.5.191.0/24", "gateway": "ether9", "blackhole": False, "table": "main"},
                                            {"dst": CANARY, "gateway": None, "blackhole": True, "table": "main"}]}
    c.tick()
    run = client.get(f"{API}/bgp/acceptance/{run_id}", headers=engineer).json()
    assert run["status"] == "failed" and "163.5.191.0/24" in run["error"], run


# ---------------------------------------------------------------- interlock and rollback
def test_interlock_removes_unauthorised_route_and_engages_emergency_stop(client, engineer, lab):
    c = lab["c"]
    vtysh(PS_SHIELD, "ip prefix-list SHIELD4-int permit 163.5.191.99/32", f"router bgp {SHIELD_AS}",
          "address-family ipv4 unicast", "network 163.5.191.99/32", configure=True)
    assert wait(lambda: "163.5.191.99/32" in routes(PS_LAB), 10)      # leaked (it is inside a protected prefix)
    res = c.reconcile()
    assert res["ok"] and c.last_interlock and c.last_interlock[0]["prefix"] == "163.5.191.99/32"
    assert wait(lambda: "163.5.191.99/32" not in routes(PS_LAB), 10)
    assert routes(PS_LAB) == {UNRELATED}                                # the authorised route is untouched
    st = client.get(f"{API}/mitigation/status", headers=engineer).json()
    assert st["emergency_stop"] is True
    r = client.post(f"{API}/mitigation/preview", json={"target": "163.5.191.31", "strategy": "rtbh_internal"}, headers=engineer).json()
    assert r["blocked"]


def test_withdraw_all_rolls_back_everything(client, engineer, lab):
    c = lab["c"]
    blackhole(client, engineer, "163.5.191.31", c)
    assert wait(lambda: routes(PS_LAB) == {UNRELATED, NEW})
    r = client.post(f"{API}/mitigation/withdraw-all", json={"reason": "rollback drill"}, headers=engineer)
    assert r.status_code == 200 and r.json()["withdrawn"] == 2
    c.tick()
    assert wait(lambda: routes(PS_LAB) == set(), 15)
    with session_factory()() as db:
        assert {a.state for a in db.execute(select(MitigationAction)).scalars()} == {ActionState.WITHDRAWN}


def test_production_off_removes_production_sessions(client, engineer, as_role, lab):
    c = lab["c"]
    assert client.post(f"{API}/system/production?enabled=true", headers=mfa_admin(client)).status_code == 200
    c.reconcile()
    assert f"neighbor {PROD} " in vtysh(PS_SHIELD, "show running-config")
    assert client.post(f"{API}/system/production?enabled=false", headers=as_role(Role.NOC_OPERATOR)).status_code == 200
    c.tick()
    c.reconcile()
    assert f"neighbor {PROD} " not in vtysh(PS_SHIELD, "show running-config")
    assert wait(lambda: routes(PS_LAB) == set(), 15)


def test_editing_a_production_session_resets_acceptance(client, engineer, lab):
    nid = lab["ids"]["to-prod"]
    with session_factory()() as db, db.begin():
        db.execute(text("UPDATE bgp_neighbors SET acceptance_passed_at = now() WHERE id = :i"), {"i": nid})
    assert client.patch(f"{API}/bgp/neighbors/{nid}", json={"remote_port": 11299}, headers=engineer).status_code == 200
    with session_factory()() as db:
        assert db.get(BgpNeighbor, nid).acceptance_passed_at is None


def test_acceptance_refuses_customer_addresses_and_needs_confirmation(client, engineer, lab):
    client.post(f"{API}/customers/ips", json={"address": "163.5.191.77", "customer_ref": "C-9", "service_type": "vps"}, headers=engineer)
    r = client.post(f"{API}/bgp/acceptance", json={"peer": "internal", "target": "163.5.191.77", "confirm_unused": True}, headers=engineer)
    assert r.status_code == 422 and "customer" in r.json()["detail"]
    r = client.post(f"{API}/bgp/acceptance", json={"peer": "internal", "target": "163.5.191.250"}, headers=engineer)
    assert r.status_code == 422
    with session_factory()() as db:
        assert db.execute(select(AcceptanceRun)).first() is None

