"""Read-only poller against the RouterOS simulator, real PostgreSQL and Redis."""
import json
import os

import pytest
import redis
from sqlalchemy import select

from app import security
from app.db import session_factory
from app.mikrotik.poller import KEY_IFACES, MikroTikPoller, merge_bgp
from app.mikrotik.simulator import RouterOSSimulator
from app.models import BgpNeighbor, BgpPurpose, DeviceStatus, ProtectedPrefix, Router, RouterEvent, RouterModel, RouterState

R = redis.Redis.from_url(os.environ["SHIELD_REDIS_URL"], decode_responses=True)
try:
    R.ping()
    HAVE_REDIS = True
except redis.RedisError:
    HAVE_REDIS = False
pytestmark = pytest.mark.skipif(not HAVE_REDIS, reason="Redis not available")

USER, PW = "shield-ro", "Test-Password-123"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture(autouse=True)
def _flush():
    R.flushdb()


@pytest.fixture
def sim():
    s = RouterOSSimulator(host="127.0.0.2").start()
    yield s
    s.stop()


def add_router(sim, *, password=PW, name="edge-r1", use_tls=False):
    with session_factory()() as db, db.begin():
        r = Router(name=name, model=RouterModel.CCR2004, mgmt_address=sim.host, api_port=sim.port, use_tls=use_tls,
                   verify_tls=True, api_username=USER, api_password_enc=security.encrypt_secret(password))
        db.add(r)
        db.add(ProtectedPrefix(prefix="163.5.191.0/24", description="VPS"))
        db.flush()
        db.add(BgpNeighbor(name="upstream-a", router_id=r.id, purpose=BgpPurpose.TRANSIT, local_asn=154950,
                           remote_asn=174, neighbor_address="198.51.100.1"))
        return r.id


def poller():
    clock = Clock()
    rows = []
    p = MikroTikPoller(rds=R, clock=clock, ch_insert=rows.extend)
    p.reload()
    return p, clock, rows


def state(rid):
    with session_factory()() as db:
        return db.get(RouterState, rid), db.get(Router, rid), \
            db.execute(select(RouterEvent).where(RouterEvent.router_id == rid).order_by(RouterEvent.id)).scalars().all()


def test_full_poll_stores_state_and_checks(sim):
    rid = add_router(sim)
    p, clock, _ = poller()
    (rt, tier), = p.due()
    assert tier == "full"
    assert p.poll(rt, tier)["ok"]
    st, r, events = state(rid)
    assert st.ok and st.identity == "edge-r1" and st.version.startswith("7.16")
    assert r.status == DeviceStatus.DEGRADED          # the shield-rtbh session is idle in the simulator
    assert r.identity == "edge-r1" and r.last_seen_at is not None
    assert {i["name"] for i in st.interfaces} >= {"sfp-sfpplus1", "ether1"}
    assert [x["dst"] for x in st.routes["items"]].count("163.5.191.0/24") == 1
    assert st.permissions["group"] == "shield-read" and st.permissions["write_policies"] == []
    codes = {c["code"] for c in st.checks}
    assert "perm_ok" in codes and "tls_plain" in codes
    assert events == []
    with session_factory()() as db:
        n = db.execute(select(BgpNeighbor)).scalar_one()
        assert n.last_state == "established"
    # Only print commands were ever sent.
    assert all(w[0] == "/login" or w[0].endswith("/print") for w in sim.commands)


def test_interface_rates_published(sim):
    rid = add_router(sim)
    p, clock, rows = poller()
    rt = p.routers[rid]
    p.poll(rt, "full")
    clock.t += 10
    sim._last_tick -= 10  # the simulator advances counters by wall time; pretend 10 s passed
    out = p.poll(rt, "interfaces")
    assert out["rates"] >= 2
    rate = json.loads(R.hget(KEY_IFACES, f"{sim.host}|sfp-sfpplus1"))
    assert rate["source"] == "routeros" and rate["provenance"] == "measured"
    assert 1.5e9 < rate["in_bps"] < 3.5e9          # simulator runs 2.4 Gbps on this port
    assert any(r["if_name"] == "sfp-sfpplus1" for r in rows)


def test_full_poll_due_schedule(sim):
    rid = add_router(sim)
    p, clock, _ = poller()
    p.poll(p.routers[rid], "full")
    assert p.due() == []
    clock.t += 10
    assert [t for _, t in p.due()] == ["interfaces"]
    clock.t += 20
    assert [t for _, t in p.due()] == ["bgp"]
    clock.t += 30
    assert [t for _, t in p.due()] == ["full"]


def test_bgp_down_and_up_events(sim):
    rid = add_router(sim)
    p, clock, _ = poller()
    rt = p.routers[rid]
    p.poll(rt, "full")
    sim.update("/routing/bgp/session", {"name": "upstream-a-1"}, established="false", uptime="")
    p.poll(rt, "bgp")
    sim.update("/routing/bgp/session", {"name": "upstream-a-1"}, established="true", uptime="5s")
    p.poll(rt, "bgp")
    _, _, events = state(rid)
    assert [e.kind for e in events] == ["bgp_down", "bgp_up"]
    assert "198.51.100.1" in events[0].message


def test_unreachable_after_three_failures_then_recovered(sim):
    rid = add_router(sim)
    p, clock, _ = poller()
    rt = p.routers[rid]
    p.poll(rt, "full")
    sim.stop()
    for _ in range(3):
        assert not p.poll(rt, "interfaces")["ok"]
    st, r, events = state(rid)
    assert st.consecutive_failures == 3 and r.status == DeviceStatus.DOWN
    assert [e.kind for e in events] == ["unreachable"]
    sim2 = RouterOSSimulator(host="127.0.0.2", port=sim.port).start()
    try:
        assert p.poll(rt, "full")["ok"]
    finally:
        sim2.stop()
    st, r, events = state(rid)
    assert [e.kind for e in events] == ["unreachable", "recovered"] and st.consecutive_failures == 0


def test_wrong_password_reported_immediately(sim):
    rid = add_router(sim, password="Wrong-Password-000")
    p, clock, _ = poller()
    out = p.poll(p.routers[rid], "full")
    assert out["kind"] == "auth"
    st, r, events = state(rid)
    assert r.status == DeviceStatus.DOWN and events[0].kind == "unreachable"
    assert "log in" in events[0].message


def test_reboot_and_version_change(sim):
    rid = add_router(sim)
    p, clock, _ = poller()
    rt = p.routers[rid]
    p.poll(rt, "full")
    sim.update("/system/resource", {}, uptime="45s", version="7.17 (stable)")
    sim.state["/interface"] = [dict(i, **{"rx-byte": "0", "tx-byte": "0"}) for i in sim.state["/interface"]]
    sim.traffic_bps = {}
    clock.t += 10
    out = p.poll(rt, "interfaces")
    assert out["rates"] == 0                        # counter reset after a reboot is not a rate
    _, _, events = state(rid)
    assert {e.kind for e in events} == {"reboot", "version_change"}


def test_disabled_or_credential_less_routers_are_not_polled(sim):
    rid = add_router(sim)
    with session_factory()() as db, db.begin():
        db.get(Router, rid).enabled = False
        db.add(Router(name="nocreds", model=RouterModel.OTHER, mgmt_address="127.0.0.9", api_port=1))
    p, _, _ = poller()
    assert p.routers == {}


def test_merge_bgp_matches_sessions_to_connections():
    peers = merge_bgp({
        "connections": [{"name": "a", "remote_address": "1.1.1.1", "remote_as": 1, "disabled": False},
                        {"name": "b", "remote_address": "2.2.2.2", "remote_as": 2, "disabled": True}],
        "sessions": [{"name": "a-1", "remote_address": "1.1.1.1", "remote_as": 1, "established": True,
                      "state": "established", "uptime_seconds": 5, "prefixes_received": 3, "local_address": None},
                     {"name": "dyn", "remote_address": "3.3.3.3", "remote_as": 3, "established": False,
                      "state": "connect", "uptime_seconds": None, "prefixes_received": 0, "local_address": None}]})
    assert [(p["name"], p["state"], p["established"]) for p in peers] == [
        ("a", "established", True), ("b", "disabled", False), ("dyn", "connect", False)]
