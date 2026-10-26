"""Adapter reads and configuration checks, against the RouterOS simulator."""
import pytest

from app.mikrotik import adapter
from app.mikrotik.api import ReadOnlyClient
from app.mikrotik.simulator import RouterOSSimulator, default_state


def snapshot(state, user="shield-ro", pw="Test-Password-123"):
    s = RouterOSSimulator(users={user: pw}, state=state).start()
    try:
        with ReadOnlyClient(s.host, s.port, user, pw, use_tls=False) as c:
            return adapter.collect(c, full=True, protected=["163.5.191.0/24"], username=user), s.commands
    finally:
        s.stop()


def codes(snap, tls="pinned", collector="10.255.0.10"):
    return {f["code"]: f["level"] for f in adapter.findings(snap, mgmt_address="10.255.0.1", model="ccr2004",
                                                            collector_address=collector, tls_verified_by=tls)}


def test_well_configured_router_passes():
    snap, cmds = snapshot(default_state())
    assert snap["errors"] == {}
    assert snap["traffic_flow"]["sampling_rate"] == 1024
    assert codes(snap) == {"flow_ok": "ok", "perm_ok": "ok"}
    assert all(w[0] == "/login" or w[0].endswith("/print") for w in cmds)


def test_routes_only_for_protected_prefixes():
    snap, cmds = snapshot(default_state())
    dsts = {r["dst"] for r in snap["routes"]}
    assert "163.5.191.0/24" in dsts and "0.0.0.0/0" not in dsts and "77.107.95.0/24" not in dsts
    assert not any(w == ["/ip/route/print"] for w in cmds)  # never an unfiltered route print


@pytest.mark.parametrize("change,expected", [
    (lambda s: s["/ip/traffic-flow"][0].update(enabled="false"), "flow_disabled"),
    (lambda s: s["/ip/traffic-flow/target"][0].update({"dst-address": "192.0.2.9"}), "flow_wrong_target"),
    (lambda s: s.__setitem__("/ip/traffic-flow/target", []), "flow_no_target"),
    (lambda s: s["/ip/traffic-flow/target"][0].update(version="5"), "flow_v5"),
    (lambda s: s["/ip/traffic-flow/target"][0].update({"src-address": "0.0.0.0"}), "flow_src"),
    (lambda s: s["/ip/traffic-flow"][0].update({"packet-sampling": "false"}), "flow_unsampled"),
    (lambda s: s["/ip/traffic-flow"][0].update({"sampling-space": "0"}), "flow_sampling_space"),
    (lambda s: s["/ip/traffic-flow"][0].update({"active-flow-timeout": "30m"}), "flow_timeout"),
    (lambda s: s["/ip/traffic-flow"][0].update(interfaces="all"), "flow_all_interfaces"),
    (lambda s: s.__setitem__("/interface/ethernet/switch", [{"name": "switch1", "l3-hw-offloading": "true"}]), "l3hw"),
    (lambda s: s["/ip/service"][0].update(disabled="false"), "api_plain"),
    (lambda s: s["/ip/service"][1].update(address=""), "api_open"),
    (lambda s: s["/user"][1].update(group="full"), "perm_write"),
    (lambda s: s["/user"][1].update(address=""), "perm_any_address"),
])
def test_misconfigurations_are_reported(change, expected):
    st = default_state()
    change(st)
    snap, _ = snapshot(st)
    c = codes(snap)
    assert expected in c, c
    if expected.startswith("flow"):
        assert "flow_ok" not in c


def test_tls_modes_reported():
    snap, _ = snapshot(default_state())
    assert codes(snap, tls="none")["tls_unverified"] == "warn"
    assert codes(snap, tls="plain")["tls_plain"] == "warn"


def test_missing_section_is_a_finding_not_a_failure():
    st = default_state()
    del st["/routing/bgp/session"]
    snap, _ = snapshot(st)
    assert "bgp" in snap["errors"] and snap["system"]["identity"] == "edge-r1"
    assert codes(snap)["read_bgp"] == "warn"
