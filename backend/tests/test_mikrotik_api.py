"""RouterOS API client against the protocol simulator."""
import hashlib
import socket

import pytest

from app.mikrotik.api import (
    ConnectError, LoginError, ReadOnlyClient, TLSUntrusted, TrapError, WriteRefused, _Reader, encode_sentence,
    encode_length,
)
from app.mikrotik.simulator import RouterOSSimulator

USER, PW = "shield-ro", "Test-Password-123"


@pytest.fixture
def sim():
    s = RouterOSSimulator().start()
    yield s
    s.stop()


@pytest.fixture
def tls_sim():
    s = RouterOSSimulator(tls=True).start()
    yield s
    s.stop()


def client(s, **kw):
    kw.setdefault("use_tls", False)
    return ReadOnlyClient(s.host, s.port, kw.pop("user", USER), kw.pop("password", PW), **kw)


def logins(s):
    return [c for c in s.commands if c[0] == "/login"]


@pytest.mark.parametrize("n", [0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0xFFFFFFF, 0x10000000])
def test_length_encoding_round_trip(n):
    a, b = socket.socketpair()
    try:
        a.sendall(encode_length(n))
        assert _Reader(b).length() == n
    finally:
        a.close(); b.close()


def test_long_words_round_trip():
    a, b = socket.socketpair()
    try:
        words = ["!re", "=comment=" + "x" * 20000, "=name=é"]
        a.sendall(encode_sentence(words))
        assert _Reader(b).sentence() == words
    finally:
        a.close(); b.close()


def test_login_and_print(sim):
    with client(sim) as c:
        assert c.print("/system/identity") == [{"name": "edge-r1"}]
        res = c.print("/system/resource", proplist=["version", "board-name"])
        assert res == [{"version": "7.16.2 (stable)", "board-name": "CCR2004-1G-12S+2XS"}]
        assert len(c.print("/ip/route", queries=["blackhole=true"])) == 1
        with pytest.raises(TrapError):
            c.print("/no/such/thing")
        assert c.print("/system/identity")[0]["name"] == "edge-r1"   # session survives a trap


def test_wrong_password(sim):
    with pytest.raises(LoginError):
        client(sim, password="nope").connect()


def test_unreachable():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    with pytest.raises(ConnectError):
        ReadOnlyClient("127.0.0.1", port, USER, PW, use_tls=False, timeout=1).connect()


@pytest.mark.parametrize("cmd", ["/ip/route/add", "/ip/firewall/filter/remove", "/system/reboot",
                                 "/routing/bgp/connection/set", "/ip/route/print/../add", "/user/print2"])
def test_writes_never_reach_the_router(sim, cmd):
    with client(sim) as c:
        with pytest.raises(WriteRefused):
            c.run(cmd, {"dst-address": "163.5.191.20/32", "blackhole": "yes"})
    assert all(w[0] != cmd for w in sim.commands)


def test_print_with_editing_attributes_is_refused(sim):
    with client(sim) as c:
        with pytest.raises(WriteRefused):
            c.run("/ip/route/print", {"numbers": "0", "disabled": "yes"})


def test_tls_unknown_certificate_does_not_send_credentials(tls_sim):
    with pytest.raises(TLSUntrusted) as e:
        client(tls_sim, use_tls=True, verify_tls=True).connect()
    assert e.value.fingerprint == hashlib.sha256(tls_sim.cert_der).hexdigest()
    assert logins(tls_sim) == []


def test_tls_pinned_fingerprint(tls_sim):
    fp = hashlib.sha256(tls_sim.cert_der).hexdigest()
    with client(tls_sim, use_tls=True, fingerprint=":".join(fp[i:i + 2] for i in range(0, 64, 2)).upper()) as c:
        assert c.tls.verified_by == "pinned" and c.tls.fingerprint == fp
        assert c.print("/system/identity")[0]["name"] == "edge-r1"


def test_tls_wrong_pin_refused_before_login(tls_sim):
    with pytest.raises(TLSUntrusted):
        client(tls_sim, use_tls=True, fingerprint="ab" * 32).connect()
    assert logins(tls_sim) == []


def test_tls_unverified_is_reported(tls_sim):
    with client(tls_sim, use_tls=True, verify_tls=False) as c:
        assert c.tls.verified_by == "none"


def test_bad_fingerprint_format():
    with pytest.raises(ValueError):
        ReadOnlyClient("127.0.0.1", 1, USER, PW, fingerprint="not-a-hash")
