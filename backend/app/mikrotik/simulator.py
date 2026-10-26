"""A RouterOS API simulator for tests and for trying Shield without a router.

    python -m app.mikrotik.simulator --port 18729 --tls --name edge-r1

It speaks the real API wire protocol (plain or TLS with a generated self-signed certificate),
checks the login, serves RouterOS 7-shaped data for the paths Shield reads, evaluates simple
`?key=value` queries and `.proplist`, and rejects every write with !trap, except add/remove in
/ip(v6)/firewall/raw for users listed in `writers` (Phase 9 local filtering). Interface counters
advance with simulated traffic so polled rates are realistic. It is a test fixture, not an
emulator: only what Shield needs is modelled.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import ipaddress
import socket
import ssl
import tempfile
import threading
import time

from .api import _Reader, encode_sentence


def default_state(name: str = "edge-r1", mgmt: str = "10.255.0.1", model: str = "CCR2004-1G-12S+2XS") -> dict:
    return {
        "/system/identity": [{"name": name}],
        "/system/resource": [{
            "uptime": "3w2d04:11:52", "version": "7.16.2 (stable)", "build-time": "2024-11-25 12:13:51",
            "free-memory": "3229736960", "total-memory": "4294967296", "cpu": "ARM64", "cpu-count": "4",
            "cpu-load": "7", "architecture-name": "arm64", "board-name": model, "platform": "MikroTik",
        }],
        "/system/routerboard": [{
            "routerboard": "true", "model": model, "serial-number": "HE408XYZ123",
            "firmware-type": "al2", "factory-firmware": "7.4", "current-firmware": "7.16.2", "upgrade-firmware": "7.16.2",
        }],
        "/interface": [
            _iface("*1", "sfp-sfpplus1", "ether", "Upstream A"),
            _iface("*2", "sfp-sfpplus2", "ether", "Upstream B (on edge-r2)", running=False),
            _iface("*3", "sfp-sfpplus3", "ether", "Core"),
            _iface("*4", "ether1", "ether", "Management"),
            _iface("*5", "lo", "loopback", ""),
        ],
        "/ip/address": [
            {".id": "*1", "address": f"{mgmt}/24", "network": str(ipaddress.ip_interface(f"{mgmt}/24").network.network_address),
             "interface": "ether1", "actual-interface": "ether1", "disabled": "false", "dynamic": "false"},
            {".id": "*2", "address": "198.51.100.2/30", "network": "198.51.100.0", "interface": "sfp-sfpplus1",
             "actual-interface": "sfp-sfpplus1", "disabled": "false", "dynamic": "false"},
        ],
        "/routing/bgp/connection": [
            {".id": "*1", "name": "upstream-a", "remote.address": "198.51.100.1", "remote.as": "174",
             "local.role": "ebgp", "as": "154950", "address-families": "ip", "router-id": mgmt,
             "input.filter": "upstream-a-in", "output.filter-chain": "upstream-a-out", "disabled": "false"},
            {".id": "*2", "name": "shield-rtbh", "remote.address": "10.255.0.10", "remote.as": "154950",
             "local.role": "ibgp", "as": "154950", "address-families": "ip", "disabled": "false"},
        ],
        "/routing/bgp/session": [
            {".id": "*1", "name": "upstream-a-1", "remote.address": "198.51.100.1", "remote.as": "174",
             "local.address": "198.51.100.2", "local.as": "154950", "established": "true", "uptime": "2d03:14:07",
             "prefix-count": "981234", "remote.messages": "51234", "local.messages": "1211"},
        ],
        "/ip/route": [
            {".id": "*1", "dst-address": "163.5.191.0/24", "routing-table": "main", "gateway": "sfp-sfpplus3",
             "distance": "1", "active": "true", "static": "true", "comment": "VPS block 1"},
            {".id": "*2", "dst-address": "77.107.95.0/24", "routing-table": "main", "gateway": "sfp-sfpplus3",
             "distance": "1", "active": "true", "static": "true"},
            {".id": "*3", "dst-address": "163.52.252.0/23", "routing-table": "main", "blackhole": "true",
             "distance": "254", "active": "true", "static": "true", "comment": "aggregate anchor"},
            {".id": "*4", "dst-address": "0.0.0.0/0", "routing-table": "main", "gateway": "198.51.100.1",
             "distance": "20", "active": "true", "bgp": "true"},
        ],
        "/ip/traffic-flow": [{
            "enabled": "true", "interfaces": "sfp-sfpplus1", "cache-entries": "256k",
            "active-flow-timeout": "1m", "inactive-flow-timeout": "15s", "packet-sampling": "true",
            "sampling-interval": "1", "sampling-space": "1023",
        }],
        "/ip/traffic-flow/target": [
            {".id": "*1", "dst-address": "10.255.0.10", "port": "4739", "version": "ipfix",
             "src-address": mgmt, "disabled": "false"},
        ],
        "/ip/service": [
            {".id": "*1", "name": "api", "port": "8728", "disabled": "true", "address": ""},
            {".id": "*2", "name": "api-ssl", "port": "8729", "disabled": "false", "address": "10.255.0.10/32",
             "certificate": "api-ssl"},
            {".id": "*3", "name": "winbox", "port": "8291", "disabled": "false", "address": "10.255.0.0/24"},
        ],
        "/interface/ethernet/switch": [],
        "/ip/firewall/raw": [
            {".id": "*1", "chain": "prerouting", "action": "accept", "src-address": "10.255.0.0/24",
             "comment": "management", "disabled": "false", "packets": "1200", "bytes": "96000"},
            {".id": "*2", "chain": "prerouting", "action": "drop", "src-address-list": "bogons",
             "comment": "operator bogon filter", "disabled": "false", "packets": "55", "bytes": "3300"},
        ],
        "/ipv6/firewall/raw": [],
        "/user": [
            {".id": "*1", "name": "admin", "group": "full", "address": "", "disabled": "false"},
            {".id": "*2", "name": "shield-ro", "group": "shield-read", "address": "10.255.0.10/32", "disabled": "false"},
            {".id": "*3", "name": "shield-fw", "group": "shield-filter", "address": "10.255.0.10/32", "disabled": "false"},
        ],
        "/user/group": [
            {".id": "*1", "name": "full", "policy": "local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,sensitive,api,romon,rest-api"},
            {".id": "*2", "name": "shield-read", "policy": "read,api,test,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api"},
            {".id": "*3", "name": "shield-filter", "policy": "read,write,api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api"},
        ],
    }


def _iface(id_, name, type_, comment, running=True):
    return {".id": id_, "name": name, "default-name": name, "type": type_, "mtu": "1500", "actual-mtu": "1500",
            "mac-address": "48:A9:8A:00:00:0" + id_[-1], "running": "true" if running else "false",
            "disabled": "false", "comment": comment, "rx-byte": "0", "tx-byte": "0", "rx-packet": "0",
            "tx-packet": "0", "rx-drop": "0", "tx-drop": "0", "rx-error": "0", "tx-error": "0", "link-downs": "0"}


class RouterOSSimulator:
    def __init__(self, host="127.0.0.1", port=0, tls=False, users=None, state=None,
                 traffic_bps: dict[str, float] | None = None, writers: set[str] | None = None):
        self.users = users or {"shield-ro": "Test-Password-123"}
        self.writers = writers or set()
        self._next_id = 100
        self.state = state or default_state()
        self.lock = threading.Lock()
        self.traffic_bps = traffic_bps if traffic_bps is not None else {"sfp-sfpplus1": 2.4e9, "sfp-sfpplus3": 0.6e9}
        self.commands: list[list[str]] = []
        self.conns: list[socket.socket] = []
        self._last_tick = time.monotonic()
        self.srv = socket.create_server((host, port))
        self.host, self.port = self.srv.getsockname()[:2]
        self.ctx = None
        self.cert_der = None
        if tls:
            self.ctx, self.cert_der = _self_signed_context()
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self._stop = True
        for c in [self.srv, *self.conns]:
            try:
                c.shutdown(socket.SHUT_RDWR)   # wakes a blocked accept()/recv(); close() alone does not
            except OSError:
                pass
            try:
                c.close()
            except OSError:
                pass
        self.conns.clear()

    # ------------------------------------------------------------ state helpers
    def set(self, path: str, rows: list[dict]):
        with self.lock:
            self.state[path] = rows

    def update(self, path: str, match: dict, **changes):
        with self.lock:
            for r in self.state[path]:
                if all(r.get(k) == v for k, v in match.items()):
                    r.update({k.replace("_", "-"): v for k, v in changes.items()})

    def _advance_counters(self):
        now = time.monotonic()
        dt_s, self._last_tick = now - self._last_tick, now
        for r in self.state["/interface"]:
            bps = self.traffic_bps.get(r["name"], 0.0)
            if bps and r["running"] == "true":
                r["rx-byte"] = str(int(r["rx-byte"]) + int(bps / 8 * dt_s))
                r["rx-packet"] = str(int(r["rx-packet"]) + int(bps / 8 / 800 * dt_s))
                r["tx-byte"] = str(int(r["tx-byte"]) + int(bps / 80 * dt_s))
                r["tx-packet"] = str(int(r["tx-packet"]) + int(bps / 80 / 300 * dt_s))

    # ------------------------------------------------------------ server
    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            self.conns.append(conn)
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        try:
            if self.ctx:
                conn = self.ctx.wrap_socket(conn, server_side=True)
            conn.settimeout(30)
            rd = _Reader(conn)
            authed = False
            user = None
            while True:
                words = rd.sentence()
                if not words:
                    continue
                with self.lock:
                    self.commands.append(words)
                cmd = words[0]
                attrs = {w[1:].partition("=")[0]: w[1:].partition("=")[2] for w in words[1:] if w.startswith("=")}
                queries = [w[1:] for w in words[1:] if w.startswith("?")]
                if cmd == "/login":
                    if self.users.get(attrs.get("name")) == attrs.get("password"):
                        authed = True
                        user = attrs.get("name")
                        conn.sendall(encode_sentence(["!done"]))
                    else:
                        conn.sendall(encode_sentence(["!trap", "=message=invalid user name or password (6)"])
                                     + encode_sentence(["!done"]))
                    continue
                if not authed:
                    conn.sendall(encode_sentence(["!fatal", "not logged in"]))
                    return
                if cmd == "/quit":
                    conn.sendall(encode_sentence(["!fatal", "session terminated on request"]))
                    return
                conn.sendall(self._reply(cmd, attrs, queries, user))
        except (OSError, ConnectionError, ssl.SSLError):
            pass
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def count_packets(self, path: str, comment: str, packets: int, nbytes: int = 0) -> None:
        """Advance a rule's counters (tests: traffic matched by a drop rule)."""
        with self.lock:
            for r in self.state[path]:
                if r.get("comment") == comment:
                    r["packets"] = str(int(r.get("packets", "0")) + packets)
                    r["bytes"] = str(int(r.get("bytes", "0")) + nbytes)

    def _write(self, cmd: str, attrs: dict, user: str | None) -> bytes:
        trap = lambda m: encode_sentence(["!trap", f"=message={m}"]) + encode_sentence(["!done"])  # noqa: E731
        base, _, verb = cmd.rpartition("/")
        if user not in self.writers or base not in ("/ip/firewall/raw", "/ipv6/firewall/raw") or verb not in ("add", "remove"):
            return trap("not enough permissions (9)")
        with self.lock:
            rows = self.state.setdefault(base, [])
            if verb == "remove":
                n = len(rows)
                rows[:] = [r for r in rows if r.get(".id") != attrs.get("numbers")]
                return encode_sentence(["!done"]) if len(rows) < n else trap("no such item")
            self._next_id += 1
            rid = f"*{self._next_id:X}"
            row = {".id": rid, **{k: v for k, v in attrs.items() if k != "place-before"}, "packets": "0", "bytes": "0",
                   "disabled": attrs.get("disabled", "false").replace("no", "false")}
            before = attrs.get("place-before")
            idx = next((i for i, r in enumerate(rows) if r.get(".id") == before), None) if before else None
            if before and idx is None:
                return trap("no such item")
            rows.insert(idx if idx is not None else len(rows), row)
            return encode_sentence(["!done", f"=ret={rid}"])

    def _reply(self, cmd: str, attrs: dict, queries: list[str], user: str | None = None) -> bytes:
        if not cmd.endswith("/print"):
            return self._write(cmd, attrs, user)
        path = cmd[: -len("/print")]
        with self.lock:
            if path == "/interface":
                self._advance_counters()
            rows = copy.deepcopy(self.state.get(path))
        if rows is None:
            return encode_sentence(["!trap", "=message=no such command prefix"]) + encode_sentence(["!done"])
        for q in queries:
            k, _, v = q.partition("=")
            rows = [r for r in rows if r.get(k, "false" if v in ("false", "no") else None) == v
                    or (v in ("yes", "true") and r.get(k) in ("yes", "true"))]
        if "count-only" in attrs:
            return encode_sentence(["!done", f"=ret={len(rows)}"])
        prop = attrs.get(".proplist")
        out = b""
        for r in rows:
            if prop:
                r = {k: v for k, v in r.items() if k in prop.split(",")}
            out += encode_sentence(["!re"] + [f"={k}={v}" for k, v in r.items()])
        return out + encode_sentence(["!done"])


def _self_signed_context():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "routeros-simulator")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = f"{d}/c.pem", f"{d}/k.pem"
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    return ctx, cert.public_bytes(serialization.Encoding.DER)


def main(argv=None):
    ap = argparse.ArgumentParser(description="RouterOS API simulator (lab/testing only)")
    ap.add_argument("--host", default="127.0.0.1", help="listen address (keep it on loopback or a lab network)")
    ap.add_argument("--model", default="CCR2004-1G-12S+2XS")
    ap.add_argument("--port", type=int, default=18729)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--name", default="edge-r1")
    ap.add_argument("--mgmt", default="10.255.0.1")
    ap.add_argument("--user", default="shield-ro")
    ap.add_argument("--password", default="Test-Password-123")
    a = ap.parse_args(argv)
    sim = RouterOSSimulator(a.host, a.port, a.tls, {a.user: a.password}, default_state(a.name, a.mgmt, a.model)).start()
    from .api import colon_fingerprint
    fp = colon_fingerprint(__import__("hashlib").sha256(sim.cert_der).hexdigest()) if sim.cert_der else None
    print(f"RouterOS simulator '{a.name}' on {sim.host}:{sim.port} tls={a.tls} user={a.user}"
          + (f"\ncertificate sha256 {fp}" if fp else ""), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        sim.stop()
    return 0


if __name__ == "__main__":
    main()
