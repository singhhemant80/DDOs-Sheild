"""RouterOS API client (plain API on 8728 or API-SSL on 8729) with a hard read-only guard.

Protocol summary: a *sentence* is a sequence of length-prefixed *words* ended by an empty word.
The client sends `/path/command` plus `=attr=value` / `?query` words; the router replies with
`!re` sentences (one per item), then `!done`; errors are `!trap` (then `!done`) or `!fatal`
(connection closed). RouterOS 7.18+ may answer `!empty` when nothing matches.
Login on RouterOS 6.43+ / v7: `/login =name= =password=`.

Read-only guard (Phase 5): Shield must not be able to change a router, whatever the account's
permissions. Every command is checked before anything is sent:
  * the command must be `.../print` (or `/login`, `/quit`);
  * only the attributes in READ_ATTRS may be passed (notably NOT `file=`: `print file=x` writes a
    file on the router; nor `numbers=`, `disabled=`, ... which belong to editing commands);
  * query words (`?k=v`) are allowed: they only filter.
A violation raises WriteRefused and nothing is transmitted.

TLS: with a pinned SHA-256 fingerprint the connection is accepted only if the certificate matches.
Without a pin and with verification on, the certificate must chain to a trusted CA and match the
address; otherwise TLSUntrusted is raised *before the password is sent*, carrying the fingerprint
the router presented so an operator can compare it and pin it.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import socket
import ssl
import time
from dataclasses import dataclass

DEFAULT_TIMEOUT = 5.0
MAX_WORD = 16 * 1024 * 1024
READ_COMMAND = re.compile(r"^/(?:[a-z0-9][a-z0-9\-]*/)*print$")
READ_ATTRS = {".proplist", "stats", "count-only", "detail", "without-paging", ".tag"}


class RouterOSError(Exception):
    """Base class. `kind` is a short machine-readable reason for the UI."""
    kind = "error"


class ConnectError(RouterOSError):
    kind = "unreachable"


class TLSUntrusted(ConnectError):
    kind = "tls_untrusted"

    def __init__(self, message: str, fingerprint: str | None = None):
        super().__init__(message)
        self.fingerprint = fingerprint  # hex, lowercase, no separators


class LoginError(RouterOSError):
    kind = "auth"


class TrapError(RouterOSError):
    kind = "trap"

    def __init__(self, message: str, category: str | None = None):
        super().__init__(message)
        self.category = category


class FatalError(ConnectError):
    kind = "fatal"


class WriteRefused(RouterOSError):
    kind = "write_refused"


# ---------------------------------------------------------------- wire format
def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x8000).to_bytes(2, "big")
    if n < 0x200000:
        return (n | 0xC00000).to_bytes(3, "big")
    if n < 0x10000000:
        return (n | 0xE0000000).to_bytes(4, "big")
    return b"\xf0" + n.to_bytes(4, "big")


def encode_word(w: str) -> bytes:
    b = w.encode("utf-8")
    return encode_length(len(b)) + b


def encode_sentence(words: list[str]) -> bytes:
    return b"".join(encode_word(w) for w in words) + b"\x00"


class _Reader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise ConnectError("connection closed by router")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def length(self) -> int:
        c = self.read(1)[0]
        if c < 0x80:
            return c
        if c < 0xC0:
            return ((c & 0x3F) << 8) | self.read(1)[0]
        if c < 0xE0:
            return ((c & 0x1F) << 16) | int.from_bytes(self.read(2), "big")
        if c < 0xF0:
            return ((c & 0x0F) << 24) | int.from_bytes(self.read(3), "big")
        if c == 0xF0:
            return int.from_bytes(self.read(4), "big")
        raise FatalError(f"invalid length prefix 0x{c:02x}")

    def word(self) -> str:
        n = self.length()
        if n > MAX_WORD:
            raise FatalError("word too long")
        return self.read(n).decode("utf-8", errors="replace")

    def sentence(self) -> list[str]:
        words = []
        while True:
            w = self.word()
            if w == "":
                return words
            words.append(w)


def parse_attrs(words: list[str]) -> dict[str, str]:
    out = {}
    for w in words:
        if w.startswith("="):
            k, _, v = w[1:].partition("=")
            out[k] = v
    return out


def check_read_only(words: list[str]) -> None:
    """Raise WriteRefused unless the sentence is a pure read. Called before every send."""
    if not words:
        raise WriteRefused("empty command")
    cmd = words[0]
    if cmd in ("/login", "/quit"):
        return
    if not READ_COMMAND.match(cmd):
        raise WriteRefused(f"Shield is in read-only mode: {cmd!r} is not a print command")
    for w in words[1:]:
        if w.startswith("?"):
            continue
        if w.startswith("="):
            name = w[1:].partition("=")[0]
            if name not in READ_ATTRS:
                raise WriteRefused(f"Shield is in read-only mode: argument {name!r} is not allowed")
            continue
        if w.startswith(".tag="):
            continue
        raise WriteRefused(f"unexpected word {w!r}")


def normalise_fingerprint(fp: str) -> str:
    """Accept 'AB:CD:...', 'abcd...', spaces; return 64 lowercase hex digits."""
    h = re.sub(r"[\s:]", "", fp or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", h):
        raise ValueError("a SHA-256 fingerprint has 64 hexadecimal digits")
    return h


def colon_fingerprint(fp: str) -> str:
    h = normalise_fingerprint(fp).upper()
    return ":".join(h[i:i + 2] for i in range(0, 64, 2))


# ---------------------------------------------------------------- client
@dataclass
class TLSInfo:
    verified_by: str = "plain"    # "pinned" | "ca" | "none" (TLS, not verified) | "plain" (no TLS)
    fingerprint: str | None = None
    version: str | None = None


class ReadOnlyClient:
    def __init__(self, host: str, port: int, username: str, password: str, *, use_tls: bool = True,
                 verify_tls: bool = True, fingerprint: str | None = None, timeout: float = DEFAULT_TIMEOUT):
        self.host, self.port, self.username, self.password = host, port, username, password
        self.use_tls, self.verify_tls, self.timeout = use_tls, verify_tls, timeout
        self.pin = normalise_fingerprint(fingerprint) if fingerprint else None
        self.sock: socket.socket | None = None
        self.reader: _Reader | None = None
        self.tls = TLSInfo()
        self.last_latency_ms: float | None = None
        self.refused_writes = 0

    # --- connection --------------------------------------------------------------------------
    def _tcp(self) -> socket.socket:
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as e:
            raise ConnectError(f"cannot reach {self.host}:{self.port}: {e.strerror or e}") from None
        s.settimeout(self.timeout)
        return s

    def connect(self) -> "ReadOnlyClient":
        sock = self._tcp()
        if self.use_tls:
            sock = self._tls(sock)
        self.sock, self.reader = sock, _Reader(sock)
        self._login()
        return self

    def _tls(self, raw: socket.socket) -> socket.socket:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ca_mode = self.verify_tls and not self.pin
        if ca_mode:
            ctx.load_default_certs()
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # pinned: the fingerprint comparison below is the check
        try:
            s = ctx.wrap_socket(raw, server_hostname=self.host)
        except ssl.SSLCertVerificationError as e:
            raw.close()
            fp = fetch_certificate(self.host, self.port, self.timeout).get("fingerprint_hex")
            raise TLSUntrusted(f"the router's certificate is not trusted ({e.verify_message}). "
                               "Compare its fingerprint with the router and pin it.", fp) from None
        except (ssl.SSLError, OSError) as e:
            raw.close()
            raise ConnectError(f"TLS handshake failed ({e}). Is a certificate assigned to the api-ssl service?") from None
        der = s.getpeercert(binary_form=True) or b""
        fp = hashlib.sha256(der).hexdigest() if der else None
        self.tls = TLSInfo(fingerprint=fp, version=s.version())
        if self.pin:
            if not fp or not hmac.compare_digest(fp, self.pin):
                s.close()
                raise TLSUntrusted(
                    f"the router presented certificate {colon_fingerprint(fp) if fp else '(none)'}, "
                    f"not the pinned {colon_fingerprint(self.pin)}. If it was replaced on purpose, pin the new one.", fp)
            self.tls.verified_by = "pinned"
        else:
            self.tls.verified_by = "ca" if ca_mode else "none"
        return s

    def _login(self) -> None:
        try:
            replies = self._talk(["/login", f"=name={self.username}", f"=password={self.password}"])
        except TrapError as e:
            self.close()
            raise LoginError(f"login refused: {e}") from None
        if replies and "ret" in replies[-1]:
            self.close()
            raise LoginError("this router uses the pre-6.43 login method; RouterOS 7 is required")

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock, self.reader = None, None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    # --- commands ----------------------------------------------------------------------------
    def _talk(self, words: list[str]) -> list[dict]:
        """Send one sentence; return the attribute dicts of !re replies followed by the !done attrs."""
        try:
            check_read_only(words)
        except WriteRefused:
            self.refused_writes += 1
            raise
        if not self.sock or not self.reader:
            raise ConnectError("not connected")
        t0 = time.monotonic()
        rows: list[dict] = []
        trap: TrapError | None = None
        try:
            self.sock.sendall(encode_sentence(words))
            while True:
                s = self.reader.sentence()
                if not s:
                    continue
                kind, attrs = s[0], parse_attrs(s[1:])
                if kind == "!re":
                    rows.append(attrs)
                elif kind == "!trap":
                    trap = TrapError(attrs.get("message", "error"), attrs.get("category"))
                elif kind == "!fatal":
                    self.close()
                    raise FatalError(s[1] if len(s) > 1 else "router closed the session")
                elif kind == "!empty":
                    continue
                elif kind == "!done":
                    rows.append(attrs)
                    break
        except (socket.timeout, TimeoutError):
            self.close()
            raise ConnectError(f"router did not answer within {self.timeout:.0f} s") from None
        except (OSError, ssl.SSLError) as e:
            self.close()
            raise ConnectError(f"connection lost: {e}") from None
        self.last_latency_ms = round((time.monotonic() - t0) * 1000, 1)
        if trap is not None:
            raise trap
        return rows

    def run(self, command: str, attrs: dict[str, str] | None = None, queries: list[str] | None = None) -> list[dict]:
        words = [command] + [f"={k}={v}" for k, v in (attrs or {}).items()] + [f"?{q}" for q in (queries or [])]
        return self._talk(words)[:-1]

    def print(self, path: str, *, proplist: list[str] | None = None, queries: list[str] | None = None,
              stats: bool = False) -> list[dict]:
        attrs: dict[str, str] = {}
        if stats:
            attrs["stats"] = ""
        if proplist:
            attrs[".proplist"] = ",".join(proplist)
        return self.run(f"{path.rstrip('/')}/print", attrs, queries)

    def count(self, path: str, queries: list[str] | None = None) -> int:
        words = [f"{path.rstrip('/')}/print", "=count-only="] + [f"?{q}" for q in (queries or [])]
        done = self._talk(words)[-1]
        try:
            return int(done.get("ret", "0"))
        except ValueError:
            return 0


def fetch_certificate(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Read the certificate the router presents, trusting nothing and sending no credentials, so an
    operator can compare its fingerprint with `/certificate print detail` on the router and pin it."""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise ConnectError(f"cannot reach {host}:{port}: {e.strerror or e}") from None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True) or b""
            version = s.version()
    except (ssl.SSLError, OSError) as e:
        raise ConnectError(f"TLS handshake failed ({e}). Is a certificate assigned to the api-ssl service?") from None
    fp = hashlib.sha256(der).hexdigest()
    info: dict = {"fingerprint": colon_fingerprint(fp), "fingerprint_hex": fp, "tls_version": version}
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        info.update(subject=c.subject.rfc4514_string(), issuer=c.issuer.rfc4514_string(),
                    not_after=c.not_valid_after_utc.isoformat(), self_signed=c.subject == c.issuer)
    except Exception:  # the fingerprint is what matters
        pass
    return info
