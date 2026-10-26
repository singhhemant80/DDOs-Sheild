"""IP address -> origin AS lookup, for showing where attack traffic comes from.

Uses the iptoasn.com "ip2asn-combined" table (public domain): one line per announced range,
`range_start  range_end  AS_number  country  AS_description`, tab-separated, gzip-compressed.
It is downloaded at install time and weekly by `python -m app.cli update-asn`. The table is loaded
lazily, reloaded when the file changes, and looked up with a binary search.

AS 0 in the table means "not routed": no AS announces the address (often spoofed or bogon).
"""
from __future__ import annotations

import bisect
from array import array
import gzip
import ipaddress
import logging
import os
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from .config import get_settings

log = logging.getLogger("shield.asn")
MIN_ROWS = 1000  # a downloaded table smaller than this is rejected as broken


@dataclass(frozen=True)
class AsInfo:
    asn: int
    name: str
    country: str


class AsnTable:
    # IPv4 ranges in compact arrays (most of the table); IPv6 as Python ints. `info` is shared.
    def __init__(self, starts4, ends4, idx4, starts6, ends6, idx6, infos: list, loaded_from: str, mtime: float):
        self._s4, self._e4, self._i4 = starts4, ends4, idx4
        self._s6, self._e6, self._i6 = starts6, ends6, idx6
        self._infos = infos
        self._by_asn: dict[int, AsInfo] = {}
        for i in infos:
            self._by_asn.setdefault(i.asn, i)
        self.loaded_from, self.mtime = loaded_from, mtime

    def by_asn(self, asn: int) -> AsInfo | None:
        return self._by_asn.get(asn)

    @property
    def size(self) -> int:
        return len(self._s4) + len(self._s6)

    def lookup(self, ip: str) -> AsInfo | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        s, e, inf = (self._s4, self._e4, self._i4) if a.version == 4 else (self._s6, self._e6, self._i6)
        n = int(a)
        i = bisect.bisect_right(s, n) - 1
        if i >= 0 and n <= e[i]:
            return self._infos[inf[i]]
        return None


def parse(lines, path: str = "", mtime: float = 0.0) -> AsnTable:
    v4: list[tuple[int, int, int]] = []
    v6: list[tuple[int, int, int]] = []
    infos: list[AsInfo] = []
    index: dict[tuple[int, str, str], int] = {}
    for line in lines:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 5:
            continue
        try:
            a, b = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
            asn = int(parts[2])
        except ValueError:
            continue
        if a.version != b.version:
            continue
        key = (asn, parts[3], parts[4])
        k = index.get(key)
        if k is None:
            k = index[key] = len(infos)
            infos.append(AsInfo(asn, (parts[4] or f"AS{asn}") if asn else "Not routed",
                                parts[3] if asn and parts[3] != "None" else ""))
        (v4 if a.version == 4 else v6).append((int(a), int(b), k))
    v4.sort()
    v6.sort()
    return AsnTable(array("I", (r[0] for r in v4)), array("I", (r[1] for r in v4)), array("I", (r[2] for r in v4)),
                    [r[0] for r in v6], [r[1] for r in v6], array("I", (r[2] for r in v6)), infos, path, mtime)


_lock = threading.Lock()
_table: AsnTable | None = None
_checked = 0.0


def table() -> AsnTable | None:
    """The current table, reloading it if the file changed (checked at most once a minute)."""
    global _table, _checked
    import time
    path = get_settings().asn_db_path
    now = time.time()
    with _lock:
        if _table is not None and _table.loaded_from == path and now - _checked < 60:
            return _table
        _checked = now
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            _table = None
            return None
        if _table is not None and _table.loaded_from == path and _table.mtime == mtime:
            return _table
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                t = parse(f, path, mtime)
        except (OSError, EOFError) as e:
            log.warning("cannot read ASN database %s: %s", path, e)
            return _table
        _table = t
        log.info("ASN database loaded: %d ranges from %s", t.size, path)
        return _table


def status() -> dict:
    t = table()
    if t is None:
        return {"loaded": False, "path": get_settings().asn_db_path}
    return {"loaded": True, "ranges": t.size,
            "updated_at": datetime.fromtimestamp(t.mtime, UTC).isoformat()}


def update(url: str | None = None, path: str | None = None) -> int:
    """Download the table, check it, and replace the current file atomically. Returns ranges."""
    s = get_settings()
    url, path = url or s.asn_db_url, path or s.asn_db_path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".asn-", suffix=".gz")
    try:
        with os.fdopen(fd, "wb") as out, httpx.stream("GET", url, timeout=120, follow_redirects=True) as r:
            r.raise_for_status()
            for chunk in r.iter_bytes(1 << 16):
                out.write(chunk)
        with gzip.open(tmp, "rt", encoding="utf-8", errors="replace") as f:
            n = parse(f).size
        if n < MIN_ROWS:
            raise ValueError(f"downloaded table has only {n} ranges")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        return n
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
