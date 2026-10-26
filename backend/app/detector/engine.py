"""Detection engine: turns one-second traffic snapshots into incident decisions.

Pure and deterministic: no database, no Redis, no wall clock. The service feeds it snapshots
and persists the events it returns. Everything here is unit-tested second by second.

Decision model (per destination address, and per protected prefix for carpet bombing)
--------------------------------------------------------------------------------------
1. Each second, `classify` compares the destination's rates with its profile thresholds and
   returns *signals*: an attack vector, its measured rate, the threshold, and how specific the
   vector is (a single reflection source port is very specific; "lots of packets" is not).
2. A second with any signal is *hot*.
3. idle -> SUSPECTED   when `suspect_hits` of the last `suspect_window` seconds are hot.
4. SUSPECTED -> CONFIRMED when at least 80% of the last `confirm_seconds` seconds were hot AND
   the current confidence >= `confirm_confidence`. Only confirmed attacks may ever be mitigated.
5. SUSPECTED -> resolved ("cleared_unconfirmed") after `suspect_timeout_seconds` without a hot second.
6. CONFIRMED -> resolved ("ended") after `release_seconds` consecutive quiet seconds (not hot and
   below half the packet threshold), so a pulsing attack does not flap.

Time only advances on seconds that have data. If the collector stops, nothing is resolved:
missing data is not evidence that an attack ended.

Confidence (0..1) = quality x (0.30 magnitude + 0.30 specificity + 0.25 persistence + 0.15 baseline)
  magnitude   how far over threshold (3x or more = 1.0)
  specificity how characteristic the vector is (see VECTOR_SPECIFICITY)
  persistence share of hot seconds in the confirm window
  baseline    how far above this destination's learned normal for this hour of the week
              (0.6 when there is not yet enough history)
  quality     1.0 for sampled/measured data, 0.7 when the sampling rate was unknown (estimated)
"""
from __future__ import annotations

import ipaddress
import math
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Iterable

Net = ipaddress.IPv4Network | ipaddress.IPv6Network

REFLECTION_VECTORS = {
    53: "dns_amplification", 123: "ntp_amplification", 1900: "ssdp_amplification",
    389: "cldap_amplification", 11211: "memcached_amplification", 19: "chargen_amplification",
    161: "snmp_amplification", 3702: "wsd_amplification", 5683: "coap_amplification",
    3283: "ard_amplification", 111: "portmap_amplification", 137: "netbios_amplification",
}

VECTOR_SPECIFICITY = {
    **{v: 1.0 for v in REFLECTION_VECTORS.values()},
    "syn_flood": 0.9, "icmp_flood": 0.85, "fragment_flood": 0.85, "ack_flood": 0.8, "rst_flood": 0.8,
    "udp_flood": 0.7, "carpet_bombing": 0.75, "volumetric_pps": 0.5, "volumetric_bps": 0.5,
    "traffic_anomaly": 0.3,
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
BASELINE_MIN_SAMPLES = 30
CONFIRM_HOT_SHARE = 0.8
QUIET_PPS_SHARE = 0.5


# ---------------------------------------------------------------- profiles
@dataclass(frozen=True)
class Profile:
    id: int
    name: str
    scope: Net
    dst_pps: float | None = 100_000
    dst_bps: float | None = 1e9
    syn_pps: float | None = 50_000
    tcp_flag_pps: float | None = 100_000
    udp_pps: float | None = 100_000
    icmp_pps: float | None = 20_000
    reflect_pps: float | None = 20_000
    frag_pps: float | None = 20_000
    prefix_pps: float | None = 500_000
    prefix_bps: float | None = 5e9
    baseline_factor: float = 4.0
    anomaly_min_pps: float = 20_000
    suspect_hits: int = 3
    suspect_window: int = 5
    confirm_seconds: int = 20
    confirm_confidence: float = 0.7
    release_seconds: int = 120
    suspect_timeout_seconds: int = 60

    @classmethod
    def from_row(cls, r) -> "Profile":
        f = lambda v: None if v is None else float(v)  # noqa: E731
        return cls(
            id=r.id, name=r.name, scope=ipaddress.ip_network(str(r.scope)),
            dst_pps=f(r.dst_pps), dst_bps=f(r.dst_bps), syn_pps=f(r.syn_pps), tcp_flag_pps=f(r.tcp_flag_pps),
            udp_pps=f(r.udp_pps), icmp_pps=f(r.icmp_pps), reflect_pps=f(r.reflect_pps), frag_pps=f(r.frag_pps),
            prefix_pps=f(r.prefix_pps), prefix_bps=f(r.prefix_bps), baseline_factor=float(r.baseline_factor),
            anomaly_min_pps=float(r.anomaly_min_pps), suspect_hits=r.suspect_hits, suspect_window=r.suspect_window,
            confirm_seconds=r.confirm_seconds, confirm_confidence=float(r.confirm_confidence),
            release_seconds=r.release_seconds, suspect_timeout_seconds=r.suspect_timeout_seconds)


class ProfileSet:
    """Most-specific-wins lookup. Customer overrides replace dst_pps / dst_bps for one address."""

    def __init__(self, profiles: Iterable[Profile], customer_overrides: dict[str, tuple[float | None, float | None]] | None = None):
        self.profiles = sorted(profiles, key=lambda p: p.scope.prefixlen, reverse=True)
        self.overrides = customer_overrides or {}
        self._cache: dict[str, Profile] = {}

    def for_net(self, net: Net) -> Profile:
        key = str(net)
        p = self._cache.get(key)
        if p is None:
            p = next((x for x in self.profiles if x.scope.version == net.version and net.subnet_of(x.scope)), None)
            if p is None:
                p = Profile(id=0, name="built-in", scope=ipaddress.ip_network("::/0" if net.version == 6 else "0.0.0.0/0"))
            o = self.overrides.get(key)
            if o:
                from dataclasses import replace
                p = replace(p, dst_pps=o[0] if o[0] is not None else p.dst_pps,
                            dst_bps=o[1] if o[1] is not None else p.dst_bps)
            self._cache[key] = p
        return p


# ---------------------------------------------------------------- samples & signals
@dataclass
class Sample:
    pps: float = 0.0
    bps: float = 0.0
    tcp: float = 0.0
    udp: float = 0.0
    icmp: float = 0.0
    other: float = 0.0
    syn: float = 0.0
    ack: float = 0.0
    rst: float = 0.0
    frag: float = 0.0
    reflect: dict[int, float] = field(default_factory=dict)
    sources: float = 0.0
    provenance: str = "sampled"
    top_share: float = 1.0  # prefix aggregates: share of the busiest destination

    @classmethod
    def from_dst(cls, d: dict) -> "Sample":
        return cls(pps=d.get("pps", 0.0), bps=d.get("bps", 0.0), tcp=d.get("tcp_pps", 0.0), udp=d.get("udp_pps", 0.0),
                   icmp=d.get("icmp_pps", 0.0), other=d.get("other_pps", 0.0), syn=d.get("syn_pps", 0.0),
                   ack=d.get("ack_pps", 0.0), rst=d.get("rst_pps", 0.0), frag=d.get("frag_pps", 0.0),
                   reflect={int(k): v for k, v in (d.get("reflect") or {}).items()},
                   sources=d.get("sources_est", 0.0), provenance=d.get("provenance", "sampled"))

    def add(self, o: "Sample") -> None:
        for f in ("pps", "bps", "tcp", "udp", "icmp", "other", "syn", "ack", "rst", "frag"):
            setattr(self, f, getattr(self, f) + getattr(o, f))
        for k, v in o.reflect.items():
            self.reflect[k] = self.reflect.get(k, 0.0) + v
        self.sources = max(self.sources, o.sources)
        if o.provenance == "estimated":
            self.provenance = "estimated"

    def metrics(self) -> dict:
        return {"pps": round(self.pps), "bps": round(self.bps), "tcp_pps": round(self.tcp), "udp_pps": round(self.udp),
                "icmp_pps": round(self.icmp), "syn_pps": round(self.syn), "ack_pps": round(self.ack),
                "rst_pps": round(self.rst), "frag_pps": round(self.frag), "sources_est": round(self.sources),
                "reflect": {str(k): round(v) for k, v in self.reflect.items() if v >= 1},
                "provenance": self.provenance}


@dataclass(frozen=True)
class Signal:
    vector: str
    value: float
    threshold: float

    @property
    def ratio(self) -> float:
        return self.value / self.threshold if self.threshold else 0.0

    @property
    def specificity(self) -> float:
        return VECTOR_SPECIFICITY.get(self.vector, 0.5)


def _share(part: float, whole: float) -> float:
    return part / whole if whole > 0 else 0.0


def classify(s: Sample, p: Profile, baseline: tuple[float, float] | None = None) -> list[Signal]:
    """Signals for one destination-second. `baseline` = (mean_pps, std_pps) for this hour of week."""
    out: list[Signal] = []
    reflection = False
    if p.reflect_pps:
        for port, v in s.reflect.items():
            if port in REFLECTION_VECTORS and v >= p.reflect_pps:
                out.append(Signal(REFLECTION_VECTORS[port], v, p.reflect_pps))
                reflection = True
    if p.syn_pps and s.syn >= p.syn_pps and _share(s.syn, s.tcp) >= 0.5:
        out.append(Signal("syn_flood", s.syn, p.syn_pps))
    if p.tcp_flag_pps and s.ack >= p.tcp_flag_pps and _share(s.ack, s.tcp) >= 0.6:
        out.append(Signal("ack_flood", s.ack, p.tcp_flag_pps))
    if p.tcp_flag_pps and s.rst >= p.tcp_flag_pps:
        out.append(Signal("rst_flood", s.rst, p.tcp_flag_pps))
    if p.icmp_pps and s.icmp >= p.icmp_pps and _share(s.icmp, s.pps) >= 0.5:
        out.append(Signal("icmp_flood", s.icmp, p.icmp_pps))
    if p.frag_pps and s.frag >= p.frag_pps and _share(s.frag, s.pps) >= 0.3:
        out.append(Signal("fragment_flood", s.frag, p.frag_pps))
    if p.udp_pps and not reflection and s.udp >= p.udp_pps and _share(s.udp, s.pps) >= 0.6:
        out.append(Signal("udp_flood", s.udp, p.udp_pps))
    if p.dst_pps and s.pps >= p.dst_pps:
        out.append(Signal("volumetric_pps", s.pps, p.dst_pps))
    if p.dst_bps and s.bps >= p.dst_bps:
        out.append(Signal("volumetric_bps", s.bps, p.dst_bps))
    if baseline is not None and not out:
        mean, std = baseline
        limit = max(p.anomaly_min_pps, (mean + 2.33 * std) * p.baseline_factor)
        if s.pps >= limit:
            out.append(Signal("traffic_anomaly", s.pps, limit))
    return out


def classify_prefix(s: Sample, p: Profile) -> list[Signal]:
    """Carpet bombing: the prefix as a whole is over its thresholds while no single address carries
    most of it. Adds the dominant protocol as a second vector for the operator."""
    if s.top_share >= 0.5:
        return []
    out: list[Signal] = []
    if p.prefix_pps and s.pps >= p.prefix_pps:
        out.append(Signal("carpet_bombing", s.pps, p.prefix_pps))
    elif p.prefix_bps and s.bps >= p.prefix_bps:
        out.append(Signal("carpet_bombing", s.bps, p.prefix_bps))
    if not out:
        return out
    thr = out[0].threshold
    dom = max(s.reflect.items(), key=lambda kv: kv[1], default=(0, 0.0))
    if dom[0] in REFLECTION_VECTORS and _share(dom[1], s.pps) >= 0.5:
        out.append(Signal(REFLECTION_VECTORS[dom[0]], dom[1], thr))
    elif _share(s.syn, s.pps) >= 0.5:
        out.append(Signal("syn_flood", s.syn, thr))
    elif _share(s.udp, s.pps) >= 0.6:
        out.append(Signal("udp_flood", s.udp, thr))
    elif _share(s.icmp, s.pps) >= 0.5:
        out.append(Signal("icmp_flood", s.icmp, thr))
    return out


def severity_of(signals: list[Signal], s: Sample) -> str:
    if not signals:
        return "info"
    strong = [x for x in signals if x.vector != "traffic_anomaly"]
    if not strong:
        return "low"
    r = max(x.ratio for x in strong)
    sev = "low" if r < 2 else "medium" if r < 5 else "high" if r < 20 else "critical"
    if s.bps >= 10e9:
        sev = "critical"
    elif s.bps >= 1e9 and SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index("high"):
        sev = "high"
    return sev


def confidence_of(signals: list[Signal], s: Sample, persistence: float,
                  baseline: tuple[float, float] | None) -> tuple[float, dict]:
    if not signals:
        return 0.0, {"magnitude": 0, "specificity": 0, "persistence": round(persistence, 3), "baseline": 0, "quality": 1}
    magnitude = min(1.0, max(0.0, (max(x.ratio for x in signals) - 1) / 2))
    specificity = max(x.specificity for x in signals)
    if baseline is not None:
        mean, std = baseline
        z = (s.pps - mean) / max(std, mean * 0.1, 1.0)
        base = min(1.0, max(0.0, z / 6))
    else:
        base = 0.6
    quality = 0.7 if s.provenance == "estimated" else 1.0
    conf = quality * (0.30 * magnitude + 0.30 * specificity + 0.25 * persistence + 0.15 * base)
    return round(min(1.0, conf), 3), {
        "magnitude": round(magnitude, 3), "specificity": round(specificity, 3),
        "persistence": round(persistence, 3), "baseline": round(base, 3), "quality": quality,
        "baseline_known": baseline is not None,
    }


# ---------------------------------------------------------------- baselines
@dataclass
class _Stat:
    mean: float = 0.0
    var: float = 0.0
    n: int = 0

    def update(self, x: float) -> None:
        self.n += 1
        a = max(1.0 / self.n, 0.05)  # exact mean for the first 20 samples, then EWMA
        d = x - self.mean
        self.mean += a * d
        self.var = (1 - a) * (self.var + a * d * d)


def hour_of_week(ts: int) -> int:
    d = datetime.fromtimestamp(ts, UTC)
    return d.weekday() * 24 + d.hour


class Baselines:
    """Per-destination packet-rate baseline per UTC hour of the week, learned from one-minute
    averages of minutes with traffic, excluding minutes during an open incident."""

    def __init__(self):
        self.stats: dict[tuple[str, int], _Stat] = {}
        self.dirty: set[tuple[str, int]] = set()

    def get(self, key: str, ts: int) -> tuple[float, float] | None:
        st = self.stats.get((key, hour_of_week(ts)))
        if st is None or st.n < BASELINE_MIN_SAMPLES:
            return None
        return st.mean, math.sqrt(max(st.var, 0.0))

    def learn(self, key: str, minute_ts: int, avg_pps: float) -> None:
        k = (key, hour_of_week(minute_ts))
        self.stats.setdefault(k, _Stat()).update(avg_pps)
        self.dirty.add(k)

    def load(self, key: str, slot: int, mean: float, std: float, n: int) -> None:
        self.stats[(key, slot)] = _Stat(mean=mean, var=std * std, n=n)

    def take_dirty(self) -> list[tuple[str, int, float, float, int]]:
        out = []
        for k in self.dirty:
            st = self.stats[k]
            out.append((k[0], k[1], st.mean, math.sqrt(max(st.var, 0.0)), st.n))
        self.dirty.clear()
        return out


# ---------------------------------------------------------------- state machine
@dataclass
class Event:
    kind: str            # suspected | confirmed | escalated | vectors_changed | update | resolved
    key: str             # "163.5.191.20/32" or "163.5.191.0/24"
    scope: str           # host | prefix
    prefix: str | None
    ts: int
    status: str
    severity: str
    vectors: list[str]
    confidence: float      # peak so far
    current_confidence: float
    breakdown: dict
    sample: dict
    peak_pps: float
    peak_bps: float
    profile_id: int
    signals: list[dict]
    resolution: str | None = None
    started_ts: int = 0
    confirmed_ts: int | None = None


@dataclass
class _Track:
    key: str
    scope: str
    prefix: str | None
    profile: Profile
    history: deque = field(default_factory=lambda: deque(maxlen=600))  # (ts, hot)
    status: str = "idle"
    started_ts: int = 0
    confirmed_ts: int | None = None
    last_hot_ts: int = 0
    quiet_seconds: int = 0
    seconds_since_hot: int = 0
    severity: str = "info"
    vectors: set = field(default_factory=set)
    peak_conf: float = 0.0
    peak_pps: float = 0.0
    peak_bps: float = 0.0
    seen_ts: int = 0

    def hot_count(self, n: int) -> int:
        return sum(1 for _, h in list(self.history)[-n:] if h)


class Engine:
    IDLE_FORGET_SECONDS = 600

    def __init__(self, profiles: ProfileSet, baselines: Baselines | None = None):
        self.profiles = profiles
        self.baselines = baselines or Baselines()
        self.tracks: dict[str, _Track] = {}
        self.suppressed: dict[str, int] = {}
        self._minute: int | None = None
        self._minute_sums: dict[str, tuple[float, int]] = {}
        self.last_ts: int | None = None

    def set_profiles(self, profiles: ProfileSet) -> None:
        self.profiles = profiles
        for t in self.tracks.values():
            t.profile = profiles.for_net(ipaddress.ip_network(t.key))

    # --- external control -------------------------------------------------------------------
    def restore(self, key: str, scope: str, prefix: str | None, status: str, started_ts: int,
                confirmed_ts: int | None, severity: str, vectors: list[str], peak_conf: float,
                peak_pps: float, peak_bps: float) -> None:
        """Resume an open incident after a restart. Timers start fresh: if traffic is already quiet
        it is released after the normal quiet period, never instantly."""
        t = self._track(key, scope, prefix)
        t.status = "confirmed" if status in ("confirmed", "mitigating", "mitigated") else "suspected"
        t.started_ts, t.confirmed_ts, t.severity = started_ts, confirmed_ts, severity
        t.vectors, t.peak_conf, t.peak_pps, t.peak_bps = set(vectors), peak_conf, peak_pps, peak_bps

    def close(self, key: str, suppress_until: int | None = None) -> None:
        """Incident ended outside the engine (e.g. marked false positive)."""
        self.tracks.pop(key, None)
        if suppress_until:
            self.suppressed[key] = suppress_until

    def open_keys(self) -> list[str]:
        return [k for k, t in self.tracks.items() if t.status != "idle"]

    # --- main loop ----------------------------------------------------------------------------
    def tick(self, snap: dict) -> list[Event]:
        ts = int(snap["ts"])
        if self.last_ts is not None and ts <= self.last_ts:
            return []  # duplicate or out-of-order second
        self.last_ts = ts
        events: list[Event] = []
        seen: set[str] = set()
        prefixes: dict[str, Sample] = {}
        tops: dict[str, float] = {}

        for d in snap.get("dsts", []):
            s = Sample.from_dst(d)
            key = _host_key(d["ip"])
            seen.add(key)
            self._accumulate_minute(key, ts, s.pps)
            events += self._step(key, "host", d.get("prefix"), ts, s)
            pfx = d.get("prefix")
            if pfx:
                agg = prefixes.setdefault(pfx, Sample(reflect={}))
                agg.add(s)
                tops[pfx] = max(tops.get(pfx, 0.0), s.pps)

        # Prefix aggregates (carpet bombing).
        for pfx, agg in prefixes.items():
            agg.top_share = tops[pfx] / agg.pps if agg.pps else 1.0
            seen.add(pfx)
            events += self._step(pfx, "prefix", pfx, ts, agg)

        # Tracked keys with no traffic this second: a real zero (the collector reported the second).
        for key, t in list(self.tracks.items()):
            if key not in seen:
                events += self._step(key, t.scope, t.prefix, ts, Sample(reflect={}))

        self._roll_minute(ts)
        for k, until in list(self.suppressed.items()):
            if until <= ts:
                del self.suppressed[k]
        return events

    # --- internals ----------------------------------------------------------------------------
    def _track(self, key: str, scope: str, prefix: str | None) -> _Track:
        t = self.tracks.get(key)
        if t is None:
            t = _Track(key=key, scope=scope, prefix=prefix, profile=self.profiles.for_net(ipaddress.ip_network(key)))
            self.tracks[key] = t
        return t

    def _step(self, key: str, scope: str, prefix: str | None, ts: int, s: Sample) -> list[Event]:
        t = self.tracks.get(key)
        if t is None:
            # Fast path: do not allocate state for quiet destinations.
            p = self.profiles.for_net(ipaddress.ip_network(key))
            if s.pps < _min_threshold(p, scope):
                return []
            t = self._track(key, scope, prefix)
        p = t.profile
        baseline = self.baselines.get(key, ts) if scope == "host" else None
        signals = classify(s, p, baseline) if scope == "host" else classify_prefix(s, p)
        hot = bool(signals)
        t.history.append((ts, hot))
        t.seen_ts = ts
        if hot:
            t.last_hot_ts = ts
            t.seconds_since_hot = 0
        else:
            t.seconds_since_hot += 1
        window = max(1, min(p.confirm_seconds, len(t.history)))
        persistence = t.hot_count(window) / window
        conf, breakdown = confidence_of(signals, s, persistence, baseline)
        quiet = (not hot) and s.pps < QUIET_PPS_SHARE * (p.dst_pps or p.prefix_pps or float("inf"))
        t.quiet_seconds = t.quiet_seconds + 1 if quiet else 0

        events: list[Event] = []
        mk = lambda kind, **kw: self._event(kind, t, ts, s, signals, conf, breakdown, **kw)  # noqa: E731

        if t.status == "idle":
            if hot and t.hot_count(p.suspect_window) >= p.suspect_hits and self.suppressed.get(key, 0) <= ts:
                t.status, t.started_ts = "suspected", ts
                t.vectors, t.severity = set(), "info"
                t.peak_conf = t.peak_pps = t.peak_bps = 0.0
                self._absorb(t, s, signals, conf)
                events.append(mk("suspected"))
            elif not hot and ts - t.last_hot_ts > self.IDLE_FORGET_SECONDS:
                self.tracks.pop(key, None)
            return events

        before_sev, before_vec = t.severity, set(t.vectors)
        if hot:
            self._absorb(t, s, signals, conf)
        if t.status == "suspected":
            held = len(t.history) >= p.confirm_seconds and \
                t.hot_count(p.confirm_seconds) >= math.ceil(CONFIRM_HOT_SHARE * p.confirm_seconds)
            if hot and held and conf >= p.confirm_confidence:
                t.status, t.confirmed_ts = "confirmed", ts
                events.append(mk("confirmed"))
            elif t.seconds_since_hot >= p.suspect_timeout_seconds:
                events.append(mk("resolved", resolution="cleared_unconfirmed"))
                self._reset(t)
                return events
        elif t.status == "confirmed" and t.quiet_seconds >= p.release_seconds:
            events.append(mk("resolved", resolution="ended"))
            self._reset(t)
            return events

        if SEVERITY_ORDER.index(t.severity) > SEVERITY_ORDER.index(before_sev):
            events.append(mk("escalated", previous=before_sev))
        if t.vectors != before_vec:
            events.append(mk("vectors_changed", previous=sorted(before_vec)))
        events.append(mk("update"))
        return events

    def _absorb(self, t: _Track, s: Sample, signals: list[Signal], conf: float) -> None:
        t.vectors |= {x.vector for x in signals}
        # A precise vector makes the generic labels redundant.
        if t.vectors - {"volumetric_pps", "volumetric_bps", "traffic_anomaly"}:
            t.vectors -= {"traffic_anomaly"}
        sev = severity_of(signals, s)
        if SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index(t.severity):
            t.severity = sev
        t.peak_conf = max(t.peak_conf, conf)
        t.peak_pps = max(t.peak_pps, s.pps)
        t.peak_bps = max(t.peak_bps, s.bps)

    def _reset(self, t: _Track) -> None:
        t.status, t.started_ts, t.confirmed_ts = "idle", 0, None
        t.vectors, t.severity, t.quiet_seconds = set(), "info", 0
        t.history.clear()

    def _event(self, kind: str, t: _Track, ts: int, s: Sample, signals: list[Signal], conf: float,
               breakdown: dict, resolution: str | None = None, **extra) -> Event:
        b = dict(breakdown)
        b.update(extra)
        return Event(kind=kind, key=t.key, scope=t.scope, prefix=t.prefix, ts=ts,
                     status="resolved" if kind == "resolved" else t.status, severity=t.severity,
                     vectors=_ordered(t.vectors), confidence=round(t.peak_conf, 3), current_confidence=conf,
                     breakdown=b, sample=s.metrics(), peak_pps=t.peak_pps, peak_bps=t.peak_bps,
                     profile_id=t.profile.id,
                     signals=[{"vector": x.vector, "value": round(x.value), "threshold": round(x.threshold),
                               "ratio": round(x.ratio, 2)} for x in signals],
                     resolution=resolution, started_ts=t.started_ts, confirmed_ts=t.confirmed_ts)

    # --- baseline learning (per minute, never during an incident) ------------------------------
    def _accumulate_minute(self, key: str, ts: int, pps: float) -> None:
        s, n = self._minute_sums.get(key, (0.0, 0))
        self._minute_sums[key] = (s + pps, n + 1)

    def _roll_minute(self, ts: int) -> None:
        minute = ts - ts % 60
        if self._minute is None:
            self._minute = minute
        if minute == self._minute:
            return
        for key, (s, n) in self._minute_sums.items():
            t = self.tracks.get(key)
            if t is not None and t.status != "idle":
                continue
            self.baselines.learn(key, self._minute, s / 60.0)  # absent seconds count as zero
        self._minute_sums.clear()
        self._minute = minute


def _min_threshold(p: Profile, scope: str) -> float:
    if scope == "prefix":
        return min(x for x in (p.prefix_pps, p.prefix_bps and p.prefix_bps / 12000, float("inf")) if x)
    vals = [p.dst_pps, p.syn_pps, p.tcp_flag_pps, p.udp_pps, p.icmp_pps, p.reflect_pps, p.frag_pps,
            p.anomaly_min_pps, p.dst_bps and p.dst_bps / 12000]  # bps over max-size packets
    return min((v for v in vals if v), default=float("inf"))


def _host_key(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    return f"{a}/{a.max_prefixlen}"


def _ordered(vectors: set[str]) -> list[str]:
    return sorted(vectors, key=lambda v: (-VECTOR_SPECIFICITY.get(v, 0.5), v))
