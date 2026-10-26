"""shield-detector: drives the engine from the collector's Redis stream and persists incidents.

    python -m app.detector                       # run the service
    python -m app.detector rebuild-baselines     # seed baselines from ClickHouse history

Persistence rules
- One open incident per target (enforced by a unique index); the engine's events update it.
- Timeline rows for every state change; evidence rows every 10 s while open (every 60 s after
  the first hour) so long attacks do not flood the database.
- If no snapshot arrives for DATA_GAP_SECONDS while incidents are open, a "data_gap" event is
  recorded. Nothing is resolved during a gap.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import signal
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import redis
from sqlalchemy import cast, select, text
from sqlalchemy.dialects.postgresql import CIDR, insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import telemetry as tm
from ..changes import get_setting
from ..db import session_factory
from ..models import (
    OPEN_INCIDENT_STATES, AttackIncident, AttackIncidentEvent, CustomerIpAssignment, DetectionEvidence,
    DetectionProfile, IncidentStatus, ProtectedPrefix, TrafficBaseline,
)
from .engine import Baselines, Engine, Event, Profile, ProfileSet

log = logging.getLogger("shield.detector")

STREAM = "shield:traffic:stream"
CHAN_EVENTS = "shield:events"
KEY_STATUS = "shield:detector:status"
DATA_GAP_SECONDS = 5
EVIDENCE_EVERY = 10
EVIDENCE_EVERY_LATE = 60
EVIDENCE_LATE_AFTER = 360  # rows
DB_UPDATE_EVERY = 5
PUBLISH_UPDATE_EVERY = 2


def _dt(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, UTC)


def load_profiles(db: Session) -> ProfileSet:
    rows = db.execute(select(DetectionProfile).where(DetectionProfile.enabled)).scalars().all()
    overrides = {}
    for c in db.execute(select(CustomerIpAssignment).where(
            (CustomerIpAssignment.pps_threshold.is_not(None)) | (CustomerIpAssignment.bps_threshold.is_not(None)))).scalars():
        net = ipaddress.ip_network(str(c.address))
        if net.prefixlen == net.max_prefixlen:
            overrides[str(net)] = (c.pps_threshold, c.bps_threshold)
    return ProfileSet([Profile.from_row(r) for r in rows], overrides)


def load_baselines(db: Session) -> Baselines:
    bl = Baselines()
    for r in db.execute(select(TrafficBaseline).where(TrafficBaseline.metric == "pps")).scalars():
        bl.load(str(r.scope), r.slot, float(r.mean), float(r.stddev), r.samples)
    return bl


def save_baselines(db: Session, rows: list[tuple[str, int, float, float, int]]) -> None:
    if not rows:
        return
    stmt = insert(TrafficBaseline).values([
        {"scope": k, "metric": "pps", "slot": slot, "mean": round(m, 4), "stddev": round(s, 4),
         "p95": round(m + 1.645 * s, 4), "p99": round(m + 2.326 * s, 4), "samples": n}
        for k, slot, m, s, n in rows])
    stmt = stmt.on_conflict_do_update(
        constraint="uq_baseline_scope_metric_slot",
        set_={"mean": stmt.excluded.mean, "stddev": stmt.excluded.stddev, "p95": stmt.excluded.p95,
              "p99": stmt.excluded.p99, "samples": stmt.excluded.samples, "updated_at": text("now()")})
    db.execute(stmt)


class DetectorService:
    def __init__(self, rds: redis.Redis | None = None):
        self.sf = session_factory()
        self.rds = rds or redis.Redis.from_url(tm.get_settings().redis_url, decode_responses=True,
                                               socket_timeout=10, socket_connect_timeout=3)
        with self.sf() as db:
            self.engine = Engine(load_profiles(db), load_baselines(db))
            self.fp_suppress = int(get_setting(db, "false_positive_suppress_minutes", 30)) * 60
        self.incidents: dict[str, uuid.UUID] = {}   # engine key -> incident id
        self.evidence_count: dict[uuid.UUID, int] = {}
        self.last_evidence: dict[uuid.UUID, int] = {}
        self.last_db_update: dict[uuid.UUID, int] = {}
        self.last_publish: dict[uuid.UUID, int] = {}
        self.last_snapshot_ts: int | None = None
        self.last_snapshot_wall = time.time()
        self.in_gap = False
        self.processed = 0
        self.started = time.time()
        self.stream_id = "$"
        self._housekeeping = {"profiles": 0.0, "external": 0.0, "baselines": time.time(), "status": 0.0}
        self._restore()

    # ------------------------------------------------------------ startup
    def _restore(self) -> None:
        with self.sf() as db:
            rows = db.execute(select(AttackIncident).where(AttackIncident.status.in_(OPEN_INCIDENT_STATES))).scalars().all()
            for r in rows:
                key = str(r.target)
                prefix = None
                if r.protected_prefix_id:
                    pp = db.get(ProtectedPrefix, r.protected_prefix_id)
                    prefix = str(pp.prefix) if pp else None
                self.engine.restore(
                    key, r.scope, prefix, r.status.value, int(r.first_detected_at.timestamp()),
                    int(r.confirmed_at.timestamp()) if r.confirmed_at else None, r.severity.value, list(r.vectors),
                    float(r.confidence), float(r.peak_pps or 0), float(r.peak_bps or 0))
                self.incidents[key] = r.id
                self.evidence_count[r.id] = db.execute(text(
                    "SELECT count(*) FROM detection_evidence WHERE incident_id = :i"), {"i": r.id}).scalar_one()
                self._timeline(db, r.id, int(time.time()), "detector_restarted",
                               {"note": "Detector restarted; timers resumed from now."})
            db.commit()
        if self.incidents:
            log.info("resumed %d open incidents", len(self.incidents))

    # ------------------------------------------------------------ main loop
    def run(self) -> None:
        stop = False

        def _stop(*_):
            nonlocal stop
            stop = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        log.info("detector started")
        while not stop:
            self.poll_once()
        self._persist_baselines()
        log.info("detector stopped")

    def poll_once(self, block_ms: int = 1000) -> int:
        """Read and process pending snapshots, then do periodic housekeeping. Returns snapshots processed."""
        n = 0
        try:
            resp = self.rds.xread({STREAM: self.stream_id}, count=50, block=block_ms)
        except redis.RedisError as e:
            log.warning("redis unavailable: %s", e)
            time.sleep(2)
            resp = []
        for _, entries in resp or []:
            for entry_id, fields in entries:
                self.stream_id = entry_id
                try:
                    self.process(json.loads(fields["d"]))
                    n += 1
                except Exception:  # one bad snapshot must not kill detection
                    log.exception("failed to process snapshot %s", entry_id)
        now = time.time()
        self._check_gap(now)
        last = self._housekeeping
        if now - last["profiles"] > 30:
            self._reload_profiles(); last["profiles"] = now
        if now - last["external"] > 10:
            self._sync_external(); last["external"] = now
        if now - last["baselines"] > 300:
            self._persist_baselines(); last["baselines"] = now
        if now - last["status"] > 5:
            self._publish_status(); last["status"] = now
        return n

    def process(self, snap: dict) -> list[Event]:
        events = self.engine.tick(snap)
        self.last_snapshot_ts = int(snap["ts"])
        self.last_snapshot_wall = time.time()
        self.processed += 1
        if self.in_gap:
            self.in_gap = False
            with self.sf() as db:
                for iid in self.incidents.values():
                    self._timeline(db, iid, self.last_snapshot_ts, "data_resumed", {})
                db.commit()
        if events:
            self.handle(events)
        return events

    # ------------------------------------------------------------ persistence
    def handle(self, events: list[Event]) -> None:
        with self.sf() as db:
            for e in events:
                try:
                    with db.begin_nested():
                        self._apply(db, e)
                except IntegrityError:
                    log.exception("could not persist %s for %s", e.kind, e.key)
            db.commit()

    def _apply(self, db: Session, e: Event) -> None:
        if e.kind == "suspected":
            iid = self._open(db, e)
        else:
            iid = self.incidents.get(e.key)
            if iid is None:
                return  # e.g. closed externally between ticks
        inc = db.get(AttackIncident, iid)
        if inc is None:
            self.incidents.pop(e.key, None)
            return
        inc.severity, inc.vectors = e.severity, e.vectors
        inc.confidence = Decimal(str(e.confidence))
        inc.peak_pps, inc.peak_bps = int(e.peak_pps), int(e.peak_bps)
        inc.peak_provenance = e.sample["provenance"] if e.peak_pps else inc.peak_provenance
        if e.signals:
            inc.last_hot_at = _dt(e.ts)

        if e.kind == "update":
            if e.ts - self.last_db_update.get(iid, 0) >= DB_UPDATE_EVERY:
                inc.current = self._current(e)
                inc.confidence_breakdown = e.breakdown
                self.last_db_update[iid] = e.ts
            self._maybe_evidence(db, iid, e)
            if e.ts - self.last_publish.get(iid, 0) >= PUBLISH_UPDATE_EVERY:
                self._publish(inc, "update", e)
                self.last_publish[iid] = e.ts
            return

        inc.current = self._current(e)
        inc.confidence_breakdown = e.breakdown
        if e.kind == "confirmed":
            inc.status = IncidentStatus.CONFIRMED
            inc.confirmed_at = _dt(e.ts)
        elif e.kind == "resolved":
            inc.status = IncidentStatus.RESOLVED
            inc.resolved_at = _dt(e.ts)
            inc.resolution = e.resolution
        detail = {"severity": e.severity, "vectors": e.vectors, "confidence": e.current_confidence,
                  "signals": e.signals, "pps": e.sample["pps"], "bps": e.sample["bps"]}
        if e.kind == "resolved":
            detail["resolution"] = e.resolution
        if "previous" in e.breakdown:
            detail["previous"] = e.breakdown["previous"]
        self._timeline(db, iid, e.ts, e.kind, detail)
        self._evidence(db, iid, e)
        self._publish(inc, e.kind, e)
        if e.kind == "resolved":
            for d in (self.incidents,):
                d.pop(e.key, None)
            for d in (self.evidence_count, self.last_evidence, self.last_db_update, self.last_publish):
                d.pop(iid, None)

    def _open(self, db: Session, e: Event) -> uuid.UUID:
        pp_id = db.execute(select(ProtectedPrefix.id).where(
            cast(e.key, CIDR).op("<<=")(ProtectedPrefix.prefix))).scalar()
        existing = db.execute(select(AttackIncident).where(
            AttackIncident.target == e.key, AttackIncident.status.in_(OPEN_INCIDENT_STATES))).scalar_one_or_none()
        if existing is not None:   # already open (e.g. restored with different state): reuse it
            self.incidents[e.key] = existing.id
            return existing.id
        inc = AttackIncident(
            target=e.key, scope=e.scope, protected_prefix_id=pp_id, status=IncidentStatus.SUSPECTED,
            severity=e.severity, vectors=e.vectors, confidence=Decimal(str(e.confidence)),
            peak_pps=int(e.peak_pps), peak_bps=int(e.peak_bps), peak_provenance=e.sample["provenance"],
            first_detected_at=_dt(e.started_ts or e.ts), last_hot_at=_dt(e.ts), profile_id=e.profile_id or None,
            current=self._current(e), confidence_breakdown=e.breakdown)
        db.add(inc)
        db.flush()
        self.incidents[e.key] = inc.id
        self.evidence_count[inc.id] = 0
        return inc.id

    @staticmethod
    def _current(e: Event) -> dict:
        return {"ts": e.ts, **e.sample, "confidence": e.current_confidence, "signals": e.signals}

    def _timeline(self, db: Session, iid, ts: int, kind: str, detail: dict, actor: str = "detector") -> None:
        db.add(AttackIncidentEvent(incident_id=iid, at=_dt(ts), kind=kind, actor=actor, detail=detail))

    def _maybe_evidence(self, db: Session, iid, e: Event) -> None:
        n = self.evidence_count.get(iid, 0)
        every = EVIDENCE_EVERY if n < EVIDENCE_LATE_AFTER else EVIDENCE_EVERY_LATE
        if e.ts - self.last_evidence.get(iid, 0) >= every:
            self._evidence(db, iid, e)

    def _evidence(self, db: Session, iid, e: Event) -> None:
        rows = e.signals or [{"vector": "pps", "value": e.sample["pps"], "threshold": None, "unit": "pps"}]
        for s in rows:
            details = {"sample": e.sample, "breakdown": e.breakdown, "status": e.status, "unit": s.get("unit", "pps")}
            db.add(DetectionEvidence(incident_id=iid, observed_at=_dt(e.ts), metric=s["vector"][:32],
                                     value=s["value"], threshold=s.get("threshold"),
                                     provenance=e.sample["provenance"], source="detector", details=details))
        self.evidence_count[iid] = self.evidence_count.get(iid, 0) + 1
        self.last_evidence[iid] = e.ts

    # ------------------------------------------------------------ live events
    def _publish(self, inc: AttackIncident, kind: str, e: Event) -> None:
        msg = {"type": "incident", "event": kind, "incident": {
            "id": str(inc.id), "target": e.key, "scope": e.scope, "prefix": e.prefix,
            "status": "resolved" if kind == "resolved" else e.status, "severity": e.severity,
            "vectors": e.vectors, "confidence": e.confidence, "current_confidence": e.current_confidence,
            "peak_pps": e.peak_pps, "peak_bps": e.peak_bps, "pps": e.sample["pps"], "bps": e.sample["bps"],
            "provenance": e.sample["provenance"], "first_detected_ts": e.started_ts,
            "confirmed_ts": e.confirmed_ts, "resolution": e.resolution, "ts": e.ts}}
        try:
            self.rds.publish(CHAN_EVENTS, json.dumps(msg))
        except redis.RedisError:
            pass

    def _publish_status(self) -> None:
        st = {"ts": int(time.time()), "started_at": int(self.started), "processed": self.processed,
              "last_snapshot_ts": self.last_snapshot_ts, "open_incidents": len(self.incidents),
              "tracked_keys": len(self.engine.tracks), "in_data_gap": self.in_gap,
              "lag_seconds": round(time.time() - self.last_snapshot_ts, 1) if self.last_snapshot_ts else None}
        try:
            self.rds.set(KEY_STATUS, json.dumps(st), ex=15)
        except redis.RedisError:
            pass

    # ------------------------------------------------------------ periodic work
    def _check_gap(self, now: float) -> None:
        if self.in_gap or not self.incidents or now - self.last_snapshot_wall < DATA_GAP_SECONDS:
            return
        self.in_gap = True
        log.warning("no traffic data for %ds; open incidents are held, not resolved", DATA_GAP_SECONDS)
        with self.sf() as db:
            for iid in self.incidents.values():
                self._timeline(db, iid, int(now), "data_gap",
                               {"note": "No traffic data from the collector. The incident is held open."})
            db.commit()

    def _reload_profiles(self) -> None:
        with self.sf() as db:
            self.engine.set_profiles(load_profiles(db))
            self.fp_suppress = int(get_setting(db, "false_positive_suppress_minutes", 30)) * 60

    def _sync_external(self) -> None:
        """Pick up incidents closed by operators (false positive)."""
        if not self.incidents:
            return
        with self.sf() as db:
            rows = db.execute(select(AttackIncident.id, AttackIncident.status, AttackIncident.resolution).where(
                AttackIncident.id.in_(list(self.incidents.values())))).all()
        closed = {r.id: r.resolution for r in rows if r.status.value not in OPEN_INCIDENT_STATES}
        for key, iid in list(self.incidents.items()):
            if iid in closed:
                until = (self.last_snapshot_ts or int(time.time())) + self.fp_suppress \
                    if closed[iid] == "false_positive" else None
                self.engine.close(key, until)
                self.incidents.pop(key, None)
                log.info("incident %s for %s closed by an operator (%s)", iid, key, closed[iid])

    def _persist_baselines(self) -> None:
        rows = self.engine.baselines.take_dirty()
        if rows:
            with self.sf() as db:
                save_baselines(db, rows)
                db.commit()


# ---------------------------------------------------------------- seed baselines from history
def rebuild_baselines(days: int = 28) -> int:
    """Recompute hour-of-week baselines from ClickHouse 1-minute rollups (minutes with traffic)."""
    sql = """
        SELECT dst, (toDayOfWeek(m) - 1) * 24 + toHour(m) AS slot,
               avg(p) AS mean, stddevPop(p) AS std, count() AS n
        FROM (SELECT ts AS m, dst, avgMerge(pps_avg) AS p FROM dst_1m
              WHERE ts >= now() - INTERVAL {days:UInt32} DAY GROUP BY m, dst)
        GROUP BY dst, slot HAVING n >= 3"""
    rows = tm.ch_query(sql, {"days": days})
    out = []
    for r in rows:
        a = ipaddress.ip_address(r["dst"])
        out.append((f"{a}/{a.max_prefixlen}", int(r["slot"]), float(r["mean"]), float(r["std"]), int(r["n"])))
    with session_factory()() as db:
        for i in range(0, len(out), 1000):
            save_baselines(db, out[i:i + 1000])
        db.commit()
    return len(out)


def main(argv=None) -> int:
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="shield-detector")
    sub = ap.add_subparsers(dest="cmd")
    rb = sub.add_parser("rebuild-baselines", help="seed baselines from ClickHouse history")
    rb.add_argument("--days", type=int, default=28)
    args = ap.parse_args(argv)
    if args.cmd == "rebuild-baselines":
        n = rebuild_baselines(args.days)
        print(f"wrote {n} destination/hour-of-week baselines")
        return 0
    DetectorService().run()
    return 0

