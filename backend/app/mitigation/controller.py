"""shield-mitigator: carries out approved mitigation actions and keeps the speaker in step.

The speaker follows the bgp_speaker setting: SimulatedSpeaker (nothing leaves Shield) or, from
Shield's FRR (staging peers, plus production peers once switched on and accepted). The workflow,
checks, timings and failure handling are the same for both.

Loop (every second):
  1. expire proposals nobody approved in time
  2. propose actions for confirmed incidents that match an enabled mitigation policy
  3. execute approved actions: re-check the plan, record intent (route row "pending_announce")
     BEFORE telling the speaker, announce, read back and compare, then mark active
  4. withdraw actions asked to withdraw; roll back failed ones
  5. at the end of an action's duration: extend while its incident is still hot, otherwise withdraw
  6. reconcile with the speaker at start and every 30 s: re-announce routes that should be there and
     are not; withdraw Shield routes that are there and should not be

Only one controller may act at a time (PostgreSQL advisory lock); a second instance waits as standby.
Withdrawals only ever remove a route the speaker says belongs to the same action, so a stale action
can never withdraw a newer action's route for the same address.
"""
from __future__ import annotations

import json
import logging
import signal
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Callable

import redis
from sqlalchemy import cast, select, text
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.orm import Session

from .. import audit
from ..changes import get_setting
from ..config import get_settings
from ..db import get_engine, session_factory
from ..models import ActionState as S
from ..models import (
    AttackIncident, AttackIncidentEvent, IncidentStatus, MitigationAction, MitigationPolicy, RtbhMode, RtbhRoute,
    RtbhStatus,
)
from . import service
from .acceptance import AcceptanceRunner, run_interlock
from .planner import RTBH_STRATEGIES, PlanRequest, build_plan
from .speaker import Route, SimulatedSpeaker, Speaker, SpeakerError, SpeakerRefused, make_speaker
from .state import record, transition

log = logging.getLogger("shield.mitigator")

KEY_STATUS = "shield:mitigator:status"
LOCK_ID = 0x5348_4D49  # "SHMI"
ACTOR = "controller"
RETRY_EVERY = 2.0
RECONCILE_EVERY = 30.0
AUTO_EVERY = 5.0
HOT_WINDOW = timedelta(seconds=120)


def _route_of(a: MitigationAction) -> Route:
    r = (a.plan or {}).get("route") or {}
    return Route(peer=r.get("peer", "internal"), prefix=r.get("prefix", str(a.target)),
                 communities=tuple(r.get("communities") or ()), next_hop=r.get("next_hop"),
                 no_export=bool(r.get("no_export", True)), action_id=str(a.id))


class Controller:
    def __init__(self, rds: redis.Redis | None = None, sessions: Callable[[], Session] | None = None,
                 speaker: Speaker | None = None, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        s = get_settings()
        self.rds = rds or redis.Redis.from_url(s.redis_url, socket_timeout=2, socket_connect_timeout=2,
                                               decode_responses=True)
        self.sessions = sessions or session_factory()
        self._fixed_speaker = speaker is not None
        self.speaker = speaker or SimulatedSpeaker(self.rds)
        self.clock = clock
        self.next_try: dict[uuid.UUID, float] = {}
        self.last_reconcile_at = 0.0
        self.last_auto_at = 0.0
        self.last_reconcile: dict = {}
        self.leader = False
        self._lock_conn = None
        self.acceptance = AcceptanceRunner(self)
        self.last_interlock: list[dict] = []

    # ------------------------------------------------------------ leadership
    def acquire_lock(self) -> bool:
        if self._lock_conn is None:
            self._lock_conn = get_engine().connect()
        self.leader = bool(self._lock_conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": LOCK_ID}).scalar())
        self._lock_conn.commit()
        return self.leader

    def release_lock(self) -> None:
        if self._lock_conn is not None:
            try:
                self._lock_conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK_ID})
                self._lock_conn.commit()
            finally:
                self._lock_conn.close()
                self._lock_conn = None
        self.leader = False

    # ------------------------------------------------------------ one pass
    def select_speaker(self) -> bool:
        """Follow the bgp_speaker setting. Returns True if the speaker changed."""
        if self._fixed_speaker:
            return False
        with self.sessions() as db:
            want = get_setting(db, "bgp_speaker", "simulated")
        if want == self.speaker.name:
            return False
        log.warning("switching BGP speaker from %s to %s", self.speaker.name, want)
        self.speaker = make_speaker(want, self.rds, self.sessions)
        return True

    def tick(self, *, force_reconcile: bool = False) -> None:
        mono = time.monotonic()
        try:
            if self.select_speaker():
                force_reconcile = True
        except Exception:
            log.exception("could not select the BGP speaker")
        steps = [self.expire_proposals, self.execute_pending, self.process_withdrawals, self.rollback_failed,
                 self.process_expiry, self.acceptance.tick]
        if force_reconcile or mono - self.last_auto_at >= AUTO_EVERY:
            steps.insert(1, self.auto_propose)
            self.last_auto_at = mono
        for step in steps:
            try:
                step()
            except Exception:
                log.exception("%s failed", step.__name__)
        if force_reconcile or mono - self.last_reconcile_at >= RECONCILE_EVERY:
            self.last_reconcile_at = mono
            try:
                self.reconcile()
            except Exception:
                log.exception("reconcile failed")
        self.publish_status()

    def _ids(self, *states: S) -> list[uuid.UUID]:
        with self.sessions() as db:
            return list(db.execute(select(MitigationAction.id).where(MitigationAction.state.in_(states))
                                   .order_by(MitigationAction.created_at)).scalars())

    def _due(self, aid: uuid.UUID) -> bool:
        return self.next_try.get(aid, 0) <= time.monotonic()

    def _later(self, aid: uuid.UUID) -> None:
        self.next_try[aid] = time.monotonic() + RETRY_EVERY

    def _lock(self, db: Session, aid: uuid.UUID, *states: S) -> MitigationAction | None:
        return db.execute(select(MitigationAction).where(MitigationAction.id == aid, MitigationAction.state.in_(states))
                          .with_for_update(skip_locked=True)).scalar_one_or_none()

    # ------------------------------------------------------------ 1. proposals expire
    def expire_proposals(self) -> int:
        n = 0
        with self.sessions() as db, db.begin():
            ttl = int(get_setting(db, "proposal_ttl_minutes", 15))
            old = db.execute(select(MitigationAction).where(
                MitigationAction.state == S.PROPOSED, MitigationAction.created_at < self.clock() - timedelta(minutes=ttl))
                .with_for_update(skip_locked=True)).scalars().all()
            for a in old:
                a.rejected_reason = f"expired: not approved within {ttl} min"
                a.completed_at = self.clock()
                transition(db, a, S.REJECTED, ACTOR, "expired", reason=a.rejected_reason)
                n += 1
        return n

    # ------------------------------------------------------------ 2. policy proposals
    def auto_propose(self) -> int:
        made = 0
        with self.sessions() as db, db.begin():
            policies = db.execute(select(MitigationPolicy).where(MitigationPolicy.enabled)
                                  .order_by(MitigationPolicy.priority, MitigationPolicy.id)).scalars().all()
            if not policies:
                return 0
            incidents = db.execute(select(AttackIncident).where(AttackIncident.status == IncidentStatus.CONFIRMED)).scalars().all()
            now = self.clock()
            for inc in incidents:
                live = db.execute(select(MitigationAction.id).where(
                    cast(str(inc.target), CIDR) == MitigationAction.target,
                    MitigationAction.state.in_([S.PROPOSED, S.APPROVED, S.EXECUTING, S.ACTIVE, S.WITHDRAWING]))).first()
                if live:
                    continue
                pol = next((p for p in policies if self._matches(db, p, inc, now)), None)
                if pol is None:
                    continue
                strategy = next((s for s in pol.allowed_strategies if s in RTBH_STRATEGIES), None)
                if strategy is None:
                    continue
                running = db.execute(select(MitigationAction.id).where(
                    MitigationAction.policy_id == pol.id,
                    MitigationAction.state.in_([S.PROPOSED, S.APPROVED, S.EXECUTING, S.ACTIVE]))).all()
                key = f"auto:{inc.id}:{pol.id}"
                if len(running) >= pol.max_concurrent_actions:
                    self._blocked_once(db, inc, pol, [{"level": "block", "code": "policy_concurrency",
                                                        "message": f"Policy {pol.name} already has {len(running)} live actions."}])
                    continue
                req = PlanRequest(target=str(inc.target), strategy=strategy, incident_id=str(inc.id),
                                  duration_seconds=pol.mitigation_duration_seconds, automatic=True,
                                  auto_approve=not pol.requires_approval)
                plan = build_plan(db, req, now)
                if pol.max_scope_prefix_len and int(plan["target"].split("/")[1]) < pol.max_scope_prefix_len:
                    plan["checks"].append({"level": "block", "code": "policy_scope",
                                           "message": f"Policy {pol.name} allows /{pol.max_scope_prefix_len} or longer."})
                    plan["blocked"] = True
                if plan.blocked:
                    self._blocked_once(db, inc, pol, plan["checks"])
                    continue
                if service.existing_for_key(db, key):
                    continue  # proposed before and since rejected/expired: do not nag
                actions = service.propose(db, req, key=key, actor=f"policy {pol.name}", policy_id=pol.id, plan=plan)
                made += len(actions)
                if not pol.requires_approval:
                    for a in actions:
                        a.approved_at = now
                        transition(db, a, S.APPROVED, f"policy {pol.name}", "auto_approved",
                                   note="policy does not require approval and automation is on")
        return made

    @staticmethod
    def _matches(db: Session, p: MitigationPolicy, inc: AttackIncident, now: datetime) -> bool:
        inside = db.execute(select(cast(str(inc.target), CIDR).op("<<=")(cast(str(p.scope), CIDR)))).scalar()
        if not inside:
            return False
        if p.vectors and not set(p.vectors) & set(inc.vectors or []):
            return False
        if float(inc.confidence) < float(p.min_confidence):
            return False
        if inc.confirmed_at is None or inc.confirmed_at > now - timedelta(seconds=p.min_duration_seconds):
            return False
        if p.pps_threshold and (inc.peak_pps or 0) < p.pps_threshold:
            return False
        if p.bps_threshold and (inc.peak_bps or 0) < p.bps_threshold:
            return False
        return True

    def _blocked_once(self, db: Session, inc: AttackIncident, pol: MitigationPolicy, checks: list) -> None:
        seen = db.execute(select(AttackIncidentEvent.id).where(
            AttackIncidentEvent.incident_id == inc.id, AttackIncidentEvent.kind == "mitigation_blocked")).first()
        if seen:
            return
        db.add(AttackIncidentEvent(incident_id=inc.id, at=self.clock(), kind="mitigation_blocked", actor=f"policy {pol.name}",
                                   detail={"policy": pol.name,
                                           "reasons": [c["message"] for c in checks if c["level"] == "block"]}))

    # ------------------------------------------------------------ 3. execute
    def execute_pending(self) -> int:
        n = 0
        for aid in self._ids(S.APPROVED, S.EXECUTING):
            if self._due(aid):
                n += self.execute_one(aid)
        return n

    def execute_one(self, aid: uuid.UUID) -> int:
        with self.sessions() as db, db.begin():
            a = self._lock(db, aid, S.APPROVED, S.EXECUTING)
            if a is None:
                return 0
            if a.state == S.APPROVED:
                unattended = a.automatic and a.approved_by_id is None
                plan = service.recheck(db, [a], automatic=unattended, auto_approve=unattended)
                if plan.blocked:
                    reasons = [c["message"] for c in plan["checks"] if c["level"] == "block"]
                    a.rejected_reason = "blocked at execution: " + "; ".join(reasons)
                    a.completed_at = self.clock()
                    transition(db, a, S.REJECTED, ACTOR, "blocked_at_execution", reasons=reasons)
                    return 0
                a.started_at = self.clock()
                transition(db, a, S.EXECUTING, ACTOR, "executing", speaker=self.speaker.name)
            route = self._route_row(db, a)
            expected = _route_of(a)
            started = a.started_at
            timeout = a.timeout_seconds
        # Intent is committed; now talk to the speaker (outside any transaction).
        err = None
        refused = False
        try:
            self.speaker.announce(expected)
            got = self.speaker.routes().get(expected.key)
            if got is None or not got.same_attributes(expected) or got.action_id != expected.action_id:
                err = "announced, but the route is not on the speaker as planned"
            elif hasattr(self.speaker, "verify"):
                err = self.speaker.verify(expected)   # e.g. FRR: really advertised to every session
        except SpeakerError as e:
            err = str(e)
            refused = isinstance(e, SpeakerRefused)
        with self.sessions() as db, db.begin():
            a = self._lock(db, aid, S.EXECUTING, S.WITHDRAWING)
            if a is None:
                return 0
            route = db.get(RtbhRoute, route)
            now = self.clock()
            if err is None:
                route.status = RtbhStatus.VERIFIED
                route.announced_at = route.announced_at or now
                route.verified_at = now
                route.last_verify_result = {"ok": True, "at": now.isoformat(), "speaker": self.speaker.name}
                if a.state == S.WITHDRAWING:
                    return 1  # withdrawn while announcing; the withdrawal step removes it
                duration = int((a.plan or {}).get("duration_seconds") or 3600)
                a.expires_at = now + timedelta(seconds=duration)
                if a.policy_id:
                    pol = db.get(MitigationPolicy, a.policy_id)
                    if pol:
                        a.hold_until = now + timedelta(seconds=pol.min_hold_seconds)
                a.error = None
                transition(db, a, S.ACTIVE, ACTOR, "active", route=expected.key,
                           simulation=self.speaker.name == "simulated", speaker=self.speaker.name)
                audit.record(db, audit.SYSTEM_ACTOR, "mitigation.announce", "mitigation_action", a.id,
                             after={"route": (a.plan or {}).get("route", {}).get("description"), "speaker": self.speaker.name})
                self.next_try.pop(aid, None)
                announced = True
            else:
                announced = False
                a.attempts += 1
                a.error = err
                route.last_verify_result = {"ok": False, "at": now.isoformat(), "error": err}
                record(db, a, None, ACTOR, "announce_failed", error=err, attempt=a.attempts)
                if a.state == S.EXECUTING and (refused or (now - started).total_seconds() >= timeout):
                    route.status = RtbhStatus.FAILED
                    a.completed_at = now
                    transition(db, a, S.FAILED, ACTOR, "failed",
                               error=err if refused else f"gave up after {timeout} s: {err}")
                self._later(aid)
        if announced:
            # After every real announcement: nothing but authorised routes may be leaving.
            try:
                self.last_interlock = run_interlock(self) or self.last_interlock
            except SpeakerError as e:
                log.warning("interlock check failed: %s", e)
            return 1
        return 0

    def _route_row(self, db: Session, a: MitigationAction) -> int:
        row = db.execute(select(RtbhRoute).where(RtbhRoute.action_id == a.id)
                         .order_by(RtbhRoute.id.desc())).scalars().first()
        if row is None or row.status in (RtbhStatus.WITHDRAWN, RtbhStatus.FAILED):
            r = (a.plan or {}).get("route") or {}
            row = RtbhRoute(action_id=a.id, mode=RtbhMode.UPSTREAM if a.upstream_id else RtbhMode.INTERNAL,
                            prefix=str(a.target), upstream_id=a.upstream_id, communities=r.get("communities") or [],
                            next_hop=r.get("next_hop"), status=RtbhStatus.PENDING_ANNOUNCE, speaker=self.speaker.name)
            db.add(row)
            db.flush()
        return row.id

    # ------------------------------------------------------------ 4. withdraw / roll back
    def process_withdrawals(self) -> int:
        n = 0
        for aid in self._ids(S.WITHDRAWING):
            if self._due(aid):
                n += self._remove(aid, S.WITHDRAWING, S.WITHDRAWN, "withdrawn")
        return n

    def rollback_failed(self) -> int:
        n = 0
        for aid in self._ids(S.FAILED):
            if self._due(aid):
                n += self._remove(aid, S.FAILED, S.ROLLED_BACK, "rolled_back")
        return n

    def _remove(self, aid: uuid.UUID, frm: S, to: S, kind: str) -> int:
        with self.sessions() as db:
            a = db.get(MitigationAction, aid)
            if a is None or a.state != frm:
                return 0
            expected = _route_of(a)
        err = None
        try:
            got = self.speaker.routes().get(expected.key)
            if got is not None and got.action_id == expected.action_id:
                self.speaker.withdraw(expected)
                if expected.key in self.speaker.routes():
                    err = "withdrawn, but the route is still on the speaker"
        except SpeakerError as e:
            err = str(e)
        with self.sessions() as db, db.begin():
            a = self._lock(db, aid, frm)
            if a is None:
                return 0
            now = self.clock()
            rows = db.execute(select(RtbhRoute).where(RtbhRoute.action_id == aid,
                                                      RtbhRoute.status != RtbhStatus.WITHDRAWN)).scalars().all()
            if err:
                a.error = err
                record(db, a, None, ACTOR, f"{kind}_failed", error=err)
                for r in rows:
                    r.status = RtbhStatus.WITHDRAWING if frm == S.WITHDRAWING else r.status
                    r.withdraw_requested_at = r.withdraw_requested_at or now
                self._later(aid)
                return 0
            for r in rows:
                r.withdraw_requested_at = r.withdraw_requested_at or now
                r.withdrawn_at = now
                r.withdraw_verified_at = now
                r.status = RtbhStatus.WITHDRAWN
            a.completed_at = now
            transition(db, a, to, ACTOR, kind, reason=a.withdraw_reason or a.error)
            audit.record(db, audit.SYSTEM_ACTOR, f"mitigation.{'withdraw' if to == S.WITHDRAWN else 'rollback'}",
                         "mitigation_action", a.id, after={"route": expected.key, "reason": a.withdraw_reason or a.error})
            self.next_try.pop(aid, None)
            return 1

    # ------------------------------------------------------------ 5. duration
    def process_expiry(self) -> int:
        n = 0
        with self.sessions() as db, db.begin():
            now = self.clock()
            due = db.execute(select(MitigationAction).where(
                MitigationAction.state == S.ACTIVE, MitigationAction.expires_at <= now)
                .with_for_update(skip_locked=True)).scalars().all()
            for a in due:
                if a.hold_until and a.hold_until > now:
                    continue
                inc = db.get(AttackIncident, a.incident_id) if a.incident_id else None
                hot = inc is not None and inc.status in (IncidentStatus.CONFIRMED, IncidentStatus.SUSPECTED) \
                    and inc.last_hot_at is not None and inc.last_hot_at >= now - HOT_WINDOW
                if hot:
                    secs = int((a.plan or {}).get("duration_seconds") or 3600)
                    service.extend(db, a, secs, actor=ACTOR, why="attack still in progress")
                else:
                    service.withdraw(db, a, actor=ACTOR, reason="duration ended")
                n += 1
        return n

    # ------------------------------------------------------------ 6. reconcile
    def reconcile(self) -> dict:
        try:
            if hasattr(self.speaker, "sync"):
                self.speaker.sync()          # sessions and policies first (e.g. after FRR restarted)
            rib = self.speaker.routes()
            found = run_interlock(self)
            if found:
                self.last_interlock = found
        except SpeakerError as e:
            self.last_reconcile = {"at": self.clock().isoformat(), "ok": False, "error": str(e)}
            return self.last_reconcile
        reannounced, withdrawn, errors = [], [], []
        with self.sessions() as db:
            active = db.execute(select(MitigationAction).where(MitigationAction.state == S.ACTIVE)).scalars().all()
            desired = {_route_of(a).key: (a.id, _route_of(a)) for a in active}
            executing = {str(x) for x in db.execute(select(MitigationAction.id).where(
                MitigationAction.state.in_([S.APPROVED, S.EXECUTING]))).scalars()}
        for key, (aid, want) in desired.items():
            got = rib.get(key)
            if got is not None and got.same_attributes(want) and got.action_id == want.action_id:
                continue
            try:
                self.speaker.announce(want)
                reannounced.append(key)
                self._note(aid, "reconciled_reannounced", route=key,
                           found="missing" if got is None else "different attributes or owner")
            except SpeakerError as e:
                errors.append(f"{key}: {e}")
        for key, got in rib.items():
            if key in desired or (got.action_id in executing):
                continue
            try:
                self.speaker.withdraw(got)
                withdrawn.append(key)
                if got.action_id:
                    try:
                        self._note(uuid.UUID(got.action_id), "reconciled_orphan_withdrawn", route=key)
                    except ValueError:
                        pass
            except SpeakerError as e:
                errors.append(f"{key}: {e}")
        if reannounced or withdrawn:
            with self.sessions() as db, db.begin():
                audit.record(db, audit.SYSTEM_ACTOR, "mitigation.reconcile", "speaker", self.speaker.name,
                             after={"reannounced": reannounced, "withdrawn": withdrawn})
        self.last_reconcile = {"at": self.clock().isoformat(), "ok": not errors, "routes": len(desired),
                               "reannounced": reannounced, "withdrawn": withdrawn, "errors": errors}
        if reannounced or withdrawn or errors:
            log.warning("reconcile: %s", self.last_reconcile)
        return self.last_reconcile

    def _note(self, aid: uuid.UUID, kind: str, **detail) -> None:
        with self.sessions() as db, db.begin():
            a = db.get(MitigationAction, aid)
            if a is not None:
                record(db, a, None, ACTOR, kind, **detail)

    # ------------------------------------------------------------ service
    def publish_status(self) -> None:
        try:
            rib = len(self.speaker.routes())
        except SpeakerError:
            rib = None
        peers = None
        if hasattr(self.speaker, "peer_status"):
            try:
                peers = self.speaker.peer_status()
            except SpeakerError as e:
                peers = {"error": str(e)}
        try:
            self.rds.set(KEY_STATUS, json.dumps({
                "ts": int(time.time()), "mode": "simulation" if self.speaker.name == "simulated" else "staging",
                "speaker": self.speaker.name, "leader": self.leader, "peers": peers,
                "speaker_routes": rib, "last_reconcile": self.last_reconcile,
                "last_interlock": self.last_interlock}), ex=30)
        except redis.RedisError:
            pass

    def run(self) -> None:
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        log.info("mitigation controller started; BGP speaker follows the bgp_speaker setting "
                 "(simulated, or FRR: staging peers, plus production peers when switched on)")
        while not stop.is_set():
            if not self.leader:
                try:
                    if not self.acquire_lock():
                        self.publish_status()
                        log.info("another controller is active; standing by")
                        stop.wait(5)
                        continue
                except Exception:
                    log.exception("could not take the controller lock")
                    stop.wait(5)
                    continue
                log.info("controller lock taken; reconciling with the speaker")
                self.tick(force_reconcile=True)
                continue
            self.tick()
            stop.wait(1)
        self.release_lock()
        log.info("mitigation controller stopped")


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    Controller().run()
    return 0
