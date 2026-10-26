"""Phase 8: acceptance runs and the safety interlock.

Acceptance run (one Shield BGP peer, i.e. a provider's blackhole service or your own edge routers)
  baseline     record what every Shield session advertises and the routers' routes
  announcing   announce a canary /32 you nominated (an unused address of yours) through the normal
               action workflow, approved by the person who started the run
  verifying    every session advertises exactly what is authorised; the canary only to the tested
               peer; nothing else changed
  router_check (your own routers only) a router has installed the canary as a blackhole and its
               other routes for protected prefixes are unchanged
  withdrawing  withdraw the canary; every session back to what is authorised
  passed       the peer's production sessions may now carry real blackholes
Any failure withdraws the canary and leaves the sessions unaccepted.

Interlock (every reconcile and after every announcement)
  What each session really advertises must be a subset of what open actions authorise for it.
  Anything else is removed immediately, Shield's policies are re-applied, and the emergency stop
  is engaged so nothing new is announced until a person has looked.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import AcceptanceRun, ActionState, BgpNeighbor, BgpPurpose, MitigationAction, Router, RouterState, SystemSetting
from . import service
from .planner import PlanRequest
from .speaker import SpeakerError

log = logging.getLogger("shield.acceptance")

RUN_TIMEOUT = timedelta(minutes=10)
STEP_TIMEOUT = {"announcing": timedelta(seconds=120), "router_check": timedelta(seconds=180),
                "withdrawing": timedelta(seconds=120)}
OPEN_FOR_LEDGER = ("executing", "active", "withdrawing", "failed")


def now() -> datetime:
    return datetime.now(UTC)


def authorised(db: Session, canary_only: bool = False) -> dict[str, set[str]]:
    """Peer key -> prefixes that open actions allow on that peer (only acceptance canaries when
    canary_only: what a production session that has not passed acceptance may receive)."""
    out: dict[str, set[str]] = {}
    for a in db.execute(select(MitigationAction).where(MitigationAction.state.in_(OPEN_FOR_LEDGER))).scalars():
        r = (a.plan or {}).get("route") or {}
        if not r.get("peer"):
            continue
        if canary_only and (a.plan or {}).get("acceptance_peer") != r["peer"]:
            continue
        out.setdefault(r["peer"], set()).add(str(ipaddress.ip_network(r.get("prefix") or str(a.target))))
    return out


def violations(advertised: dict[str, dict], allowed: dict[str, set[str]],
               canary: dict[str, set[str]] | None = None) -> list[dict]:
    bad = []
    for addr, s in advertised.items():
        ok = allowed if s.get("accepted", True) or canary is None else canary
        extra = set(s["prefixes"]) - ok.get(s["peer"], set())
        bad += [{"session": addr, "name": s["name"], "peer": s["peer"], "prefix": p} for p in sorted(extra)]
    return bad


def engage_emergency_stop(db: Session, why: str) -> None:
    for key, value in (("rtbh_emergency_disable", True), ("automation_enabled", False)):
        row = db.get(SystemSetting, key)
        if row is not None:
            row.value = value
            row.updated_at = now()
    audit.record(db, audit.SYSTEM_ACTOR, "system.safety_interlock", "system_setting", "rtbh_emergency_disable",
                 after={"reason": why})


def _router_routes(db: Session) -> dict[int, dict]:
    out = {}
    for st, r in db.execute(select(RouterState, Router).join(Router, Router.id == RouterState.router_id)
                            .where(Router.enabled)):
        routes = (st.routes or {})
        out[st.router_id] = {"name": r.name, "ok": st.ok, "at": routes.get("at"),
                             "items": [(x["dst"], x.get("gateway"), bool(x.get("blackhole")), x.get("table"))
                                       for x in routes.get("items", [])]}
    return out


class AcceptanceRunner:
    def __init__(self, controller):
        self.c = controller

    # ------------------------------------------------------------ helpers
    def _note(self, run: AcceptanceRun, step: str, ok: bool, detail: str) -> None:
        run.steps = [*(run.steps or []), {"at": now().isoformat(), "step": step, "ok": ok, "detail": detail}]

    def _goto(self, run: AcceptanceRun, step: str) -> None:
        run.step, run.step_started_at = step, now()

    def _fail(self, db: Session, run: AcceptanceRun, why: str) -> None:
        self._note(run, run.step, False, why)
        run.status, run.error, run.finished_at = "failed", why, now()
        if run.action_id:
            a = db.get(MitigationAction, run.action_id)
            if a is not None and a.state in (ActionState.PROPOSED, ActionState.APPROVED, ActionState.EXECUTING,
                                             ActionState.ACTIVE, ActionState.FAILED):
                try:
                    service.withdraw(db, a, actor="acceptance", reason=f"acceptance run failed: {why}")
                except service.Conflict:
                    pass
        audit.record(db, audit.SYSTEM_ACTOR, "acceptance.failed", "acceptance_run", run.id,
                     after={"peer": run.peer, "target": str(run.target), "error": why})
        log.warning("acceptance run %s failed: %s", run.id, why)

    def _check_sessions(self, db: Session, run: AcceptanceRun, expect_canary: bool) -> str | None:
        try:
            adv = self.c.speaker.advertised()
        except SpeakerError as e:
            return f"could not read the sessions: {e}"
        allowed = authorised(db)
        canary = str(ipaddress.ip_network(str(run.target)))
        bad = violations(adv, allowed, authorised(db, canary_only=True))
        if bad:
            return "unexpected routes advertised: " + ", ".join(f"{b['prefix']} to {b['session']}" for b in bad)
        tested = [a for a, s in adv.items() if s["peer"] == run.peer]
        if not tested:
            return f"no configured session for {run.peer}"
        for a, s in adv.items():
            has = canary in s["prefixes"]
            if s["peer"] == run.peer and has != expect_canary:
                return f"canary {'missing from' if expect_canary else 'still advertised to'} {s['name']} ({a})"
            if s["peer"] != run.peer and has and canary not in allowed.get(s["peer"], set()):
                return f"canary leaked to {s['name']} ({a})"
        return None

    # ------------------------------------------------------------ the step machine
    def tick(self) -> None:
        if not hasattr(self.c.speaker, "advertised"):
            return
        with self.c.sessions() as db:
            ids = list(db.execute(select(AcceptanceRun.id).where(AcceptanceRun.status.in_(["pending", "running"]))).scalars())
        for rid in ids:
            try:
                with self.c.sessions() as db, db.begin():
                    run = db.execute(select(AcceptanceRun).where(AcceptanceRun.id == rid).with_for_update(skip_locked=True)).scalar_one_or_none()
                    if run is not None and run.status in ("pending", "running"):
                        self._advance(db, run)
                    passed = run is not None and run.status == "passed"
                if passed and hasattr(self.c.speaker, "sync"):
                    self.c.speaker.sync()   # the accepted sessions now get the peer's full route-map
            except Exception as e:  # one broken run must not stop the controller
                log.exception("acceptance run %s", rid)
                with self.c.sessions() as db, db.begin():
                    run = db.get(AcceptanceRun, rid)
                    if run and run.status in ("pending", "running"):
                        self._fail(db, run, f"internal error: {e}")

    def _advance(self, db: Session, run: AcceptanceRun) -> None:
        t = now()
        if run.started_at and t - run.started_at > RUN_TIMEOUT:
            return self._fail(db, run, "the run took longer than 10 minutes")
        limit = STEP_TIMEOUT.get(run.step)
        if limit and run.step_started_at and t - run.step_started_at > limit:
            return self._fail(db, run, f"step {run.step} did not complete in {int(limit.total_seconds())} s")
        getattr(self, f"_step_{run.step}")(db, run)

    def _step_pending(self, db: Session, run: AcceptanceRun) -> None:
        run.status = "running"
        problem = self._check_sessions(db, run, expect_canary=False)
        if problem:
            return self._fail(db, run, f"before starting: {problem}")
        run.baseline = {"routers": _router_routes(db), "at": now().isoformat()}
        self._note(run, "baseline", True, "sessions advertise only authorised routes; router routes recorded")
        if run.peer == "internal":
            req = PlanRequest(target=str(run.target), strategy="rtbh_internal", duration_seconds=600,
                              acceptance_peer=run.peer)
        else:
            req = PlanRequest(target=str(run.target), strategy="rtbh_upstream", duration_seconds=600,
                              upstream_ids=[int(run.peer.split(":")[1])], acceptance_peer=run.peer)
        try:
            actions = service.propose(db, req, key=f"acceptance:{run.id}", actor="acceptance",
                                      user_id=run.started_by_id)
        except service.Conflict as e:
            reasons = [c["message"] for c in e.checks if c["level"] == "block"]
            return self._fail(db, run, "canary refused: " + ("; ".join(reasons) or str(e)))
        a = actions[0]
        a.approved_by_id, a.approved_at = run.started_by_id, now()
        a.plan = {**a.plan, "acceptance_run_id": str(run.id)}
        from .state import transition
        transition(db, a, ActionState.APPROVED, "acceptance", "approved", note="approved by starting the acceptance run")
        run.action_id = a.id
        self._note(run, "announcing", True, f"canary {run.target} approved for {run.peer}")
        self._goto(run, "announcing")

    def _step_announcing(self, db: Session, run: AcceptanceRun) -> None:
        a = db.get(MitigationAction, run.action_id)
        if a is None or a.state in (ActionState.REJECTED, ActionState.FAILED, ActionState.ROLLED_BACK,
                                    ActionState.WITHDRAWN):
            return self._fail(db, run, f"canary not announced: {a.rejected_reason or a.error if a else 'action missing'}")
        if a.state != ActionState.ACTIVE:
            return
        problem = self._check_sessions(db, run, expect_canary=True)
        if problem:
            return self._fail(db, run, problem)
        self._note(run, "verifying", True, "canary advertised on the tested sessions only; nothing else changed")
        if run.peer == "internal" and any(r["ok"] for r in (run.baseline.get("routers") or {}).values()):
            self._goto(run, "router_check")
        else:
            self._note(run, "router_check", True, "skipped: no router Shield can read is linked to this peer"
                       if run.peer == "internal" else "not applicable to a provider's blackhole service")
            self._start_withdraw(db, run, a)

    def _step_router_check(self, db: Session, run: AcceptanceRun) -> None:
        canary = str(ipaddress.ip_network(str(run.target)))
        allowed = {p for ps in authorised(db).values() for p in ps}
        base = run.baseline.get("routers") or {}
        now_r = _router_routes(db)
        fresh = {}
        for rid, r in now_r.items():
            b = base.get(str(rid)) or base.get(rid)
            if b is None or not r["at"] or not run.step_started_at or datetime.fromisoformat(r["at"]) <= run.step_started_at:
                continue
            fresh[rid] = (b, r)
        if not fresh:
            return  # wait for the next full router poll (every 60 s)
        seen = [r["name"] for _, (b, r) in fresh.items() if any(i[0] == canary and i[2] for i in map(tuple, r["items"]))]
        for rid, (b, r) in fresh.items():
            before = {tuple(i) for i in b["items"] if tuple(i)[0] not in allowed | {canary}}
            after = {tuple(i) for i in r["items"] if tuple(i)[0] not in allowed | {canary}}
            if before != after:
                diff = sorted({i[0] for i in before ^ after})
                return self._fail(db, run, f"router {r['name']}: routes for {', '.join(diff)} changed during the run")
        if not seen:
            return self._fail(db, run, "no router installed the canary as a blackhole: check the router's session "
                                       "from Shield and its import filter (BGP sessions, Router filter)")
        self._note(run, "router_check", True, f"blackhole installed on {', '.join(seen)}; other routes unchanged")
        self._start_withdraw(db, run, db.get(MitigationAction, run.action_id))

    def _start_withdraw(self, db: Session, run: AcceptanceRun, a: MitigationAction) -> None:
        service.withdraw(db, a, actor="acceptance", reason="acceptance run: canary withdrawn")
        self._goto(run, "withdrawing")

    def _step_withdrawing(self, db: Session, run: AcceptanceRun) -> None:
        a = db.get(MitigationAction, run.action_id)
        if a is None or a.state != ActionState.WITHDRAWN:
            return
        problem = self._check_sessions(db, run, expect_canary=False)
        if problem:
            return self._fail(db, run, f"after withdrawal: {problem}")
        self._note(run, "withdrawing", True, "canary withdrawn; sessions back to authorised routes only")
        run.status, run.step, run.finished_at = "passed", "passed", now()
        for n in self._neighbors(db, run.peer):
            n.acceptance_passed_at, n.acceptance_run_id = now(), run.id
        audit.record(db, audit.SYSTEM_ACTOR, "acceptance.passed", "acceptance_run", run.id,
                     after={"peer": run.peer, "target": str(run.target)})

    @staticmethod
    def _neighbors(db: Session, peer: str) -> list[BgpNeighbor]:
        q = select(BgpNeighbor).where(BgpNeighbor.router_id.is_(None), BgpNeighbor.managed_by_shield)
        if peer == "internal":
            q = q.where(BgpNeighbor.purpose == BgpPurpose.RTBH_SIGNAL)
        else:
            q = q.where(BgpNeighbor.purpose == BgpPurpose.RTBH_UPSTREAM, BgpNeighbor.upstream_id == int(peer.split(":")[1]))
        return db.execute(q).scalars().all()


def run_interlock(controller) -> list[dict]:
    """Remove anything a session advertises that no open action authorises; engage the emergency
    stop if anything was found."""
    sp = controller.speaker
    if not hasattr(sp, "advertised"):
        return []
    adv = sp.advertised()
    with controller.sessions() as db:
        bad = violations(adv, authorised(db), authorised(db, canary_only=True))
    if not bad:
        return []
    for b in bad:
        try:
            sp.remove_unauthorised(b["peer"], b["prefix"])
        except SpeakerError as e:
            b["error"] = str(e)
    with controller.sessions() as db, db.begin():
        why = "unauthorised routes were being advertised and have been removed: " + \
              ", ".join(f"{b['prefix']} to {b['name']}" for b in bad)
        engage_emergency_stop(db, why)
    try:
        import json
        controller.rds.publish("shield:events", json.dumps({"type": "mitigation", "event": "safety_interlock",
                                                            "actor": "controller", "detail": {"removed": bad}}))
    except Exception:
        pass
    log.error("SAFETY INTERLOCK: %s", bad)
    return bad


__all__ = ["AcceptanceRunner", "authorised", "run_interlock", "violations"]
