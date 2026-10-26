"""Mitigation center API (Phase 6: SIMULATION ONLY - nothing is announced to any router or provider).

Every write needs a role permission; proposals need an Idempotency-Key header so a retried request
never creates a second action. Plans are rebuilt (and must still pass) at approval and again just
before the controller executes them.
"""
from __future__ import annotations

import json
import uuid
from decimal import Decimal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, netvalidate as nv
from .. import telemetry as tm
from ..changes import get_setting, record_change
from ..db import get_db
from ..deps import Principal, require
from ..detector.engine import VECTOR_SPECIFICITY
from ..mitigation import service
from ..mitigation.planner import RTBH_STRATEGIES, PlanRequest, build_plan
from ..mitigation.speaker import SpeakerError
from ..mitigation.state import action_out
from ..models import (
    ActionState, AttackIncident, MitigationAction, MitigationActionEvent, MitigationPolicy, RtbhRoute, RtbhStatus,
    UpstreamProvider, User,
)
from ..rbac import Perm, has_perm

router = APIRouter(prefix="/mitigation", tags=["mitigation"])

STATE_GROUPS = {
    "live": ["proposed", "approved", "executing", "active", "withdrawing", "failed"],
    "proposed": ["proposed"], "active": ["approved", "executing", "active", "withdrawing"],
    "closed": ["rejected", "withdrawn", "rolled_back"],
}


class PlanIn(BaseModel):
    target: str = Field(max_length=64)
    strategy: str = "rtbh_upstream"
    upstream_ids: list[int] | None = None
    incident_id: uuid.UUID | None = None
    duration_minutes: int | None = Field(None, ge=5, le=1440)

    def request(self, automatic: bool = False) -> PlanRequest:
        return PlanRequest(target=self.target, strategy=self.strategy,
                           upstream_ids=sorted(set(self.upstream_ids)) if self.upstream_ids is not None else None,
                           incident_id=str(self.incident_id) if self.incident_id else None,
                           duration_seconds=self.duration_minutes * 60 if self.duration_minutes else None,
                           automatic=automatic)


class ReasonIn(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class ExtendIn(BaseModel):
    minutes: int = Field(ge=5, le=1440)


def _conflict(e: service.Conflict) -> HTTPException:
    return HTTPException(status.HTTP_409_CONFLICT, {"message": str(e), "checks": e.checks})


def _names(db: Session) -> tuple[dict, dict]:
    ups = dict(db.execute(select(UpstreamProvider.id, UpstreamProvider.name)).all())
    users = {str(k): v for k, v in db.execute(select(User.id, User.username)).all()}
    return ups, users


def _out(a: MitigationAction, ups: dict, users: dict) -> dict:
    o = action_out(a)
    o["upstream"] = ups.get(a.upstream_id)
    o["requested_by"] = users.get(o["requested_by_id"])
    o["approved_by"] = users.get(o["approved_by_id"])
    return o


def _get(db: Session, action_id: uuid.UUID, lock: bool = False) -> MitigationAction:
    q = select(MitigationAction).where(MitigationAction.id == action_id)
    a = db.execute(q.with_for_update() if lock else q).scalar_one_or_none()
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Action not found")
    return a


# ---------------------------------------------------------------- plan / propose
@router.post("/preview")
def preview(body: PlanIn, _: Principal = Depends(require(Perm.MITIGATION_PROPOSE)), db: Session = Depends(get_db)):
    """What would be announced, every safety check, and the impact. Changes nothing."""
    if body.incident_id and db.get(AttackIncident, body.incident_id) is None:
        raise HTTPException(422, "incident_id does not exist")
    return dict(build_plan(db, body.request()))


@router.post("/actions", status_code=201)
def propose(body: PlanIn, response: Response, p: Principal = Depends(require(Perm.MITIGATION_PROPOSE)),
            db: Session = Depends(get_db),
            idempotency_key: str = Header(..., alias="Idempotency-Key", pattern=r"^[A-Za-z0-9._:-]{8,100}$")):
    if body.incident_id and db.get(AttackIncident, body.incident_id) is None:
        raise HTTPException(422, "incident_id does not exist")
    key = f"user:{p.user.id}:{idempotency_key}"
    replay = bool(service.existing_for_key(db, key))
    try:
        actions = service.propose(db, body.request(), key=key, actor=p.user.username, user_id=p.user.id)
    except service.Conflict as e:
        raise _conflict(e) from None
    if replay:
        response.status_code = status.HTTP_200_OK
    else:
        audit.record(db, p.actor, "mitigation.propose", "mitigation_group", actions[0].group_id,
                     after={"target": str(actions[0].target), "strategy": body.strategy,
                            "routes": [a.plan["route"]["description"] for a in actions], "simulation": True})
    ups, users = _names(db)
    return {"group_id": str(actions[0].group_id), "replayed": replay, "actions": [_out(a, ups, users) for a in actions]}


# ---------------------------------------------------------------- list / detail
@router.get("/actions")
def list_actions(state: str = Query("live", pattern="^(live|proposed|active|closed|all)$"),
                 incident_id: uuid.UUID | None = None, limit: int = Query(200, ge=1, le=1000),
                 _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    q = select(MitigationAction).order_by(MitigationAction.created_at.desc()).limit(limit)
    if state != "all":
        q = q.where(MitigationAction.state.in_(STATE_GROUPS[state]))
    if incident_id:
        q = q.where(MitigationAction.incident_id == incident_id)
    ups, users = _names(db)
    return [_out(a, ups, users) for a in db.execute(q).scalars()]


@router.get("/actions/{action_id}")
def action_detail(action_id: uuid.UUID, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    a = _get(db, action_id)
    ups, users = _names(db)
    group = service.group_of(db, a)
    ids = [x.id for x in group]
    events = db.execute(select(MitigationActionEvent).where(MitigationActionEvent.action_id.in_(ids))
                        .order_by(MitigationActionEvent.at, MitigationActionEvent.id)).scalars()
    routes = db.execute(select(RtbhRoute).where(RtbhRoute.action_id.in_(ids)).order_by(RtbhRoute.id)).scalars()
    return {
        **_out(a, ups, users),
        "group": [_out(x, ups, users) for x in group],
        "events": [{"at": e.at, "action_id": str(e.action_id), "from": e.from_state, "to": e.to_state, "actor": e.actor,
                    "detail": e.detail} for e in events],
        "routes": [_route_out(r, ups) for r in routes],
        "checks_at_approval": (a.plan or {}).get("checks_at_approval"),
    }


# ---------------------------------------------------------------- decisions
@router.post("/actions/{action_id}/approve")
def approve(action_id: uuid.UUID, p: Principal = Depends(require(Perm.MITIGATION_APPROVE)), db: Session = Depends(get_db)):
    """Approves the whole request (all upstreams proposed together)."""
    a = _get(db, action_id, lock=True)
    group = service.group_of(db, a)
    try:
        service.approve(db, group, actor=p.user.username, user_id=p.user.id, mfa=p.mfa)
    except service.Conflict as e:
        raise _conflict(e) from None
    audit.record(db, p.actor, "mitigation.approve", "mitigation_group", a.group_id,
                 after={"target": str(a.target), "actions": [str(x.id) for x in group], "simulation": True})
    ups, users = _names(db)
    return [_out(x, ups, users) for x in group]


@router.post("/actions/{action_id}/reject")
def reject(action_id: uuid.UUID, body: ReasonIn, p: Principal = Depends(require(Perm.MITIGATION_APPROVE)),
           db: Session = Depends(get_db)):
    a = _get(db, action_id, lock=True)
    group = [x for x in service.group_of(db, a) if x.state in (ActionState.PROPOSED, ActionState.APPROVED)]
    try:
        service.reject(db, group or [a], actor=p.user.username, reason=body.reason)
    except service.Conflict as e:
        raise _conflict(e) from None
    audit.record(db, p.actor, "mitigation.reject", "mitigation_group", a.group_id, after={"reason": body.reason})
    ups, users = _names(db)
    return [_out(x, ups, users) for x in group or [a]]


@router.post("/actions/{action_id}/withdraw")
def withdraw(action_id: uuid.UUID, body: ReasonIn, whole_group: bool = False,
             p: Principal = Depends(require(Perm.MITIGATION_WITHDRAW)), db: Session = Depends(get_db)):
    a = _get(db, action_id, lock=True)
    targets = [x for x in service.group_of(db, a) if x.state in service.LIVE or x.state == ActionState.FAILED] \
        if whole_group else [a]
    try:
        for x in targets:
            service.withdraw(db, x, actor=p.user.username, user_id=p.user.id, reason=body.reason)
    except service.Conflict as e:
        raise _conflict(e) from None
    audit.record(db, p.actor, "mitigation.withdraw", "mitigation_action", a.id,
                 after={"actions": [str(x.id) for x in targets], "reason": body.reason})
    ups, users = _names(db)
    return [_out(x, ups, users) for x in targets]


@router.post("/actions/{action_id}/extend")
def extend(action_id: uuid.UUID, body: ExtendIn, p: Principal = Depends(require(Perm.MITIGATION_APPROVE)),
           db: Session = Depends(get_db)):
    a = _get(db, action_id, lock=True)
    try:
        service.extend(db, a, body.minutes * 60, actor=p.user.username, why="extended by operator")
    except service.Conflict as e:
        raise _conflict(e) from None
    audit.record(db, p.actor, "mitigation.extend", "mitigation_action", a.id, after={"minutes": body.minutes})
    ups, users = _names(db)
    return _out(a, ups, users)


# ---------------------------------------------------------------- routes and controller
def _route_out(r: RtbhRoute, ups: dict) -> dict:
    return {"id": r.id, "action_id": str(r.action_id), "mode": r.mode.value, "prefix": str(r.prefix),
            "upstream_id": r.upstream_id, "upstream": ups.get(r.upstream_id), "communities": list(r.communities),
            "next_hop": str(r.next_hop) if r.next_hop else None, "status": r.status.value, "speaker": r.speaker,
            "announced_at": r.announced_at, "verified_at": r.verified_at, "withdrawn_at": r.withdrawn_at,
            "last_verify_result": r.last_verify_result}


@router.get("/routes")
def routes(state: str = Query("live", pattern="^(live|all)$"), limit: int = Query(200, ge=1, le=2000),
           _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    q = select(RtbhRoute).order_by(RtbhRoute.id.desc()).limit(limit)
    if state == "live":
        q = q.where(RtbhRoute.status != RtbhStatus.WITHDRAWN)
    ups, _u = _names(db)
    ledger = [_route_out(r, ups) for r in db.execute(q).scalars()]
    try:
        from ..db import session_factory
        from ..mitigation.speaker import make_speaker
        rib = make_speaker(get_setting(db, "bgp_speaker", "simulated"), tm.rds(), session_factory()).routes()
        speaker = {"available": True, "routes": [
            {"key": k, "prefix": r.prefix, "peer": r.peer, "communities": list(r.communities), "next_hop": r.next_hop,
             "no_export": r.no_export, "action_id": r.action_id,
             "upstream": ups.get(int(r.peer.split(":")[1])) if r.peer.startswith("upstream:") else "own routers"}
            for k, r in sorted(rib.items())]}
    except (SpeakerError, ValueError) as e:
        speaker = {"available": False, "reason": str(e), "routes": []}
    return {"simulation": get_setting(db, "bgp_speaker", "simulated") == "simulated", "ledger": ledger, "speaker": speaker,
            "limit": int(get_setting(db, "global_max_rtbh_routes", 50))}


@router.get("/status")
def controller_status(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    try:
        raw = tm.rds().get("shield:mitigator:status")
    except Exception:
        raw = None
    st = json.loads(raw) if raw else None
    counts = dict(db.execute(select(MitigationAction.state, func.count()).group_by(MitigationAction.state)).all())
    speaker = get_setting(db, "bgp_speaker", "simulated")
    return {
        "mode": "simulation" if speaker == "simulated" else "staging", "speaker": speaker,
        "controller": st, "running": st is not None,
        "counts": {k.value: v for k, v in counts.items()},
        "automation_enabled": get_setting(db, "automation_enabled", False),
        "emergency_stop": get_setting(db, "rtbh_emergency_disable", False),
        "four_eyes_approval": get_setting(db, "four_eyes_approval", False),
        "require_mfa_for_mitigation": get_setting(db, "require_mfa_for_mitigation", False),
    }


# ---------------------------------------------------------------- policies
class PolicyIn(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9 _.-]{1,64}$")
    enabled: bool = False
    priority: int = Field(100, ge=0, le=10000)
    scope: str
    vectors: list[str] = Field(default_factory=list, max_length=40)
    min_confidence: float = Field(0.9, ge=0, le=1)
    min_duration_seconds: int = Field(60, ge=0, le=86400)
    pps_threshold: int | None = Field(None, gt=0)
    bps_threshold: int | None = Field(None, gt=0)
    allowed_strategies: list[str] = Field(default_factory=lambda: ["rtbh_upstream"])
    requires_approval: bool = True
    max_scope_prefix_len: int = Field(32, ge=0, le=128)
    mitigation_duration_seconds: int = Field(3600, ge=300, le=86400)
    min_hold_seconds: int = Field(600, ge=0, le=86400)
    recovery_quiet_seconds: int = Field(300, ge=0, le=86400)
    cooldown_seconds: int = Field(900, ge=0, le=86400)
    max_concurrent_actions: int = Field(5, ge=1, le=1000)
    rollback_procedure: str | None = Field(None, max_length=2000)

    @field_validator("scope")
    @classmethod
    def _scope(cls, v: str) -> str:
        return str(nv.parse_prefix(v))

    @field_validator("vectors")
    @classmethod
    def _vectors(cls, v: list[str]) -> list[str]:
        bad = [x for x in v if x not in VECTOR_SPECIFICITY]
        if bad:
            raise ValueError(f"unknown vectors: {', '.join(bad)}")
        return sorted(set(v))

    @field_validator("allowed_strategies")
    @classmethod
    def _strategies(cls, v: list[str]) -> list[str]:
        if not v or any(s not in RTBH_STRATEGIES for s in v):
            raise ValueError("only rtbh_upstream and rtbh_internal are available in this release")
        return v


def _policy_out(p: MitigationPolicy) -> dict:
    return {c.key: (float(getattr(p, c.key)) if isinstance(getattr(p, c.key), Decimal) else
                    str(getattr(p, c.key)) if c.key == "scope" else getattr(p, c.key))
            for c in MitigationPolicy.__table__.columns}


@router.get("/policies")
def list_policies(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return [_policy_out(p) for p in db.execute(select(MitigationPolicy).order_by(MitigationPolicy.priority,
                                                                               MitigationPolicy.id)).scalars()]


def _policy_guard(body: PolicyIn, p: Principal) -> None:
    """A policy that acts without approval is automation: it needs the automation permission."""
    if body.enabled and not body.requires_approval and not has_perm(p.user.role, Perm.AUTOMATION_ENABLE):
        raise HTTPException(403, "Only roles that may enable automation can enable a policy that acts without approval")


@router.post("/policies", status_code=201)
def create_policy(body: PolicyIn, p: Principal = Depends(require(Perm.CONFIG_POLICY)), db: Session = Depends(get_db)):
    _policy_guard(body, p)
    pol = MitigationPolicy(**{**body.model_dump(), "min_confidence": Decimal(str(body.min_confidence))})
    db.add(pol)
    record_change(db, p.actor, "mitigation_policy.create", "mitigation_policy", pol)
    return _policy_out(pol)


@router.put("/policies/{policy_id}")
def update_policy(policy_id: int, body: PolicyIn, p: Principal = Depends(require(Perm.CONFIG_POLICY)),
                  db: Session = Depends(get_db)):
    pol = db.get(MitigationPolicy, policy_id)
    if pol is None:
        raise HTTPException(404, "Policy not found")
    _policy_guard(body, p)
    before = audit.snapshot(pol)
    for k, v in body.model_dump().items():
        setattr(pol, k, Decimal(str(v)) if k == "min_confidence" else v)
    pol.version += 1
    record_change(db, p.actor, "mitigation_policy.update", "mitigation_policy", pol, before=before)
    return _policy_out(pol)


@router.delete("/policies/{policy_id}", status_code=204)
def delete_policy(policy_id: int, p: Principal = Depends(require(Perm.CONFIG_POLICY)), db: Session = Depends(get_db)):
    pol = db.get(MitigationPolicy, policy_id)
    if pol is None:
        raise HTTPException(404, "Policy not found")
    before = audit.snapshot(pol)
    db.delete(pol)
    record_change(db, p.actor, "mitigation_policy.delete", "mitigation_policy", None, entity_id=policy_id, before=before)
