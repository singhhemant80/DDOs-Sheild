"""Incidents (attacks) and detection profiles."""
from __future__ import annotations

import ipaddress
import json
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import redis
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import case, cast, func, or_, select
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.orm import Session

from .. import attack_sources as srcs
from .. import audit
from .. import netvalidate as nv
from .. import telemetry as tm
from ..changes import record_change
from ..db import get_db
from ..deps import Principal, require
from ..models import (
    OPEN_INCIDENT_STATES, AttackIncident, AttackIncidentEvent, CustomerIpAssignment, DetectionEvidence,
    DetectionProfile, IncidentStatus, ProtectedPrefix, User,
)
from ..rbac import Perm
from .prefixes import eligibility_for

router = APIRouter(tags=["attacks"])
CHAN_EVENTS = "shield:events"
KEY_DETECTOR = "shield:detector:status"


# ================================================================ schemas
class IncidentOut(BaseModel):
    id: uuid.UUID
    target: str
    scope: str
    prefix: str | None
    status: str
    severity: str
    vectors: list[str]
    confidence: float
    current_confidence: float | None
    peak_pps: int | None
    peak_bps: int | None
    peak_provenance: str | None
    first_detected_at: datetime
    confirmed_at: datetime | None
    resolved_at: datetime | None
    last_hot_at: datetime | None
    resolution: str | None
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    customer: dict | None
    current: dict
    duration_seconds: int
    top_asns: list[dict] = []


class TimelineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    at: datetime
    kind: str
    actor: str
    detail: dict


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    observed_at: datetime
    metric: str
    value: float
    threshold: float | None
    provenance: str
    details: dict


class IncidentDetail(IncidentOut):
    confidence_breakdown: dict
    profile: dict | None
    timeline: list[TimelineOut]
    evidence: list[EvidenceOut]
    eligibility: dict | None


class NoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


class FalsePositiveIn(BaseModel):
    note: str = Field(min_length=3, max_length=2000, description="Why this was not an attack")


# ================================================================ helpers
def _customers(db: Session, targets: list[str]) -> dict[str, dict]:
    out = {}
    for t in set(targets):
        c = db.execute(select(CustomerIpAssignment).where(
            cast(t, CIDR).op("<<=")(CustomerIpAssignment.address))).scalar_one_or_none()
        if c:
            out[t] = {"customer_ref": c.customer_ref, "customer_name": c.customer_name,
                      "service_type": c.service_type.value, "proxmox_vmid": c.proxmox_vmid}
    return out


def _out(db: Session, inc: AttackIncident, customers: dict, prefixes: dict, users: dict) -> dict:
    end = inc.resolved_at or datetime.now(UTC)
    t = str(inc.target)
    return dict(
        id=inc.id, target=t, scope=inc.scope, prefix=prefixes.get(inc.protected_prefix_id),
        status=inc.status.value, severity=inc.severity.value, vectors=list(inc.vectors),
        confidence=float(inc.confidence), current_confidence=(inc.current or {}).get("confidence"),
        peak_pps=inc.peak_pps, peak_bps=inc.peak_bps,
        peak_provenance=inc.peak_provenance.value if inc.peak_provenance else None,
        first_detected_at=inc.first_detected_at, confirmed_at=inc.confirmed_at, resolved_at=inc.resolved_at,
        last_hot_at=inc.last_hot_at, resolution=inc.resolution, acknowledged_at=inc.acknowledged_at,
        acknowledged_by=users.get(inc.acknowledged_by_id), customer=customers.get(t), current=inc.current or {},
        duration_seconds=max(0, int((end - inc.first_detected_at).total_seconds())),
        top_asns=srcs.top_asns(inc.sources_summary),
    )


def _lookups(db: Session, rows: list[AttackIncident]):
    prefixes = {p.id: str(p.prefix) for p in db.execute(select(ProtectedPrefix)).scalars()}
    uids = {r.acknowledged_by_id for r in rows if r.acknowledged_by_id}
    users = {u.id: u.username for u in db.execute(select(User).where(User.id.in_(uids))).scalars()} if uids else {}
    return _customers(db, [str(r.target) for r in rows if r.scope == "host"]), prefixes, users


def _get(db: Session, incident_id: uuid.UUID, lock: bool = False) -> AttackIncident:
    q = select(AttackIncident).where(AttackIncident.id == incident_id)
    if lock:
        q = q.with_for_update()
    inc = db.execute(q).scalar_one_or_none()
    if inc is None:
        raise HTTPException(404, "Incident not found")
    return inc


def _publish(inc: AttackIncident, event: str, actor: str) -> None:
    msg = {"type": "incident", "event": event, "actor": actor, "incident": {
        "id": str(inc.id), "target": str(inc.target), "scope": inc.scope, "status": inc.status.value,
        "severity": inc.severity.value, "vectors": list(inc.vectors), "confidence": float(inc.confidence),
        "acknowledged": inc.acknowledged_at is not None, "resolution": inc.resolution, "ts": int(time.time())}}
    try:
        tm.rds().publish(CHAN_EVENTS, json.dumps(msg))
    except redis.RedisError:
        pass


# ================================================================ incidents
@router.get("/attacks", response_model=list[IncidentOut])
def list_incidents(
    state: str = Query("open", pattern="^(open|closed|all)$"),
    severity: str | None = Query(None, pattern="^(info|low|medium|high|critical)$"),
    q: str | None = Query(None, max_length=64, description="Address or prefix to search within"),
    confirmed_only: bool = False,
    since: datetime | None = None,
    before: datetime | None = Query(None, description="Paging cursor: first_detected_at of the last row"),
    limit: int = Query(100, ge=1, le=500),
    _: Principal = Depends(require(Perm.VIEW)),
    db: Session = Depends(get_db),
):
    stmt = select(AttackIncident)
    if state == "open":
        stmt = stmt.where(AttackIncident.status.in_(OPEN_INCIDENT_STATES))
    elif state == "closed":
        stmt = stmt.where(AttackIncident.status.notin_(OPEN_INCIDENT_STATES))
    if severity:
        stmt = stmt.where(AttackIncident.severity == severity)
    if confirmed_only:
        stmt = stmt.where(AttackIncident.confirmed_at.is_not(None))
    if since:
        stmt = stmt.where(AttackIncident.first_detected_at >= since)
    if before:
        stmt = stmt.where(AttackIncident.first_detected_at < before)
    if q:
        try:
            net = nv.parse_target(q)
        except ValueError:
            raise HTTPException(422, "q must be an IP address or prefix") from None
        c = cast(str(net), CIDR)
        stmt = stmt.where(or_(AttackIncident.target.op("<<=")(c), c.op("<<=")(AttackIncident.target)))
    if state == "open":
        rank = case({"critical": 0, "high": 1, "medium": 2, "low": 3}, value=AttackIncident.severity, else_=4)
        confirmed_first = case((AttackIncident.confirmed_at.is_not(None), 0), else_=1)
        order = [confirmed_first, rank, AttackIncident.first_detected_at.desc()]
    else:
        order = [AttackIncident.first_detected_at.desc()]
    rows = db.execute(stmt.order_by(*order).limit(limit)).scalars().all()
    cust, pref, users = _lookups(db, rows)
    return [_out(db, r, cust, pref, users) for r in rows]


@router.get("/attacks/summary")
def summary(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    rows = db.execute(select(AttackIncident.status, AttackIncident.severity, func.count())
                      .where(AttackIncident.status.in_(OPEN_INCIDENT_STATES))
                      .group_by(AttackIncident.status, AttackIncident.severity)).all()
    since = datetime.fromtimestamp(time.time() - 86400, UTC)
    confirmed_24h = db.execute(select(func.count()).select_from(AttackIncident).where(
        AttackIncident.confirmed_at >= since)).scalar_one()
    out = {"open": 0, "suspected": 0, "confirmed": 0, "by_severity": {}, "confirmed_last_24h": confirmed_24h,
           "unacknowledged": db.execute(select(func.count()).select_from(AttackIncident).where(
               AttackIncident.status.in_(OPEN_INCIDENT_STATES), AttackIncident.acknowledged_at.is_(None))).scalar_one()}
    for status, sev, n in rows:
        out["open"] += n
        key = "suspected" if status == IncidentStatus.SUSPECTED else "confirmed"
        out[key] += n
        out["by_severity"][sev.value] = out["by_severity"].get(sev.value, 0) + n
    return out


@router.get("/attacks/{incident_id}", response_model=IncidentDetail)
def incident_detail(incident_id: uuid.UUID, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    inc = _get(db, incident_id)
    cust, pref, users = _lookups(db, [inc])
    timeline = db.execute(select(AttackIncidentEvent).where(AttackIncidentEvent.incident_id == inc.id)
                          .order_by(AttackIncidentEvent.at, AttackIncidentEvent.id)).scalars().all()
    evidence = db.execute(select(DetectionEvidence).where(DetectionEvidence.incident_id == inc.id)
                          .order_by(DetectionEvidence.observed_at.desc()).limit(300)).scalars().all()
    profile = db.get(DetectionProfile, inc.profile_id) if inc.profile_id else None
    elig = eligibility_for(db, ipaddress.ip_network(str(inc.target))).model_dump()
    return {**_out(db, inc, cust, pref, users), "confidence_breakdown": inc.confidence_breakdown or {},
            "profile": None if profile is None else {"id": profile.id, "name": profile.name, "scope": str(profile.scope)},
            "timeline": timeline, "evidence": list(reversed(evidence)), "eligibility": elig}


@router.get("/attacks/{incident_id}/series")
def incident_series(incident_id: uuid.UUID, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """Traffic to the target from 5 minutes before detection to 2 minutes after the end.

    Per-second data (dst_1s) is kept 30 days; older incidents use the 1-minute rollups (180 days)."""
    inc = _get(db, incident_id)
    start = int(inc.first_detected_at.timestamp()) - 300
    end = int((inc.resolved_at or datetime.now(UTC)).timestamp()) + 120
    minute = start < time.time() - 29 * 86400
    step = max(60 if minute else 1, (end - start) // 720)
    params = {"step": step, "since": tm.utc(start), "until": tm.utc(min(end, int(time.time())))}
    host = inc.scope == "host"
    if host:
        params["dst"] = str(ipaddress.ip_network(str(inc.target)).network_address)
    else:
        params["prefix"] = str(inc.target)
    if minute:
        where = "dst = {dst:String}" if host else "dst IN (SELECT DISTINCT dst FROM dst_1m WHERE prefix = {prefix:String})"
        sql = f"""SELECT t, avg(p) AS pps, avg(b) AS bps, avg(u) AS udp_pps, avg(s) AS syn_pps FROM (
                   SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL {{step:UInt32}} SECOND)) AS t, ts,
                          sum(pa) AS p, sum(ba) AS b, sum(ua) AS u, sum(sa) AS s FROM (
                     SELECT ts, dst, avgMerge(pps_avg) AS pa, avgMerge(bps_avg) AS ba, avgMerge(udp_avg) AS ua,
                            avgMerge(syn_avg) AS sa
                     FROM dst_1m WHERE {where} AND ts >= {{since:DateTime('UTC')}} AND ts <= {{until:DateTime('UTC')}}
                     GROUP BY ts, dst)
                   GROUP BY t, ts) GROUP BY t ORDER BY t"""
    elif host:
        sql = """SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL {step:UInt32} SECOND)) AS t,
                        avg(pps) AS pps, avg(bps) AS bps, avg(tcp_pps) AS tcp_pps, avg(udp_pps) AS udp_pps,
                        avg(icmp_pps) AS icmp_pps, avg(syn_pps) AS syn_pps, avg(frag_pps) AS frag_pps
                 FROM dst_1s WHERE dst = {dst:String}
                   AND ts >= {since:DateTime('UTC')} AND ts <= {until:DateTime('UTC')}
                 GROUP BY t ORDER BY t"""
    else:
        sql = """SELECT t, avg(p) AS pps, avg(b) AS bps, avg(u) AS udp_pps, avg(s) AS syn_pps FROM (
                   SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL {step:UInt32} SECOND)) AS t, ts,
                          sum(pps) AS p, sum(bps) AS b, sum(udp_pps) AS u, sum(syn_pps) AS s
                   FROM dst_1s WHERE prefix = {prefix:String}
                     AND ts >= {since:DateTime('UTC')} AND ts <= {until:DateTime('UTC')}
                   GROUP BY t, ts) GROUP BY t ORDER BY t"""
    try:
        rows = tm.ch_query(sql, params)
    except tm.ClickHouseUnavailable:
        return {"available": False, "reason": "ClickHouse unavailable", "points": []}
    return {"available": True, "step_seconds": step, "from": start, "to": end, "points": rows,
            "resolution": "1m" if minute else "1s"}


@router.get("/attacks/{incident_id}/sources")
def incident_sources(incident_id: uuid.UUID, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """Who sent the traffic: top source addresses, their networks (AS) and countries.

    Closed incidents return the summary stored when they closed; open ones are computed live."""
    inc = _get(db, incident_id)
    closed = inc.status.value not in OPEN_INCIDENT_STATES
    if closed and inc.sources_summary:
        return {**inc.sources_summary, "stored": True}
    try:
        out = srcs.summarize(inc)
    except tm.ClickHouseUnavailable:
        return {"available": False, "reason": "ClickHouse unavailable", "sources": [], "asns": [], "countries": [],
                "stored": False}
    if closed and inc.resolved_at and (datetime.now(UTC) - inc.resolved_at).total_seconds() > 30:
        inc.sources_summary = out   # keep it beyond the per-source data's 90 days
        db.commit()
    return {**out, "stored": False}


def _require_open(inc: AttackIncident) -> None:
    if inc.status.value not in OPEN_INCIDENT_STATES:
        raise HTTPException(409, "Incident is already closed")


@router.post("/attacks/{incident_id}/acknowledge", response_model=IncidentOut)
def acknowledge(incident_id: uuid.UUID, p: Principal = Depends(require(Perm.INCIDENT_ACK)), db: Session = Depends(get_db)):
    inc = _get(db, incident_id, lock=True)
    if inc.acknowledged_at is None:
        inc.acknowledged_at = datetime.now(UTC)
        inc.acknowledged_by_id = p.user.id
        db.add(AttackIncidentEvent(incident_id=inc.id, at=inc.acknowledged_at, kind="acknowledged",
                                   actor=p.user.username, detail={}))
        audit.record(db, p.actor, "incident.acknowledge", "incident", inc.id, after={"target": str(inc.target)})
        db.flush()
        _publish(inc, "acknowledged", p.user.username)
    cust, pref, users = _lookups(db, [inc])
    return _out(db, inc, cust, pref, users)


@router.post("/attacks/{incident_id}/false-positive", response_model=IncidentOut)
def false_positive(incident_id: uuid.UUID, body: FalsePositiveIn, p: Principal = Depends(require(Perm.INCIDENT_ACK)),
                   db: Session = Depends(get_db)):
    """Close the incident as not an attack. The detector stops tracking it and will not report the same
    target again for `false_positive_suppress_minutes`. Consider raising that target's thresholds."""
    inc = _get(db, incident_id, lock=True)
    _require_open(inc)
    if inc.status.value in ("mitigating", "mitigated"):
        raise HTTPException(409, "Withdraw the mitigation before marking the incident a false positive")
    before = {"status": inc.status.value}
    now = datetime.now(UTC)
    inc.status, inc.resolution, inc.resolved_at = IncidentStatus.FALSE_POSITIVE, "false_positive", now
    inc.notes = ((inc.notes + "\n") if inc.notes else "") + f"False positive ({p.user.username}): {body.note}"
    db.add(AttackIncidentEvent(incident_id=inc.id, at=now, kind="false_positive", actor=p.user.username,
                               detail={"note": body.note}))
    audit.record(db, p.actor, "incident.false_positive", "incident", inc.id, before=before,
                 after={"status": "false_positive", "target": str(inc.target), "note": body.note})
    db.flush()
    _publish(inc, "false_positive", p.user.username)
    cust, pref, users = _lookups(db, [inc])
    return _out(db, inc, cust, pref, users)


@router.post("/attacks/{incident_id}/notes", status_code=204)
def add_note(incident_id: uuid.UUID, body: NoteIn, p: Principal = Depends(require(Perm.INCIDENT_ACK)),
             db: Session = Depends(get_db)):
    inc = _get(db, incident_id)
    db.add(AttackIncidentEvent(incident_id=inc.id, at=datetime.now(UTC), kind="note", actor=p.user.username,
                               detail={"note": body.note}))
    audit.record(db, p.actor, "incident.note", "incident", inc.id, after={"note": body.note})


@router.get("/detection/status")
def detector_status(_: Principal = Depends(require(Perm.VIEW))):
    try:
        raw = tm.rds().get(KEY_DETECTOR)
    except redis.RedisError:
        raw = None
    if not raw:
        return {"running": False, "reason": "no status published in the last 15s"}
    st = json.loads(raw)
    st["running"] = True
    return st


# ================================================================ detection profiles
class ProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    scope: str
    enabled: bool = True
    dst_pps: int | None = Field(None, gt=0)
    dst_bps: int | None = Field(None, gt=0)
    syn_pps: int | None = Field(None, gt=0)
    tcp_flag_pps: int | None = Field(None, gt=0)
    udp_pps: int | None = Field(None, gt=0)
    icmp_pps: int | None = Field(None, gt=0)
    reflect_pps: int | None = Field(None, gt=0)
    frag_pps: int | None = Field(None, gt=0)
    prefix_pps: int | None = Field(None, gt=0)
    prefix_bps: int | None = Field(None, gt=0)
    baseline_factor: float = Field(4.0, ge=1, le=1000)
    anomaly_min_pps: int = Field(20000, ge=0)
    suspect_hits: int = Field(3, ge=1, le=60)
    suspect_window: int = Field(5, ge=1, le=60)
    confirm_seconds: int = Field(20, ge=3, le=600)
    confirm_confidence: float = Field(0.7, gt=0, le=1)
    release_seconds: int = Field(120, ge=10, le=3600)
    suspect_timeout_seconds: int = Field(60, ge=10, le=3600)
    notes: str | None = Field(None, max_length=2000)

    @field_validator("scope")
    @classmethod
    def _scope(cls, v: str) -> str:
        return str(nv.parse_prefix(v))


class ProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    scope: str
    enabled: bool
    is_default: bool
    dst_pps: int | None
    dst_bps: int | None
    syn_pps: int | None
    tcp_flag_pps: int | None
    udp_pps: int | None
    icmp_pps: int | None
    reflect_pps: int | None
    frag_pps: int | None
    prefix_pps: int | None
    prefix_bps: int | None
    baseline_factor: float
    anomaly_min_pps: int
    suspect_hits: int
    suspect_window: int
    confirm_seconds: int
    confirm_confidence: float
    release_seconds: int
    suspect_timeout_seconds: int
    notes: str | None
    updated_at: datetime

    @field_validator("scope", mode="before")
    @classmethod
    def _s(cls, v):
        return str(v)


def _profile_values(body: ProfileIn) -> dict:
    d = body.model_dump()
    if d["suspect_hits"] > d["suspect_window"]:
        raise HTTPException(422, "suspect_hits cannot exceed suspect_window")
    d["baseline_factor"] = Decimal(str(d["baseline_factor"]))
    d["confirm_confidence"] = Decimal(str(d["confirm_confidence"]))
    return d


@router.get("/detection/profiles", response_model=list[ProfileOut])
def list_profiles(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return db.execute(select(DetectionProfile).order_by(DetectionProfile.is_default.desc(),
                                                        func.masklen(DetectionProfile.scope),
                                                        DetectionProfile.scope)).scalars().all()


@router.post("/detection/profiles", response_model=ProfileOut, status_code=201)
def create_profile(body: ProfileIn, p: Principal = Depends(require(Perm.CONFIG_POLICY)), db: Session = Depends(get_db)):
    d = _profile_values(body)
    if ipaddress.ip_network(d["scope"]).prefixlen == 0:
        raise HTTPException(422, "The /0 defaults already exist; edit them instead")
    prof = DetectionProfile(**d, is_default=False)
    db.add(prof)
    record_change(db, p.actor, "detection_profile.create", "detection_profile", prof)
    return prof


@router.put("/detection/profiles/{profile_id}", response_model=ProfileOut)
def update_profile(profile_id: int, body: ProfileIn, p: Principal = Depends(require(Perm.CONFIG_POLICY)),
                   db: Session = Depends(get_db)):
    prof = db.get(DetectionProfile, profile_id)
    if prof is None:
        raise HTTPException(404, "Profile not found")
    d = _profile_values(body)
    if prof.is_default:
        if d["scope"] != str(prof.scope):
            raise HTTPException(422, "The scope of a default profile cannot change")
        if not d["enabled"]:
            raise HTTPException(422, "Default profiles cannot be disabled; turn off individual checks instead")
    before = audit.snapshot(prof)
    for k, v in d.items():
        setattr(prof, k, v)
    record_change(db, p.actor, "detection_profile.update", "detection_profile", prof, before=before)
    return prof


@router.delete("/detection/profiles/{profile_id}", status_code=204)
def delete_profile(profile_id: int, p: Principal = Depends(require(Perm.CONFIG_POLICY)), db: Session = Depends(get_db)):
    prof = db.get(DetectionProfile, profile_id)
    if prof is None:
        raise HTTPException(404, "Profile not found")
    if prof.is_default:
        raise HTTPException(409, "Default profiles cannot be deleted")
    before = audit.snapshot(prof)
    db.delete(prof)
    record_change(db, p.actor, "detection_profile.delete", "detection_profile", None, entity_id=profile_id,
                  before=before)

