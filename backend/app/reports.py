"""Reports (Phase 10): what was attacked, how hard, from where, and what Shield did about it."""
from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AttackIncident, CustomerIpAssignment, MitigationAction, IncidentStatus

STRATEGY_WORD = {"rtbh_upstream": "Upstream blackhole", "rtbh_internal": "Internal blackhole",
                 "local_filter": "Filter on router", "steering": "Steering", "scrubbing": "Scrubbing"}


def _window(days: int | None, since: datetime | None, until: datetime | None) -> tuple[datetime, datetime]:
    until = until or datetime.now(UTC)
    since = since or until - timedelta(days=days or 30)
    return since, until


def incidents(db: Session, since: datetime, until: datetime, confirmed_only: bool = True) -> list[AttackIncident]:
    q = select(AttackIncident).where(AttackIncident.first_detected_at >= since, AttackIncident.first_detected_at < until)
    if confirmed_only:
        q = q.where(AttackIncident.confirmed_at.is_not(None))
    return db.execute(q.order_by(AttackIncident.first_detected_at)).scalars().all()


def summary(db: Session, days: int | None = 30, since: datetime | None = None, until: datetime | None = None) -> dict:
    since, until = _window(days, since, until)
    incs = incidents(db, since, until)
    fps = [i for i in incidents(db, since, until, confirmed_only=False) if i.status == IncidentStatus.FALSE_POSITIVE]
    now = datetime.now(UTC)
    dur = [((i.resolved_at or now) - i.first_detected_at).total_seconds() for i in incs]
    by_sev = Counter(i.severity.value for i in incs)
    by_vec = Counter(v for i in incs for v in (i.vectors or []))
    by_target = Counter(str(i.target) for i in incs)
    by_day: dict[str, int] = {}
    d = since.date()
    while d <= until.date() and len(by_day) < 3700:   # every day of the period, also the quiet ones
        by_day[d.strftime("%Y-%m-%d")] = 0
        d += timedelta(days=1)
    for i in incs:
        k = i.first_detected_at.astimezone(UTC).strftime("%Y-%m-%d")
        by_day[k] = by_day.get(k, 0) + 1
    asn = defaultdict(lambda: {"asn": None, "as_name": None, "attacks": 0, "packets": 0})
    for i in incs:
        for a in ((i.sources_summary or {}).get("asns") or [])[:10]:
            if a.get("asn") is None:
                continue
            row = asn[a["asn"]]
            row.update(asn=a["asn"], as_name=a.get("as_name"))
            row["attacks"] += 1
            row["packets"] += int(a.get("packets") or 0)
    custs = {str(c.address): c for c in db.execute(select(CustomerIpAssignment)).scalars()}
    peak = max(incs, key=lambda i: i.peak_bps or 0, default=None)
    acts = db.execute(select(MitigationAction).where(MitigationAction.created_at >= since,
                                                     MitigationAction.created_at < until)).scalars().all()
    mit = defaultdict(lambda: Counter())
    for a in acts:
        mit[a.strategy.value][a.state.value] += 1
    auto = sum(1 for a in acts if a.automatic)
    return {
        "from": since.isoformat(), "to": until.isoformat(),
        "attacks": len(incs), "false_positives": len(fps),
        "by_severity": dict(by_sev), "by_vector": dict(by_vec.most_common()),
        "per_day": dict(sorted(by_day.items())),
        "total_attack_minutes": round(sum(dur) / 60), "longest_minutes": round(max(dur, default=0) / 60),
        "median_minutes": round(sorted(dur)[len(dur) // 2] / 60) if dur else 0,
        "peak": None if peak is None or not peak.peak_bps else {
            "target": str(peak.target), "bps": peak.peak_bps, "pps": peak.peak_pps, "incident_id": str(peak.id),
            "at": peak.first_detected_at.isoformat()},
        "top_targets": [{"target": t, "attacks": n, "customer": (custs.get(t) and custs[t].customer_ref) or None}
                        for t, n in by_target.most_common(10)],
        "top_source_networks": sorted(asn.values(), key=lambda r: (-r["attacks"], -r["packets"]))[:10],
        "mitigations": {STRATEGY_WORD.get(k, k): dict(v) for k, v in mit.items()},
        "mitigations_total": len(acts), "mitigations_automatic": auto,
    }


def as_alert(s: dict, dedup_key: str, base_url: str = ""):
    from .notify.events import Alert
    days = max(1, round((datetime.fromisoformat(s["to"]) - datetime.fromisoformat(s["from"])).total_seconds() / 86400))
    lines = [f"{s['attacks']} attacks ({', '.join(f'{n} {k}' for k, n in s['by_severity'].items()) or 'none'})",
             f"Attack time {s['total_attack_minutes']} min; longest {s['longest_minutes']} min"]
    if s["peak"]:
        lines.append(f"Largest: {s['peak']['bps'] / 1e9:.2f} Gb/s to {s['peak']['target']}")
    if s["top_targets"]:
        lines.append("Most attacked: " + ", ".join(f"{t['target']} ({t['attacks']})" for t in s["top_targets"][:3]))
    if s["top_source_networks"]:
        lines.append("Main source networks: " + ", ".join(f"AS{r['asn']} {(r['as_name'] or '')[:20]}".strip()
                                                         for r in s["top_source_networks"][:3]))
    lines.append(f"Mitigations: {s['mitigations_total']} ({s['mitigations_automatic']} by policy)")
    return Alert("report", "info", dedup_key, f"Shield report, last {'24 hours' if days == 1 else f'{days} days'}",
                 lines, None, (base_url.rstrip("/") + "/reports") if base_url else None)


def incidents_csv(db: Session, days: int | None = 30, since=None, until=None) -> str:
    since, until = _window(days, since, until)
    custs = {str(c.address): c for c in db.execute(select(CustomerIpAssignment)).scalars()}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "target", "customer", "status", "severity", "vectors", "started_utc", "confirmed_utc", "ended_utc",
                "minutes", "peak_pps", "peak_bps", "confidence", "top_source_networks", "mitigations"])
    now = datetime.now(UTC)
    acts = defaultdict(list)
    for a in db.execute(select(MitigationAction).where(MitigationAction.incident_id.is_not(None))).scalars():
        acts[a.incident_id].append(f"{a.strategy.value}:{a.state.value}")
    for i in incidents(db, since, until, confirmed_only=False):
        c = custs.get(str(i.target))
        nets = "; ".join(f"AS{a['asn']} {a.get('as_name') or ''} {round((a.get('share') or 0) * 100)}%".strip()
                         for a in ((i.sources_summary or {}).get("asns") or [])[:3] if a.get("asn") is not None)
        w.writerow([i.id, str(i.target), c.customer_ref if c else "", i.status.value, i.severity.value, " ".join(i.vectors or []),
                    i.first_detected_at.isoformat(), i.confirmed_at.isoformat() if i.confirmed_at else "",
                    i.resolved_at.isoformat() if i.resolved_at else "",
                    round(((i.resolved_at or now) - i.first_detected_at).total_seconds() / 60, 1),
                    i.peak_pps or "", i.peak_bps or "", float(i.confidence), nets, " ".join(acts.get(i.id, []))])
    return buf.getvalue()
