"""Turns Shield's live events and periodic health checks into alerts.

An Alert has a type, a severity, a dedup key (the same thing happening again within a channel's
cooldown is not sent twice), a one-line title and a few detail lines."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]

# type -> (label, default severity)
EVENT_TYPES: dict[str, tuple[str, str]] = {
    "incident_confirmed": ("Attack confirmed", "high"),
    "incident_escalated": ("Attack severity increased", "high"),
    "incident_resolved": ("Attack ended", "info"),
    "incident_unacknowledged": ("Attack not acknowledged (escalation)", "critical"),
    "mitigation_active": ("Mitigation active", "medium"),
    "mitigation_failed": ("Mitigation failed", "high"),
    "mitigation_withdrawn": ("Mitigation withdrawn", "info"),
    "mitigation_proposed": ("Mitigation waiting for approval", "medium"),
    "safety_interlock": ("Safety interlock tripped", "critical"),
    "emergency_stop": ("Emergency stop engaged", "high"),
    "bgp_session_down": ("BGP session down", "high"),
    "bgp_session_up": ("BGP session up", "info"),
    "router_unreachable": ("Router unreachable", "high"),
    "router_recovered": ("Router reachable again", "info"),
    "router_rebooted": ("Router rebooted", "medium"),
    "link_saturated": ("Upstream link near capacity", "high"),
    "collector_no_data": ("No flow data", "high"),
    "report": ("Scheduled report", "info"),
    "test": ("Test message", "info"),
}


def sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 2


@dataclass
class Alert:
    type: str
    severity: str
    dedup_key: str
    title: str
    lines: list[str] = field(default_factory=list)
    incident_id: str | None = None
    link: str | None = None

    def text(self) -> str:
        head = f"[{self.severity.upper()}] {self.title}"
        body = "\n".join(self.lines)
        return head + ("\n" + body if body else "") + (f"\n{self.link}" if self.link else "")

    def payload(self) -> dict:
        return {"type": self.type, "severity": self.severity, "title": self.title, "lines": self.lines,
                "incident_id": self.incident_id, "link": self.link}


def _rate(pps, bps) -> str:
    out = []
    if pps:
        out.append(f"{float(pps) / 1000:,.0f} kpps")
    if bps:
        out.append(f"{float(bps) / 1e9:,.2f} Gb/s")
    return ", ".join(out)


def from_event(msg: dict, base_url: str = "") -> list[Alert]:
    """Alerts for one message published on shield:events."""
    t = msg.get("type")
    link = lambda path: (base_url.rstrip("/") + path) if base_url else None  # noqa: E731
    if t == "incident":
        inc = msg.get("incident") or {}
        ev = msg.get("event")
        iid = inc.get("id")
        vectors = ", ".join(v.replace("_", " ") for v in inc.get("vectors") or [])
        sev = inc.get("severity") or "high"
        if ev == "confirmed":
            return [Alert("incident_confirmed", sev, f"incident:{iid}:confirmed",
                          f"Attack on {inc.get('target')}: {vectors or 'traffic anomaly'}",
                          [f"Peak {_rate(inc.get('peak_pps'), inc.get('peak_bps'))}" if inc.get("peak_pps") else "",
                           f"Confidence {float(inc.get('confidence') or 0):.0%}"], iid, link(f"/attacks/{iid}"))]
        if ev == "escalated":
            return [Alert("incident_escalated", sev, f"incident:{iid}:escalated:{sev}",
                          f"Attack on {inc.get('target')} is now {sev}",
                          [vectors, f"Peak {_rate(inc.get('peak_pps'), inc.get('peak_bps'))}"], iid, link(f"/attacks/{iid}"))]
        if ev in ("resolved", "false_positive"):
            return [Alert("incident_resolved", "info", f"incident:{iid}:resolved",
                          f"Attack on {inc.get('target')} ended" + (" (marked not an attack)" if ev == "false_positive" else ""),
                          [], iid, link(f"/attacks/{iid}"))]
        return []
    if t == "mitigation":
        ev = msg.get("event")
        a = msg.get("action") or {}
        aid = a.get("id")
        what = a.get("description") or f"{a.get('strategy', 'mitigation')} for {a.get('target')}"
        sim = " (simulation)" if a.get("dry_run") else ""
        if ev == "safety_interlock":
            removed = (msg.get("detail") or {}).get("removed") or []
            return [Alert("safety_interlock", "critical", "interlock",
                          "Safety interlock: unauthorised routes removed, new blackholes stopped",
                          [f"{b.get('prefix')} to {b.get('name')}" for b in removed[:10]], None, link("/mitigation"))]
        kind = {"active": "mitigation_active", "failed": "mitigation_failed", "withdrawn": "mitigation_withdrawn",
                "rolled_back": "mitigation_failed", "proposed": "mitigation_proposed"}.get(ev)
        if not kind:
            return []
        title = {"mitigation_active": f"Mitigation active{sim}: {what}",
                 "mitigation_failed": f"Mitigation failed{sim}: {what}",
                 "mitigation_withdrawn": f"Mitigation withdrawn{sim}: {what}",
                 "mitigation_proposed": f"Waiting for approval: {what}"}[kind]
        lines = [x for x in [(msg.get("detail") or {}).get("error"), (msg.get("detail") or {}).get("reason")] if x]
        return [Alert(kind, EVENT_TYPES[kind][1], f"action:{aid}:{kind}", title, lines, a.get("incident_id"),
                      link(f"/mitigation/{aid}"))]
    if t == "router_event":
        kind = {"unreachable": "router_unreachable", "recovered": "router_recovered", "bgp_down": "bgp_session_down",
                "bgp_up": "bgp_session_up", "reboot": "router_rebooted"}.get(msg.get("kind"))
        if not kind:
            return []
        rid = msg.get("router_id")
        return [Alert(kind, EVENT_TYPES[kind][1], f"router:{rid}:{kind}:{msg.get('message', '')[:60]}",
                      f"{msg.get('router')}: {msg.get('message')}", [], None, link(f"/routers/{rid}"))]
    return []
