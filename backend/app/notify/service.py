"""shield-notifier: sends alerts to e-mail, Telegram and webhook channels.

Sources
  * live events on Redis shield:events (attacks, mitigation actions, the safety interlock)
  * router events from the read-only poller (unreachable, BGP session down/up, reboots)
  * periodic checks: attacks confirmed but not acknowledged (escalation), upstream links near
    capacity, no flow data, the emergency stop being engaged
  * scheduled reports (daily or weekly summary) for channels that ask for them

For each alert and each enabled channel that wants it (event type and minimum severity), a row is
written to `notifications`. The same dedup key on the same channel within the channel's cooldown is
recorded as suppressed, not sent. Delivery is retried with back-off (up to 5 attempts).
"""
from __future__ import annotations

import json
import logging
import signal
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import redis
from sqlalchemy import select

from .. import security
from .. import telemetry as tm
from ..changes import get_setting
from ..config import get_settings
from ..db import session_factory
from ..models import (
    AttackIncident, IncidentStatus, Notification, NotificationChannel, RouterEvent, Router, Severity, UpstreamProvider,
)
from . import senders
from .events import EVENT_TYPES, Alert, from_event, sev_rank

log = logging.getLogger("shield.notifier")
CHAN_EVENTS = "shield:events"
KEY_STATUS = "shield:notifier:status"
MAX_ATTEMPTS = 5
CHECK_EVERY = 15.0


def channel_wants(ch: NotificationChannel, a: Alert) -> bool:
    if not ch.enabled:
        return False
    if a.type == "test":
        return False      # tests are sent to one channel explicitly
    if ch.event_types and a.type not in ch.event_types:
        return False
    if a.type == "report":
        return True
    return sev_rank(a.severity) >= sev_rank(ch.min_severity.value if hasattr(ch.min_severity, "value") else ch.min_severity)


class Notifier:
    def __init__(self, rds: redis.Redis | None = None, sessions=None, transport=None, smtp_factory=None,
                 clock=lambda: datetime.now(UTC)):
        s = get_settings()
        self.rds = rds or redis.Redis.from_url(s.redis_url, decode_responses=True, socket_timeout=5, socket_connect_timeout=3)
        self.sessions = sessions or session_factory()
        self.transport, self.smtp_factory, self.clock = transport, smtp_factory, clock
        self.last_router_event = None
        self.state: dict = {}            # dedup memory for periodic checks
        self.sent = self.failed = self.suppressed = 0

    # ------------------------------------------------------------ queueing
    def enqueue(self, alerts: list[Alert]) -> int:
        """Write a notification row per (alert, channel that wants it). Returns rows to send."""
        if not alerts:
            return 0
        n = 0
        now = self.clock()
        with self.sessions() as db, db.begin():
            chans = db.execute(select(NotificationChannel).where(NotificationChannel.enabled)).scalars().all()
            for a in alerts:
                for ch in chans:
                    if not channel_wants(ch, a):
                        continue
                    n += self._row(db, ch, a, now)
        return n

    def _row(self, db, ch: NotificationChannel, a: Alert, now: datetime) -> int:
        recent = db.execute(select(Notification.id).where(
            Notification.channel_id == ch.id, Notification.dedup_key == a.dedup_key[:128],
            Notification.status.in_(("pending", "sent")),
            Notification.created_at >= now - timedelta(seconds=ch.cooldown_seconds))).first()
        status = "suppressed" if recent else "pending"
        iid = a.incident_id
        if iid:
            try:
                iid = iid if db.get(AttackIncident, uuid.UUID(str(iid))) else None
            except ValueError:
                iid = None
        db.add(Notification(channel_id=ch.id, event_type=a.type[:48], severity=Severity(a.severity), dedup_key=a.dedup_key[:128],
                            incident_id=iid, payload=a.payload(), status=status))
        if recent:
            self.suppressed += 1
        return 0 if recent else 1

    # ------------------------------------------------------------ delivery
    def deliver(self) -> int:
        """Send pending notifications that are due. Returns the number sent."""
        now = self.clock()
        done = 0
        with self.sessions() as db:
            rows = db.execute(select(Notification.id).where(Notification.status == "pending")
                              .order_by(Notification.id).limit(100)).scalars().all()
        for nid in rows:
            with self.sessions() as db, db.begin():
                n = db.execute(select(Notification).where(Notification.id == nid, Notification.status == "pending")
                               .with_for_update(skip_locked=True)).scalar_one_or_none()
                if n is None:
                    continue
                if n.attempts and n.created_at + timedelta(seconds=10 * 2 ** n.attempts) > now:
                    continue     # back-off
                ch = db.get(NotificationChannel, n.channel_id)
                alert = Alert(n.event_type, n.severity.value, n.dedup_key, n.payload.get("title", ""),
                              n.payload.get("lines") or [], n.payload.get("incident_id"), n.payload.get("link"))
                try:
                    secret = security.decrypt_secret(ch.secret_enc) if ch.secret_enc else None
                    senders.send(ch.kind.value, ch.config or {}, secret, alert, self.transport, self.smtp_factory)
                    n.status, n.sent_at, n.error = "sent", now, None
                    done += 1
                    self.sent += 1
                except senders.SendError as e:
                    n.attempts += 1
                    n.error = str(e)[:500]
                    if n.attempts >= MAX_ATTEMPTS:
                        n.status = "failed"
                        self.failed += 1
                        log.warning("notification %s to %s failed: %s", n.id, ch.name, e)
                except Exception as e:   # bad secret, bad config: do not retry forever
                    n.attempts = MAX_ATTEMPTS
                    n.status, n.error = "failed", f"{type(e).__name__}: {e}"[:500]
                    self.failed += 1
        return done

    def send_test(self, channel_id: int) -> tuple[bool, str | None]:
        """Send a test message to one channel now (used by the API)."""
        with self.sessions() as db, db.begin():
            ch = db.get(NotificationChannel, channel_id)
            a = Alert("test", "info", f"test:{time.time()}", "Test message from Crapplet DDoS Shield",
                      ["If you can read this, this channel works."])
            n = Notification(channel_id=ch.id, event_type="test", severity=Severity.INFO, dedup_key=a.dedup_key,
                             payload=a.payload(), status="pending", attempts=0)
            db.add(n)
            try:
                secret = security.decrypt_secret(ch.secret_enc) if ch.secret_enc else None
                senders.send(ch.kind.value, ch.config or {}, secret, a, self.transport, self.smtp_factory)
                n.status, n.sent_at = "sent", self.clock()
                return True, None
            except Exception as e:
                n.status, n.error, n.attempts = "failed", str(e)[:500], 1
                return False, str(e)

    # ------------------------------------------------------------ sources
    def base_url(self) -> str:
        with self.sessions() as db:
            return str(get_setting(db, "dashboard_url", "") or "")

    def handle_message(self, raw: str) -> int:
        try:
            msg = json.loads(raw)
        except ValueError:
            return 0
        return self.enqueue(from_event(msg, self.base_url()))

    def poll_router_events(self) -> int:
        with self.sessions() as db:
            if self.last_router_event is None:   # start from now: do not replay history
                self.last_router_event = db.execute(select(RouterEvent.id).order_by(RouterEvent.id.desc()).limit(1)).scalar() or 0
                return 0
            rows = db.execute(select(RouterEvent, Router.name).join(Router, Router.id == RouterEvent.router_id)
                              .where(RouterEvent.id > self.last_router_event).order_by(RouterEvent.id).limit(500)).all()
        alerts = []
        base = self.base_url()
        for e, name in rows:
            self.last_router_event = e.id
            alerts += from_event({"type": "router_event", "kind": e.kind, "router_id": e.router_id, "router": name,
                                  "message": e.message}, base)
        return self.enqueue(alerts)

    def check(self) -> int:
        """Periodic conditions that are not events."""
        alerts: list[Alert] = []
        now = self.clock()
        base = self.base_url()
        link = (lambda p: base.rstrip("/") + p) if base else (lambda p: None)
        with self.sessions() as db:
            # Escalation: confirmed attacks nobody acknowledged, per channel's escalate_after_seconds.
            chans = db.execute(select(NotificationChannel).where(NotificationChannel.enabled,
                                                                 NotificationChannel.escalate_after_seconds.is_not(None))).scalars().all()
            if chans:
                open_inc = db.execute(select(AttackIncident).where(
                    AttackIncident.status.in_([IncidentStatus.CONFIRMED, IncidentStatus.MITIGATING, IncidentStatus.MITIGATED]),
                    AttackIncident.acknowledged_at.is_(None), AttackIncident.confirmed_at.is_not(None))).scalars().all()
                esc: list[tuple[NotificationChannel, Alert]] = []
                for inc in open_inc:
                    for ch in chans:
                        if inc.confirmed_at <= now - timedelta(seconds=ch.escalate_after_seconds):
                            mins = int((now - inc.confirmed_at).total_seconds() // 60)
                            esc.append((ch, Alert("incident_unacknowledged", "critical", f"incident:{inc.id}:unacked",
                                                  f"Attack on {inc.target} not acknowledged for {mins} min",
                                                  [", ".join(inc.vectors or [])], str(inc.id), link(f"/attacks/{inc.id}"))))
            else:
                esc = []
            emergency = bool(get_setting(db, "rtbh_emergency_disable", False))
            ups = db.execute(select(UpstreamProvider).where(UpstreamProvider.enabled, UpstreamProvider.capacity_mbps.is_not(None),
                                                            UpstreamProvider.interface_name.is_not(None))).scalars().all()
            routers = dict(db.execute(select(Router.id, Router.name)).all())
        if esc:
            with self.sessions() as db, db.begin():
                for ch, a in esc:
                    ch = db.get(NotificationChannel, ch.id)
                    # once per incident per channel (cooldown does not apply: escalation is a one-off)
                    seen = db.execute(select(Notification.id).where(Notification.channel_id == ch.id,
                                                                    Notification.dedup_key == a.dedup_key)).first()
                    if not seen:
                        db.add(Notification(channel_id=ch.id, event_type=a.type, severity=Severity.CRITICAL,
                                            dedup_key=a.dedup_key, incident_id=a.incident_id, payload=a.payload(),
                                            status="pending"))
        # Emergency stop engaged (edge-triggered).
        if emergency and not self.state.get("emergency"):
            alerts.append(Alert("emergency_stop", "high", f"emergency:{now:%Y%m%d%H%M}",
                                "Emergency stop engaged: automatic mitigation off, new blackholes blocked", [],
                                None, link("/settings")))
        self.state["emergency"] = emergency
        # Upstream links near capacity, from measured interface rates.
        try:
            ifaces = tm.interfaces()
        except Exception:
            ifaces = []
        for u in ups:
            rate = max((max(i.get("in_bps") or 0, i.get("out_bps") or 0) for i in ifaces
                        if i.get("if_name") == u.interface_name or i.get("name") == u.interface_name), default=0)
            cap = u.capacity_mbps * 1e6
            hot = rate >= cap * u.saturation_threshold_pct / 100
            key = f"sat:{u.id}"
            if hot and not self.state.get(key):
                alerts.append(Alert("link_saturated", "high", f"link:{u.id}:saturated",
                                    f"{u.name} at {rate / cap:.0%} of {u.capacity_mbps / 1000:g} Gb/s",
                                    [f"Interface {u.interface_name}" + (f" on {routers.get(u.router_id)}" if u.router_id else ""),
                                     "Filtering on your router cannot help a full link: blackhole or divert upstream."],
                                    None, link("/traffic")))
            self.state[key] = hot
        # No flow data while the collector is running (exporters went quiet).
        try:
            cs = tm.collector_status()
        except Exception:
            cs = {}
        quiet = bool(cs.get("running")) and bool(cs.get("exporters")) and all(e.get("stale") for e in cs.get("exporters", []))
        if quiet and not self.state.get("quiet"):
            alerts.append(Alert("collector_no_data", "high", "collector:quiet", "No flow data from any router",
                                ["Shield cannot see attacks until the routers' flow export resumes."], None, link("/health")))
        self.state["quiet"] = quiet
        return self.enqueue(alerts)

    # ------------------------------------------------------------ reports
    def reports(self) -> int:
        """Daily (08:00 server time) and weekly (Monday 08:00) summaries for channels that ask."""
        from .. import reports
        now_local = datetime.now()
        if now_local.hour < 8:
            return 0
        n = 0
        with self.sessions() as db:
            chans = [c for c in db.execute(select(NotificationChannel).where(NotificationChannel.enabled)).scalars()
                     if (c.config or {}).get("reports") in ("daily", "weekly")]
            for ch in chans:
                freq = ch.config["reports"]
                if freq == "weekly" and now_local.weekday() != 0:
                    continue
                stamp = now_local.strftime("%Y-%m-%d")
                key = f"report:{freq}:{stamp}"
                seen = db.execute(select(Notification.id).where(Notification.channel_id == ch.id,
                                                                Notification.dedup_key == key)).first()
                if seen:
                    continue
                days = 1 if freq == "daily" else 7
                s = reports.summary(db, days=days)
                a = reports.as_alert(s, key, self.base_url())
                with self.sessions() as w, w.begin():
                    w.add(Notification(channel_id=ch.id, event_type="report", severity=Severity.INFO, dedup_key=key,
                                       payload=a.payload(), status="pending"))
                n += 1
        return n

    # ------------------------------------------------------------ loop
    def publish_status(self) -> None:
        try:
            self.rds.set(KEY_STATUS, json.dumps({"ts": int(time.time()), "sent": self.sent, "failed": self.failed,
                                                 "suppressed": self.suppressed}), ex=60)
        except redis.RedisError:
            pass

    def run(self) -> None:
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        log.info("notifier started")
        ps = None
        last_check = 0.0
        while not stop.is_set():
            try:
                if ps is None:
                    ps = self.rds.pubsub(ignore_subscribe_messages=True)
                    ps.subscribe(CHAN_EVENTS)
                m = ps.get_message(timeout=1.0)
                while m:
                    if m.get("type") == "message":
                        self.handle_message(m["data"])
                    m = ps.get_message(timeout=0.01)
            except redis.RedisError as e:
                log.warning("redis unavailable: %s", e)
                ps = None
                stop.wait(3)
            if time.monotonic() - last_check >= CHECK_EVERY:
                last_check = time.monotonic()
                for step in (self.poll_router_events, self.check, self.reports):
                    try:
                        step()
                    except Exception:
                        log.exception("%s failed", step.__name__)
                self.publish_status()
            try:
                self.deliver()
            except Exception:
                log.exception("delivery failed")
        log.info("notifier stopped")


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    Notifier().run()
    return 0


__all__ = ["Notifier", "main", "EVENT_TYPES"]
