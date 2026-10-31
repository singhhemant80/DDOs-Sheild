"""Production readiness and hardening checks (Phase 10).

Everything here only reads: the database, Shield's own settings and a few files the installer and
the backup job write. Each check says ok / warn / problem / unknown and how to fix it."""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit
from .changes import get_setting
from .config import get_settings
from .models import NotificationChannel, Role, Router, RouterState, User

ETC = os.environ.get("SHIELD_ETC", "/etc/crapplet-shield")
STATE = os.environ.get("SHIELD_STATE_DIR", "/var/lib/crapplet-shield")


def _c(out, area, key, level, title, fix=None, detail=None):
    out.append({"area": area, "key": key, "level": level, "title": title, "fix": fix, "detail": detail})


def checks(db: Session) -> list[dict]:
    out: list[dict] = []
    s = get_settings()
    now = datetime.now(UTC)

    # --- accounts ------------------------------------------------------------------------
    admins = db.execute(select(User).where(User.role == Role.ADMIN, User.is_active)).scalars().all()
    no_mfa = [u.username for u in admins if not u.mfa_enabled]
    _c(out, "Accounts", "admin_mfa", "problem" if no_mfa else "ok",
       f"Administrators without two-factor: {', '.join(no_mfa)}" if no_mfa else "Every administrator uses two-factor",
       "Settings → My account → Set up two-factor, for each administrator." if no_mfa else None)
    for key, label in (("require_mfa_for_admin", "Two-factor required for administrator logins"),
                       ("require_mfa_for_mitigation", "Two-factor required to approve mitigations")):
        on = bool(get_setting(db, key, False))
        _c(out, "Accounts", key, "ok" if on else "warn", label + (" (on)" if on else " (off)"),
           None if on else f"Settings → {key} → on (after every administrator has set up two-factor).")
    if any(u.username == "admin" for u in admins):
        _c(out, "Accounts", "admin_name", "warn", "An administrator is called 'admin'",
           "Create a named administrator for each person and disable the shared 'admin' account.")
    n_users = db.execute(select(func.count()).select_from(User).where(User.is_active)).scalar_one()
    if len(admins) == n_users and n_users > 1:
        _c(out, "Accounts", "least_privilege", "warn", "Every user is an administrator",
           "Give NOC staff the NOC operator role and engineers the network engineer role.")

    # --- dashboard exposure ------------------------------------------------------------------
    try:
        nets = open(os.path.join(ETC, "mgmt-nets")).read().split()
        open_all = any(n in ("0.0.0.0/0", "::/0") for n in nets)
        _c(out, "Exposure", "mgmt_nets", "warn" if open_all else "ok",
           "The dashboard is reachable from anywhere" if open_all else f"Dashboard limited to {', '.join(nets)}",
           "Reinstall with SHIELD_MGMT_NETS=\"<your office/VPN ranges>\" when you can; until then keep two-factor "
           "required for everyone." if open_all else None)
    except OSError:
        _c(out, "Exposure", "mgmt_nets", "unknown", "Cannot read the dashboard allow-list", None)
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(open(os.path.join(ETC, "tls", "shield.crt"), "rb").read())
        self_signed = cert.issuer == cert.subject
        days = (cert.not_valid_after_utc - now).days
        lvl = "problem" if days < 7 else ("warn" if self_signed or days < 30 else "ok")
        _c(out, "Exposure", "tls_cert", lvl,
           ("Self-signed HTTPS certificate" if self_signed else "HTTPS certificate from a CA") + f", expires in {days} days",
           "Use a certificate from a CA (e.g. Let's Encrypt) for the dashboard's name: replace "
           f"{ETC}/tls/shield.crt and shield.key and reload nginx." if lvl != "ok" else None)
    except (OSError, ValueError):
        _c(out, "Exposure", "tls_cert", "unknown", "Cannot read the HTTPS certificate", None)
    _c(out, "Exposure", "api_docs", "warn" if s.docs_enabled else "ok",
       "API documentation pages are served" if s.docs_enabled else "API documentation pages are off",
       "Set SHIELD_ENV=production in shield.env." if s.docs_enabled else None)

    # --- secrets and data --------------------------------------------------------------------
    _c(out, "Data", "credential_key", "ok" if s.credential_key else "problem",
       "Router and provider credentials are encrypted" if s.credential_key else "SHIELD_CREDENTIAL_KEY is not set",
       None if s.credential_key else "Set SHIELD_CREDENTIAL_KEY in shield.env (the installer does this).")
    _c(out, "Data", "clickhouse_auth", "ok" if s.clickhouse_password else "warn",
       "ClickHouse requires a password" if s.clickhouse_password else "ClickHouse is used without a password",
       None if s.clickhouse_password else "Re-run the installer; it creates Shield's ClickHouse login.")
    try:
        rep = audit.verify_chain(db)
        ok = getattr(rep, "ok", None)
        _c(out, "Data", "audit_chain", "ok" if ok else "problem",
           "Audit log hash chain intact" if ok else "Audit log hash chain is broken",
           None if ok else "Investigate: python -m app.cli verify-audit shows where the chain breaks.")
    except Exception as e:
        _c(out, "Data", "audit_chain", "unknown", f"Audit chain not checked ({type(e).__name__})")
    try:
        b = json.load(open(os.path.join(STATE, "last-backup")))
        at = datetime.fromisoformat(b["at"].replace("Z", "+00:00"))
        age = now - at
        _c(out, "Data", "backup", "ok" if age < timedelta(hours=36) else "problem",
           f"Last database backup {int(age.total_seconds() // 3600)} h ago ({b.get('file')})",
           None if age < timedelta(hours=36) else "Check: systemctl status shield-backup.service; "
           "copy backups off the server as well.")
    except (OSError, ValueError, KeyError):
        _c(out, "Data", "backup", "warn", "No database backup recorded yet",
           "The nightly backup (shield-backup.timer) records it here; run it once: systemctl start shield-backup. "
           "Keep copies off the server too.")

    # --- routers -----------------------------------------------------------------------------
    for r, st in db.execute(select(Router, RouterState).outerjoin(RouterState, RouterState.router_id == Router.id)
                            .where(Router.enabled)).all():
        perms = (st.permissions or {}) if st else {}
        if perms.get("write_policies"):
            _c(out, "Routers", f"ro_{r.id}", "problem", f"{r.name}: the polling account can change the router",
               "Put it in a group with only read,api,test (deploy/mikrotik/shield-readonly.rsc).")
        elif st is not None and st.ok:
            _c(out, "Routers", f"ro_{r.id}", "ok", f"{r.name}: polling account is read-only")
        if r.filter_password_enc and not r.tls_fingerprint and not r.verify_tls:
            _c(out, "Routers", f"tls_{r.id}", "problem", f"{r.name}: write access without a verified or pinned certificate",
               "Pin the router's certificate (router page → Get certificate).")

    # --- operations --------------------------------------------------------------------------
    chans = db.execute(select(NotificationChannel).where(NotificationChannel.enabled)).scalars().all()
    _c(out, "Operations", "alerts", "ok" if chans else "problem",
       f"{len(chans)} alert channel(s) enabled" if chans else "No alert channel: nobody is told about attacks",
       None if chans else "Alerts → Add channel (e-mail, Telegram or webhook), then Send test.")
    if chans and not any(c.escalate_after_seconds for c in chans):
        _c(out, "Operations", "escalation", "warn", "No channel escalates unacknowledged attacks",
           "Alerts → edit a channel (e.g. the on-call phone) → Escalate after 10 minutes.")
    if not get_setting(db, "dashboard_url", ""):
        _c(out, "Operations", "dashboard_url", "warn", "Alerts carry no link to the dashboard",
           "Settings → dashboard_url = https://<your Shield address>")
    if get_setting(db, "rtbh_emergency_disable", False):
        _c(out, "Operations", "emergency", "warn", "The emergency stop is on: new blackholes are blocked",
           "Settings → Automatic mitigation → Turn on, once the cause is understood.")
    sim = [k for k in ("bgp_speaker", "filter_backend", "steering_backend", "scrubbing_backend")
           if get_setting(db, k, "simulated") == "simulated"]
    _c(out, "Operations", "simulation", "warn" if len(sim) == 4 else "ok",
       "Every mitigation runs in simulation" if len(sim) == 4 else
       ("Real mitigation enabled" + (f"; still simulated: {', '.join(sim)}" if sim else "")),
       "Follow docs/production.md to go live with at least one method." if len(sim) == 4 else None)
    return out


def summary(items: list[dict]) -> dict:
    c = {k: sum(1 for i in items if i["level"] == k) for k in ("ok", "warn", "problem", "unknown")}
    return {"counts": c, "ready": c["problem"] == 0}
