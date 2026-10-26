"""Administrative CLI.

  python -m app.cli create-admin --username admin
  python -m app.cli reset-password --username admin [--generate]
  python -m app.cli seed --file ../config/network.example.yaml [--allow-lab-ranges]
  python -m app.cli purge-retention
  python -m app.cli verify-audit
  python -m app.cli update-asn [--url URL]
"""
from __future__ import annotations

import argparse
import getpass
import sys
from datetime import UTC, datetime, timedelta

import yaml
from sqlalchemy import delete, func, select

from . import audit, netvalidate as nv, security
from .changes import get_setting, record_change
from .db import session_factory
from .models import (
    AuthSession, BgpNeighbor, FlowSummary, LoginAttempt, Notification, ProtectedPrefix, Role, Router, SystemHealth,
    UpstreamProvider, UpstreamRtbhPolicy, User,
)

CLI = audit.Actor(None, "cli")


def create_admin(args) -> int:
    if args.if_none:
        with session_factory()() as db:
            if db.execute(select(func.count()).select_from(User)).scalar_one() > 0:
                print("Users already exist; no administrator created.")
                return 0
    if args.password_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = args.password or getpass.getpass("Password: ")
        if not args.password and pw != getpass.getpass("Repeat: "):
            print("Passwords do not match", file=sys.stderr)
            return 1
    problems = security.password_problems(pw, args.username)
    if problems:
        print("Password " + "; ".join(problems), file=sys.stderr)
        return 1
    with session_factory()() as db, db.begin():
        if db.execute(select(User).where(func.lower(User.username) == args.username.lower())).first():
            print(f"User {args.username} already exists", file=sys.stderr)
            return 1
        u = User(username=args.username, role=Role.ADMIN, password_hash=security.hash_password(pw),
                 email=args.email)
        db.add(u)
        record_change(db, CLI, "user.create", "user", u, note="created via CLI")
    print(f"Administrator {args.username} created.")
    return 0


def reset_password(args) -> int:
    """Set a user's password from the server (root shell only: it reads the database credentials).
    Signs the user out everywhere and clears any lockout. MFA stays as it was unless --clear-mfa."""
    if args.generate:
        import secrets
        pw = f"Sh-{secrets.token_hex(9)}-{secrets.token_hex(3)}"
    elif args.password_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("New password: ")
        if pw != getpass.getpass("Repeat: "):
            print("Passwords do not match", file=sys.stderr)
            return 1
    problems = security.password_problems(pw, args.username)
    if problems:
        print("Password " + "; ".join(problems), file=sys.stderr)
        return 1
    with session_factory()() as db, db.begin():
        u = db.execute(select(User).where(func.lower(User.username) == args.username.lower())).scalar_one_or_none()
        if u is None:
            print(f"No user {args.username}", file=sys.stderr)
            return 1
        now = datetime.now(UTC)
        u.password_hash = security.hash_password(pw)
        u.password_changed_at = now
        u.failed_login_count = 0
        u.locked_until = None
        u.is_active = True
        if args.clear_mfa:
            u.mfa_enabled, u.mfa_secret_enc = False, None
        for sess in db.execute(select(AuthSession).where(AuthSession.user_id == u.id,
                                                         AuthSession.revoked_at.is_(None))).scalars():
            sess.revoked_at, sess.revoke_reason = now, "password_reset_cli"
        audit.record(db, CLI, "user.password_reset", "user", u.id,
                     after={"username": u.username, "mfa_cleared": bool(args.clear_mfa)})
    if args.generate:
        print(f"New password for {args.username}: {pw}")
    else:
        print(f"Password for {args.username} changed.")
    print("All of this user's sessions were signed out.")
    return 0


def seed(args) -> int:
    """Load inventory from YAML. Idempotent: existing names/prefixes are skipped, never overwritten.
    Mitigation flags are always seeded as disabled; enable them deliberately via the API."""
    with open(args.file) as f:
        cfg = yaml.safe_load(f)
    created = 0
    with session_factory()() as db, db.begin():
        routers = {}
        for r in cfg.get("routers", []):
            obj = db.execute(select(Router).where(Router.name == r["name"])).scalar_one_or_none()
            if obj is None:
                obj = Router(name=r["name"], model=r["model"], role=r.get("role", "primary"),
                             mgmt_address=r["mgmt_address"], api_port=r.get("api_port", 8729),
                             access_mode="read_only", dry_run=True, notes=r.get("notes"))
                db.add(obj)
                record_change(db, CLI, "router.create", "router", obj, note="seed")
                created += 1
            routers[r["name"]] = obj
        db.flush()
        upstreams = {}
        for u in cfg.get("upstreams", []):
            obj = db.execute(select(UpstreamProvider).where(UpstreamProvider.name == u["name"])).scalar_one_or_none()
            if obj is None:
                nv.validate_asn(u["asn"])
                obj = UpstreamProvider(
                    name=u["name"], asn=u["asn"], description=u.get("description"),
                    router_id=routers[u["router"]].id if u.get("router") else None,
                    interface_name=u.get("interface"), capacity_mbps=u.get("capacity_mbps"),
                    ddos_protected=u.get("ddos_protected", False))
                db.add(obj)
                db.flush()
                record_change(db, CLI, "upstream.create", "upstream", obj, note="seed")
                created += 1
                pol = u.get("rtbh_policy")
                if pol:
                    p = UpstreamRtbhPolicy(
                        upstream_id=obj.id, enabled=False,
                        communities=[nv.normalise_community(c) for c in pol.get("communities", [])],
                        next_hop=pol.get("next_hop"), min_prefix_len=pol.get("min_prefix_len", 32),
                        max_prefix_len=pol.get("max_prefix_len", 32), max_routes=pol.get("max_routes", 10),
                        documentation_ref=pol.get("documentation_ref"))
                    db.add(p)
                    record_change(db, CLI, "rtbh_policy.put", "upstream_rtbh_policy", p, note="seed (disabled, unverified)")
            upstreams[u["name"]] = obj
        db.flush()
        local_asn = cfg.get("local_asn")
        for n in cfg.get("bgp_neighbors", []):
            if db.execute(select(BgpNeighbor).where(BgpNeighbor.name == n["name"])).first():
                continue
            obj = BgpNeighbor(
                name=n["name"], router_id=routers[n["router"]].id if n.get("router") else None,
                upstream_id=upstreams[n["upstream"]].id if n.get("upstream") else None,
                purpose=n["purpose"], local_asn=n.get("local_asn", local_asn), remote_asn=n["remote_asn"],
                neighbor_address=n["neighbor_address"], local_address=n.get("local_address"),
                max_prefix_out=n.get("max_prefix_out"), managed_by_shield=n.get("managed_by_shield", False))
            db.add(obj)
            record_change(db, CLI, "bgp_neighbor.create", "bgp_neighbor", obj, note="seed")
            created += 1
        for p in cfg.get("protected_prefixes", []):
            net = nv.validate_public_prefix(p["prefix"], allow_lab_ranges=args.allow_lab_ranges)
            if db.execute(select(ProtectedPrefix).where(ProtectedPrefix.prefix == str(net))).first():
                continue
            obj = ProtectedPrefix(prefix=str(net), description=p.get("description"),
                                  ownership_evidence=p.get("ownership_evidence"),
                                  min_mitigation_prefix_len=net.max_prefixlen)
            db.add(obj)
            record_change(db, CLI, "prefix.create", "protected_prefix", obj, note="seed (mitigation disabled)")
            created += 1
    print(f"Seed complete: {created} objects created. Mitigation flags and RTBH policies are DISABLED; "
          "verify ownership and upstream documentation, then enable via the API.")
    return 0


def purge_retention(_args) -> int:
    with session_factory()() as db, db.begin():
        now = datetime.now(UTC)
        plan = [
            (FlowSummary, FlowSummary.bucket_start, "retention_flow_summaries_days", 30),
            (LoginAttempt, LoginAttempt.at, "retention_login_attempts_days", 180),
            (SystemHealth, SystemHealth.checked_at, "retention_system_health_days", 30),
            (Notification, Notification.created_at, "retention_notifications_days", 90),
        ]
        for model, col, key, default in plan:
            days = int(get_setting(db, key, default))
            n = db.execute(delete(model).where(col < now - timedelta(days=days))).rowcount
            print(f"{model.__tablename__}: deleted {n} rows older than {days} days")
    return 0


def verify_audit(_args) -> int:
    with session_factory()() as db:
        r = audit.verify_chain(db)
    print(f"ok={r.ok} checked={r.checked} head={r.head_hash} first_bad_id={r.first_bad_id} reason={r.reason}")
    return 0 if r.ok else 2


def update_asn(args) -> int:
    from . import asn
    try:
        n = asn.update(url=args.url)
    except Exception as e:  # network, HTTP, bad file: keep the current table
        print(f"ASN table not updated: {e}", file=sys.stderr)
        return 1
    print(f"ASN table updated: {n} ranges")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="shield")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("create-admin")
    a.add_argument("--username", required=True)
    a.add_argument("--email")
    a.add_argument("--password", help="non-interactive (avoid: ends up in shell history)")
    a.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    a.add_argument("--if-none", action="store_true", help="do nothing if any user already exists")
    a.set_defaults(fn=create_admin)
    r = sub.add_parser("reset-password", help="set a user's password from the server console")
    r.add_argument("--username", required=True)
    g = r.add_mutually_exclusive_group()
    g.add_argument("--generate", action="store_true", help="generate a strong password and print it")
    g.add_argument("--password-stdin", action="store_true")
    r.add_argument("--clear-mfa", action="store_true", help="also remove two-factor (lost authenticator)")
    r.set_defaults(fn=reset_password)
    s = sub.add_parser("seed")
    s.add_argument("--file", required=True)
    s.add_argument("--allow-lab-ranges", action="store_true", help="permit documentation/private ranges (lab only)")
    s.set_defaults(fn=seed)
    sub.add_parser("purge-retention").set_defaults(fn=purge_retention)
    sub.add_parser("verify-audit").set_defaults(fn=verify_audit)
    u = sub.add_parser("update-asn", help="download the IP-to-ASN table used to name attack sources")
    u.add_argument("--url", help="download from this URL instead of the configured one")
    u.set_defaults(fn=update_asn)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
