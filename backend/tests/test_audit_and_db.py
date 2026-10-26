"""Audit chain integrity and database-level safety constraints (defence in depth below the API)."""
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, InternalError

from app import audit
from app.models import ActionState, MitigationAction, ProtectedPrefix, Strategy


def test_changes_are_audited_and_chain_verifies(client, engineer):
    client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24"}, headers=engineer)
    client.post("/api/v1/prefixes", json={"prefix": "77.107.95.0/24"}, headers=engineer)
    rows = client.get("/api/v1/audit", params={"action": "prefix.create"}, headers=engineer).json()
    assert len(rows) == 2 and rows[0]["after"]["prefix"] == "77.107.95.0/24"
    v = client.get("/api/v1/audit/verify", headers=engineer).json()
    assert v["ok"] and v["checked"] == 3  # 1 login + 2 creates


def test_audit_rows_cannot_be_modified(db, client, engineer):
    client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24"}, headers=engineer)
    with pytest.raises((InternalError, DBAPIError)):
        db.execute(text("UPDATE audit_log SET actor_username='mallory'"))
    db.rollback()
    with pytest.raises((InternalError, DBAPIError)):
        db.execute(text("DELETE FROM audit_log"))


def test_tampering_is_detected(db, client, engineer, _schema):
    client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24"}, headers=engineer)
    with _schema.begin() as c:  # simulate a DB superuser bypassing the trigger
        c.execute(text("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_immutable"))
        c.execute(text("UPDATE audit_log SET actor_username='mallory' WHERE action='prefix.create'"))
        c.execute(text("ALTER TABLE audit_log ENABLE TRIGGER trg_audit_immutable"))
    r = audit.verify_chain(db)
    assert not r.ok and r.reason == "entry content does not match its hash"


# ---------------------------------------------------------------- mitigation targets (acceptance)
def _pp(db, prefix="163.5.191.0/24", **kw):
    pp = ProtectedPrefix(prefix=prefix, ownership_verified=True, ownership_evidence="test",
                         rtbh_allowed=True, min_mitigation_prefix_len=32, **kw)
    db.add(pp)
    db.flush()
    return pp


def _action(pp, target, **kw):
    kw.setdefault("state", ActionState.PROPOSED)
    return MitigationAction(idempotency_key=str(uuid.uuid4()), strategy=Strategy.RTBH_INTERNAL, target=target,
                            protected_prefix_id=pp.id, **kw)


def test_db_rejects_mitigation_outside_protected_prefix(db):
    pp = _pp(db)
    db.add(_action(pp, "77.107.95.10/32"))
    with pytest.raises(DBAPIError) as e:
        db.flush()
    assert "not inside" in str(e.value)


def test_db_rejects_mitigation_broader_than_allowed(db):
    pp = _pp(db)
    db.add(_action(pp, "163.5.191.0/24"))
    with pytest.raises(DBAPIError) as e:
        db.flush()
    assert "broader than allowed" in str(e.value)


def test_db_rejects_mitigation_on_disabled_prefix(db):
    pp = _pp(db, enabled=False)
    db.add(_action(pp, "163.5.191.9/32"))
    with pytest.raises(DBAPIError):
        db.flush()


def test_db_allows_host_route_and_blocks_duplicate_live_action(db):
    pp = _pp(db)
    db.add(_action(pp, "163.5.191.9/32"))
    db.flush()
    db.add(_action(pp, "163.5.191.9/32"))
    with pytest.raises(IntegrityError):
        db.flush()


def test_db_rejects_unapproved_manual_action_in_approved_state(db):
    pp = _pp(db)
    db.add(_action(pp, "163.5.191.9/32", state=ActionState.APPROVED))
    with pytest.raises(IntegrityError):
        db.flush()


def test_db_rejects_mitigation_flags_without_ownership(db):
    db.add(ProtectedPrefix(prefix="163.5.191.0/24", rtbh_allowed=True))
    with pytest.raises(IntegrityError):
        db.flush()


def test_db_rejects_enabling_unverified_rtbh_policy(db):
    from app.models import UpstreamProvider, UpstreamRtbhPolicy
    u = UpstreamProvider(name="A", asn=174)
    db.add(u)
    db.flush()
    db.add(UpstreamRtbhPolicy(upstream_id=u.id, enabled=True, communities=["174:666"]))
    with pytest.raises(IntegrityError):
        db.flush()


def test_health_endpoints(client, engineer):
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    d = client.get("/api/v1/health/details", headers=engineer).json()
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    import os
    here = os.path.dirname(__file__)
    cfg = Config(os.path.join(here, "..", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(here, "..", "migrations"))
    assert d["schema_revision"] == ScriptDirectory.from_config(cfg).get_current_head()
    assert d["automation_enabled"] is False


def test_cli_reset_password(capsys):
    from app import cli
    from app.db import session_factory
    from app.models import AuditLog, Role, User
    from sqlalchemy import select
    from tests.conftest import make_user
    make_user("opsadmin", Role.ADMIN)
    with session_factory()() as db, db.begin():
        u = db.execute(select(User).where(User.username == "opsadmin")).scalar_one()
        u.failed_login_count, u.mfa_enabled = 7, True
    assert cli.main(["reset-password", "--username", "opsadmin", "--generate", "--clear-mfa"]) == 0
    pw = capsys.readouterr().out.split("opsadmin: ")[1].split()[0]
    with session_factory()() as db:
        u = db.execute(select(User).where(User.username == "opsadmin")).scalar_one()
        from app import security
        assert security.verify_password(u.password_hash, pw) and u.failed_login_count == 0 and not u.mfa_enabled
        assert db.execute(select(AuditLog).where(AuditLog.action == "user.password_reset")).first()
    assert cli.main(["reset-password", "--username", "nobody", "--generate"]) == 1
