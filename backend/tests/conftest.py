"""Test fixtures. Requires a disposable PostgreSQL database:

    SHIELD_TEST_DATABASE_URL=postgresql+psycopg://postgres@127.0.0.1/shield_test pytest

The schema is rebuilt with Alembic once per session (so migrations are tested too), and
all tables are truncated between tests.
"""
from __future__ import annotations

import os
import secrets

import pytest
from cryptography.fernet import Fernet

TEST_DB = os.environ.get("SHIELD_TEST_DATABASE_URL")
if not TEST_DB:
    pytest.exit("Set SHIELD_TEST_DATABASE_URL to a disposable PostgreSQL database", returncode=2)

os.environ["SHIELD_DATABASE_URL"] = TEST_DB
os.environ["SHIELD_ENV"] = "test"
os.environ["SHIELD_SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["SHIELD_CREDENTIAL_KEY"] = Fernet.generate_key().decode()

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from app import security  # noqa: E402
from app.db import session_factory  # noqa: E402
from app.models import DEFAULT_SETTINGS, Role, User  # noqa: E402
from app.ratelimit import limiter  # noqa: E402

HERE = os.path.dirname(__file__)
PASSWORD = "Correct-Horse-9-Battery"


@pytest.fixture(scope="session", autouse=True)
def _schema():
    eng = create_engine(TEST_DB)
    with eng.begin() as c:
        c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    cfg = Config(os.path.join(HERE, "..", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(HERE, "..", "migrations"))
    command.upgrade(cfg, "head")
    yield eng


@pytest.fixture(autouse=True)
def _clean(_schema):
    limiter.reset()
    yield
    with _schema.begin() as c:
        tables = [r[0] for r in c.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT IN ('alembic_version','system_settings')"))]
        c.execute(text("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_immutable"))
        c.execute(text("TRUNCATE " + ", ".join(tables) + " RESTART IDENTITY CASCADE"))
        c.execute(text("ALTER TABLE audit_log ENABLE TRIGGER trg_audit_immutable"))
        for k, (v, _) in DEFAULT_SETTINGS.items():
            c.execute(text("UPDATE system_settings SET value = CAST(:v AS jsonb) WHERE key = :k"),
                      {"k": k, "v": __import__("json").dumps(v)})


@pytest.fixture
def db():
    s = session_factory()()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def client():
    from app.main import app
    return TestClient(app)


def make_user(username: str, role: Role, password: str = PASSWORD) -> User:
    with session_factory()() as s, s.begin():
        u = User(username=username, role=role, password_hash=security.hash_password(password))
        s.add(u)
    return u


def login(client, username: str, password: str = PASSWORD, **extra) -> dict:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password, **extra})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def as_role(client):
    """as_role(Role.ADMIN) -> headers dict for a fresh user with that role."""
    counter = {"n": 0}

    def _f(role: Role) -> dict:
        counter["n"] += 1
        name = f"{role.value.replace('_', '')}{counter['n']}"
        make_user(name, role)
        return {"Authorization": f"Bearer {login(client, name)['access_token']}"}

    return _f


@pytest.fixture
def admin(as_role):
    return as_role(Role.ADMIN)


@pytest.fixture
def engineer(as_role):
    return as_role(Role.NETWORK_ENGINEER)
