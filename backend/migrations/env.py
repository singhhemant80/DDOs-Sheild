import os

from alembic import context
from sqlalchemy import create_engine, pool

from app import models  # noqa: F401  (registers tables)
from app.db import Base

target_metadata = Base.metadata


def _url() -> str:
    url = os.environ.get("SHIELD_DATABASE_URL") or context.config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError("Set SHIELD_DATABASE_URL")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
