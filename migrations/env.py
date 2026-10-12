"""Alembic migration environment using the configured PostgreSQL URL."""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from aegis.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata
database_url = os.environ.get("AEGIS_DATABASE_URL")
if not database_url or not database_url.startswith("postgresql+psycopg://"):
    raise ValueError("AEGIS_DATABASE_URL must use postgresql+psycopg")


def run_migrations_offline() -> None:
    context.configure(
        url=database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
