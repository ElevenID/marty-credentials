"""Manage verification service database migrations."""

import argparse
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

MIGRATIONS_DIR = Path(__file__).parent / "infrastructure" / "migrations"
VERSION_SCHEMA = "verification_service"


def _sync_database_url() -> str:
    value = os.environ.get("DATABASE_URL")
    if not value:
        raise RuntimeError("DATABASE_URL environment variable is required")
    url = make_url(value)
    if url.get_backend_name() == "postgresql":
        url = url.set(drivername="postgresql+psycopg")
    return url.render_as_string(hide_password=False)


def ensure_version_schema(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {VERSION_SCHEMA}"))
    finally:
        engine.dispose()


def get_config(database_url: str) -> Config:
    config = Config(str(MIGRATIONS_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    # Revisions are reviewed, hand-authored DDL; the migration job does not
    # need to import the application ORM or the microservices framework.
    config.attributes["target_metadata"] = None
    return config


def upgrade() -> None:
    database_url = _sync_database_url()
    ensure_version_schema(database_url)
    command.upgrade(get_config(database_url), "head")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("upgrade", "current", "history"))
    args = parser.parse_args()
    database_url = _sync_database_url()
    config = get_config(database_url)
    if args.command == "upgrade":
        ensure_version_schema(database_url)
        command.upgrade(config, "head")
    elif args.command == "current":
        command.current(config)
    else:
        command.history(config, verbose=True)


if __name__ == "__main__":
    main()
