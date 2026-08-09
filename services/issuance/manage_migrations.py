"""
Issuance Service Migration Management

This module provides migration management for the issuance service using
the MMF framework's migration infrastructure.
"""

import os
import sys
from pathlib import Path

from mmf.framework.infrastructure.migration import (
    AlembicMigrationAdapter,
    MigrationError,
)
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from services.issuance.infrastructure.models import mapper_registry

service_root = Path(__file__).parent
metadata = mapper_registry.metadata
ISSUANCE_SCHEMA = "issuance_service"


def _sync_database_url() -> str:
    """Return the configured database URL using Alembic's sync driver."""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is required")
    return database_url.replace("+asyncpg", "")


def ensure_issuance_schema() -> None:
    """Create Alembic's version-table schema before the first revision.

    Alembic creates its version table before executing the initial revision.
    Because that version table is scoped to ``issuance_service``, a new Marty
    database must create this service-owned schema at the migration boundary
    after the platform migrations have installed shared prerequisite schemas.
    The initial revision retains its idempotent schema creation for backwards
    compatibility with existing databases.
    """
    engine = create_engine(_sync_database_url())
    try:
        with engine.begin() as connection:
            connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {ISSUANCE_SCHEMA}"))
    finally:
        engine.dispose()


def get_migration_adapter() -> AlembicMigrationAdapter:
    """Create and return configured migration adapter."""
    from alembic.config import Config

    sync_url = _sync_database_url()

    adapter = AlembicMigrationAdapter(
        database_url=sync_url,
        metadata=metadata,
    )

    # Configure the adapter to use existing migration infrastructure
    # (matches the pattern in run_all_migrations.py)
    migrations_dir = service_root / "infrastructure" / "migrations"
    adapter._service_name = "issuance"
    adapter._migrations_dir = migrations_dir

    alembic_ini_path = migrations_dir / "alembic.ini"
    adapter.alembic_cfg = Config(str(alembic_ini_path))
    adapter.alembic_cfg.set_main_option("script_location", str(migrations_dir))
    adapter.alembic_cfg.set_main_option("sqlalchemy.url", sync_url)
    adapter.alembic_cfg.attributes["target_metadata"] = metadata

    return adapter


def upgrade() -> None:
    """Run all pending migrations."""
    try:
        ensure_issuance_schema()
        adapter = get_migration_adapter()
        adapter.upgrade("head")
        print("✓ Issuance service migrations completed")
    except (MigrationError, SQLAlchemyError) as e:
        print(f"✗ Migration failed: {e}")
        sys.exit(1)


def downgrade(revision: str = "-1") -> None:
    """Rollback to a specific revision."""
    try:
        adapter = get_migration_adapter()
        adapter.downgrade(revision)
        print(f"✓ Rolled back to {revision}")
    except MigrationError as e:
        print(f"✗ Rollback failed: {e}")
        sys.exit(1)


def current() -> None:
    """Show current revision."""
    try:
        adapter = get_migration_adapter()
        rev = adapter.current()
        print(f"Current revision: {rev or 'None'}")
    except MigrationError as e:
        print(f"✗ Failed to get current revision: {e}")
        sys.exit(1)


def history() -> None:
    """Show migration history."""
    try:
        adapter = get_migration_adapter()
        revisions = adapter.history(verbose=True)
        for rev in revisions:
            print(f"  {rev}")
    except MigrationError as e:
        print(f"✗ Failed to get history: {e}")
        sys.exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Manage issuance service migrations")
    parser.add_argument(
        "command",
        choices=["upgrade", "downgrade", "current", "history"],
        help="Migration command to execute",
    )
    parser.add_argument(
        "--revision",
        default="-1",
        help="Revision for downgrade (default: -1)",
    )

    args = parser.parse_args()

    if args.command == "upgrade":
        upgrade()
    elif args.command == "downgrade":
        downgrade(args.revision)
    elif args.command == "current":
        current()
    elif args.command == "history":
        history()
