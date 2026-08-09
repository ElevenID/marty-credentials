from __future__ import annotations

import sys
import types
from pathlib import Path

from sqlalchemy import MetaData

ROOT = Path(__file__).resolve().parents[2]


def _load_module(monkeypatch):
    migration = types.ModuleType("mmf.framework.infrastructure.migration")
    migration.AlembicMigrationAdapter = object
    migration.MigrationError = RuntimeError
    monkeypatch.setitem(sys.modules, "mmf", types.ModuleType("mmf"))
    monkeypatch.setitem(sys.modules, "mmf.framework", types.ModuleType("mmf.framework"))
    monkeypatch.setitem(
        sys.modules,
        "mmf.framework.infrastructure",
        types.ModuleType("mmf.framework.infrastructure"),
    )
    monkeypatch.setitem(sys.modules, "mmf.framework.infrastructure.migration", migration)

    models = types.ModuleType("services.issuance.infrastructure.models")
    models.mapper_registry = types.SimpleNamespace(metadata=MetaData())
    monkeypatch.setitem(sys.modules, "services.issuance.infrastructure.models", models)

    sys.path.insert(0, str(ROOT))
    try:
        sys.modules.pop("services.issuance.manage_migrations", None)
        from services.issuance import manage_migrations

        return manage_migrations
    finally:
        sys.path.pop(0)


def test_upgrade_bootstraps_version_table_schema_before_alembic(monkeypatch) -> None:
    module = _load_module(monkeypatch)
    calls: list[str] = []

    class Connection:
        def execute(self, statement) -> None:
            calls.append(str(statement))

    class Begin:
        def __enter__(self):
            return Connection()

        def __exit__(self, *_args) -> None:
            return None

    class Engine:
        def begin(self):
            return Begin()

        def dispose(self) -> None:
            calls.append("dispose")

    class Adapter:
        def upgrade(self, revision: str) -> None:
            calls.append(f"upgrade:{revision}")

    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://marty:test@postgres/marty")
    monkeypatch.setattr(module, "create_engine", lambda url: calls.append(url) or Engine())
    monkeypatch.setattr(module, "get_migration_adapter", lambda: Adapter())

    module.upgrade()

    assert calls == [
        "postgresql://marty:test@postgres/marty",
        "CREATE SCHEMA IF NOT EXISTS issuance_service",
        "dispose",
        "upgrade:head",
    ]
