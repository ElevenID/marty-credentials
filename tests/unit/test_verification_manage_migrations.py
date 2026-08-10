from __future__ import annotations

from unittest.mock import MagicMock

from alembic.script import ScriptDirectory
from verification import manage_migrations


def test_sync_database_url_uses_psycopg_driver(monkeypatch) -> None:
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:secret@postgres/marty_credentials",
    )

    assert manage_migrations._sync_database_url() == (
        "postgresql+psycopg://marty:secret@postgres/marty_credentials"
    )


def test_upgrade_bootstraps_version_schema_before_alembic(monkeypatch) -> None:
    calls: list[str] = []
    engine = MagicMock()
    connection = MagicMock()
    engine.begin.return_value.__enter__.return_value = connection
    monkeypatch.setenv("DATABASE_URL", "postgresql://marty:secret@postgres/marty_credentials")
    monkeypatch.setattr(
        manage_migrations,
        "create_engine",
        lambda url: calls.append(url) or engine,
    )
    monkeypatch.setattr(
        manage_migrations.command,
        "upgrade",
        lambda _config, revision: calls.append(f"upgrade:{revision}"),
    )

    manage_migrations.upgrade()

    assert calls == [
        "postgresql+psycopg://marty:secret@postgres/marty_credentials",
        "upgrade:head",
    ]
    assert str(connection.execute.call_args.args[0]) == (
        "CREATE SCHEMA IF NOT EXISTS verification_service"
    )
    engine.dispose.assert_called_once_with()


def test_verification_migration_graph_has_exactly_one_head() -> None:
    config = manage_migrations.get_config("postgresql+psycopg://unused/unused")

    assert ScriptDirectory.from_config(config).get_heads() == ["202608091200"]
