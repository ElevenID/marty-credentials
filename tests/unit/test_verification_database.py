from __future__ import annotations

import pytest
from verification.infrastructure.persistence import database
from verification.infrastructure.persistence.postgres_repository import (
    VerificationSessionModel,
)


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="DATABASE_URL environment variable is required"):
        database._database_url()


@pytest.mark.parametrize(
    "configured,expected_driver",
    [
        ("postgresql://user:secret@db:5432/verification", "postgresql+asyncpg"),
        ("postgresql+psycopg://user:secret@db/verification", "postgresql+asyncpg"),
        ("postgresql+asyncpg://user:secret@db/verification", "postgresql+asyncpg"),
        ("sqlite+aiosqlite:///verification.db", "sqlite+aiosqlite"),
    ],
)
def test_database_url_selects_an_async_driver(
    monkeypatch: pytest.MonkeyPatch,
    configured: str,
    expected_driver: str,
) -> None:
    monkeypatch.setenv("DATABASE_URL", configured)

    assert database._database_url().drivername == expected_driver


def test_verification_model_uses_service_owned_metadata() -> None:
    assert VerificationSessionModel.metadata is database.Base.metadata
