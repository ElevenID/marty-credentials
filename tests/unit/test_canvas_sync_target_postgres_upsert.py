from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from issuance.domain.entities import CanvasEvidenceSyncTarget
from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository


class _ReturningResult:
    def __init__(self, row) -> None:
        self._row = row

    def first(self):
        return self._row


class _FakeSession:
    def __init__(self, row) -> None:
        self.row = row
        self.statements = []
        self.committed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def execute(self, statement):
        self.statements.append(statement)
        return _ReturningResult(self.row)

    async def commit(self) -> None:
        self.committed = True


class _FakeSessionFactory:
    def __init__(self, session: _FakeSession) -> None:
        self.session = session

    def __call__(self):
        return self.session


class _NoopTransaction:
    async def __aenter__(self):
        return None

    async def __aexit__(self, *_args):
        return None


class _SequencedFakeSession(_FakeSession):
    def __init__(self, rows) -> None:
        super().__init__(None)
        self.rows = list(rows)

    def begin(self):
        return _NoopTransaction()

    async def execute(self, statement):
        self.statements.append(statement)
        return _ReturningResult(self.rows.pop(0))


def _updated_columns(statement) -> set[str]:
    return {
        getattr(column, "key", str(column))
        for column in statement._values
    }


@pytest.mark.asyncio
async def test_target_upsert_returns_canonical_id_before_job_enqueue() -> None:
    canonical_created_at = datetime(2026, 7, 14, tzinfo=UTC)
    session = _FakeSession(
        SimpleNamespace(id="canonical-target-id", created_at=canonical_created_at)
    )
    repo = PostgresIssuanceRepository(_FakeSessionFactory(session))
    raced_target = CanvasEvidenceSyncTarget(
        id="losing-concurrent-id",
        organization_id="org-1",
        platform_id="platform-1",
        binding_id="binding-1",
        logical_key="application:application-1",
        application_id="application-1",
    )

    await repo.save_canvas_sync_target(raced_target)

    assert session.committed
    assert len(session.statements) == 1
    assert raced_target.id == "canonical-target-id"
    assert raced_target.created_at == canonical_created_at


@pytest.mark.asyncio
async def test_postgres_target_heartbeat_updates_only_operational_metadata() -> None:
    heartbeat_at = datetime(2026, 7, 15, tzinfo=UTC)
    session = _SequencedFakeSession(
        [
            SimpleNamespace(metadata={"configuration_marker": "keep"}),
            SimpleNamespace(id="target-1"),
        ]
    )
    repo = PostgresIssuanceRepository(_FakeSessionFactory(session))

    assert await repo.touch_canvas_sync_target_worker_heartbeat(
        organization_id="org-1",
        target_id="target-1",
        expected_config_version=7,
        worker_id="worker-1",
        heartbeat_at=heartbeat_at,
    )

    assert len(session.statements) == 2
    update_statement = session.statements[1]
    assert _updated_columns(update_statement) == {"metadata", "updated_at"}
    compiled = str(update_statement)
    assert "config_version" in compiled
    assert "enabled" in compiled
    metadata = update_statement.compile().params["metadata"]
    assert metadata == {
        "configuration_marker": "keep",
        "worker_id": "worker-1",
        "worker_heartbeat_at": heartbeat_at.isoformat(),
    }


@pytest.mark.asyncio
async def test_postgres_target_success_marker_cannot_write_configuration_fields() -> None:
    succeeded_at = datetime(2026, 7, 15, 1, tzinfo=UTC)
    session = _SequencedFakeSession([SimpleNamespace(id="target-1")])
    repo = PostgresIssuanceRepository(_FakeSessionFactory(session))

    assert await repo.mark_canvas_sync_target_succeeded(
        organization_id="org-1",
        target_id="target-1",
        expected_config_version=7,
        succeeded_at=succeeded_at,
    )

    assert session.committed
    assert len(session.statements) == 1
    update_statement = session.statements[0]
    assert _updated_columns(update_statement) == {"last_succeeded_at", "updated_at"}
    compiled = str(update_statement)
    assert "config_version" in compiled
    assert "enabled" in compiled
