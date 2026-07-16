from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from issuance.application.canvas_readiness import evaluate_canvas_binding_readiness
from issuance.domain.entities import (
    CanvasEvidenceSyncJob,
    CanvasEvidenceSyncJobStatus,
    CanvasEvidenceSyncTarget,
    CanvasPlatform,
    CanvasProgramBinding,
    CanvasSyncReadinessState,
)
from issuance.infrastructure.adapters.memory_repository import (
    InMemoryIssuanceRepository,
)
from issuance.infrastructure.adapters.postgres_repository import (
    PostgresIssuanceRepository,
)
from sqlalchemy.dialects import postgresql

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)


def _target(
    *,
    organization_id: str = "org-1",
    platform_id: str = "platform-1",
    binding_id: str = "binding-1",
    next_run_at: datetime = NOW + timedelta(minutes=15),
) -> CanvasEvidenceSyncTarget:
    return CanvasEvidenceSyncTarget(
        organization_id=organization_id,
        platform_id=platform_id,
        binding_id=binding_id,
        logical_key=f"target:{organization_id}:{platform_id}:{binding_id}",
        schedule_seconds=15 * 60,
        next_run_at=next_run_at,
    )


@pytest.mark.asyncio
async def test_memory_readiness_state_is_exactly_tenant_platform_binding_scoped() -> None:
    repo = InMemoryIssuanceRepository()
    own = _target()
    foreign_org = _target(organization_id="org-foreign")
    foreign_platform = _target(platform_id="platform-foreign")
    foreign_binding = _target(binding_id="binding-foreign")
    for target in (own, foreign_org, foreign_platform, foreign_binding):
        await repo.save_canvas_sync_target(target)
    for target in (foreign_org, foreign_platform, foreign_binding):
        await repo.save_canvas_sync_job(
            CanvasEvidenceSyncJob(
                organization_id=target.organization_id,
                target_id=target.id,
                status=CanvasEvidenceSyncJobStatus.DEAD_LETTER,
                created_at=NOW - timedelta(days=1),
            )
        )

    state = await repo.get_canvas_sync_readiness_state(
        "org-1",
        "platform-1",
        "binding-1",
        now=NOW,
    )
    assert state == CanvasSyncReadinessState()

    await repo.save_canvas_sync_job(
        CanvasEvidenceSyncJob(
            organization_id=own.organization_id,
            target_id=own.id,
            status=CanvasEvidenceSyncJobStatus.DEAD_LETTER,
            created_at=NOW,
        )
    )
    state = await repo.get_canvas_sync_readiness_state(
        "org-1",
        "platform-1",
        "binding-1",
        now=NOW,
    )
    assert state.dead_lettered is True
    assert state.stale_backlog is False


@pytest.mark.asyncio
async def test_memory_backlog_blocks_only_after_two_target_intervals() -> None:
    repo = InMemoryIssuanceRepository()
    target = _target(next_run_at=NOW - timedelta(minutes=30))
    await repo.save_canvas_sync_target(target)
    job = CanvasEvidenceSyncJob(
        organization_id=target.organization_id,
        target_id=target.id,
        status=CanvasEvidenceSyncJobStatus.QUEUED,
        created_at=NOW - timedelta(minutes=30),
    )
    await repo.save_canvas_sync_job(job)

    at_boundary = await repo.get_canvas_sync_readiness_state(
        target.organization_id,
        target.platform_id,
        target.binding_id,
        now=NOW,
    )
    assert at_boundary.stale_backlog is False

    older = await repo.get_canvas_sync_readiness_state(
        target.organization_id,
        target.platform_id,
        target.binding_id,
        now=NOW + timedelta(microseconds=1),
    )
    assert older.stale_backlog is True


class _Result:
    def __init__(self, row: SimpleNamespace) -> None:
        self._row = row

    def one(self) -> SimpleNamespace:
        return self._row


class _Session:
    def __init__(self, row: SimpleNamespace) -> None:
        self.row = row
        self.statements = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def execute(self, statement):
        self.statements.append(statement)
        return _Result(self.row)


class _SessionFactory:
    def __init__(self, session: _Session) -> None:
        self.session = session

    def __call__(self):
        return self.session


@pytest.mark.asyncio
async def test_postgres_readiness_query_is_scoped_and_returns_sanitized_state() -> None:
    session = _Session(
        SimpleNamespace(
            dead_lettered=True,
            stale_active_job=False,
            stale_due_target=True,
        )
    )
    repo = PostgresIssuanceRepository(_SessionFactory(session))

    state = await repo.get_canvas_sync_readiness_state(
        "org-1",
        "platform-1",
        "binding-1",
        now=NOW,
    )

    assert state == CanvasSyncReadinessState(
        dead_lettered=True,
        stale_backlog=True,
    )
    assert len(session.statements) == 1
    compiled = session.statements[0].compile(dialect=postgresql.dialect())
    sql = str(compiled).lower()
    params = {
        item
        for value in compiled.params.values()
        for item in (value if isinstance(value, list) else [value])
    }
    assert "canvas_evidence_sync_targets.organization_id" in sql
    assert "canvas_evidence_sync_jobs.organization_id" in sql
    assert "canvas_evidence_sync_targets.platform_id" in sql
    assert "canvas_evidence_sync_targets.binding_id" in sql
    assert "extract(epoch from" in sql
    assert "greatest" in sql
    assert {"org-1", "platform-1", "binding-1", "dead_letter"}.issubset(params)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("state", "failed_code", "ready_code"),
    [
        (
            CanvasSyncReadinessState(dead_lettered=True),
            "sync_dead_letter_jobs",
            "sync_backlog_freshness",
        ),
        (
            CanvasSyncReadinessState(stale_backlog=True),
            "sync_backlog_freshness",
            "sync_dead_letter_jobs",
        ),
    ],
)
async def test_composite_readiness_publishes_stable_sanitized_blockers(
    monkeypatch: pytest.MonkeyPatch,
    state: CanvasSyncReadinessState,
    failed_code: str,
    ready_code: str,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
    )
    binding = CanvasProgramBinding(
        id="binding-1",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
    )

    async def readiness_state(*_args, **_kwargs):
        return state

    monkeypatch.setattr(repo, "get_canvas_sync_readiness_state", readiness_state)
    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=None,
        credential_template=None,
        credential_status_profile=None,
        rollout_allowed=True,
        now=NOW,
    )
    by_code = {check.code: check for check in result.checks}

    assert result.ready is False
    assert by_code[failed_code].status == "failed"
    assert by_code[failed_code].blocking is True
    assert by_code[failed_code].remediation
    assert by_code[ready_code].status == "ready"
    assert by_code[ready_code].remediation == ""
    assert set(by_code[failed_code].to_dict()) == {
        "code",
        "component",
        "status",
        "blocking",
        "remediation",
        "timestamp",
    }


@pytest.mark.asyncio
async def test_composite_readiness_fails_closed_when_sync_state_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
    )
    binding = CanvasProgramBinding(
        id="binding-1",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
    )

    async def unavailable(*_args, **_kwargs):
        raise RuntimeError("provider detail must not escape readiness")

    monkeypatch.setattr(repo, "get_canvas_sync_readiness_state", unavailable)
    result = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=None,
        credential_template=None,
        credential_status_profile=None,
        rollout_allowed=True,
        now=NOW,
    )
    by_code = {check.code: check for check in result.checks}

    assert by_code["sync_dead_letter_jobs"].status == "failed"
    assert by_code["sync_backlog_freshness"].status == "failed"
    assert "provider detail" not in str(
        [by_code["sync_dead_letter_jobs"].to_dict(), by_code["sync_backlog_freshness"].to_dict()]
    )
