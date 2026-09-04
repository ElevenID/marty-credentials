"""Exercise actual legacy worker lifecycle boundaries without a live database."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from issuance import canvas_worker
from issuance.domain.entities import CanvasEvidenceSyncJobStatus
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository

from tests.unit.test_canvas_worker import _config, _worker_target


@asynccontextmanager
async def _owned_loop(**arguments):
    task = asyncio.create_task(canvas_worker.run_canvas_sync_worker_loop(**arguments))
    try:
        yield task
    finally:
        if not task.done():
            task.cancel()
            with suppress(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=1)


class _ObservedStopEvent(asyncio.Event):
    def __init__(self) -> None:
        super().__init__()
        self.poll_started = asyncio.Event()

    async def wait(self) -> bool:
        self.poll_started.set()
        return await super().wait()


@pytest.mark.asyncio
async def test_stop_before_loop_starts_no_new_cycle(monkeypatch: pytest.MonkeyPatch) -> None:
    stop = asyncio.Event()
    stop.set()
    cycle = AsyncMock()
    monkeypatch.setattr(canvas_worker, "run_canvas_sync_worker_cycle", cycle)

    await asyncio.wait_for(
        canvas_worker.run_canvas_sync_worker_loop(repo=Mock(), config=_config(), stop_event=stop),
        timeout=1,
    )
    cycle.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("termination", ["stop", "cancel"])
async def test_poll_wait_is_interruptible_and_never_starts_a_later_cycle(
    termination: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = _ObservedStopEvent()
    cycle = AsyncMock()
    monkeypatch.setattr(canvas_worker, "run_canvas_sync_worker_cycle", cycle)

    async with _owned_loop(
        repo=Mock(), config=replace(_config(), poll_seconds=60), stop_event=stop
    ) as task:
        await asyncio.wait_for(stop.poll_started.wait(), timeout=1)
        if termination == "stop":
            stop.set()
            await asyncio.wait_for(task, timeout=1)
        else:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=1)
    cycle.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("first_cycle_fails", [False, True])
async def test_poll_timeout_and_cycle_failure_continue_with_the_same_worker_identity(
    first_cycle_fails: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = asyncio.Event()
    observations: list[dict] = []
    repo = Mock()
    config = replace(_config(), poll_seconds=0.01)
    processor = AsyncMock()

    async def cycle(**arguments):
        observations.append(arguments)
        if len(observations) == 1:
            if first_cycle_fails:
                raise RuntimeError("synthetic cycle failure")
        else:
            stop.set()

    monkeypatch.setattr(canvas_worker, "run_canvas_sync_worker_cycle", cycle)
    async with _owned_loop(repo=repo, config=config, processor=processor, stop_event=stop) as task:
        await asyncio.wait_for(task, timeout=1)

    assert len(observations) == 2
    for observed in observations:
        assert observed["repo"] is repo
        assert observed["config"] is config
        assert observed["processor"] is processor
        assert observed["heartbeat"].worker_id == config.worker_id
    assert observations[0]["heartbeat"] is observations[1]["heartbeat"]
    processor.assert_not_called()


@pytest.mark.asyncio
async def test_external_cancellation_awaits_active_cycle_cleanup_and_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()
    cleaned = asyncio.Event()

    async def cycle(**_arguments):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    wrapped = AsyncMock(side_effect=cycle)
    monkeypatch.setattr(canvas_worker, "run_canvas_sync_worker_cycle", wrapped)
    async with _owned_loop(repo=Mock(), config=_config()) as task:
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)
    assert cleaned.is_set()
    wrapped.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["return", "error", "cancel"])
async def test_initialized_main_always_awaits_engine_disposal_after_loop_exit(
    outcome: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from issuance.infrastructure.adapters import postgres_repository
    from sqlalchemy.ext import asyncio as sqlalchemy_async

    events: list[str] = []
    engine = SimpleNamespace(dispose=AsyncMock(side_effect=lambda: events.append("dispose")))
    session_factory = Mock()
    repository = Mock()
    create_engine = Mock(return_value=engine)
    create_sessions = Mock(return_value=session_factory)
    create_repository = Mock(return_value=repository)
    monkeypatch.setattr(sqlalchemy_async, "create_async_engine", create_engine)
    monkeypatch.setattr(sqlalchemy_async, "async_sessionmaker", create_sessions)
    monkeypatch.setattr(postgres_repository, "PostgresIssuanceRepository", create_repository)
    monkeypatch.setenv("DATABASE_URL", "postgresql://oracle:synthetic@unused.invalid/oracle")
    monkeypatch.setenv("CANVAS_SYNC_WORKER_ID", "lifecycle-oracle")
    monkeypatch.delenv("CANVAS_SYNC_PROCESSOR", raising=False)
    for name in (
        "CANVAS_SYNC_WORKER_BATCH_SIZE",
        "CANVAS_SYNC_WORKER_LEASE_SECONDS",
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS",
        "CANVAS_SYNC_SCHEDULE_LIMIT",
        "CANVAS_OAUTH_REVOCATION_BATCH_SIZE",
        "CANVAS_SYNC_WORKER_POLL_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)

    async def loop(**arguments):
        assert arguments["repo"] is repository
        assert arguments["config"].worker_id == "lifecycle-oracle"
        assert arguments["processor"] is None
        events.append("loop")
        if outcome == "error":
            raise RuntimeError("synthetic loop failure")
        if outcome == "cancel":
            raise asyncio.CancelledError

    monkeypatch.setattr(canvas_worker, "run_canvas_sync_worker_loop", loop)
    if outcome == "return":
        await asyncio.wait_for(canvas_worker._main(), timeout=1)
    else:
        error_type = RuntimeError if outcome == "error" else asyncio.CancelledError
        with pytest.raises(error_type):
            await asyncio.wait_for(canvas_worker._main(), timeout=1)
    assert events == ["loop", "dispose"]
    engine.dispose.assert_awaited_once()
    create_engine.assert_called_once_with(
        "postgresql+asyncpg://oracle:synthetic@unused.invalid/oracle",
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        hide_parameters=True,
    )
    create_sessions.assert_called_once_with(engine, expire_on_commit=False)
    create_repository.assert_called_once_with(session_factory)


@pytest.mark.asyncio
async def test_real_cycle_cancellation_joins_processor_and_lease_renewal_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")
    repo = InMemoryIssuanceRepository()
    await _worker_target(repo)
    entered = asyncio.Event()
    cleaned = asyncio.Event()

    async def processor(_repo, _target):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    existing_tasks = asyncio.all_tasks()
    task = asyncio.create_task(
        canvas_worker.run_canvas_sync_worker_cycle(
            repo=repo,
            config=_config(),
            processor=processor,
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        renewal_tasks = [
            pending
            for pending in asyncio.all_tasks() - existing_tasks
            if pending.get_coro().__name__ == "_maintain_job_lease"
        ]
        assert len(renewal_tasks) == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)
        assert cleaned.is_set()
        assert all(renewal.done() for renewal in renewal_tasks)
        assert not (asyncio.all_tasks() - existing_tasks)
        jobs = await repo.list_canvas_sync_jobs("org-1")
        assert len(jobs) == 1
        assert jobs[0].status == CanvasEvidenceSyncJobStatus.LEASED
    finally:
        if not task.done():
            task.cancel()
            with suppress(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=1)
