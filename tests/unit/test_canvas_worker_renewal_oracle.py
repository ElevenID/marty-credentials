"""Observe real worker lease/heartbeat transitions without a live database."""

from __future__ import annotations

import asyncio
import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from issuance import canvas_worker
from issuance.domain.entities import CanvasEvidenceSyncJobStatus, CanvasWorkerHeartbeat
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository

from tests.unit.test_canvas_worker import _config, _worker_target


async def _lease_context(monkeypatch: pytest.MonkeyPatch, *, lease_seconds: int = 60):
    repo = InMemoryIssuanceRepository()
    target = await _worker_target(repo)
    config = replace(_config(), lease_seconds=lease_seconds)
    await repo.enqueue_canvas_sync_job(target)
    leased = await repo.lease_canvas_sync_jobs(
        worker_id=config.worker_id, limit=1, lease_seconds=lease_seconds
    )
    assert len(leased) == 1
    job = copy.deepcopy(leased[0])
    now = datetime.now(UTC) + timedelta(seconds=1)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is UTC
            return now

    sleep = AsyncMock(side_effect=[None, asyncio.CancelledError()])
    # Replace only the worker's reference: do not patch the shared asyncio module.
    monkeypatch.setattr(canvas_worker, "asyncio", SimpleNamespace(sleep=sleep))
    monkeypatch.setattr(canvas_worker, "datetime", Clock)
    save = AsyncMock(wraps=repo.save_canvas_sync_job_if_leased)
    touch = AsyncMock(wraps=repo.touch_canvas_sync_target_worker_heartbeat)
    upsert = AsyncMock(wraps=repo.upsert_canvas_worker_heartbeat)
    monkeypatch.setattr(repo, "save_canvas_sync_job_if_leased", save)
    monkeypatch.setattr(repo, "touch_canvas_sync_target_worker_heartbeat", touch)
    monkeypatch.setattr(repo, "upsert_canvas_worker_heartbeat", upsert)
    return SimpleNamespace(
        repo=repo,
        target=copy.deepcopy(target),
        job=job,
        config=config,
        heartbeat=CanvasWorkerHeartbeat(worker_id=config.worker_id),
        now=now,
        sleep=sleep,
        save=save,
        touch=touch,
        upsert=upsert,
    )


async def _renew(context) -> None:
    await asyncio.wait_for(
        canvas_worker._maintain_job_lease(
            repo=context.repo,
            job=context.job,
            target=context.target,
            config=context.config,
            heartbeat=context.heartbeat,
        ),
        timeout=1,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("lease_seconds", "interval"), [(30, 10.0), (60, 20.0), (90, 30.0), (120, 30.0)]
)
async def test_successful_renewal_updates_detached_lease_and_both_heartbeats(
    lease_seconds: int, interval: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = await _lease_context(monkeypatch, lease_seconds=lease_seconds)
    original = copy.deepcopy(context.job)
    with pytest.raises(asyncio.CancelledError):
        await _renew(context)

    assert [call.args for call in context.sleep.await_args_list] == [(interval,), (interval,)]
    context.save.assert_awaited_once()
    saved = context.save.await_args.args[0]
    assert saved is not context.job
    assert context.save.await_args.kwargs == {"worker_id": context.config.worker_id}
    assert context.job.lease_expires_at == context.now + timedelta(seconds=lease_seconds)
    assert context.job.updated_at == saved.updated_at
    for field in (
        "id",
        "organization_id",
        "target_id",
        "status",
        "attempt_count",
        "lease_owner",
        "started_at",
    ):
        assert getattr(context.job, field) == getattr(original, field)
    persisted = await context.repo.list_canvas_sync_jobs("org-1")
    assert persisted == [context.job]
    context.touch.assert_awaited_once_with(
        organization_id=context.target.organization_id,
        target_id=context.target.id,
        expected_config_version=context.target.config_version,
        worker_id=context.config.worker_id,
        heartbeat_at=context.now,
    )
    context.upsert.assert_awaited_once_with(context.heartbeat)
    assert context.heartbeat.last_heartbeat_at == context.now
    assert context.heartbeat.metadata == {
        "phase": "processing",
        "leased_jobs": 1,
        "process": "standalone",
        "processor_configured": True,
    }
    target = await context.repo.get_canvas_sync_target_for_org("org-1", context.target.id)
    assert target.metadata["worker_id"] == context.config.worker_id
    assert target.metadata["worker_heartbeat_at"] == context.now.isoformat()


@pytest.mark.asyncio
@pytest.mark.parametrize("local_change", ["owner", "status"])
async def test_local_ownership_loss_returns_without_repository_writes(
    local_change: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = await _lease_context(monkeypatch)
    if local_change == "owner":
        context.job.lease_owner = "another-worker"
    else:
        context.job.status = CanvasEvidenceSyncJobStatus.SUCCEEDED
    original = copy.deepcopy(context.job)
    await _renew(context)
    assert context.job == original
    context.sleep.assert_awaited_once_with(20.0)
    context.save.assert_not_awaited()
    context.touch.assert_not_awaited()
    context.upsert.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fence", ["missing", "organization", "owner", "status", "expiry", "attempt"]
)
async def test_repository_fence_loss_does_not_update_detached_state_or_heartbeats(
    fence: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = await _lease_context(monkeypatch)
    stored = copy.deepcopy(context.job)
    if fence == "missing":
        context.job.id = "missing-job"
    elif fence == "organization":
        context.job.organization_id = "other-org"
    else:
        if fence == "owner":
            stored.lease_owner = "another-worker"
        elif fence == "status":
            stored.status = CanvasEvidenceSyncJobStatus.SUCCEEDED
        elif fence == "expiry":
            stored.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        else:
            stored.attempt_count += 1
        await context.repo.save_canvas_sync_job(stored)
    original = copy.deepcopy(context.job)
    durable_before = copy.deepcopy(await context.repo.list_canvas_sync_jobs("org-1"))
    await _renew(context)
    context.sleep.assert_awaited_once_with(20.0)
    context.save.assert_awaited_once()
    context.touch.assert_not_awaited()
    context.upsert.assert_not_awaited()
    assert context.job == original
    assert await context.repo.list_canvas_sync_jobs("org-1") == durable_before


@pytest.mark.asyncio
async def test_cancellation_during_renewal_wait_does_not_attempt_a_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = await _lease_context(monkeypatch)
    context.sleep.side_effect = asyncio.CancelledError()
    original = copy.deepcopy(context.job)
    with pytest.raises(asyncio.CancelledError):
        await _renew(context)
    assert context.job == original
    context.save.assert_not_awaited()
    context.touch.assert_not_awaited()
    context.upsert.assert_not_awaited()


@pytest.mark.asyncio
async def test_repository_error_propagates_without_claiming_renewal_or_liveness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = await _lease_context(monkeypatch)
    context.save.side_effect = RuntimeError("synthetic repository error")
    original = copy.deepcopy(context.job)
    with pytest.raises(RuntimeError, match="synthetic repository error"):
        await _renew(context)
    assert context.job == original
    context.save.assert_awaited_once()
    context.touch.assert_not_awaited()
    context.upsert.assert_not_awaited()


@pytest.mark.asyncio
async def test_target_generation_change_does_not_refresh_that_target_heartbeat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = await _lease_context(monkeypatch)
    changed_target = replace(context.target, config_version=context.target.config_version + 1)
    await context.repo.save_canvas_sync_target(changed_target)
    with pytest.raises(asyncio.CancelledError):
        await _renew(context)
    context.save.assert_awaited_once()
    context.touch.assert_awaited_once()
    context.upsert.assert_awaited_once()
    persisted_target = await context.repo.get_canvas_sync_target_for_org("org-1", context.target.id)
    assert persisted_target.config_version == changed_target.config_version
    assert "worker_heartbeat_at" not in persisted_target.metadata
    assert "worker_id" not in persisted_target.metadata
    # Legacy renewal continues and marks process liveness even when the target
    # heartbeat CAS rejects the old generation. This is not Rust cutover approval.
    assert context.job.lease_expires_at == context.now + timedelta(seconds=60)


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_write", ["target", "process"])
async def test_heartbeat_error_preserves_already_committed_lease_and_propagates(
    failed_write: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = await _lease_context(monkeypatch)
    heartbeat_before = copy.deepcopy(context.heartbeat)
    writer = context.touch if failed_write == "target" else context.upsert
    writer.side_effect = RuntimeError("synthetic heartbeat write error")
    with pytest.raises(RuntimeError, match="synthetic heartbeat write error"):
        await _renew(context)
    context.save.assert_awaited_once()
    context.touch.assert_awaited_once()
    assert context.job.lease_expires_at == context.now + timedelta(seconds=60)
    assert await context.repo.list_canvas_sync_jobs("org-1") == [context.job]
    target = await context.repo.get_canvas_sync_target_for_org("org-1", context.target.id)
    if failed_write == "target":
        context.upsert.assert_not_awaited()
        assert context.heartbeat == heartbeat_before
        assert "worker_heartbeat_at" not in target.metadata
    else:
        context.upsert.assert_awaited_once()
        assert target.metadata["worker_heartbeat_at"] == context.now.isoformat()
        # Local heartbeat mutation precedes persistence; a failed write must not
        # be mistaken for durable process-liveness evidence by a Rust port.
        assert context.heartbeat.last_heartbeat_at == context.now
