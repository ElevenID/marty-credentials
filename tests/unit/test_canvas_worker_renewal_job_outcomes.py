"""Freeze real legacy job outcomes after the independent maintainer fails."""

from __future__ import annotations

import asyncio
import copy
import json
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import DEFAULT, AsyncMock

import pytest
from issuance import canvas_worker
from issuance.application.canvas_sync_service import CanvasSyncProcessingError
from issuance.domain.entities import CanvasWorkerHeartbeat
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository

from tests.unit.test_canvas_worker import _config, _worker_target

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2] / "contracts/canvas-worker-renewal-job-outcomes.json"
    ).read_text(encoding="utf-8")
)


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_write", FIXTURE["renewal_failures"])
@pytest.mark.parametrize("fence", FIXTURE["durable_fences_before_processor_exit"])
@pytest.mark.parametrize("outcome", FIXTURE["processor_outcomes"], ids=lambda case: case["name"])
async def test_renewal_error_is_observed_after_processor_outcome_persistence(
    failed_write: str, fence: str, outcome: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")
    repo = InMemoryIssuanceRepository()
    target = await _worker_target(repo)
    config = replace(_config(), job_timeout_seconds=0.5 if outcome["name"] == "deadline" else 10)
    await repo.enqueue_canvas_sync_job(target)
    jobs = await repo.lease_canvas_sync_jobs(
        worker_id=config.worker_id, limit=1, lease_seconds=config.lease_seconds
    )
    assert len(jobs) == 1
    job = copy.deepcopy(jobs[0])
    entered, release, cleaned, renew = (asyncio.Event() for _ in range(4))
    failed = asyncio.Event()
    failure = RuntimeError("synthetic renewal failure")

    async def processor(_repo, _target):
        entered.set()
        try:
            await release.wait()
            if outcome["name"] in ("retry", "terminal"):
                raise CanvasSyncProcessingError(
                    outcome["error_code"],
                    "Synthetic processing failure",
                    retryable=outcome["name"] == "retry",
                )
            return {"facts_changed": 1}
        finally:
            cleaned.set()

    async def renewal_wait(interval):
        assert interval == 20
        await renew.wait()

    # Only this module's sleep reference changes; actual timeout/task APIs and
    # the global asyncio module remain intact. No job/maintainer implementation
    # is replaced. The controlled sleep is released only after processing starts.
    worker_asyncio = SimpleNamespace(**vars(asyncio))
    worker_asyncio.sleep = renewal_wait
    monkeypatch.setattr(canvas_worker, "asyncio", worker_asyncio)
    method = {
        "lease": "save_canvas_sync_job_if_leased",
        "target": "touch_canvas_sync_target_worker_heartbeat",
        "process": "upsert_canvas_worker_heartbeat",
    }[failed_write]

    def fail_once_after_processing_starts(*_args, **_kwargs):
        if entered.is_set() and not failed.is_set():
            failed.set()
            raise failure
        # Initial heartbeat and later fenced outcome writes use the real repo.
        return DEFAULT

    monkeypatch.setattr(
        repo,
        method,
        AsyncMock(wraps=getattr(repo, method), side_effect=fail_once_after_processing_starts),
    )
    prior_tasks = asyncio.all_tasks()
    task = asyncio.create_task(
        canvas_worker._process_leased_job(
            repo=repo,
            job=job,
            heartbeat=CanvasWorkerHeartbeat(worker_id=config.worker_id),
            config=config,
            processor=processor,
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        maintainers = [
            owned
            for owned in asyncio.all_tasks() - prior_tasks
            if owned.get_coro().__name__ == "_maintain_job_lease"
        ]
        assert len(maintainers) == 1
        renew.set()
        # Awaiting the actual child observes its error without cancelling or
        # replacing the still-pending job handler. Its later await raises again.
        with pytest.raises(RuntimeError) as renewal_error:
            await asyncio.wait_for(asyncio.shield(maintainers[0]), timeout=1)
        assert renewal_error.value is failure
        assert failed.is_set()
        assert {
            "processor_still_active": not cleaned.is_set(),
            "job_handler_still_pending": not task.done(),
            "durable_job_status": (await repo.list_canvas_sync_jobs("org-1"))[0].status.value,
        } == FIXTURE["after_renewal_error"]

        if fence != "unchanged":
            durable = copy.deepcopy((await repo.list_canvas_sync_jobs("org-1"))[0])
            if fence == "owner":
                durable.lease_owner = "another-worker"
            elif fence == "expiry":
                durable.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            elif fence == "attempt":
                durable.attempt_count += 1
            else:
                pytest.fail(f"unobserved durable fence: {fence}")
            await repo.save_canvas_sync_job(durable)

        if outcome["name"] == "cancel":
            task.cancel()
        elif outcome["name"] != "deadline":
            release.set()
        with pytest.raises(RuntimeError) as escaped:
            await asyncio.wait_for(task, timeout=2)
        assert escaped.value is failure, "cleanup re-raises the original renewal exception"
        assert FIXTURE["handler_exit_after_processor_termination"] == "renewal_exception"
        assert cleaned.is_set() is FIXTURE["processor_cleanup_acknowledged"]
        persisted = await repo.list_canvas_sync_jobs("org-1")
        assert len(persisted) == 1
        expected = outcome if fence == "unchanged" else FIXTURE["fenced_outcome"]
        assert persisted[0].status.value == expected["durable_status"]
        assert (persisted[0].completed_at is not None) is expected["completed"]
        assert persisted[0].last_error_code == expected["error_code"]
        if fence != "unchanged":
            assert persisted == [durable], (
                "stale processor outcomes must not overwrite a newer lease"
            )
        assert all(maintainer.done() for maintainer in maintainers)
        assert not (asyncio.all_tasks() - prior_tasks), "no owned task escapes the observation"
    finally:
        if not task.done():
            task.cancel()
        # Retrieve even an unexpectedly early exception; failed observations
        # must not leave an unacknowledged owned task behind.
        with suppress(asyncio.CancelledError, RuntimeError):
            await asyncio.wait_for(task, timeout=1)
