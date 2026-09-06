"""Observe real worker error branches; never log exception objects or tracebacks."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import replace

import httpx
import pytest
from issuance import canvas_worker
from issuance.domain.entities import CanvasEvidenceSyncJobStatus
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository

from tests.unit.test_canvas_worker import _config, _pending_oauth_revocation, _worker_target

SENTINEL = "synthetic-access-token-provider-body-do-not-log"


@pytest.fixture(autouse=True)
def _enable_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")


def _assert_private_record(
    caplog: pytest.LogCaptureFixture, event: str, exception_class: str, **identifiers: str
) -> None:
    records = [
        record for record in caplog.records
        if record.name == canvas_worker.__name__ and record.levelno == logging.ERROR
    ]
    assert len(records) == 1
    record = records[0]
    assert record.exc_info is None
    assert record.exc_text is None
    assert record.stack_info is None
    assert not record.args
    assert SENTINEL not in caplog.text
    assert SENTINEL not in repr(vars(record))
    standard = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}
    structured = {key: value for key, value in vars(record).items() if key not in standard}
    assert structured == {"event": event, "exception_class": exception_class, **identifiers}
    rendered = json.loads(logging.Formatter().format(record))
    messages = {
        "canvas_oauth_disconnect_marker_failed": "Canvas OAuth platform disconnect marker failed",
        "canvas_sync_job_failed": "Canvas sync job failed",
        "canvas_sync_job_outcome_failed": "Canvas sync job escaped outcome handling",
        "canvas_sync_cycle_failed": "Canvas synchronization worker cycle failed",
    }
    assert rendered == {"message": messages[event], **structured}


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [None, 429, 503])
async def test_unexpected_processing_error_is_private_and_keeps_retry_semantics(
    status: int | None, caplog: pytest.LogCaptureFixture
) -> None:
    repo = InMemoryIssuanceRepository()
    target = await _worker_target(repo)
    error: Exception = RuntimeError(SENTINEL)
    if status is not None:
        request = httpx.Request("GET", f"https://canvas.example.invalid/{SENTINEL}")
        response = httpx.Response(status, request=request, text=SENTINEL)
        error = httpx.HTTPStatusError(SENTINEL, request=request, response=response)

    async def processor(_repo, _target):
        raise error

    result = await canvas_worker.run_canvas_sync_worker_cycle(
        repo=repo, config=_config(), processor=processor,
    )
    assert (result.succeeded, result.retried, result.dead_lettered) == (0, 1, 0)
    job = (await repo.list_canvas_sync_jobs("org-1"))[0]
    assert job.status == CanvasEvidenceSyncJobStatus.RETRY
    assert job.attempt_count == 1
    assert job.last_error_code == (
        "canvas_rate_limited" if status == 429 else "canvas_sync_unexpected_error"
    )
    assert job.last_error_summary == f"Canvas synchronization failed ({type(error).__name__})"
    assert job.result == {}
    assert job.lease_owner is None
    assert target.enabled
    _assert_private_record(caplog, "canvas_sync_job_failed", type(error).__name__, job_id=job.id)


@pytest.mark.asyncio
async def test_disconnect_marker_error_keeps_remote_revoke_and_local_cleanup(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = InMemoryIssuanceRepository()
    connection = await _pending_oauth_revocation(repo)
    revoked: list[str] = []

    async def revoker(**kwargs):
        revoked.append(kwargs["access_token"])

    async def fail_marker(*_args, **_kwargs):
        raise RuntimeError(SENTINEL)

    monkeypatch.setattr(repo, "patch_canvas_platform_connection_config", fail_marker)
    result = await canvas_worker.process_canvas_oauth_revocation_retries(
        repo=repo, config=_config(), revoker=revoker,
    )
    assert result == (1, 0)
    assert revoked == ["access-token-value"]
    assert await repo.get_canvas_oauth_connection("org-1", connection.platform_id) is None
    for secret in ["access-secret-1", "refresh-secret-1"]:
        assert await repo.get_integration_secret_value("org-1", secret) is None
    _assert_private_record(
        caplog, "canvas_oauth_disconnect_marker_failed", "RuntimeError",
        organization_id="org-1", platform_id=connection.platform_id,
    )


@pytest.mark.asyncio
async def test_escaped_job_error_is_private_and_does_not_cancel_successful_sibling(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = InMemoryIssuanceRepository()
    failing = await _worker_target(repo)
    await _worker_target(repo, suffix="-sibling")
    read_target = repo.get_canvas_sync_target_for_org

    async def read_or_fail(organization_id, target_id):
        if target_id == failing.id:
            raise RuntimeError(SENTINEL)
        return await read_target(organization_id, target_id)

    async def processor(_repo, _target):
        return {"facts_changed": 1}

    monkeypatch.setattr(repo, "get_canvas_sync_target_for_org", read_or_fail)
    result = await canvas_worker.run_canvas_sync_worker_cycle(
        repo=repo, config=_config(), processor=processor,
    )
    assert (result.leased, result.succeeded, result.retried, result.dead_lettered) == (2, 1, 0, 0)
    jobs = {job.target_id: job for job in await repo.list_canvas_sync_jobs("org-1")}
    assert jobs[failing.id].status == CanvasEvidenceSyncJobStatus.LEASED
    assert jobs[failing.id].lease_owner == _config().worker_id
    _assert_private_record(
        caplog, "canvas_sync_job_outcome_failed", "RuntimeError", job_id=jobs[failing.id].id,
    )


@pytest.mark.asyncio
async def test_cycle_failure_is_private_and_next_real_cycle_reaches_idle(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = InMemoryIssuanceRepository()
    stop = asyncio.Event()
    list_due = repo.list_canvas_oauth_revocation_retries
    attempts = 0

    async def fail_once(**kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError(SENTINEL)
        stop.set()
        return await list_due(**kwargs)

    monkeypatch.setattr(repo, "list_canvas_oauth_revocation_retries", fail_once)
    await asyncio.wait_for(
        canvas_worker.run_canvas_sync_worker_loop(
            repo=repo, config=replace(_config(), poll_seconds=0.001), stop_event=stop,
        ),
        timeout=2,
    )
    assert attempts == 2
    heartbeat = await repo.get_fresh_canvas_worker_heartbeat(role="canvas_sync", max_age_seconds=120)
    assert heartbeat is not None
    assert heartbeat.metadata["phase"] == "idle"
    _assert_private_record(caplog, "canvas_sync_cycle_failed", "RuntimeError")
