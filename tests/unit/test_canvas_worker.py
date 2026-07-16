from __future__ import annotations

import asyncio
import copy
from datetime import UTC, datetime, timedelta

import pytest
from issuance.application.canvas_oauth import CanvasOAuthError
from issuance.application.canvas_sync_jobs import (
    CanvasSyncLeaseLostError,
    complete_canvas_sync_job,
)
from issuance.application.canvas_sync_service import CanvasSyncProcessingError
from issuance.canvas_worker import (
    CanvasSyncWorkerConfig,
    process_canvas_oauth_revocation_retries,
    run_canvas_sync_worker_cycle,
)
from issuance.domain.entities import (
    Application,
    CanvasEvidenceSyncJobStatus,
    CanvasEvidenceSyncTarget,
    CanvasEvidenceSyncTargetType,
    CanvasOAuthConnection,
    CanvasOAuthConnectionStatus,
    CanvasPlatform,
    CanvasProgramBinding,
    OrganizationIntegrationSecret,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository


@pytest.fixture(autouse=True)
def _enable_canvas_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")


async def _worker_target(
    repo: InMemoryIssuanceRepository,
    *,
    metadata: dict | None = None,
    suffix: str = "",
) -> CanvasEvidenceSyncTarget:
    platform = CanvasPlatform(
        id=f"platform-1{suffix}",
        organization_id="org-1",
        canvas_account_id=f"account-1{suffix}",
        enabled=True,
    )
    binding = CanvasProgramBinding(
        id=f"binding-1{suffix}",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id="template-1",
        credential_template_id="credential-template-1",
        enabled=True,
    )
    app = Application(
        id=f"application-1{suffix}",
        organization_id="org-1",
        application_template_id="template-1",
    )
    target = CanvasEvidenceSyncTarget(
        organization_id="org-1",
        platform_id=platform.id,
        binding_id=binding.id,
        target_type=CanvasEvidenceSyncTargetType.LEARNER_APPLICATION,
        logical_key=f"application:{app.id}",
        application_id=app.id,
        next_run_at=datetime.now(UTC) - timedelta(seconds=1),
        metadata=dict(metadata or {}),
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    await repo.save_application(app)
    await repo.save_canvas_sync_target(target)
    return target


def _config(worker_id: str = "canvas-worker-1") -> CanvasSyncWorkerConfig:
    return CanvasSyncWorkerConfig(
        worker_id=worker_id,
        batch_size=10,
        lease_seconds=60,
        schedule_limit=100,
        poll_seconds=0.1,
    )


@pytest.mark.asyncio
async def test_worker_schedules_leases_completes_and_heartbeats() -> None:
    repo = InMemoryIssuanceRepository()
    target = await _worker_target(repo)

    async def processor(_repo, processed_target):
        assert processed_target.id == target.id
        return {
            "application_id": target.application_id,
            "config_version": target.config_version,
            "facts_changed": 2,
            "provider_payload": {"must": "not be persisted"},
        }

    result = await run_canvas_sync_worker_cycle(
        repo=repo,
        config=_config(),
        processor=processor,
    )

    assert result.scheduled == 1
    assert result.leased == 1
    assert result.succeeded == 1
    jobs = await repo.list_canvas_sync_jobs("org-1")
    assert len(jobs) == 1
    assert jobs[0].status == CanvasEvidenceSyncJobStatus.SUCCEEDED
    assert jobs[0].result == {
        "application_id": target.application_id,
        "config_version": target.config_version,
        "facts_changed": 2,
    }
    assert target.last_succeeded_at is not None
    assert target.metadata["worker_id"] == "canvas-worker-1"
    heartbeat = await repo.get_fresh_canvas_worker_heartbeat(
        role="canvas_sync",
        max_age_seconds=120,
    )
    assert heartbeat is not None
    assert heartbeat.worker_id == "canvas-worker-1"
    assert heartbeat.metadata["process"] == "standalone"
    assert heartbeat.metadata["processor_configured"] is True


@pytest.mark.asyncio
async def test_worker_starts_every_job_before_a_later_batch_lease_can_expire() -> None:
    repo = InMemoryIssuanceRepository()
    await _worker_target(repo)
    await _worker_target(repo, suffix="-2")
    started: set[str] = set()
    all_started = asyncio.Event()

    async def processor(_repo, processed_target):
        started.add(processed_target.id)
        if len(started) == 2:
            all_started.set()
        await asyncio.wait_for(all_started.wait(), timeout=1)
        return {"facts_changed": 1}

    result = await asyncio.wait_for(
        run_canvas_sync_worker_cycle(
            repo=repo,
            config=_config(),
            processor=processor,
        ),
        timeout=2,
    )

    assert len(started) == 2
    assert result.leased == 2
    assert result.succeeded == 2


@pytest.mark.asyncio
async def test_reclaimed_lease_fences_stale_worker_completion() -> None:
    repo = InMemoryIssuanceRepository()
    target = await _worker_target(repo)
    await repo.enqueue_canvas_sync_job(target)
    worker_a_job = (await repo.lease_canvas_sync_jobs(worker_id="worker-a"))[0]
    stale_worker_a_job = copy.deepcopy(worker_a_job)

    # Simulate worker A pausing past expiry and worker B reclaiming the job.
    worker_a_job.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert await repo.lease_canvas_sync_jobs(worker_id="worker-b") == []
    worker_a_job.available_at = datetime.now(UTC) - timedelta(seconds=1)
    worker_b_job = (await repo.lease_canvas_sync_jobs(worker_id="worker-b"))[0]
    assert worker_b_job.attempt_count == 2

    with pytest.raises(CanvasSyncLeaseLostError):
        await complete_canvas_sync_job(
            repo=repo,
            job=stale_worker_a_job,
            worker_id="worker-a",
            target_config_version=target.config_version,
            result={"facts_changed": 1},
        )

    current = await repo.get_canvas_sync_job_for_org("org-1", worker_b_job.id)
    assert current is not None
    assert current.status == CanvasEvidenceSyncJobStatus.LEASED
    assert current.lease_owner == "worker-b"
    assert current.attempt_count == 2


@pytest.mark.asyncio
async def test_target_operational_updates_cannot_overwrite_concurrent_configuration() -> None:
    repo = InMemoryIssuanceRepository()
    target = await _worker_target(repo)
    target.metadata = {"configuration_marker": "version-1"}
    await repo.save_canvas_sync_target(target)
    await repo.enqueue_canvas_sync_job(target)
    leased = (await repo.lease_canvas_sync_jobs(worker_id="worker-a"))[0]
    stale_config_version = target.config_version

    concurrent = copy.deepcopy(target)
    concurrent.config_version = stale_config_version + 1
    concurrent.enabled = False
    concurrent.schedule_seconds = 1800
    concurrent.metadata = {"configuration_marker": "version-2"}
    await repo.save_canvas_sync_target(concurrent)

    heartbeat_written = await repo.touch_canvas_sync_target_worker_heartbeat(
        organization_id=target.organization_id,
        target_id=target.id,
        expected_config_version=stale_config_version,
        worker_id="worker-a",
        heartbeat_at=datetime.now(UTC),
    )
    assert heartbeat_written is False

    completed = await complete_canvas_sync_job(
        repo=repo,
        job=leased,
        worker_id="worker-a",
        target_config_version=stale_config_version,
        result={"facts_changed": 1},
    )
    assert completed.status == CanvasEvidenceSyncJobStatus.SUCCEEDED
    stored = await repo.get_canvas_sync_target_for_org(target.organization_id, target.id)
    assert stored is not None
    assert stored.config_version == stale_config_version + 1
    assert stored.enabled is False
    assert stored.schedule_seconds == 1800
    assert stored.metadata == {"configuration_marker": "version-2"}
    assert stored.last_succeeded_at is None


@pytest.mark.asyncio
async def test_worker_honors_retry_after_without_persisting_provider_error() -> None:
    repo = InMemoryIssuanceRepository()
    await _worker_target(repo)
    before = datetime.now(UTC)

    async def processor(_repo, _target):
        raise CanvasSyncProcessingError(
            "canvas_rate_limited",
            "Canvas asked the worker to retry",
            retry_after_seconds=120,
        )

    result = await run_canvas_sync_worker_cycle(
        repo=repo,
        config=_config(),
        processor=processor,
    )

    assert result.retried == 1
    job = (await repo.list_canvas_sync_jobs("org-1"))[0]
    assert job.status == CanvasEvidenceSyncJobStatus.RETRY
    assert job.available_at >= before + timedelta(seconds=119)
    assert job.last_error_code == "canvas_rate_limited"
    assert job.last_error_summary == "Canvas asked the worker to retry"


@pytest.mark.asyncio
async def test_worker_bounds_entire_target_processing_with_wall_clock_deadline() -> None:
    repo = InMemoryIssuanceRepository()
    await _worker_target(repo)
    processor_cancelled = asyncio.Event()

    async def processor(_repo, _target):
        try:
            await asyncio.Event().wait()
        finally:
            processor_cancelled.set()

    config = CanvasSyncWorkerConfig(
        worker_id="canvas-worker-deadline",
        batch_size=1,
        lease_seconds=60,
        job_timeout_seconds=0.01,
        schedule_limit=1,
        poll_seconds=0.1,
    )
    result = await asyncio.wait_for(
        run_canvas_sync_worker_cycle(
            repo=repo,
            config=config,
            processor=processor,
        ),
        timeout=1,
    )

    assert processor_cancelled.is_set()
    assert result.retried == 1
    job = (await repo.list_canvas_sync_jobs("org-1"))[0]
    assert job.status == CanvasEvidenceSyncJobStatus.RETRY
    assert job.last_error_code == "canvas_sync_deadline_exceeded"


@pytest.mark.asyncio
async def test_worker_dead_letters_non_retryable_target_and_never_signs() -> None:
    repo = InMemoryIssuanceRepository()
    await _worker_target(repo, metadata={"refresh_token": "prohibited"})
    processor_called = False

    async def processor(_repo, _target):
        nonlocal processor_called
        processor_called = True
        return {"credential_id": "must-never-exist"}

    result = await run_canvas_sync_worker_cycle(
        repo=repo,
        config=_config(),
        processor=processor,
    )

    assert not processor_called
    assert result.dead_lettered == 1
    job = (await repo.list_canvas_sync_jobs("org-1"))[0]
    assert job.status == CanvasEvidenceSyncJobStatus.DEAD_LETTER
    assert job.last_error_code == "canvas_sync_target_contains_secret"


@pytest.mark.asyncio
async def test_worker_dead_letters_processor_signing_outcome() -> None:
    repo = InMemoryIssuanceRepository()
    await _worker_target(repo)

    async def processor(_repo, _target):
        return {"issued_credential_id": "credential-1"}

    result = await run_canvas_sync_worker_cycle(
        repo=repo,
        config=_config(),
        processor=processor,
    )
    assert result.dead_lettered == 1
    job = (await repo.list_canvas_sync_jobs("org-1"))[0]
    assert job.last_error_code == "canvas_background_signing_forbidden"


async def _pending_oauth_revocation(repo: InMemoryIssuanceRepository) -> CanvasOAuthConnection:
    platform = CanvasPlatform(
        id="oauth-platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
        connection_config={"oauth_status": "revocation_pending"},
    )
    access = OrganizationIntegrationSecret(
        id="access-secret-1",
        organization_id="org-1",
        name="Canvas OAuth access token",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value="access-token-value",
    )
    refresh = OrganizationIntegrationSecret(
        id="refresh-secret-1",
        organization_id="org-1",
        name="Canvas OAuth refresh token",
        provider="canvas",
        purpose="oauth_refresh_token",
        secret_value="refresh-token-value",
    )
    connection = CanvasOAuthConnection(
        id="oauth-connection-1",
        organization_id="org-1",
        platform_id=platform.id,
        canvas_base_url=str(platform.canvas_base_url),
        platform_config_version=platform.config_version,
        access_token_secret_ref=access.secret_ref,
        refresh_token_secret_ref=refresh.secret_ref,
        status=CanvasOAuthConnectionStatus.REVOCATION_PENDING,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_integration_secret(access)
    await repo.save_integration_secret(refresh)
    await repo.save_canvas_oauth_connection(connection)
    return connection


@pytest.mark.asyncio
async def test_worker_revokes_remote_oauth_before_deleting_local_material() -> None:
    repo = InMemoryIssuanceRepository()
    connection = await _pending_oauth_revocation(repo)
    calls: list[tuple[str, str]] = []

    async def revoker(*, client, canvas_base_url, access_token):
        assert client.follow_redirects is False
        calls.append((canvas_base_url, access_token))

    succeeded, retried = await process_canvas_oauth_revocation_retries(
        repo=repo,
        config=_config(),
        revoker=revoker,
    )

    assert (succeeded, retried) == (1, 0)
    assert calls == [("https://canvas.example.edu", "access-token-value")]
    assert await repo.get_canvas_oauth_connection("org-1", connection.platform_id) is None
    assert await repo.get_integration_secret_value("org-1", "access-secret-1") is None
    assert await repo.get_integration_secret_value("org-1", "refresh-secret-1") is None
    platform = await repo.get_canvas_platform_for_org("org-1", connection.platform_id)
    assert platform is not None
    assert platform.connection_config["oauth_status"] == "disconnected"


@pytest.mark.asyncio
async def test_worker_reschedules_failed_oauth_revocation_and_keeps_tokens() -> None:
    repo = InMemoryIssuanceRepository()
    connection = await _pending_oauth_revocation(repo)

    async def revoker(**_kwargs):
        raise CanvasOAuthError("Canvas OAuth token revocation failed with HTTP 503")

    succeeded, retried = await process_canvas_oauth_revocation_retries(
        repo=repo,
        config=_config(),
        revoker=revoker,
    )

    assert (succeeded, retried) == (0, 1)
    pending = await repo.get_canvas_oauth_connection("org-1", connection.platform_id)
    assert pending is not None
    assert pending.status == CanvasOAuthConnectionStatus.REVOCATION_PENDING
    assert pending.revoke_retry_count == 1
    assert pending.revoke_retry_at is not None and pending.revoke_retry_at > datetime.now(UTC)
    assert pending.revoke_last_error_code == "canvas_oauth_revoke_rejected"
    assert pending.refresh_lease_owner is None
    assert await repo.get_integration_secret_value("org-1", "access-secret-1") == "access-token-value"


@pytest.mark.asyncio
async def test_oauth_revocation_lease_is_owner_conditional() -> None:
    repo = InMemoryIssuanceRepository()
    connection = await _pending_oauth_revocation(repo)
    first = await repo.acquire_canvas_oauth_revocation_lease(
        organization_id="org-1",
        platform_id=connection.platform_id,
        lease_owner="worker-a",
    )
    second = await repo.acquire_canvas_oauth_revocation_lease(
        organization_id="org-1",
        platform_id=connection.platform_id,
        lease_owner="worker-b",
    )
    assert first is not None
    assert second is None
    assert not await repo.complete_canvas_oauth_revocation(
        organization_id="org-1",
        platform_id=connection.platform_id,
        lease_owner="worker-b",
    )
    assert not await repo.reschedule_canvas_oauth_revocation(
        organization_id="org-1",
        platform_id=connection.platform_id,
        lease_owner="worker-b",
        retry_at=datetime.now(UTC) + timedelta(minutes=1),
        error_code="wrong_owner",
    )
    assert await repo.reschedule_canvas_oauth_revocation(
        organization_id="org-1",
        platform_id=connection.platform_id,
        lease_owner="worker-a",
        retry_at=datetime.now(UTC) + timedelta(minutes=1),
        error_code="canvas_oauth_revoke_unavailable",
    )
