"""Standalone PostgreSQL-backed worker for portable Canvas synchronization.

Run with::

    python -m issuance.canvas_worker

This module is intentionally not imported or started by the FastAPI lifespan.
Competing scheduler/worker replicas are safe because repository leasing uses
``FOR UPDATE SKIP LOCKED`` and enforces one active job per target.
"""

from __future__ import annotations

import asyncio
import copy
import importlib
import logging
import os
import secrets
import socket
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from issuance.application.canvas_lti_services import canvas_http_client
from issuance.application.canvas_oauth import CanvasOAuthError, revoke_canvas_oauth_token
from issuance.application.canvas_sync_jobs import (
    CanvasSyncLeaseLostError,
    complete_canvas_sync_job,
    fail_canvas_sync_job,
)
from issuance.application.canvas_sync_service import (
    CanvasSyncProcessingError,
    CanvasSyncProcessor,
    canvas_sync_processor_is_configured,
    process_canvas_sync_target,
)
from issuance.domain.entities import (
    CanvasEvidenceSyncJob,
    CanvasEvidenceSyncJobStatus,
    CanvasEvidenceSyncTarget,
    CanvasWorkerHeartbeat,
)
from issuance.domain.ports import IIssuanceRepository

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CanvasSyncWorkerConfig:
    worker_id: str
    batch_size: int = 10
    lease_seconds: int = 120
    job_timeout_seconds: float = 600.0
    schedule_limit: int = 100
    oauth_revocation_limit: int = 25
    poll_seconds: float = 5.0

    @classmethod
    def from_env(cls) -> CanvasSyncWorkerConfig:
        identity = os.environ.get("CANVAS_SYNC_WORKER_ID") or (
            f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        )
        return cls(
            worker_id=identity,
            batch_size=max(1, int(os.environ.get("CANVAS_SYNC_WORKER_BATCH_SIZE", "10"))),
            lease_seconds=max(30, int(os.environ.get("CANVAS_SYNC_WORKER_LEASE_SECONDS", "120"))),
            # Bound the complete target evaluation, including every paginated
            # Canvas collection. Per-request inactivity timeouts alone do not
            # provide a wall-clock ceiling across many valid slow pages.
            job_timeout_seconds=max(
                30.0,
                min(
                    3600.0,
                    float(os.environ.get("CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS", "600")),
                ),
            ),
            schedule_limit=max(1, int(os.environ.get("CANVAS_SYNC_SCHEDULE_LIMIT", "100"))),
            oauth_revocation_limit=max(
                1,
                int(os.environ.get("CANVAS_OAUTH_REVOCATION_BATCH_SIZE", "25")),
            ),
            # Keep waits bounded so shutdown and operational updates remain responsive.
            poll_seconds=max(0.1, min(60.0, float(os.environ.get("CANVAS_SYNC_WORKER_POLL_SECONDS", "5")))),
        )


@dataclass(frozen=True)
class CanvasSyncWorkerCycleResult:
    scheduled: int
    leased: int
    succeeded: int
    retried: int
    dead_lettered: int
    oauth_revocations_succeeded: int
    oauth_revocations_retried: int


def _organization_secret_id(secret_ref: str | None, organization_id: str) -> str | None:
    if not secret_ref:
        return None
    prefix = f"org_secret://{organization_id}/"
    normalized = str(secret_ref).strip()
    if not normalized.startswith(prefix):
        return None
    secret_id = normalized[len(prefix) :].strip()
    return secret_id if secret_id and "/" not in secret_id else None


def _oauth_revocation_delay_seconds(retry_count: int, exc: BaseException) -> int:
    exponent = min(max(retry_count, 0), 11)
    base_delay = min(21600, 30 * (2**exponent))
    jitter = secrets.randbelow(max(1, base_delay // 4 + 1))
    delay = base_delay + jitter
    retry_after = _retry_after_seconds(exc)
    if retry_after is not None:
        delay = max(delay, retry_after)
    return min(delay, 86400)


def _oauth_revocation_error_code(exc: BaseException) -> str:
    message = str(exc).lower() if isinstance(exc, CanvasOAuthError) else ""
    if "http 429" in message or "rate limit" in message:
        return "canvas_oauth_revoke_rate_limited"
    if isinstance(exc, CanvasOAuthError):
        return "canvas_oauth_revoke_rejected"
    if isinstance(exc, httpx.TimeoutException):
        return "canvas_oauth_revoke_timeout"
    return "canvas_oauth_revoke_unavailable"


async def process_canvas_oauth_revocation_retries(
    *,
    repo: IIssuanceRepository,
    config: CanvasSyncWorkerConfig,
    revoker: Any = revoke_canvas_oauth_token,
    heartbeat: CanvasWorkerHeartbeat | None = None,
    processor_configured: bool | None = None,
) -> tuple[int, int]:
    """Remotely revoke due Canvas grants, then delete local token material.

    Connections are conditionally leased using the existing refresh-lease
    columns. This prevents a failed replica from resurrecting a connection
    another replica has already revoked and deleted.
    """

    due = await repo.list_canvas_oauth_revocation_retries(
        limit=config.oauth_revocation_limit,
    )
    succeeded = 0
    retried = 0
    lease_seconds = max(30, min(config.lease_seconds, 300))
    for pending in due:
        if heartbeat is not None:
            await _write_worker_heartbeat(
                repo=repo,
                heartbeat=heartbeat,
                phase="oauth_revocation",
                processor_configured=processor_configured,
            )
        connection = await repo.acquire_canvas_oauth_revocation_lease(
            organization_id=pending.organization_id,
            platform_id=pending.platform_id,
            lease_owner=config.worker_id,
            lease_seconds=lease_seconds,
        )
        if connection is None:
            continue

        access_secret_id = _organization_secret_id(
            connection.access_token_secret_ref,
            connection.organization_id,
        )
        refresh_secret_id = _organization_secret_id(
            connection.refresh_token_secret_ref,
            connection.organization_id,
        )
        platform = await repo.get_canvas_platform_for_org(
            connection.organization_id,
            connection.platform_id,
        )
        access_token = (
            await repo.get_integration_secret_value(
                connection.organization_id,
                access_secret_id,
            )
            if access_secret_id
            else None
        )
        if not str(connection.canvas_base_url or "").strip():
            error: BaseException = CanvasOAuthError("Pinned Canvas OAuth origin is unavailable")
        elif not access_secret_id or not access_token:
            error = CanvasOAuthError("Organization-owned Canvas access token is unavailable")
        else:
            error = None
            try:
                async with canvas_http_client(timeout=10.0) as client:
                    await revoker(
                        client=client,
                        canvas_base_url=connection.canvas_base_url,
                        access_token=access_token,
                    )
            except Exception as exc:  # noqa: BLE001 - persist a bounded retry, never the token
                error = exc

        if error is not None:
            error_code = _oauth_revocation_error_code(error)
            delay = _oauth_revocation_delay_seconds(connection.revoke_retry_count, error)
            rescheduled = await repo.reschedule_canvas_oauth_revocation(
                organization_id=connection.organization_id,
                platform_id=connection.platform_id,
                lease_owner=config.worker_id,
                retry_at=datetime.now(UTC) + timedelta(seconds=delay),
                error_code=error_code,
            )
            if rescheduled:
                retried += 1
            logger.warning(
                "Canvas OAuth revocation retry scheduled org=%s platform=%s code=%s",
                connection.organization_id,
                connection.platform_id,
                error_code,
            )
            continue

        deleted = await repo.complete_canvas_oauth_revocation(
            organization_id=connection.organization_id,
            platform_id=connection.platform_id,
            lease_owner=config.worker_id,
        )
        if not deleted:
            continue

        try:
            if platform is not None:
                await repo.patch_canvas_platform_connection_config(
                    connection.organization_id,
                    connection.platform_id,
                    expected_config_version=platform.config_version,
                    patch={
                        "oauth_status": "disconnected",
                        "granted_scopes": [],
                        "oauth_capabilities": [],
                    },
                    remove_keys=("oauth_pending_authorization_id",),
                )
        except Exception:  # noqa: BLE001 - remote revoke/local connection deletion already succeeded
            logger.exception(
                "Canvas OAuth platform disconnect marker failed org=%s platform=%s",
                connection.organization_id,
                connection.platform_id,
            )
        finally:
            # The remote token is already revoked and the connection record is
            # gone. Clean local secrets last so a crash can never leave a live
            # remote token with no retry record.
            secret_ids = {item for item in (access_secret_id, refresh_secret_id) if item}
            for secret_id in secret_ids:
                await repo.delete_integration_secret(secret_id)
        succeeded += 1
    return succeeded, retried


def load_canvas_sync_processor(path: str | None) -> CanvasSyncProcessor | None:
    """Load ``module:function`` configured for the worker process."""

    normalized = str(path or "").strip()
    if not normalized:
        return None
    module_name, separator, attribute = normalized.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("CANVAS_SYNC_PROCESSOR must use module:function syntax")
    processor = getattr(importlib.import_module(module_name), attribute, None)
    if not callable(processor):
        raise ValueError(f"Canvas sync processor is not callable: {normalized}")
    return processor


def _retry_after_seconds(exc: BaseException) -> int | None:
    direct = getattr(exc, "retry_after_seconds", None)
    if direct is not None:
        with suppress(TypeError, ValueError):
            return max(0, min(int(direct), 86400))

    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    value = headers.get("Retry-After") if headers is not None else None
    if value is None:
        return None
    with suppress(TypeError, ValueError):
        return max(0, min(int(str(value).strip()), 86400))
    with suppress(TypeError, ValueError, OverflowError):
        retry_at = parsedate_to_datetime(str(value))
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        return max(
            0,
            min(int((retry_at - datetime.now(UTC)).total_seconds()), 86400),
        )
    return None


def _safe_result(result: dict[str, Any]) -> dict[str, Any]:
    """Persist bounded operational counters/IDs, never provider payloads."""

    allowed = {
        "application_id",
        "candidate_id",
        "candidate_state",
        "config_version",
        "requirements_checked",
        "facts_observed",
        "facts_changed",
        "negative_observations",
        "review_created",
        "identity_link_required",
        "candidates_seen",
        "pending_claim",
        "observations_written",
        "facts_created",
        "facts_reused",
        "policy_allowed",
        "no_change",
    }
    sanitized: dict[str, Any] = {}
    for key, value in result.items():
        if key not in allowed:
            continue
        if isinstance(value, bool) or value is None:
            sanitized[key] = value
        elif isinstance(value, int):
            sanitized[key] = max(0, value)
        elif isinstance(value, str):
            sanitized[key] = value[:200]
    return sanitized


async def _write_worker_heartbeat(
    *,
    repo: IIssuanceRepository,
    heartbeat: CanvasWorkerHeartbeat,
    phase: str,
    jobs: int = 0,
    processor_configured: bool | None = None,
) -> None:
    heartbeat.last_heartbeat_at = datetime.now(UTC)
    heartbeat.metadata = {
        "phase": phase,
        "leased_jobs": max(0, jobs),
        "process": "standalone",
        **(
            {"processor_configured": processor_configured}
            if processor_configured is not None
            else {}
        ),
    }
    await repo.upsert_canvas_worker_heartbeat(heartbeat)


async def _write_target_heartbeat(
    *,
    repo: IIssuanceRepository,
    target: CanvasEvidenceSyncTarget,
    worker_id: str,
) -> bool:
    now = datetime.now(UTC)
    return await repo.touch_canvas_sync_target_worker_heartbeat(
        organization_id=target.organization_id,
        target_id=target.id,
        expected_config_version=target.config_version,
        worker_id=worker_id,
        heartbeat_at=now,
    )


async def _maintain_job_lease(
    *,
    repo: IIssuanceRepository,
    job: CanvasEvidenceSyncJob,
    target: CanvasEvidenceSyncTarget,
    heartbeat: CanvasWorkerHeartbeat,
    config: CanvasSyncWorkerConfig,
) -> None:
    interval = max(10.0, min(30.0, config.lease_seconds / 3))
    while True:
        await asyncio.sleep(interval)
        if (
            job.status != CanvasEvidenceSyncJobStatus.LEASED
            or job.lease_owner != config.worker_id
        ):
            return
        now = datetime.now(UTC)
        renewed = copy.deepcopy(job)
        renewed.lease_expires_at = now + timedelta(seconds=config.lease_seconds)
        renewed.updated_at = now
        if not await repo.save_canvas_sync_job_if_leased(
            renewed,
            worker_id=config.worker_id,
        ):
            logger.warning(
                "Canvas sync job lease renewal fenced out job=%s worker=%s attempt=%s",
                job.id,
                config.worker_id,
                job.attempt_count,
            )
            return
        # Keep the detached worker copy current for its eventual fenced outcome.
        job.lease_expires_at = renewed.lease_expires_at
        job.updated_at = renewed.updated_at
        await _write_target_heartbeat(repo=repo, target=target, worker_id=config.worker_id)
        await _write_worker_heartbeat(
            repo=repo,
            heartbeat=heartbeat,
            phase="processing",
            jobs=1,
            processor_configured=True,
        )


async def _process_leased_job(
    *,
    repo: IIssuanceRepository,
    job: CanvasEvidenceSyncJob,
    heartbeat: CanvasWorkerHeartbeat,
    config: CanvasSyncWorkerConfig,
    processor: CanvasSyncProcessor | None,
) -> CanvasEvidenceSyncJobStatus:
    target = await repo.get_canvas_sync_target_for_org(job.organization_id, job.target_id)
    if target is None:
        try:
            failed = await fail_canvas_sync_job(
                repo=repo,
                job=job,
                worker_id=config.worker_id,
                error_code="canvas_sync_target_not_found",
                error_summary="Canvas synchronization target is unavailable",
                force_dead_letter=True,
            )
        except CanvasSyncLeaseLostError:
            logger.warning("Discarded stale missing-target outcome for job %s", job.id)
            return CanvasEvidenceSyncJobStatus.LEASED
        return failed.status

    heartbeat_recorded = await _write_target_heartbeat(
        repo=repo,
        target=target,
        worker_id=config.worker_id,
    )
    if not heartbeat_recorded:
        # The target changed after the job was leased. Reload its canonical
        # configuration so validation cannot proceed with a stale enabled/version
        # snapshot merely because an operational heartbeat lost its CAS race.
        current_target = await repo.get_canvas_sync_target_for_org(
            job.organization_id,
            job.target_id,
        )
        if current_target is not None:
            target = current_target
    lease_task = asyncio.create_task(
        _maintain_job_lease(
            repo=repo,
            job=job,
            target=target,
            heartbeat=heartbeat,
            config=config,
        )
    )
    try:
        async with asyncio.timeout(config.job_timeout_seconds):
            result = await process_canvas_sync_target(repo, target, processor=processor)
    except TimeoutError:
        try:
            failed = await fail_canvas_sync_job(
                repo=repo,
                job=job,
                worker_id=config.worker_id,
                error_code="canvas_sync_deadline_exceeded",
                error_summary="Canvas synchronization exceeded its wall-clock deadline",
            )
        except CanvasSyncLeaseLostError:
            logger.warning("Discarded stale Canvas sync timeout for job %s", job.id)
            return CanvasEvidenceSyncJobStatus.LEASED
        return failed.status
    except CanvasSyncProcessingError as exc:
        try:
            failed = await fail_canvas_sync_job(
                repo=repo,
                job=job,
                worker_id=config.worker_id,
                error_code=exc.code,
                error_summary=str(exc),
                retry_after_seconds=exc.retry_after_seconds,
                force_dead_letter=not exc.retryable,
            )
        except CanvasSyncLeaseLostError:
            logger.warning("Discarded stale Canvas sync failure for job %s", job.id)
            return CanvasEvidenceSyncJobStatus.LEASED
        return failed.status
    except Exception as exc:  # noqa: BLE001 - worker must retain/retry its lease outcome
        response = getattr(exc, "response", None)
        status_code = getattr(response, "status_code", None)
        error_code = "canvas_rate_limited" if status_code == 429 else "canvas_sync_unexpected_error"
        try:
            failed = await fail_canvas_sync_job(
                repo=repo,
                job=job,
                worker_id=config.worker_id,
                error_code=error_code,
                # Never persist the provider response or exception message.
                error_summary=f"Canvas synchronization failed ({type(exc).__name__})",
                retry_after_seconds=_retry_after_seconds(exc),
            )
        except CanvasSyncLeaseLostError:
            logger.warning("Discarded stale Canvas sync exception for job %s", job.id)
            return CanvasEvidenceSyncJobStatus.LEASED
        logger.exception("Canvas sync job %s failed with %s", job.id, type(exc).__name__)
        return failed.status
    else:
        try:
            completed = await complete_canvas_sync_job(
                repo=repo,
                job=job,
                worker_id=config.worker_id,
                target_config_version=target.config_version,
                result=_safe_result(dict(result)),
            )
        except CanvasSyncLeaseLostError:
            logger.warning("Discarded stale Canvas sync completion for job %s", job.id)
            return CanvasEvidenceSyncJobStatus.LEASED
        return completed.status
    finally:
        lease_task.cancel()
        with suppress(asyncio.CancelledError):
            await lease_task


async def run_canvas_sync_worker_cycle(
    *,
    repo: IIssuanceRepository,
    config: CanvasSyncWorkerConfig,
    processor: CanvasSyncProcessor | None = None,
    heartbeat: CanvasWorkerHeartbeat | None = None,
    oauth_revoker: Any = revoke_canvas_oauth_token,
) -> CanvasSyncWorkerCycleResult:
    """Schedule due targets, lease ready jobs, and persist every outcome."""

    heartbeat = heartbeat or CanvasWorkerHeartbeat(worker_id=config.worker_id)
    processor_configured = processor is not None or canvas_sync_processor_is_configured()
    await _write_worker_heartbeat(
        repo=repo,
        heartbeat=heartbeat,
        phase="scheduling",
        processor_configured=processor_configured,
    )
    oauth_succeeded, oauth_retried = await process_canvas_oauth_revocation_retries(
        repo=repo,
        config=config,
        revoker=oauth_revoker,
        heartbeat=heartbeat,
        processor_configured=processor_configured,
    )
    scheduled = await repo.enqueue_due_canvas_sync_jobs(limit=config.schedule_limit)
    leased = await repo.lease_canvas_sync_jobs(
        worker_id=config.worker_id,
        limit=config.batch_size,
        lease_seconds=config.lease_seconds,
    )
    await _write_worker_heartbeat(
        repo=repo,
        heartbeat=heartbeat,
        phase="processing" if leased else "idle",
        jobs=len(leased),
        processor_configured=processor_configured,
    )

    # Start every leased job promptly. Processing a batch sequentially can let
    # later leases expire before their renewal task even exists, allowing a
    # second replica to reclaim and duplicate the work.
    outcomes = await asyncio.gather(
        *(
            _process_leased_job(
                repo=repo,
                job=job,
                heartbeat=heartbeat,
                config=config,
                processor=processor,
            )
            for job in leased
        ),
        return_exceptions=True,
    )
    statuses: list[CanvasEvidenceSyncJobStatus] = []
    for job, outcome in zip(leased, outcomes, strict=True):
        if isinstance(outcome, BaseException):
            # The lease remains durable and will be reclaimed after expiry;
            # wait for every sibling task so no work escapes into a later cycle.
            logger.error(
                "Canvas sync job %s escaped outcome handling with %s",
                job.id,
                type(outcome).__name__,
            )
            continue
        statuses.append(outcome)
    await _write_worker_heartbeat(
        repo=repo,
        heartbeat=heartbeat,
        phase="idle",
        processor_configured=processor_configured,
    )
    return CanvasSyncWorkerCycleResult(
        scheduled=len(scheduled),
        leased=len(leased),
        succeeded=statuses.count(CanvasEvidenceSyncJobStatus.SUCCEEDED),
        retried=statuses.count(CanvasEvidenceSyncJobStatus.RETRY),
        dead_lettered=statuses.count(CanvasEvidenceSyncJobStatus.DEAD_LETTER),
        oauth_revocations_succeeded=oauth_succeeded,
        oauth_revocations_retried=oauth_retried,
    )


async def run_canvas_sync_worker_loop(
    *,
    repo: IIssuanceRepository,
    config: CanvasSyncWorkerConfig,
    processor: CanvasSyncProcessor | None = None,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run worker cycles until cancellation or an explicit stop event."""

    stop_event = stop_event or asyncio.Event()
    heartbeat = CanvasWorkerHeartbeat(worker_id=config.worker_id)
    while not stop_event.is_set():
        try:
            await run_canvas_sync_worker_cycle(
                repo=repo,
                config=config,
                processor=processor,
                heartbeat=heartbeat,
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one scheduler failure must not kill the worker
            logger.exception("Canvas synchronization worker cycle failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=config.poll_seconds)
        except TimeoutError:
            continue


async def _main() -> None:
    from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://marty:marty_dev@postgres:5432/marty_credentials",
    )
    if not database_url.startswith("postgresql+asyncpg://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    engine = create_async_engine(database_url, pool_pre_ping=True, pool_size=5, max_overflow=5)
    repo = PostgresIssuanceRepository(async_sessionmaker(engine, expire_on_commit=False))
    config = CanvasSyncWorkerConfig.from_env()
    processor = load_canvas_sync_processor(os.environ.get("CANVAS_SYNC_PROCESSOR"))
    logger.info("Starting standalone Canvas sync worker %s", config.worker_id)
    try:
        await run_canvas_sync_worker_loop(repo=repo, config=config, processor=processor)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    asyncio.run(_main())
