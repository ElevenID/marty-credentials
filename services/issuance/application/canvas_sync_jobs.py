"""State transitions for durable Canvas evidence synchronization jobs."""

from __future__ import annotations

import copy
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from issuance.application.canvas_feature_flags import (
    portable_canvas_enabled_for_organization,
)
from issuance.domain.entities import (
    CanvasEvidenceSyncJob,
    CanvasEvidenceSyncJobStatus,
)
from issuance.domain.ports import IIssuanceRepository


class CanvasSyncLeaseLostError(RuntimeError):
    """The job lease was reclaimed or expired before an outcome was stored."""


def _require_lease(job: CanvasEvidenceSyncJob, worker_id: str) -> None:
    if job.status != CanvasEvidenceSyncJobStatus.LEASED:
        raise ValueError("Canvas sync job is not leased")
    if not worker_id or job.lease_owner != worker_id:
        raise ValueError("Canvas sync job lease is owned by another worker")
    if job.lease_expires_at is None or job.lease_expires_at <= datetime.now(UTC):
        raise ValueError("Canvas sync job lease has expired")


def _safe_error_summary(value: str | None) -> str | None:
    """Bound persisted errors; provider response bodies/tokens must not be stored."""

    if not value:
        return None
    normalized = " ".join(str(value).split())
    return normalized[:500]


async def complete_canvas_sync_job(
    *,
    repo: IIssuanceRepository,
    job: CanvasEvidenceSyncJob,
    worker_id: str,
    target_config_version: int,
    result: dict[str, Any] | None = None,
) -> CanvasEvidenceSyncJob:
    """Complete a worker-owned lease and narrowly mark its target successful."""

    _require_lease(job, worker_id)
    now = datetime.now(UTC)
    updated = copy.deepcopy(job)
    updated.status = CanvasEvidenceSyncJobStatus.SUCCEEDED
    updated.result = dict(result or {})
    updated.last_error_code = None
    updated.last_error_summary = None
    updated.lease_owner = None
    updated.lease_expires_at = None
    updated.completed_at = now
    updated.updated_at = now
    if not await repo.save_canvas_sync_job_if_leased(updated, worker_id=worker_id):
        raise CanvasSyncLeaseLostError("Canvas sync job lease was lost before completion")

    await repo.mark_canvas_sync_target_succeeded(
        organization_id=updated.organization_id,
        target_id=updated.target_id,
        expected_config_version=target_config_version,
        succeeded_at=now,
    )
    return updated


async def fail_canvas_sync_job(
    *,
    repo: IIssuanceRepository,
    job: CanvasEvidenceSyncJob,
    worker_id: str,
    error_code: str,
    error_summary: str | None = None,
    retry_after_seconds: int | None = None,
    force_dead_letter: bool = False,
) -> CanvasEvidenceSyncJob:
    """Retry with exponential jitter or move an exhausted job to dead letter."""

    _require_lease(job, worker_id)
    now = datetime.now(UTC)
    updated = copy.deepcopy(job)
    updated.last_error_code = str(error_code or "canvas_sync_failed")[:120]
    updated.last_error_summary = _safe_error_summary(error_summary)
    updated.result = {}
    updated.lease_owner = None
    updated.lease_expires_at = None
    if force_dead_letter:
        # Preserve attempt_count as the lease fencing generation while making
        # the non-retryable terminal state satisfy the database constraint.
        updated.max_attempts = max(1, updated.attempt_count)
    if force_dead_letter or updated.attempt_count >= updated.max_attempts:
        updated.status = CanvasEvidenceSyncJobStatus.DEAD_LETTER
        updated.completed_at = now
    else:
        exponent = min(max(updated.attempt_count - 1, 0), 10)
        base_delay = min(3600, 15 * (2**exponent))
        jitter = secrets.randbelow(max(1, base_delay // 3 + 1))
        delay = base_delay + jitter
        if retry_after_seconds is not None:
            delay = max(delay, max(0, min(int(retry_after_seconds), 86400)))
        updated.status = CanvasEvidenceSyncJobStatus.RETRY
        updated.available_at = now + timedelta(seconds=delay)
        updated.completed_at = None
    updated.updated_at = now
    if not await repo.save_canvas_sync_job_if_leased(updated, worker_id=worker_id):
        raise CanvasSyncLeaseLostError("Canvas sync job lease was lost before failure handling")
    return updated


async def retry_dead_letter_canvas_sync_job(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    job_id: str,
) -> CanvasEvidenceSyncJob | None:
    """Administrator retry for a tenant-owned dead-letter job."""

    job = await repo.get_canvas_sync_job_for_org(organization_id, job_id)
    if job is None:
        return None
    if not portable_canvas_enabled_for_organization(organization_id):
        raise ValueError("Portable Canvas integration is disabled for this organization")
    if job.status != CanvasEvidenceSyncJobStatus.DEAD_LETTER:
        raise ValueError("Only dead-letter Canvas sync jobs can be retried")
    retried = await repo.retry_canvas_sync_job_from_dead_letter(
        organization_id,
        job_id,
    )
    if retried is not None:
        return retried
    raise ValueError("Only dead-letter Canvas sync jobs can be retried")


async def resolve_dead_letter_canvas_sync_job(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    job_id: str,
) -> CanvasEvidenceSyncJob | None:
    """Acknowledge a tenant-owned dead letter while leaving its target stopped."""

    resolved = await repo.resolve_canvas_sync_job_dead_letter(
        organization_id,
        job_id,
    )
    if resolved is not None:
        return resolved
    job = await repo.get_canvas_sync_job_for_org(organization_id, job_id)
    if job is None:
        return None
    raise ValueError("Only dead-letter Canvas sync jobs can be resolved")
