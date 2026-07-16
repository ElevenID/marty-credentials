"""Application service for durable, tenant-scoped Canvas synchronization.

The web service only creates and inspects durable work.  Canvas reads are
performed by the separate worker process through an explicitly registered
processor.  Keeping that boundary here prevents an API request (or a
background roster scan) from signing a credential as a side effect.
"""

from __future__ import annotations

import inspect
import logging
import secrets
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from issuance.application.canvas_feature_flags import (
    portable_canvas_enabled_for_organization,
)
from issuance.domain.entities import (
    Application,
    CanvasAwardCandidateState,
    CanvasEvidenceSyncJob,
    CanvasEvidenceSyncTarget,
    CanvasEvidenceSyncTargetType,
    EventType,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
    IssuanceEvent,
)
from issuance.domain.ports import IIssuanceRepository

logger = logging.getLogger(__name__)

CanvasSyncProcessor = Callable[
    [IIssuanceRepository, CanvasEvidenceSyncTarget],
    Awaitable[Mapping[str, Any]],
]
CredentialCorrectionHandler = Callable[
    [str, str, str, IIssuanceRepository],
    Awaitable[None],
]


async def _finalize_pending_evidence_recovery(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    review_id: str,
) -> None:
    review = await repo.get_evidence_policy_review_for_org(organization_id, review_id)
    if (
        review is None
        or review.status != EvidencePolicyReviewStatus.OPEN
        or not review.resolution_recovery_pending
        or review.resolution_claim_token is not None
    ):
        return
    claim_token = secrets.token_urlsafe(32)
    claimed = await repo.claim_evidence_policy_review_resolution(
        organization_id,
        review_id,
        claim_token=claim_token,
        action="evidence_recovered",
    )
    if claimed is None:
        return
    now = datetime.now(UTC)
    event = IssuanceEvent(
        application_id=claimed.application_id,
        event_type=EventType.EVIDENCE_POLICY_REVIEW_RESOLVED,
        metadata={
            "organization_id": organization_id,
            "review_id": claimed.id,
            "credential_id": claimed.credential_id,
            "resolution_action": "evidence_recovered",
            "resolved_by": "canvas-evidence-sync",
        },
    )
    await repo.finalize_evidence_policy_review_resolution(
        organization_id,
        review_id,
        claim_token=claim_token,
        status=EvidencePolicyReviewStatus.RESOLVED,
        resolution_action="evidence_recovered",
        resolution_notes="Authoritative Canvas evidence recovered during correction handling",
        resolved_by="canvas-evidence-sync",
        resolved_at=now,
        audit_event=event,
    )


class CanvasSyncServiceError(RuntimeError):
    """Stable, sanitizable service error surfaced by APIs and workers."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CanvasSyncNotFoundError(CanvasSyncServiceError):
    """The requested tenant-owned resource does not exist."""


class CanvasSyncConflictError(CanvasSyncServiceError):
    """The resource exists but is not in a valid state for the operation."""


class CanvasSyncProcessingError(CanvasSyncServiceError):
    """Safe failure raised by an authoritative Canvas target processor."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = True,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(code, message)
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds


_registered_processor: CanvasSyncProcessor | None = None


def register_canvas_sync_processor(processor: CanvasSyncProcessor | None) -> None:
    """Register the authoritative reader used by the standalone worker.

    Registration is deliberately explicit: importing the HTTP router must not
    start work, and the default behavior is a safe retry rather than silently
    marking an unprocessed target successful.
    """

    global _registered_processor
    if processor is not None and not callable(processor):
        raise TypeError("Canvas sync processor must be callable")
    _registered_processor = processor


def canvas_sync_processor_is_configured() -> bool:
    """Return whether this process has an authoritative target reader."""

    return _registered_processor is not None


def _application_canvas_context(app: Application) -> dict[str, Any]:
    integration_context = app.integration_context if isinstance(app.integration_context, dict) else {}
    canvas = integration_context.get("canvas")
    return dict(canvas) if isinstance(canvas, dict) else {}


def _required_context_identifier(context: Mapping[str, Any], name: str) -> str:
    value = str(context.get(name) or "").strip()
    if not value:
        raise CanvasSyncConflictError(
            "canvas_application_context_incomplete",
            f"Canvas application context is missing {name}",
        )
    return value


async def enqueue_application_canvas_sync(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    application_id: str,
) -> tuple[CanvasEvidenceSyncTarget, CanvasEvidenceSyncJob]:
    """Create/update an application target and idempotently enqueue one job."""

    app = await repo.get_application(application_id)
    if app is None or app.organization_id != organization_id:
        raise CanvasSyncNotFoundError("canvas_application_not_found", "Canvas application not found")
    if not portable_canvas_enabled_for_organization(organization_id):
        raise CanvasSyncConflictError(
            "canvas_rollout_disabled",
            "Portable Canvas synchronization is not enabled for this organization",
        )

    context = _application_canvas_context(app)
    platform_id = _required_context_identifier(context, "canvas_platform_id")
    binding_id = _required_context_identifier(context, "canvas_program_binding_id")

    platform = await repo.get_canvas_platform_for_org(organization_id, platform_id)
    binding = await repo.get_canvas_program_binding_for_org(organization_id, binding_id)
    if (
        platform is None
        or binding is None
        or binding.platform_id != platform.id
    ):
        # Do not reveal which guessed cross-tenant identifier was valid.
        raise CanvasSyncNotFoundError("canvas_binding_not_found", "Canvas binding not found")
    if not platform.enabled or not binding.enabled:
        raise CanvasSyncConflictError(
            "canvas_binding_inactive",
            "Canvas platform and program binding must be active before synchronization",
        )

    target_type = (
        CanvasEvidenceSyncTargetType.ISSUED_DRIFT
        if app.credential_id
        else CanvasEvidenceSyncTargetType.LEARNER_APPLICATION
    )
    schedule_seconds = 6 * 60 * 60 if app.credential_id else 15 * 60
    logical_key = f"application:{app.id}"
    target = await repo.get_canvas_sync_target_by_logical_key(organization_id, logical_key)
    if target is None:
        target = CanvasEvidenceSyncTarget(
            organization_id=organization_id,
            platform_id=platform.id,
            binding_id=binding.id,
            target_type=target_type,
            logical_key=logical_key,
            application_id=app.id,
            schedule_seconds=schedule_seconds,
            config_version=binding.config_version,
            metadata={"created_from": "application_sync_api"},
        )
    else:
        target.platform_id = platform.id
        target.binding_id = binding.id
        target.target_type = target_type
        target.application_id = app.id
        target.schedule_seconds = schedule_seconds
        target.config_version = binding.config_version
        target.enabled = True
        target.updated_at = datetime.now(UTC)
        target.metadata = {
            **(target.metadata if isinstance(target.metadata, dict) else {}),
            "last_requested_from": "application_sync_api",
        }
    await repo.save_canvas_sync_target(target)
    job = await repo.enqueue_canvas_sync_job(target)
    return target, job


async def record_canvas_credential_claim(
    *,
    repo: IIssuanceRepository,
    application_id: str | None,
    credential_id: str,
) -> None:
    """Finalize a Canvas claim and schedule bounded post-issuance drift reads."""

    if not application_id:
        return
    app = await repo.get_application(application_id)
    if app is None:
        return
    canvas = _application_canvas_context(app)
    platform_id = str(canvas.get("canvas_platform_id") or "").strip()
    binding_id = str(canvas.get("canvas_program_binding_id") or "").strip()
    if not platform_id or not binding_id:
        return
    platform = await repo.get_canvas_platform_for_org(app.organization_id, platform_id)
    binding = await repo.get_canvas_program_binding_for_org(app.organization_id, binding_id)
    if platform is None or binding is None or binding.platform_id != platform.id:
        return

    now = datetime.now(UTC)
    app.credential_id = credential_id
    app.updated_at = now
    await repo.save_application(app)
    candidate_id = str(canvas.get("canvas_award_candidate_id") or "").strip()
    if candidate_id:
        candidate = await repo.get_canvas_award_candidate_for_org(
            app.organization_id,
            candidate_id,
        )
        if candidate is not None and candidate.application_id == app.id:
            candidate.state = CanvasAwardCandidateState.CLAIMED
            candidate.claimed_credential_id = credential_id
            candidate.updated_at = now
            await repo.save_canvas_award_candidate(candidate)

    logical_key = f"application:{app.id}"
    target = await repo.get_canvas_sync_target_by_logical_key(
        app.organization_id,
        logical_key,
    )
    if target is None:
        target = CanvasEvidenceSyncTarget(
            organization_id=app.organization_id,
            platform_id=platform.id,
            binding_id=binding.id,
            target_type=CanvasEvidenceSyncTargetType.ISSUED_DRIFT,
            logical_key=logical_key,
            application_id=app.id,
            config_version=binding.config_version,
        )
    target.target_type = CanvasEvidenceSyncTargetType.ISSUED_DRIFT
    target.schedule_seconds = 6 * 60 * 60
    target.config_version = binding.config_version
    target.next_run_at = now + timedelta(hours=6)
    target.enabled = True
    target.metadata = {
        **(target.metadata if isinstance(target.metadata, dict) else {}),
        "drift_until": (now + timedelta(days=90)).isoformat(),
        "claimed_credential_id": credential_id,
    }
    target.updated_at = now
    await repo.save_canvas_sync_target(target)


_FORBIDDEN_METADATA_KEYS = {
    "access_token",
    "refresh_token",
    "bearer",
    "authorization",
    "cookie",
    "api_key",
    "client_secret",
}


def _metadata_contains_secret(value: Any, *, path: tuple[str, ...] = ()) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).strip().lower()
            if any(fragment in normalized for fragment in _FORBIDDEN_METADATA_KEYS):
                return True
            if _metadata_contains_secret(item, path=(*path, normalized)):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_metadata_contains_secret(item, path=path) for item in value)
    if isinstance(value, str):
        return value.strip().lower().startswith("bearer ")
    return False


async def validate_canvas_sync_target(
    *,
    repo: IIssuanceRepository,
    target: CanvasEvidenceSyncTarget,
) -> None:
    """Fail closed on incomplete, foreign, or secret-bearing target metadata."""

    required_values = {
        "organization_id": target.organization_id,
        "platform_id": target.platform_id,
        "binding_id": target.binding_id,
        "logical_key": target.logical_key,
    }
    missing = sorted(name for name, value in required_values.items() if not str(value or "").strip())
    if missing:
        raise CanvasSyncProcessingError(
            "canvas_sync_target_incomplete",
            "Canvas sync target is missing " + ", ".join(missing),
            retryable=False,
        )
    if _metadata_contains_secret(target.metadata):
        raise CanvasSyncProcessingError(
            "canvas_sync_target_contains_secret",
            "Canvas sync target metadata contains prohibited authentication material",
            retryable=False,
        )

    platform = await repo.get_canvas_platform_for_org(target.organization_id, target.platform_id)
    binding = await repo.get_canvas_program_binding_for_org(target.organization_id, target.binding_id)
    if platform is None or binding is None or binding.platform_id != platform.id:
        raise CanvasSyncProcessingError(
            "canvas_sync_target_scope_invalid",
            "Canvas sync target platform or binding is unavailable",
            retryable=False,
        )
    if (
        not platform.enabled
        or platform.archived_at is not None
        or not binding.enabled
        or binding.archived_at is not None
        or not target.enabled
    ):
        if target.enabled:
            target.enabled = False
            target.updated_at = datetime.now(UTC)
            await repo.save_canvas_sync_target(target)
        raise CanvasSyncProcessingError(
            "canvas_sync_target_inactive",
            "Canvas sync target, platform, or binding is inactive",
            retryable=False,
        )
    if target.config_version != binding.config_version:
        # Configuration changes invalidate all previously authorized service
        # URLs and evidence rules. Disable the stale target so the scheduler
        # cannot repeatedly enqueue it; activation/enqueue creates or updates a
        # target at the new version after readiness succeeds again.
        target.enabled = False
        target.updated_at = datetime.now(UTC)
        await repo.save_canvas_sync_target(target)
        raise CanvasSyncProcessingError(
            "canvas_sync_target_config_stale",
            "Canvas sync target does not match the active binding configuration",
            retryable=False,
        )

    if target.target_type in {
        CanvasEvidenceSyncTargetType.LEARNER_APPLICATION,
        CanvasEvidenceSyncTargetType.ISSUED_DRIFT,
    }:
        if not target.application_id:
            raise CanvasSyncProcessingError(
                "canvas_sync_target_application_missing",
                "Canvas learner synchronization target has no application",
                retryable=False,
            )
        app = await repo.get_application(target.application_id)
        if app is None or app.organization_id != target.organization_id:
            raise CanvasSyncProcessingError(
                "canvas_sync_target_application_invalid",
                "Canvas learner synchronization application is unavailable",
                retryable=False,
            )
    elif target.target_type == CanvasEvidenceSyncTargetType.AWARD_CANDIDATE:
        if not target.candidate_id:
            raise CanvasSyncProcessingError(
                "canvas_sync_target_candidate_missing",
                "Canvas award-candidate synchronization target has no candidate",
                retryable=False,
            )
        candidate = await repo.get_canvas_award_candidate_for_org(
            target.organization_id,
            target.candidate_id,
        )
        if candidate is None:
            raise CanvasSyncProcessingError(
                "canvas_sync_target_candidate_invalid",
                "Canvas award candidate is unavailable",
                retryable=False,
            )


async def process_canvas_sync_target(
    repo: IIssuanceRepository,
    target: CanvasEvidenceSyncTarget,
    *,
    processor: CanvasSyncProcessor | None = None,
) -> Mapping[str, Any]:
    """Validate then dispatch one target to the authoritative reader hook."""

    if not portable_canvas_enabled_for_organization(target.organization_id):
        # Keep scheduled targets intact so an operator can reopen the pilot
        # without rebuilding them, but never dispatch a provider/network
        # reader while either rollout gate is closed.
        return {"no_change": True}
    await validate_canvas_sync_target(repo=repo, target=target)
    selected_processor = processor or _registered_processor
    if selected_processor is None:
        raise CanvasSyncProcessingError(
            "canvas_sync_processor_unavailable",
            "Authoritative Canvas synchronization processor is not configured",
            retryable=True,
        )
    result = selected_processor(repo, target)
    if not inspect.isawaitable(result):
        raise CanvasSyncProcessingError(
            "canvas_sync_processor_contract_invalid",
            "Canvas synchronization processor must be asynchronous",
            retryable=False,
        )
    processed = await result
    if not isinstance(processed, Mapping):
        raise CanvasSyncProcessingError(
            "canvas_sync_processor_contract_invalid",
            "Canvas synchronization processor returned an invalid result",
            retryable=False,
        )
    # Background work may prepare an unsigned candidate, but it must never
    # report issuance/signing. The wallet claim remains the only signing path.
    forbidden_outcomes = {
        "credential_id",
        "issued_credential_id",
        "signed_credential",
        "credential_jwt",
    }
    if forbidden_outcomes.intersection(processed):
        raise CanvasSyncProcessingError(
            "canvas_background_signing_forbidden",
            "Canvas synchronization attempted to return a signed credential",
            retryable=False,
        )
    return dict(processed)


async def resolve_evidence_policy_review(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    review_id: str,
    action: str,
    notes: str | None,
    resolved_by: str | None,
    credential_handler: CredentialCorrectionHandler | None = None,
) -> EvidencePolicyReview:
    """Resolve one tenant-owned correction review and apply lifecycle action."""

    normalized_action = str(action or "").strip().lower()
    if normalized_action not in {"dismiss", "suspend", "revoke"}:
        raise CanvasSyncConflictError(
            "canvas_review_action_invalid",
            "Correction action must be dismiss, suspend, or revoke",
        )
    review = await repo.get_evidence_policy_review_for_org(organization_id, review_id)
    if review is None:
        raise CanvasSyncNotFoundError(
            "canvas_review_not_found",
            "Canvas evidence correction review not found",
        )
    if review.status != EvidencePolicyReviewStatus.OPEN:
        raise CanvasSyncConflictError(
            "canvas_review_already_resolved",
            "Canvas evidence correction review is already resolved",
        )

    credential = None
    if normalized_action in {"suspend", "revoke"}:
        credential = await repo.get_credential(review.credential_id)
        if credential is None or credential.organization_id != organization_id:
            raise CanvasSyncNotFoundError(
                "canvas_review_credential_not_found",
                "Credential for Canvas evidence correction review not found",
            )
        if credential_handler is None:
            raise CanvasSyncConflictError(
                "canvas_review_lifecycle_handler_unavailable",
                "Credential status handler is unavailable",
            )

    claim_token = secrets.token_urlsafe(32)
    claimed = await repo.claim_evidence_policy_review_resolution(
        organization_id,
        review_id,
        claim_token=claim_token,
        action=normalized_action,
    )
    if claimed is None:
        raise CanvasSyncConflictError(
            "canvas_review_already_resolved",
            "Canvas evidence correction review is already claimed or resolved",
        )

    if normalized_action in {"suspend", "revoke"}:
        assert credential is not None and credential_handler is not None
        try:
            await credential_handler(
                normalized_action,
                credential.id,
                str(notes or "Canvas evidence correction review"),
                repo,
            )
        except Exception:
            released = await repo.release_evidence_policy_review_resolution(
                organization_id,
                review_id,
                claim_token=claim_token,
            )
            if released:
                try:
                    await _finalize_pending_evidence_recovery(
                        repo=repo,
                        organization_id=organization_id,
                        review_id=review_id,
                    )
                except Exception:
                    logger.exception(
                        "Failed to finalize pending Canvas evidence recovery for review %s",
                        review_id,
                    )
            raise

    now = datetime.now(UTC)
    final_status = {
        "dismiss": EvidencePolicyReviewStatus.DISMISSED,
        "suspend": EvidencePolicyReviewStatus.SUSPENDED,
        "revoke": EvidencePolicyReviewStatus.REVOKED,
    }[normalized_action]
    resolution_notes = str(notes).strip() if notes and str(notes).strip() else None
    resolution_actor = (
        str(resolved_by).strip() if resolved_by and str(resolved_by).strip() else None
    )
    audit_event = IssuanceEvent(
        application_id=claimed.application_id,
        event_type=EventType.EVIDENCE_POLICY_REVIEW_RESOLVED,
        metadata={
            "organization_id": organization_id,
            "review_id": claimed.id,
            "credential_id": claimed.credential_id,
            "resolution_action": normalized_action,
            "resolved_by": resolution_actor,
        },
    )
    finalized = await repo.finalize_evidence_policy_review_resolution(
        organization_id,
        review_id,
        claim_token=claim_token,
        status=final_status,
        resolution_action=normalized_action,
        resolution_notes=resolution_notes,
        resolved_by=resolution_actor,
        resolved_at=now,
        audit_event=audit_event,
    )
    if finalized is None:
        raise CanvasSyncConflictError(
            "canvas_review_already_resolved",
            "Canvas evidence correction review claim is no longer active",
        )
    return finalized
