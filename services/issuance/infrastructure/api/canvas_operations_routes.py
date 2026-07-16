"""Organization-scoped operational APIs for durable Canvas synchronization."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from issuance.application.canvas_sync_jobs import (
    resolve_dead_letter_canvas_sync_job,
    retry_dead_letter_canvas_sync_job,
)
from issuance.application.canvas_sync_service import (
    CanvasSyncConflictError,
    CanvasSyncNotFoundError,
    enqueue_application_canvas_sync,
    resolve_evidence_policy_review,
)
from issuance.domain.entities import (
    CanvasAwardCandidate,
    CanvasAwardCandidateState,
    CanvasEvidenceSyncJob,
    CanvasEvidenceSyncJobStatus,
    CanvasEvidenceSyncTarget,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.api.routes import (
    CredentialStatusRequest,
    _verify_management_api_key,
    revoke_credential,
    suspend_credential,
)
from pydantic import BaseModel, Field

canvas_operations_router = APIRouter(
    prefix="/v1/integrations/canvas",
    tags=["canvas-integration-operations"],
    dependencies=[Depends(_verify_management_api_key)],
)
_repository_dependency = Depends()


class CanvasSyncJobResponse(BaseModel):
    id: str
    organization_id: str
    target_id: str
    status: str
    attempt_count: int
    max_attempts: int
    available_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    last_error_code: str | None = None
    last_error_summary: str | None = None
    result: dict[str, Any] = Field(default_factory=dict)
    platform_id: str | None = None
    binding_id: str | None = None
    target_type: str | None = None
    application_id: str | None = None
    candidate_id: str | None = None
    created_at: datetime
    updated_at: datetime


class CanvasAwardCandidateResponse(BaseModel):
    id: str
    organization_id: str
    platform_id: str
    binding_id: str
    status: str
    application_id: str | None = None
    learner_identity_id: str | None = None
    observed_at: datetime
    created_at: datetime
    updated_at: datetime


class EvidencePolicyReviewResponse(BaseModel):
    id: str
    organization_id: str
    application_id: str
    credential_id: str
    binding_id: str | None = None
    status: str
    prior_decision: dict[str, Any] = Field(default_factory=dict)
    current_decision: dict[str, Any] = Field(default_factory=dict)
    triggering_fact_id: str | None = None
    resolution_action: str | None = None
    resolution_notes: str | None = None
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class EvidencePolicyReviewResolveRequest(BaseModel):
    action: Literal["dismiss", "suspend", "revoke"]
    note: str | None = Field(default=None, max_length=2000)


def _trusted_organization_id(request: Request) -> str:
    organization_id = str(request.headers.get("x-organization-id") or "").strip()
    if not organization_id:
        raise HTTPException(
            status_code=400,
            detail="X-Organization-ID is required for Canvas management",
        )
    return organization_id


def _scoped_organization_id(trusted: str, claimed: str | None) -> str:
    if claimed is not None and claimed.strip() != trusted:
        # Foreign organization probes are intentionally indistinguishable from
        # missing resources.
        raise HTTPException(status_code=404, detail="Canvas resource not found")
    return trusted


def _enum_value(value: Any) -> str:
    return str(value.value if hasattr(value, "value") else value)


def _public_error_summary(value: str | None) -> str | None:
    if not value:
        return None
    normalized = " ".join(str(value).split())[:500]
    lowered = normalized.lower()
    if any(marker in lowered for marker in ("bearer ", "access_token", "refresh_token", "secret=")):
        return "Canvas synchronization failed; authentication material was redacted"
    return normalized


def _public_job_result(value: dict[str, Any] | None) -> dict[str, Any]:
    allowed = {
        "application_id",
        "candidate_id",
        "candidate_state",
        "requirements_checked",
        "sources_checked",
        "facts_observed",
        "facts_changed",
        "facts_created",
        "facts_reused",
        "negative_observations",
        "review_created",
        "candidates_seen",
        "pending_claim",
        "identity_link_required",
        "observations_written",
        "policy_allowed",
        "no_change",
    }
    return {
        key: item
        for key, item in dict(value or {}).items()
        if key in allowed and (item is None or isinstance(item, (bool, int, str)))
    }


def _job_response(
    job: CanvasEvidenceSyncJob,
    target: CanvasEvidenceSyncTarget | None,
) -> CanvasSyncJobResponse:
    return CanvasSyncJobResponse(
        id=job.id,
        organization_id=job.organization_id,
        target_id=job.target_id,
        status=_enum_value(job.status),
        attempt_count=job.attempt_count,
        max_attempts=job.max_attempts,
        available_at=job.available_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        last_error_code=job.last_error_code,
        last_error_summary=_public_error_summary(job.last_error_summary),
        result=_public_job_result(job.result),
        platform_id=target.platform_id if target else None,
        binding_id=target.binding_id if target else None,
        target_type=_enum_value(target.target_type) if target else None,
        application_id=target.application_id if target else None,
        candidate_id=target.candidate_id if target else None,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


def _candidate_response(candidate: CanvasAwardCandidate) -> CanvasAwardCandidateResponse:
    return CanvasAwardCandidateResponse(
        id=candidate.id,
        organization_id=candidate.organization_id,
        platform_id=candidate.platform_id,
        binding_id=candidate.binding_id,
        status=_enum_value(candidate.state),
        application_id=candidate.application_id,
        learner_identity_id=candidate.learner_identity_id,
        observed_at=candidate.observed_at,
        created_at=candidate.created_at,
        updated_at=candidate.updated_at,
    )


def _review_response(review: EvidencePolicyReview) -> EvidencePolicyReviewResponse:
    return EvidencePolicyReviewResponse(
        id=review.id,
        organization_id=review.organization_id,
        application_id=review.application_id,
        credential_id=review.credential_id,
        binding_id=review.binding_id,
        status=_enum_value(review.status),
        prior_decision=dict(review.prior_decision or {}),
        current_decision=dict(review.current_decision or {}),
        triggering_fact_id=review.triggering_fact_id,
        resolution_action=review.resolution_action,
        resolution_notes=review.resolution_notes,
        resolved_by=review.resolved_by,
        resolved_at=review.resolved_at,
        created_at=review.created_at,
        updated_at=review.updated_at,
    )


def _parse_job_status(value: str | None) -> CanvasEvidenceSyncJobStatus | None:
    if not value:
        return None
    try:
        return CanvasEvidenceSyncJobStatus(value.strip().lower())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid Canvas sync job status") from exc


def _parse_candidate_state(value: str | None) -> CanvasAwardCandidateState | None:
    if not value:
        return None
    try:
        return CanvasAwardCandidateState(value.strip().lower())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid Canvas award candidate status") from exc


def _parse_review_status(value: str | None) -> EvidencePolicyReviewStatus | None:
    if not value:
        return None
    try:
        return EvidencePolicyReviewStatus(value.strip().lower())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid evidence policy review status") from exc


async def _credential_correction_handler(
    action: str,
    credential_id: str,
    reason: str,
    repo: IIssuanceRepository,
) -> None:
    request = CredentialStatusRequest(reason=reason)
    if action == "suspend":
        await suspend_credential(credential_id=credential_id, request=request, repo=repo)
    elif action == "revoke":
        await revoke_credential(credential_id=credential_id, request=request, repo=repo)
    else:  # The service only invokes this hook for lifecycle-changing actions.
        raise RuntimeError("Unsupported credential correction action")


@canvas_operations_router.post(
    "/applications/{application_id}/canvas-sync",
    response_model=CanvasSyncJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue Canvas evidence synchronization",
)
async def enqueue_canvas_application_sync_route(
    application_id: str,
    request: Request,
    repo: IIssuanceRepository = _repository_dependency,
) -> CanvasSyncJobResponse:
    organization_id = _trusted_organization_id(request)
    try:
        target, job = await enqueue_application_canvas_sync(
            repo=repo,
            organization_id=organization_id,
            application_id=application_id,
        )
    except CanvasSyncNotFoundError as exc:
        raise HTTPException(status_code=404, detail={"code": exc.code, "message": str(exc)}) from exc
    except CanvasSyncConflictError as exc:
        raise HTTPException(status_code=409, detail={"code": exc.code, "message": str(exc)}) from exc
    return _job_response(job, target)


@canvas_operations_router.get(
    "/canvas-sync-jobs",
    response_model=list[CanvasSyncJobResponse],
    summary="List Canvas synchronization job history",
)
async def list_canvas_sync_jobs_route(
    request: Request,
    organization_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    platform_id: str | None = Query(default=None),
    binding_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    repo: IIssuanceRepository = _repository_dependency,
) -> list[CanvasSyncJobResponse]:
    scoped_org = _scoped_organization_id(_trusted_organization_id(request), organization_id)
    jobs = await repo.list_canvas_sync_jobs(
        scoped_org,
        status=_parse_job_status(status_filter),
        limit=500 if (platform_id or binding_id) else limit,
    )
    responses: list[CanvasSyncJobResponse] = []
    for job in jobs:
        target = await repo.get_canvas_sync_target_for_org(scoped_org, job.target_id)
        if platform_id and (target is None or target.platform_id != platform_id):
            continue
        if binding_id and (target is None or target.binding_id != binding_id):
            continue
        responses.append(_job_response(job, target))
        if len(responses) >= limit:
            break
    return responses


@canvas_operations_router.get(
    "/canvas-sync-jobs/{job_id}",
    response_model=CanvasSyncJobResponse,
    summary="Get a Canvas synchronization job",
)
async def get_canvas_sync_job_route(
    job_id: str,
    request: Request,
    repo: IIssuanceRepository = _repository_dependency,
) -> CanvasSyncJobResponse:
    organization_id = _trusted_organization_id(request)
    job = await repo.get_canvas_sync_job_for_org(organization_id, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Canvas synchronization job not found")
    target = await repo.get_canvas_sync_target_for_org(organization_id, job.target_id)
    return _job_response(job, target)


@canvas_operations_router.post(
    "/canvas-sync-jobs/{job_id}/retry",
    response_model=CanvasSyncJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Retry a dead-letter Canvas synchronization job",
)
async def retry_canvas_sync_job_route(
    job_id: str,
    request: Request,
    repo: IIssuanceRepository = _repository_dependency,
) -> CanvasSyncJobResponse:
    organization_id = _trusted_organization_id(request)
    try:
        job = await retry_dead_letter_canvas_sync_job(
            repo=repo,
            organization_id=organization_id,
            job_id=job_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if job is None:
        raise HTTPException(status_code=404, detail="Canvas synchronization job not found")
    target = await repo.get_canvas_sync_target_for_org(organization_id, job.target_id)
    return _job_response(job, target)


@canvas_operations_router.post(
    "/canvas-sync-jobs/{job_id}/resolve",
    response_model=CanvasSyncJobResponse,
    summary="Acknowledge a Canvas synchronization dead letter",
)
async def resolve_canvas_sync_job_route(
    job_id: str,
    request: Request,
    repo: IIssuanceRepository = _repository_dependency,
) -> CanvasSyncJobResponse:
    organization_id = _trusted_organization_id(request)
    try:
        job = await resolve_dead_letter_canvas_sync_job(
            repo=repo,
            organization_id=organization_id,
            job_id=job_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if job is None:
        raise HTTPException(status_code=404, detail="Canvas synchronization job not found")
    target = await repo.get_canvas_sync_target_for_org(organization_id, job.target_id)
    return _job_response(job, target)


@canvas_operations_router.get(
    "/canvas-award-candidates",
    response_model=list[CanvasAwardCandidateResponse],
    summary="List unsigned Canvas award candidates",
)
async def list_canvas_award_candidates_route(
    request: Request,
    organization_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    platform_id: str | None = Query(default=None),
    binding_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    repo: IIssuanceRepository = _repository_dependency,
) -> list[CanvasAwardCandidateResponse]:
    scoped_org = _scoped_organization_id(_trusted_organization_id(request), organization_id)
    candidates = await repo.list_canvas_award_candidates(
        scoped_org,
        state=_parse_candidate_state(status_filter),
        binding_id=binding_id,
        limit=500 if platform_id else limit,
    )
    responses = [
        _candidate_response(candidate)
        for candidate in candidates
        if not platform_id or candidate.platform_id == platform_id
    ]
    return responses[:limit]


@canvas_operations_router.get(
    "/evidence-policy-reviews",
    response_model=list[EvidencePolicyReviewResponse],
    summary="List post-issuance Canvas evidence correction reviews",
)
async def list_evidence_policy_reviews_route(
    request: Request,
    organization_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    binding_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    repo: IIssuanceRepository = _repository_dependency,
) -> list[EvidencePolicyReviewResponse]:
    scoped_org = _scoped_organization_id(_trusted_organization_id(request), organization_id)
    reviews = await repo.list_evidence_policy_reviews(
        scoped_org,
        status=_parse_review_status(status_filter),
        limit=500 if binding_id else limit,
    )
    responses = [
        _review_response(review)
        for review in reviews
        if not binding_id or review.binding_id == binding_id
    ]
    return responses[:limit]


@canvas_operations_router.post(
    "/evidence-policy-reviews/{review_id}/resolve",
    response_model=EvidencePolicyReviewResponse,
    summary="Resolve a Canvas evidence correction review",
)
async def resolve_evidence_policy_review_route(
    review_id: str,
    payload: EvidencePolicyReviewResolveRequest,
    request: Request,
    repo: IIssuanceRepository = _repository_dependency,
) -> EvidencePolicyReviewResponse:
    organization_id = _trusted_organization_id(request)
    resolved_by = (
        request.headers.get("x-authenticated-user-id")
        or request.headers.get("x-user-id")
        or request.headers.get("x-api-key-id")
    )
    try:
        review = await resolve_evidence_policy_review(
            repo=repo,
            organization_id=organization_id,
            review_id=review_id,
            action=payload.action,
            notes=payload.note,
            resolved_by=resolved_by,
            credential_handler=_credential_correction_handler,
        )
    except CanvasSyncNotFoundError as exc:
        raise HTTPException(status_code=404, detail={"code": exc.code, "message": str(exc)}) from exc
    except CanvasSyncConflictError as exc:
        raise HTTPException(status_code=409, detail={"code": exc.code, "message": str(exc)}) from exc
    return _review_response(review)
