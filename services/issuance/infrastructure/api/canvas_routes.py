"""Canvas integration routes for issuance."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import quote, urlencode, urljoin, urlparse

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from issuance.application.application_approval import (
    approve_application_for_issuance,
    credential_context_from_template_snapshot,
)
from issuance.application.canvas_evidence_revisions import (
    record_authoritative_canvas_evidence_revision,
)
from issuance.application.canvas_feature_flags import (
    legacy_canvas_event_ingest_enabled,
    portable_canvas_enabled_for_organization,
)
from issuance.application.canvas_identity import (
    link_verified_canvas_learner_identity,
    record_verified_canvas_lti_subject,
)
from issuance.application.canvas_issuance_guard import (
    CanvasIssuanceGuardError,
    canvas_approval_credential_context,
    canvas_evidence_observation_is_fresh,
)
from issuance.application.canvas_lti_services import (
    AGS_RESULT_READ_SCOPE,
    CANVAS_COLLECTION_MAX_PAGES,
    CANVAS_COLLECTION_PAGE_MAX_BYTES,
    NRPS_MEMBERSHIP_READ_SCOPE,
    CanvasLtiServiceError,
    canvas_http_client,
    canvas_lti_trust_profile,
    parse_canvas_retry_after,
    probe_canvas_lti_platform,
    read_ags_results,
    read_limited_canvas_json_response,
    read_nrps_memberships,
    request_lti_access_token,
    resolve_canvas_lti_trust_profile,
    validate_canvas_origin,
    validate_lti_service_url,
)
from issuance.application.canvas_oauth import (
    CanvasOAuthError,
    canvas_oauth_authorization_url,
    canvas_oauth_scopes_for_capabilities,
    exchange_canvas_oauth_code,
    normalize_canvas_oauth_capabilities,
    refresh_canvas_oauth_token,
    revoke_canvas_oauth_token,
)
from issuance.application.canvas_oauth_persistence import (
    queue_canvas_oauth_revocation,
)
from issuance.application.canvas_readiness import (
    apply_canvas_readiness_result,
    canvas_binding_is_ready_for_activation,
    evaluate_canvas_binding_readiness,
    verified_canvas_binding_capabilities,
)
from issuance.application.canvas_runtime import (
    canvas_feature_enabled,
    canvas_scope_matches,
    lti_verified_launch_to_canvas_scope,
    normalize_canvas_feature_flags,
    resolve_canvas_program_binding_for_scope,
)
from issuance.application.canvas_sync_service import (
    CanvasSyncConflictError,
    CanvasSyncNotFoundError,
    CanvasSyncProcessingError,
    CanvasSyncServiceError,
    enqueue_application_canvas_sync,
    validate_canvas_sync_target,
)
from issuance.application.mip_integration_primitives import (
    canvas_lti_launch_to_mip_experience,
)
from issuance.application.rust_integration import (
    verify_canvas_lti_launch,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    CanvasAwardCandidate,
    CanvasAwardCandidateState,
    CanvasCandidateObservation,
    CanvasEvidenceFactType,
    CanvasEvidenceRequirement,
    CanvasEvidenceSource,
    CanvasEvidenceSyncJob,
    CanvasEvidenceSyncJobStatus,
    CanvasEvidenceSyncTarget,
    CanvasEvidenceSyncTargetType,
    CanvasLearnerIdentity,
    CanvasLearnerIdentityStatus,
    CanvasLtiLaunchState,
    CanvasOAuthAuthorization,
    CanvasOAuthConnection,
    CanvasOAuthConnectionStatus,
    CanvasPlatform,
    CanvasProgramBinding,
    CredentialDeliveryRecord,
    CredentialDeliveryStatus,
    DeliveryTarget,
    EventType,
    EvidenceFact,
    IssuanceEvent,
    OrganizationIntegrationSecret,
    validate_canvas_evidence_requirements,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.canvas_credentials_adapter import (
    CanvasCredentialsConfigValidationResult,
    CanvasEvidenceEventResponse,
    process_canvas_ags_score_event,
    process_canvas_evidence_event,
    process_canvas_nrps_membership_event,
    validate_canvas_credentials_config,
)
from issuance.infrastructure.api.routes import (
    _verify_management_api_key,
    apply_required_remote_issuer_context,
)
from issuance.infrastructure.api.signing_context import sign_payload_with_remote_service
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.responses import RedirectResponse

canvas_integration_router = APIRouter(prefix="/v1/integrations/canvas", tags=["canvas-integrations"])
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "http://localhost:8000").rstrip("/")
CANVAS_LTI_EXPERIENCE_BASE_URL = (
    os.environ.get("CANVAS_LTI_EXPERIENCE_BASE_URL")
    or os.environ.get("UI_BASE_URL")
    or ISSUER_BASE_URL
).rstrip("/")
CANVAS_LTI_JWKS_TTL_MINUTES = int(os.environ.get("CANVAS_LTI_JWKS_TTL_MINUTES", "1440"))
CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS = int(os.environ.get("CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS", "60"))
CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES = int(os.environ.get("CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES", "30"))
CREDENTIAL_TEMPLATE_SERVICE_URL = os.environ.get(
    "CREDENTIAL_TEMPLATE_SERVICE_URL", "http://credential-template:8000"
).rstrip("/")
REVOCATION_PROFILE_SERVICE_URL = os.environ.get(
    "REVOCATION_PROFILE_SERVICE_URL", "http://revocation-profile:8000"
).rstrip("/")
LTI_MESSAGE_TYPE_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/message_type"
LTI_VERSION_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/version"
LTI_DEPLOYMENT_ID_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/deployment_id"
LTI_DEEP_LINKING_SETTINGS_CLAIM = "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings"
LTI_DEEP_LINKING_CONTENT_ITEMS_CLAIM = "https://purl.imsglobal.org/spec/lti-dl/claim/content_items"
LTI_DEEP_LINKING_DATA_CLAIM = "https://purl.imsglobal.org/spec/lti-dl/claim/data"
LTI_AGS_ENDPOINT_CLAIM = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"
LTI_NRPS_CLAIM = "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice"


class CanvasPlatformCreate(BaseModel):
    """Caller-writable Canvas platform draft fields.

    Trust metadata, account ownership, capabilities and connection state are
    server-derived and intentionally absent from this contract.
    """

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, max_length=200)
    canvas_base_url: str = Field(min_length=1, max_length=2048)
    lti_client_id: str | None = Field(default=None, max_length=512)
    lti_deployment_id: str | None = Field(default=None, max_length=512)
    enabled: bool = False


class CanvasPlatformResponse(BaseModel):
    id: str
    organization_id: str
    canvas_account_id: str
    display_name: str | None = None
    canvas_base_url: str | None = None
    lti_client_id: str | None = None
    lti_deployment_id: str | None = None
    lti_trust_profile: Literal[
        "hosted_global", "self_managed_same_origin"
    ] = "hosted_global"
    lti_issuer: str | None = None
    lti_jwks_url: str | None = None
    lti_jwks_fetched_at: str | None = None
    lti_jwks_expires_at: str | None = None
    registration_status: str = "draft"
    connection_config: dict[str, Any] = Field(default_factory=dict)
    capability_snapshot: dict[str, Any] = Field(default_factory=dict)
    last_validated_at: str | None = None
    last_connection_error: str | None = None
    config_version: int = 1
    archived_at: str | None = None
    enabled: bool
    created_at: str
    updated_at: str


class CanvasEvidenceScopeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    course_id: str = Field(min_length=1, max_length=512)
    activity_id: str | None = Field(default=None, max_length=512)
    module_id: str | None = Field(default=None, max_length=512)
    line_item_url: str | None = Field(default=None, max_length=2048)
    resource_id: str | None = Field(default=None, max_length=1024)


class CanvasEvidencePassRuleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_score_percent: float | None = Field(default=None, ge=0, le=100)
    completed: bool | None = None


class CanvasEvidenceRequirementInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requirement_id: str | None = Field(default=None, max_length=512)
    source: Literal["ags_result", "canvas_rest"]
    fact_type: Literal[
        "canvas.assignment_score",
        "canvas.quiz_score",
        "canvas.course_completion",
        "canvas.module_completion",
    ]
    scope: CanvasEvidenceScopeInput
    pass_rule: CanvasEvidencePassRuleInput
    required: bool = True


class CanvasCredentialsConfigInput(BaseModel):
    """Tenant-writable optional projection settings with no secret selectors."""

    model_config = ConfigDict(extra="forbid")

    provider: Literal["badgr_api", "canvas_credentials_api", "bridge"] | None = None
    api_base_url: str | None = None
    issuer_id: str | None = None
    badgeclass_id: str | None = None
    assertion_scope: Literal["badgeclasses", "issuers"] | None = None
    api_token_secret_id: str | None = None
    credential_template_id: str | None = None


class CanvasProgramBindingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_template_id: str = Field(min_length=1, max_length=512)
    credential_template_id: str | None = Field(default=None, max_length=512)
    display_name: str | None = Field(default=None, max_length=200)
    auto_approve_on_evidence: bool = False
    evidence_requirements: list[CanvasEvidenceRequirementInput] = Field(min_length=1)
    canvas_scope: dict[str, str] = Field(default_factory=dict)
    delivery_mode: Literal["wallet_only", "wallet_plus_canvas_mirror"] = "wallet_only"
    approval_policy_set_id: str | None = None
    deployment_profile_id: str | None = None
    feature_flags: dict[str, bool] = Field(default_factory=dict)
    canvas_credentials: CanvasCredentialsConfigInput | None = None

    @field_validator("canvas_scope")
    @classmethod
    def validate_canvas_scope_keys(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {
            "course_id",
            "assignment_id",
            "module_id",
            "quiz_id",
            "resource_link_id",
        }
        unsupported = sorted(set(value) - allowed)
        if unsupported:
            raise ValueError(
                "Unsupported Canvas binding scope fields: " + ", ".join(unsupported)
            )
        return {key: item.strip() for key, item in value.items() if item.strip()}


class CanvasProgramBindingResponse(BaseModel):
    id: str
    organization_id: str
    platform_id: str
    canvas_account_id: str
    application_template_id: str
    credential_template_id: str
    display_name: str | None = None
    flow_mode: str
    direct_issue_enabled: bool
    auto_approve_on_evidence: bool
    evidence_requirements: list[dict[str, Any]]
    canvas_scope: dict[str, str]
    delivery_mode: str
    issuer_mode: str
    approval_policy_set_id: str | None = None
    deployment_profile_id: str | None = None
    feature_flags: dict[str, bool] = Field(default_factory=dict)
    canvas_credentials: dict[str, Any] = Field(default_factory=dict)
    config_version: int = 1
    validated_config_version: int | None = None
    readiness_checks: list[dict[str, Any]] = Field(default_factory=list)
    readiness_validated_at: str | None = None
    activated_at: str | None = None
    archived_at: str | None = None
    enabled: bool
    created_at: str
    updated_at: str


class CanvasCredentialsValidationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str | None = None
    canvas_credentials: CanvasCredentialsConfigInput


class CanvasLtiEvidenceJobStatus(BaseModel):
    """Browser-safe status for the exact application target in this session."""

    job_id: str
    status: Literal[
        "queued",
        "running",
        "retrying",
        "succeeded",
        "failed",
        "cancelled",
    ]
    requested_at: str
    completed_at: str | None = None


class CanvasLtiEvidenceSummary(BaseModel):
    required_count: int = 0
    current_authoritative_count: int = 0
    verified_authoritative_count: int = 0
    verified_required_count: int = 0
    status: Literal[
        "not_required",
        "not_observed",
        "syncing",
        "partial",
        "verified",
    ] = "not_observed"
    last_observed_at: str | None = None


class CanvasLtiEvidencePolicyStatus(BaseModel):
    status: Literal["not_evaluated", "permitted", "not_permitted"] = "not_evaluated"


class CanvasLtiClaimStatus(BaseModel):
    status: Literal[
        "not_available",
        "pending_claim",
        "ready_to_claim",
        "claimed",
    ] = "not_available"
    unsigned: bool = False
    available: bool = False


class CanvasLtiApplicationEvidenceStatusResponse(BaseModel):
    application_status: str
    sync: CanvasLtiEvidenceJobStatus | None = None
    evidence: CanvasLtiEvidenceSummary
    policy: CanvasLtiEvidencePolicyStatus
    claim: CanvasLtiClaimStatus


class CanvasLtiRegistrationResponse(BaseModel):
    platform_id: str
    developer_key_configuration: dict[str, Any]
    installation: dict[str, str]


class CanvasLtiInstallationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lti_client_id: str = Field(min_length=1)
    lti_deployment_id: str = Field(min_length=1)
    rotate_config_token: bool = False
    revoke_config_token: bool = False


class CanvasOAuthStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: str = Field(min_length=1, max_length=512)
    client_secret_secret_id: str = Field(min_length=1, max_length=512)
    capabilities: list[str] = Field(min_length=1, max_length=5)


class CanvasOAuthStartResponse(BaseModel):
    authorization_url: str
    redirect_uri: str
    scopes: list[str]


class CanvasOAuthConnectionResponse(BaseModel):
    platform_id: str
    status: str
    scopes: list[str] = Field(default_factory=list)


class CanvasReadinessCheck(BaseModel):
    code: str
    component: str
    status: str
    blocking: bool
    remediation: str
    timestamp: str


class CanvasProgramBindingValidationResponse(BaseModel):
    binding_id: str
    ready: bool
    valid: bool
    active: bool
    config_version: int
    evaluated_at: str | None = None
    checks: list[CanvasReadinessCheck] = Field(default_factory=list)


class CanvasPlatformReadinessResponse(BaseModel):
    platform_id: str
    ready: bool
    checks: list[CanvasReadinessCheck]


class CanvasIntegrationSecretCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=512)
    name: str = Field(min_length=1, max_length=200)
    provider: Literal["canvas", "canvas_credentials"] = "canvas_credentials"
    purpose: Literal["oauth_client_secret", "api_token"] = "api_token"
    secret_value: str = Field(min_length=1, max_length=16384)
    metadata: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    @model_validator(mode="after")
    def validate_provider_purpose(self) -> CanvasIntegrationSecretCreate:
        expected_purpose = {
            "canvas": "oauth_client_secret",
            "canvas_credentials": "api_token",
        }[self.provider]
        if self.purpose != expected_purpose:
            raise ValueError(
                f"Canvas integration secret provider {self.provider} requires purpose {expected_purpose}"
            )
        return self


class CanvasIntegrationSecretUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    secret_value: str | None = None
    metadata: dict[str, Any] | None = None
    enabled: bool | None = None


class CanvasIntegrationSecretResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    provider: str
    purpose: str
    secret_ref: str
    secret_hint: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    enabled: bool
    created_at: str
    updated_at: str
    last_used_at: str | None = None


class CanvasScopeDiscoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    course_id: str | None = None
    include_courses: bool = True
    include_assignments: bool = True
    include_quizzes: bool = True
    include_modules: bool = True
    limit: int = Field(default=50, ge=1, le=100)


class CanvasScopeItem(BaseModel):
    id: str
    name: str
    type: str
    url: str | None = None
    published: bool | None = None
    points_possible: float | None = None


class CanvasScopeDiscoveryResponse(BaseModel):
    platform_id: str
    organization_id: str
    canvas_base_url: str
    course_id: str | None = None
    courses: list[CanvasScopeItem] = Field(default_factory=list)
    assignments: list[CanvasScopeItem] = Field(default_factory=list)
    quizzes: list[CanvasScopeItem] = Field(default_factory=list)
    modules: list[CanvasScopeItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    fetched_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CanvasPlatformSandboxProbeResponse(BaseModel):
    platform: CanvasPlatformResponse
    probe: dict[str, Any]


class CanvasPlatformJwksRefreshResponse(BaseModel):
    platform: CanvasPlatformResponse
    refreshed: bool = True
    probe: dict[str, Any]


class CanvasProgramBindingEvidenceFlowResponse(BaseModel):
    platform: CanvasPlatformResponse
    binding: CanvasProgramBindingResponse
    flow: dict[str, Any]


class CanvasEvidenceEventStatusResponse(BaseModel):
    id: str
    provider_event_id: str
    canvas_account_id: str | None = None
    organization_id: str
    credential_template_id: str
    application_id: str | None = None
    status: str
    payload_hash: str
    issuance_transaction_id: str | None = None
    error_summary: str | None = None
    first_seen_at: str
    last_seen_at: str
    response: dict[str, Any]
    evidence_facts: list[dict[str, Any]] = Field(default_factory=list)
    policy_decision: dict[str, Any] | None = None
    replay_available: bool = True


class CanvasLtiLaunchResponse(BaseModel):
    organization_id: str
    canvas_account_id: str
    canvas_platform_id: str
    canvas_program_binding_id: str | None = None
    application_template_id: str | None = None
    credential_template_id: str | None = None
    delivery_mode: str = "wallet_only"
    deployment_profile_id: str | None = None
    feature_flags: dict[str, bool] = Field(default_factory=dict)
    evidence_requirements: list[Any] = Field(default_factory=list)
    state: str | None = None
    verified: bool = True
    issuer: str
    subject: str
    audience: list[str]
    deployment_id: str
    nonce: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None
    message_type: str | None = None
    lti_version: str | None = None
    target_link_uri: str | None = None
    context: dict[str, Any] | None = None
    roles: list[str]
    learner_identity: dict[str, Any]
    raw_claims: dict[str, Any]
    lti_capabilities: dict[str, Any] = Field(default_factory=dict)
    identity_mapping_status: str | None = None


class CanvasLtiPublicLaunchResponse(BaseModel):
    """Browser-safe launch acknowledgement; verified claims remain server-side."""

    verified: bool = True
    organization_id: str
    canvas_account_id: str
    canvas_platform_id: str
    canvas_program_binding_id: str
    application_template_id: str | None = None
    credential_template_id: str | None = None
    message_type: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    roles: list[str] = Field(default_factory=list)
    identity_mapping_status: str | None = None


class CanvasLtiExperienceSessionResponse(BaseModel):
    organization_id: str
    canvas_account_id: str
    canvas_platform_id: str
    canvas_program_binding_id: str | None = None
    application_template_id: str | None = None
    credential_template_id: str | None = None
    status: str
    application_id: str | None = None
    lti_capabilities: dict[str, Any] = Field(default_factory=dict)
    canvas_context: dict[str, Any] = Field(default_factory=dict)
    roles: list[str] = Field(default_factory=list)
    learner_display_name: str | None = None
    learner_key: str
    identity_mapping_status: str | None = None


class CanvasLtiExperienceCodeExchangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=32, max_length=256)


class CanvasLtiExperienceCodeExchangeResponse(BaseModel):
    session_token: str
    expires_at: str


class CanvasLtiApplicationBootstrapRequest(BaseModel):
    applicant_identifier: str | None = None
    applicant_data: dict[str, Any] = Field(default_factory=dict)


class CanvasLtiApplicationBootstrapResponse(BaseModel):
    application_id: str
    application_status: str
    created: bool
    organization_id: str
    application_template_id: str
    credential_template_id: str | None = None
    canvas_account_id: str
    canvas_platform_id: str | None = None
    canvas_program_binding_id: str | None = None
    canvas_context: dict[str, Any] = Field(default_factory=dict)


class CanvasApplicationApprovalRequest(BaseModel):
    """Canvas-only manual approval input from an authenticated administrator."""

    model_config = ConfigDict(extra="forbid")

    review_notes: str | None = Field(default=None, max_length=4000)


class CanvasApplicationApprovalResponse(BaseModel):
    """Sanitized result; applicant data and signing configuration stay internal."""

    application_id: str
    status: Literal["approved"]
    issuance_transaction_id: str


class CanvasLtiDeepLinkingRequest(BaseModel):
    """A confirmation-only request; all Canvas content-item data is server-owned."""

    model_config = ConfigDict(extra="forbid")


class CanvasLtiDeepLinkingResponse(BaseModel):
    canvas_platform_id: str
    organization_id: str
    canvas_account_id: str
    deep_link_return_url: str
    content_items: list[dict[str, Any]]
    jwt: str
    form_post: dict[str, Any]


async def _request_payload(request: Request) -> dict[str, Any]:
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON body") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Canvas LTI JSON body must be an object")
        return payload

    form = await request.form()
    return dict(form)


def _payload_str(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _lti_session_bearer_token(request: Request) -> str:
    authorization = (request.headers.get("authorization") or "").strip()
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail="Canvas LTI experience session bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token.strip()


def _trusted_canvas_organization_id(request: Request) -> str:
    organization_id = (request.headers.get("x-organization-id") or "").strip()
    if not organization_id:
        raise HTTPException(status_code=400, detail="X-Organization-ID is required for Canvas management")
    return organization_id


def _management_organization_id(trusted: Any, claimed: str | None = None) -> str:
    """Resolve the gateway-trusted org; the fallback only supports direct unit invocation."""

    if isinstance(trusted, str) and trusted.strip():
        organization_id = trusted.strip()
        if claimed is not None and claimed.strip() != organization_id:
            raise HTTPException(status_code=404, detail="Canvas resource not found")
        return organization_id
    if claimed is not None and claimed.strip():
        return claimed.strip()
    return ""


async def _management_canvas_platform(
    *,
    repo: IIssuanceRepository,
    platform_id: str,
    trusted_organization_id: Any,
) -> CanvasPlatform:
    if isinstance(trusted_organization_id, str) and trusted_organization_id.strip():
        platform = await repo.get_canvas_platform_for_org(trusted_organization_id.strip(), platform_id)
    else:  # Direct unit invocation; FastAPI always resolves the trusted dependency.
        platform = await repo.get_canvas_platform(platform_id)
    if platform is None or platform.archived_at is not None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
    return platform


async def _management_canvas_binding(
    *,
    repo: IIssuanceRepository,
    binding_id: str,
    trusted_organization_id: Any,
) -> CanvasProgramBinding:
    if isinstance(trusted_organization_id, str) and trusted_organization_id.strip():
        binding = await repo.get_canvas_program_binding_for_org(trusted_organization_id.strip(), binding_id)
    else:  # Direct unit invocation; FastAPI always resolves the trusted dependency.
        binding = await repo.get_canvas_program_binding(binding_id)
    if binding is None or binding.archived_at is not None:
        raise HTTPException(status_code=404, detail="Canvas program binding not found")
    return binding


async def _management_canvas_application(
    *,
    repo: IIssuanceRepository,
    application_id: str,
    trusted_organization_id: str,
) -> tuple[Application, CanvasProgramBinding, CanvasPlatform]:
    """Resolve an owned Canvas application without crossing tenant boundaries."""

    organization_id = trusted_organization_id.strip()
    app = await repo.get_application(application_id)
    if app is None or app.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Canvas application not found")

    integration_context = (
        app.integration_context if isinstance(app.integration_context, dict) else {}
    )
    canvas_context = integration_context.get("canvas")
    if not isinstance(canvas_context, dict):
        # This endpoint must never become a generic application approval path.
        raise HTTPException(status_code=404, detail="Canvas application not found")

    platform_id = str(canvas_context.get("canvas_platform_id") or "").strip()
    binding_id = str(canvas_context.get("canvas_program_binding_id") or "").strip()
    if not platform_id or not binding_id:
        raise HTTPException(
            status_code=409,
            detail="Canvas application is not ready for approval",
        )

    platform = await repo.get_canvas_platform_for_org(organization_id, platform_id)
    binding = await repo.get_canvas_program_binding_for_org(organization_id, binding_id)
    if (
        platform is None
        or binding is None
        or platform.archived_at is not None
        or binding.archived_at is not None
    ):
        raise HTTPException(status_code=404, detail="Canvas application not found")
    if binding.platform_id != platform.id:
        raise HTTPException(
            status_code=409,
            detail="Canvas application is not ready for approval",
        )
    return app, binding, platform


async def _invalidate_canvas_binding_readiness(
    *,
    repo: IIssuanceRepository,
    platform: CanvasPlatform,
) -> None:
    now = datetime.now(timezone.utc)
    for binding in await repo.list_canvas_program_bindings(
        platform.organization_id,
        platform_id=platform.id,
    ):
        if binding.archived_at is not None:
            continue
        binding.enabled = False
        binding.validated_config_version = None
        binding.readiness_checks = []
        binding.readiness_validated_at = None
        binding.activated_at = None
        binding.updated_at = now
        await repo.save_canvas_program_binding(binding)


def _canvas_oauth_redirect_uri() -> str:
    return f"{ISSUER_BASE_URL}/v1/integrations/canvas/oauth/callback"


def _canvas_oauth_completion_url(
    platform_id: str | None,
    *,
    outcome: str,
    error_code: str | None = None,
) -> str:
    base = (
        os.environ.get("CANVAS_OAUTH_COMPLETION_REDIRECT_URL")
        or f"{CANVAS_LTI_EXPERIENCE_BASE_URL}/console/integrations/canvas"
    ).strip()
    parsed = urlparse(base)
    is_local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        (parsed.scheme != "https" and not is_local_http)
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise HTTPException(status_code=409, detail="Canvas OAuth completion redirect must be a trusted HTTPS URL")
    params = {"outcome": outcome}
    if platform_id:
        params["platform_id"] = platform_id
    if error_code:
        params["error_code"] = error_code
    separator = "&" if parsed.query else "?"
    return f"{base}{separator}{urlencode(params)}"


def _normalize_canvas_base_url_or_none(canvas_base_url: str | None) -> str | None:
    if canvas_base_url is None:
        return None
    value = canvas_base_url.strip()
    if not value:
        raise HTTPException(status_code=400, detail="Canvas base URL must be a non-empty HTTPS URL")
    try:
        # Use the same DNS-pinned, exact-origin private allowlist policy as all
        # subsequent Canvas traffic.  The former Rust wrapper exposed only a
        # broad allow-private switch and made an operator allowlist unusable.
        return validate_canvas_origin(value)
    except CanvasLtiServiceError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid Canvas base URL: {exc}") from exc


def _platform_from_request(
    request: CanvasPlatformCreate,
    *,
    organization_id: str,
    existing: CanvasPlatform | None = None,
) -> CanvasPlatform:
    platform = existing or CanvasPlatform(organization_id=organization_id)
    now = datetime.now(timezone.utc)
    if existing is None:
        # Numeric Canvas account IDs may only be learned from a verified signed
        # custom claim.  A unique internal value keeps draft rows distinct.
        platform.canvas_account_id = f"unverified:{platform.id}"
    previous = (
        platform.display_name,
        platform.canvas_base_url,
        platform.lti_client_id,
        platform.lti_deployment_id,
        platform.lti_trust_profile,
        bool((platform.connection_config or {}).get("enabled_intent")),
    )
    platform.display_name = request.display_name
    platform.canvas_base_url = _normalize_canvas_base_url_or_none(request.canvas_base_url)
    platform.lti_trust_profile = resolve_canvas_lti_trust_profile(
        platform.canvas_base_url or request.canvas_base_url
    )
    platform.lti_client_id = request.lti_client_id
    platform.lti_deployment_id = request.lti_deployment_id
    config = dict(platform.connection_config or {})
    config["enabled_intent"] = bool(request.enabled)
    # Both service families are part of the approved v1 product surface.  The
    # registration generator still derives the actual scopes from this
    # server-owned intent, never from caller-provided raw scopes.
    config.setdefault("lti_capability_intent", ["ags", "nrps"])
    platform.connection_config = config
    current = (
        platform.display_name,
        platform.canvas_base_url,
        platform.lti_client_id,
        platform.lti_deployment_id,
        platform.lti_trust_profile,
        bool(config.get("enabled_intent")),
    )
    if existing is None:
        platform.enabled = False
        platform.registration_status = "draft"
    elif current != previous:
        platform.config_version += 1
        platform.enabled = False
        platform.registration_status = "draft"
        platform.capability_snapshot = {}
        platform.last_validated_at = None
        platform.last_connection_error = None
        if (
            platform.canvas_base_url != previous[1]
            or platform.lti_trust_profile != previous[4]
        ):
            platform.lti_issuer = None
            platform.lti_jwks_url = None
            platform.lti_jwks_json = None
            platform.lti_jwks_fetched_at = None
            platform.lti_jwks_expires_at = None
            platform.lti_openid_configuration = None
    platform.archived_at = None
    platform.updated_at = now
    return platform


def _platform_to_response(platform: CanvasPlatform) -> CanvasPlatformResponse:
    config = dict(platform.connection_config or {})
    safe_config = {
        key: config[key]
        for key in (
            "enabled_intent",
            "oauth_client_id",
            "oauth_status",
            "oauth_capabilities",
            "granted_scopes",
            "lti_config_token_status",
        )
        if key in config
    }
    return CanvasPlatformResponse(
        id=platform.id,
        organization_id=platform.organization_id,
        canvas_account_id=platform.canvas_account_id,
        display_name=platform.display_name,
        canvas_base_url=platform.canvas_base_url,
        lti_client_id=platform.lti_client_id,
        lti_deployment_id=platform.lti_deployment_id,
        lti_trust_profile=platform.lti_trust_profile,
        lti_issuer=platform.lti_issuer,
        lti_jwks_url=platform.lti_jwks_url,
        lti_jwks_fetched_at=platform.lti_jwks_fetched_at.isoformat() if platform.lti_jwks_fetched_at else None,
        lti_jwks_expires_at=platform.lti_jwks_expires_at.isoformat() if platform.lti_jwks_expires_at else None,
        registration_status=platform.registration_status or "draft",
        connection_config=safe_config,
        capability_snapshot=dict(platform.capability_snapshot or {}),
        last_validated_at=platform.last_validated_at.isoformat() if platform.last_validated_at else None,
        last_connection_error=platform.last_connection_error,
        config_version=platform.config_version,
        archived_at=platform.archived_at.isoformat() if platform.archived_at else None,
        enabled=platform.enabled,
        created_at=platform.created_at.isoformat(),
        updated_at=platform.updated_at.isoformat(),
    )


def _binding_to_response(
    binding: CanvasProgramBinding,
    platform: CanvasPlatform,
) -> CanvasProgramBindingResponse:
    return CanvasProgramBindingResponse(
        id=binding.id,
        organization_id=binding.organization_id,
        platform_id=binding.platform_id,
        canvas_account_id=platform.canvas_account_id,
        application_template_id=binding.application_template_id,
        credential_template_id=binding.credential_template_id,
        display_name=binding.display_name,
        flow_mode=binding.flow_mode,
        direct_issue_enabled=binding.direct_issue_enabled,
        auto_approve_on_evidence=binding.auto_approve_on_evidence,
        evidence_requirements=[
            requirement.to_dict() if isinstance(requirement, CanvasEvidenceRequirement) else requirement
            for requirement in (binding.evidence_requirements or [])
        ],
        canvas_scope=binding.canvas_scope or {},
        delivery_mode=binding.delivery_mode,
        issuer_mode=binding.issuer_mode,
        approval_policy_set_id=binding.approval_policy_set_id,
        deployment_profile_id=binding.deployment_profile_id,
        feature_flags=normalize_canvas_feature_flags(binding.feature_flags),
        canvas_credentials=binding.canvas_credentials or {},
        config_version=binding.config_version,
        validated_config_version=binding.validated_config_version,
        readiness_checks=list(binding.readiness_checks or []),
        readiness_validated_at=(
            binding.readiness_validated_at.isoformat() if binding.readiness_validated_at else None
        ),
        activated_at=binding.activated_at.isoformat() if binding.activated_at else None,
        archived_at=binding.archived_at.isoformat() if binding.archived_at else None,
        enabled=binding.enabled,
        created_at=binding.created_at.isoformat(),
        updated_at=binding.updated_at.isoformat(),
    )


def _secret_to_response(secret: OrganizationIntegrationSecret) -> CanvasIntegrationSecretResponse:
    return CanvasIntegrationSecretResponse(
        id=secret.id,
        organization_id=secret.organization_id,
        name=secret.name,
        provider=secret.provider,
        purpose=secret.purpose,
        secret_ref=secret.secret_ref,
        secret_hint=secret.secret_hint,
        metadata=secret.metadata or {},
        enabled=secret.enabled,
        created_at=secret.created_at.isoformat(),
        updated_at=secret.updated_at.isoformat(),
        last_used_at=secret.last_used_at.isoformat() if secret.last_used_at else None,
    )


def _read_secret_file(file_path: str | None) -> str:
    if not file_path:
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


async def _canvas_admin_token(
    *,
    platform: CanvasPlatform,
    repo: IIssuanceRepository,
) -> str:
    oauth_token = await _canvas_oauth_access_token(platform=platform, repo=repo)
    if oauth_token:
        return oauth_token
    allow_local_fallback = os.environ.get(
        "CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK",
        "",
    ).strip().lower() in {"1", "true", "yes", "on"}
    environment = os.environ.get("ENVIRONMENT", os.environ.get("APP_ENV", "development")).lower()
    if not allow_local_fallback or environment in {"production", "prod"}:
        return ""
    # Explicit local simulator/test compatibility only.
    token = os.environ.get("CANVAS_ADMIN_API_TOKEN", "").strip()
    if token:
        return token
    token_file = os.environ.get("CANVAS_ADMIN_API_TOKEN_FILE", "").strip()
    if token_file:
        return _read_secret_file(token_file)
    return ""


async def _canvas_oauth_access_token(
    *,
    platform: CanvasPlatform,
    repo: IIssuanceRepository,
) -> str:
    if platform.archived_at is not None:
        return ""
    connection = await repo.get_canvas_oauth_connection(platform.organization_id, platform.id)
    if (
        connection is None
        or connection.status != CanvasOAuthConnectionStatus.CONNECTED
        or connection.reauthorization_required
    ):
        return ""
    if (
        not connection.canvas_base_url
        or connection.canvas_base_url != str(platform.canvas_base_url or "")
        or connection.platform_config_version != platform.config_version
    ):
        marked = await repo.mark_canvas_oauth_reauthorization_required(
            platform.organization_id,
            platform.id,
            expected_updated_at=connection.updated_at,
        )
        if marked is not None:
            await repo.patch_canvas_platform_validation_state(
                platform.organization_id,
                platform.id,
                expected_config_version=platform.config_version,
                last_validated_at=platform.last_validated_at,
                last_connection_error="oauth_reauthorization_required",
            )
        return ""

    access_secret_id = _integration_secret_id_from_ref(
        platform.organization_id,
        connection.access_token_secret_ref,
    )
    access_token = (
        await repo.get_integration_secret_value(platform.organization_id, access_secret_id)
        if access_secret_id
        else None
    )
    now = datetime.now(timezone.utc)
    if access_token and (
        connection.token_expires_at is None
        or connection.token_expires_at > now + timedelta(seconds=60)
    ):
        return access_token

    lease_owner = f"oauth-refresh:{uuid.uuid4()}"
    leased = await repo.acquire_canvas_oauth_refresh_lease(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        lease_owner=lease_owner,
        lease_seconds=60,
    )
    if leased is None:
        # Another process owns refresh.  Do not issue a concurrent refresh or
        # serve an expired token; the caller can retry safely.
        current = await repo.get_canvas_oauth_connection(platform.organization_id, platform.id)
        if (
            current is not None
            and current.canvas_base_url == str(platform.canvas_base_url or "")
            and current.platform_config_version == platform.config_version
            and current.token_expires_at
            and current.token_expires_at > now + timedelta(seconds=60)
        ):
            current_id = _integration_secret_id_from_ref(
                platform.organization_id,
                current.access_token_secret_ref,
            )
            return (
                await repo.get_integration_secret_value(platform.organization_id, current_id)
                if current_id
                else ""
            ) or ""
        return ""

    refresh_secret_id = _integration_secret_id_from_ref(
        platform.organization_id,
        leased.refresh_token_secret_ref,
    )
    client_secret_id = _integration_secret_id_from_ref(
        platform.organization_id,
        leased.client_secret_ref,
    )
    refresh_token = (
        await repo.get_integration_secret_value(platform.organization_id, refresh_secret_id)
        if refresh_secret_id
        else None
    )
    client_secret = (
        await repo.get_integration_secret_value(platform.organization_id, client_secret_id)
        if client_secret_id
        else None
    )
    if not all((refresh_token, client_secret, leased.client_id, leased.canvas_base_url)):
        await repo.release_canvas_oauth_refresh_lease(
            organization_id=platform.organization_id,
            platform_id=platform.id,
            lease_owner=lease_owner,
            reauthorization_required=True,
        )
        return ""
    try:
        async with canvas_http_client(timeout=15.0) as client:
            refreshed = await refresh_canvas_oauth_token(
                client=client,
                canvas_base_url=leased.canvas_base_url,
                client_id=leased.client_id,
                client_secret=str(client_secret),
                refresh_token=str(refresh_token),
            )
    except CanvasOAuthError as exc:
        error_text = str(exc)
        invalid_grant = any(code in error_text for code in ("HTTP 400", "HTTP 401", "HTTP 403"))
        await repo.release_canvas_oauth_refresh_lease(
            organization_id=platform.organization_id,
            platform_id=platform.id,
            lease_owner=lease_owner,
            reauthorization_required=invalid_grant,
        )
        await repo.patch_canvas_platform_validation_state(
            platform.organization_id,
            platform.id,
            expected_config_version=platform.config_version,
            last_validated_at=platform.last_validated_at,
            last_connection_error=(
                "oauth_reauthorization_required"
                if invalid_grant
                else "oauth_refresh_failed"
            ),
        )
        if exc.retry_after_seconds is not None:
            raise CanvasLtiServiceError(
                "Canvas OAuth refresh was rate limited",
                retry_after_seconds=exc.retry_after_seconds,
            ) from exc
        return ""

    old_access_secret_id = _integration_secret_id_from_ref(
        platform.organization_id,
        leased.access_token_secret_ref,
    )
    old_refresh_secret_id = refresh_secret_id
    access_secret_id = str(uuid.uuid4())
    access_secret = OrganizationIntegrationSecret(
        id=access_secret_id,
        organization_id=platform.organization_id,
        name=f"Canvas OAuth access token - {platform.id}",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value=str(refreshed["access_token"]),
        metadata={"platform_id": platform.id},
    )
    await repo.save_integration_secret(access_secret)
    refreshed_refresh_ref = leased.refresh_token_secret_ref
    refreshed_refresh_secret_id: str | None = None
    if refreshed.get("refresh_token"):
        refreshed_refresh_secret_id = str(uuid.uuid4())
        refresh_secret = OrganizationIntegrationSecret(
            id=refreshed_refresh_secret_id,
            organization_id=platform.organization_id,
            name=f"Canvas OAuth refresh token - {platform.id}",
            provider="canvas",
            purpose="oauth_refresh_token",
            secret_value=str(refreshed["refresh_token"]),
            metadata={"platform_id": platform.id},
        )
        await repo.save_integration_secret(refresh_secret)
        refreshed_refresh_ref = refresh_secret.secret_ref
    expires_in = refreshed.get("expires_in")
    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=max(0, int(expires_in)))
        if isinstance(expires_in, (int, float))
        else None
    )
    completed = await repo.complete_canvas_oauth_refresh(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        lease_owner=lease_owner,
        access_token_secret_ref=access_secret.secret_ref,
        refresh_token_secret_ref=refreshed_refresh_ref,
        token_expires_at=expires_at,
    )
    if completed is None:
        await repo.delete_integration_secret(access_secret.id)
        if refreshed_refresh_secret_id:
            await repo.delete_integration_secret(refreshed_refresh_secret_id)
        return ""
    for stale_secret_id in (old_access_secret_id, old_refresh_secret_id):
        if stale_secret_id and stale_secret_id not in {
            access_secret.id,
            refreshed_refresh_secret_id,
        }:
            await repo.delete_integration_secret(stale_secret_id)
    patched_platform = await repo.patch_canvas_platform_validation_state(
        platform.organization_id,
        platform.id,
        expected_config_version=platform.config_version,
        last_validated_at=platform.last_validated_at,
        last_connection_error=None,
    )
    if patched_platform is None:
        # The refresh completed, but configuration changed while the network
        # request was in flight. Do not let this call use the refreshed token
        # under a stale Canvas origin/client configuration.
        await repo.mark_canvas_oauth_reauthorization_required(
            platform.organization_id,
            platform.id,
            expected_updated_at=completed.updated_at,
        )
        return ""
    return str(refreshed["access_token"])


async def _mark_rejected_canvas_oauth_token(
    *,
    repo: IIssuanceRepository,
    platform: CanvasPlatform,
    rejected_access_token: str,
) -> bool:
    """CAS-mark only the OAuth connection that still owns the rejected token."""

    connection = await repo.get_canvas_oauth_connection(
        platform.organization_id,
        platform.id,
    )
    if connection is None or connection.reauthorization_required:
        return bool(connection and connection.reauthorization_required)
    connection_updated_at = connection.updated_at
    access_secret_id = _integration_secret_id_from_ref(
        platform.organization_id,
        connection.access_token_secret_ref,
    )
    current_token = (
        await repo.get_integration_secret_value(
            platform.organization_id,
            access_secret_id,
        )
        if access_secret_id
        else None
    )
    if (
        not current_token
        or not rejected_access_token
        or not hmac.compare_digest(current_token, rejected_access_token)
    ):
        # A reconnect or concurrent refresh replaced the token while the failed
        # request was in flight. Never poison that newer connection.
        return False
    marked = await repo.mark_canvas_oauth_reauthorization_required(
        platform.organization_id,
        platform.id,
        expected_updated_at=connection_updated_at,
    )
    if marked is None:
        return False
    await repo.patch_canvas_platform_validation_state(
        platform.organization_id,
        platform.id,
        expected_config_version=platform.config_version,
        last_validated_at=platform.last_validated_at,
        last_connection_error="oauth_reauthorization_required",
    )
    return True


def _canvas_rest_oauth_reauthorization_required(response: httpx.Response) -> bool:
    # Canvas documents WWW-Authenticate as the distinction between an invalid
    # OAuth token and a valid token that lacks permission for a resource.
    return response.status_code == 401 and bool(response.headers.get("WWW-Authenticate"))


def _canvas_api_base(platform: CanvasPlatform) -> str:
    raw_base = (platform.canvas_base_url or "").strip()
    if not raw_base:
        raise HTTPException(status_code=400, detail="Canvas platform requires canvas_base_url for admin discovery")
    try:
        return validate_canvas_origin(raw_base)
    except CanvasLtiServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _canvas_collection_url(base_url: str, path: str) -> str:
    return urljoin(f"{base_url}/", f"api/v1/{path.lstrip('/')}")


async def _fetch_canvas_api_collection(
    client: httpx.AsyncClient,
    *,
    base_url: str,
    token: str,
    path: str,
    limit: int,
    require_complete: bool = False,
    repo: IIssuanceRepository | None = None,
    platform: CanvasPlatform | None = None,
) -> list[dict[str, Any]]:
    url = _canvas_collection_url(base_url, path)
    items: list[dict[str, Any]] = []
    params: dict[str, Any] | None = {"per_page": min(max(limit, 1), 100)}
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    visited_pages: set[str] = set()
    page_count = 0
    while url and len(items) < limit:
        request_url = str(httpx.URL(url).copy_merge_params(params or {}))
        if request_url in visited_pages:
            raise CanvasLtiServiceError(
                "Canvas REST pagination repeated a page",
                retryable=False,
            )
        visited_pages.add(request_url)
        page_count += 1
        if page_count > CANVAS_COLLECTION_MAX_PAGES:
            raise CanvasLtiServiceError(
                "Canvas REST pagination exceeded the page limit",
                retryable=False,
            )
        try:
            async with client.stream(
                "GET",
                url,
                headers=headers,
                params=params,
                follow_redirects=False,
            ) as response:
                if response.is_redirect:
                    raise CanvasLtiServiceError(
                        "Canvas REST collection returned a redirect",
                        retryable=False,
                    )
                if response.status_code == 429:
                    raise CanvasLtiServiceError(
                        "Canvas REST collection read was rate limited",
                        retry_after_seconds=parse_canvas_retry_after(
                            response.headers.get("Retry-After")
                        )
                        or 0,
                    )
                if response.status_code in {401, 403}:
                    reauthorization_required = _canvas_rest_oauth_reauthorization_required(
                        response
                    )
                    if reauthorization_required and repo is not None and platform is not None:
                        await _mark_rejected_canvas_oauth_token(
                            repo=repo,
                            platform=platform,
                            rejected_access_token=token,
                        )
                    raise CanvasLtiServiceError(
                        "Canvas rejected the organization OAuth token or required API scope",
                        reauthorization_required=reauthorization_required,
                    )
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    raise HTTPException(
                        status_code=502,
                        detail=f"Canvas admin discovery failed with HTTP {response.status_code}",
                    ) from exc
                payload = await read_limited_canvas_json_response(
                    response,
                    label="REST collection page",
                    max_bytes=CANVAS_COLLECTION_PAGE_MAX_BYTES,
                )
                next_url = (
                    response.links.get("next", {}).get("url")
                    if response.links
                    else None
                )
        except CanvasLtiServiceError:
            raise
        except httpx.HTTPError as exc:
            raise CanvasLtiServiceError(
                "Canvas REST collection transport failed"
            ) from exc
        if isinstance(payload, list):
            page_items = payload
        elif isinstance(payload, dict) and isinstance(payload.get("items"), list):
            page_items = payload["items"]
        else:
            if require_complete:
                raise CanvasLtiServiceError(
                    "Canvas REST collection returned an unexpected response"
                )
            raise HTTPException(status_code=502, detail="Canvas admin discovery returned an unexpected response")
        if require_complete and any(not isinstance(item, dict) for item in page_items):
            raise CanvasLtiServiceError(
                "Canvas REST collection returned malformed items"
            )
        items.extend(item for item in page_items if isinstance(item, dict))
        if require_complete and (len(items) > limit or (next_url and len(items) >= limit)):
            raise CanvasSyncProcessingError(
                "canvas_roster_collection_too_large",
                "Canvas roster exceeds the configured complete-read limit",
                retryable=False,
            )
        if next_url and len(items) < limit:
            try:
                url = validate_lti_service_url(next_url, expected_origin=base_url)
            except CanvasLtiServiceError as exc:
                if require_complete:
                    raise
                raise HTTPException(status_code=502, detail=str(exc)) from exc
        else:
            url = ""
        params = None
    return items[:limit]


async def _fetch_canvas_management_collection(
    client: httpx.AsyncClient,
    *,
    base_url: str,
    token: str,
    path: str,
    limit: int,
    repo: IIssuanceRepository,
    platform: CanvasPlatform,
) -> list[dict[str, Any]]:
    try:
        return await _fetch_canvas_api_collection(
            client,
            base_url=base_url,
            token=token,
            path=path,
            limit=limit,
            repo=repo,
            platform=platform,
        )
    except CanvasLtiServiceError as exc:
        if exc.reauthorization_required:
            raise HTTPException(
                status_code=401,
                detail="Canvas OAuth connection requires reauthorization",
            ) from exc
        headers = (
            {"Retry-After": str(exc.retry_after_seconds)}
            if exc.retry_after_seconds is not None
            else None
        )
        raise HTTPException(
            status_code=503,
            detail="Canvas discovery is temporarily unavailable",
            headers=headers,
        ) from exc


def _canvas_scope_item(raw: dict[str, Any], item_type: str) -> CanvasScopeItem | None:
    raw_id = raw.get("id") or raw.get("quiz_id") or raw.get("module_id")
    if raw_id is None:
        return None
    name = (
        raw.get("name")
        or raw.get("title")
        or raw.get("course_code")
        or raw.get("workflow_state")
        or str(raw_id)
    )
    points = raw.get("points_possible")
    try:
        points_possible = float(points) if points is not None else None
    except (TypeError, ValueError):
        points_possible = None
    published = raw.get("published")
    if published is None and "workflow_state" in raw:
        published = raw.get("workflow_state") == "available"
    return CanvasScopeItem(
        id=str(raw_id),
        name=str(name),
        type=item_type,
        url=raw.get("html_url") or raw.get("url"),
        published=published if isinstance(published, bool) else None,
        points_possible=points_possible,
    )


def _canvas_scope_items(raw_items: list[dict[str, Any]], item_type: str) -> list[CanvasScopeItem]:
    items: list[CanvasScopeItem] = []
    for raw in raw_items:
        item = _canvas_scope_item(raw, item_type)
        if item is not None:
            items.append(item)
    return items


def _normalize_canvas_binding_requirements(
    *,
    values: list[Any],
    canvas_scope: dict[str, Any],
    binding_id: str,
    existing_binding: CanvasProgramBinding | None,
) -> list[dict[str, Any]]:
    existing_by_id = {
        str(item.get("requirement_id")): item
        for item in (existing_binding.evidence_requirements if existing_binding else [])
        if isinstance(item, dict) and item.get("requirement_id")
    }
    normalized: list[dict[str, Any]] = []
    for raw in values:
        if isinstance(raw, CanvasEvidenceRequirement):
            raw = raw.to_dict()
        elif isinstance(raw, BaseModel):
            raw = raw.model_dump(exclude_none=True)
        if not isinstance(raw, dict):
            raise HTTPException(status_code=400, detail="Canvas evidence requirements must be typed objects")
        requirement_id = str(raw.get("requirement_id") or f"canvas_req_{uuid.uuid4().hex}").strip()
        existing = existing_by_id.get(requirement_id) or {}
        scope = dict(raw.get("scope") or {})
        if not scope.get("course_id") and canvas_scope.get("course_id"):
            scope["course_id"] = canvas_scope["course_id"]
        if str(raw.get("source") or "") == CanvasEvidenceSource.AGS_RESULT.value:
            existing_scope = existing.get("scope") if isinstance(existing.get("scope"), dict) else {}
            # Only a verified launch may attach a Canvas line-item URL.
            scope.pop("line_item_url", None)
            scope.pop("lineitem_url", None)
            if existing_scope.get("line_item_url"):
                scope["line_item_url"] = existing_scope["line_item_url"]
            if existing_scope.get("resource_id"):
                scope["resource_id"] = existing_scope["resource_id"]
            if not scope.get("line_item_url") and not scope.get("resource_id"):
                scope["resource_id"] = f"marty:{binding_id}:{requirement_id}"
        normalized.append(
            {
                "requirement_id": requirement_id,
                "source": raw.get("source"),
                "fact_type": raw.get("fact_type"),
                "scope": scope,
                "pass_rule": dict(raw.get("pass_rule") or {}),
                "required": raw.get("required", True),
            }
        )
    try:
        return [requirement.to_dict() for requirement in validate_canvas_evidence_requirements(normalized)]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _canvas_credentials_input_dict(
    value: CanvasCredentialsConfigInput | None,
) -> dict[str, Any]:
    if value is None:
        return {}
    return value.model_dump(exclude_none=True)


def _canvas_credentials_https_origin(value: str) -> str | None:
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return None
    return f"https://{parsed.hostname.lower()}{f':{port}' if port else ''}"


def _trusted_canvas_credentials_origins() -> set[str]:
    origins = {"https://api.badgr.io"}
    configured = [
        os.environ.get("CANVAS_CREDENTIALS_API_BASE_URL", ""),
        *os.environ.get("CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST", "").split(","),
    ]
    for value in configured:
        origin = _canvas_credentials_https_origin(str(value or "").strip())
        if origin:
            origins.add(origin)
    return origins


async def _validated_canvas_credentials_input(
    *,
    value: CanvasCredentialsConfigInput | None,
    organization_id: str,
    repo: IIssuanceRepository,
) -> dict[str, Any]:
    config = _canvas_credentials_input_dict(value)
    if not config:
        return {}

    secret_id = str(config.get("api_token_secret_id") or "").strip()
    if not secret_id:
        raise HTTPException(
            status_code=400,
            detail="Canvas Credentials configuration requires an organization-owned API token secret",
        )
    secret = await repo.get_integration_secret(secret_id)
    if (
        secret is None
        or secret.organization_id != organization_id
        or not secret.enabled
        or secret.provider != "canvas_credentials"
        or secret.purpose != "api_token"
    ):
        raise HTTPException(status_code=404, detail="Canvas Credentials API token secret was not found")
    config["api_token_secret_id"] = secret.id

    api_base_url = str(config.get("api_base_url") or "").strip()
    if api_base_url:
        parsed = urlparse(api_base_url)
        origin = _canvas_credentials_https_origin(api_base_url)
        if (
            origin is None
            or parsed.query
            or parsed.fragment
        ):
            raise HTTPException(
                status_code=400,
                detail="Canvas Credentials API base URL must be a trusted HTTPS URL",
            )
        if origin not in _trusted_canvas_credentials_origins():
            raise HTTPException(
                status_code=400,
                detail="Canvas Credentials API origin is not operator allowlisted",
            )
        config["api_base_url"] = api_base_url.rstrip("/")
    return config


async def _validate_program_binding_request(
    *,
    platform: CanvasPlatform,
    request: CanvasProgramBindingCreate,
    repo: IIssuanceRepository,
    existing_binding_id: str | None = None,
    existing_binding: CanvasProgramBinding | None = None,
) -> CanvasProgramBinding:
    template = await repo.get_application_template(request.application_template_id)
    if template is None:
        raise HTTPException(status_code=404, detail="Application template not found")
    if template.organization_id != platform.organization_id:
        raise HTTPException(status_code=409, detail="Application template belongs to a different organization")

    credential_template_id = request.credential_template_id or template.credential_template_id
    if not credential_template_id:
        raise HTTPException(status_code=400, detail="Program binding requires a credential template ID")
    if template.credential_template_id and credential_template_id != template.credential_template_id:
        raise HTTPException(status_code=409, detail="Credential template does not match application template")
    canvas_credentials = await _validated_canvas_credentials_input(
        value=request.canvas_credentials,
        organization_id=platform.organization_id,
        repo=repo,
    )
    configured_projection_template = str(
        canvas_credentials.get("credential_template_id") or ""
    ).strip()
    if configured_projection_template and configured_projection_template != credential_template_id:
        raise HTTPException(
            status_code=409,
            detail="Canvas Credentials projection must use the binding credential template",
        )

    feature_flags = normalize_canvas_feature_flags(request.feature_flags)
    if feature_flags:
        if request.evidence_requirements and not feature_flags.get("enable_canvas_evidence", False):
            raise HTTPException(status_code=409, detail="Canvas evidence requires enable_canvas_evidence in the deployment profile")
        if request.auto_approve_on_evidence and not feature_flags.get("enable_canvas_evidence", False):
            raise HTTPException(status_code=409, detail="Canvas auto-approval requires enable_canvas_evidence in the deployment profile")
        if request.delivery_mode == "wallet_plus_canvas_mirror" and not feature_flags.get("enable_canvas_mirror_publish", False):
            raise HTTPException(status_code=409, detail="Canvas mirror delivery requires enable_canvas_mirror_publish in the deployment profile")

    for candidate in await repo.list_canvas_program_bindings(
        platform.organization_id,
        platform_id=platform.id,
        application_template_id=request.application_template_id,
    ):
        if candidate.id == existing_binding_id:
            continue
        if (
            candidate.credential_template_id == credential_template_id
            and (candidate.canvas_scope or {}) == (request.canvas_scope or {})
        ):
            raise HTTPException(status_code=409, detail="A Canvas program binding already exists for this template and scope")

    binding = CanvasProgramBinding(id=existing_binding_id or str(uuid.uuid4()))
    binding.organization_id = platform.organization_id
    binding.platform_id = platform.id
    binding.application_template_id = request.application_template_id
    binding.credential_template_id = credential_template_id
    binding.display_name = request.display_name
    binding.flow_mode = "elevenid_orchestrated_canvas_evidence"
    binding.direct_issue_enabled = False
    binding.auto_approve_on_evidence = request.auto_approve_on_evidence
    binding.evidence_requirements = _normalize_canvas_binding_requirements(
        values=list(request.evidence_requirements or []),
        canvas_scope=dict(request.canvas_scope or {}),
        binding_id=binding.id,
        existing_binding=existing_binding,
    )
    binding.canvas_scope = dict(request.canvas_scope or {})
    binding.delivery_mode = request.delivery_mode or "wallet_only"
    binding.issuer_mode = "org_managed"
    binding.approval_policy_set_id = request.approval_policy_set_id or template.approval_policy_set_id
    binding.deployment_profile_id = request.deployment_profile_id
    binding.feature_flags = feature_flags
    binding.canvas_credentials = canvas_credentials
    if existing_binding is not None:
        binding.created_at = existing_binding.created_at
        binding.config_version = existing_binding.config_version + 1
    binding.validated_config_version = None
    binding.readiness_checks = []
    binding.readiness_validated_at = None
    binding.activated_at = None
    binding.archived_at = None
    binding.credential_template_snapshot = {}
    # Configuration writes always return to draft; activation is a separate,
    # fail-closed operation after readiness validation.
    binding.enabled = False
    return binding


def _integration_secret_id_from_ref(organization_id: str, secret_ref: str | None) -> str | None:
    prefix = f"org_secret://{organization_id}/"
    value = str(secret_ref or "")
    if not value.startswith(prefix):
        return None
    secret_id = value[len(prefix) :].strip()
    return secret_id or None


async def _parse_lti_launch_submission(request: Request) -> tuple[str, str]:
    payload = await _request_payload(request)
    id_token = _payload_str(payload, "id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="Canvas LTI launch requires id_token")

    state = _payload_str(payload, "state")
    if not state:
        raise HTTPException(status_code=400, detail="Canvas LTI launch requires server-generated state")

    return id_token, state


async def _parse_lti_login_submission(request: Request) -> dict[str, str | None]:
    payload = await _request_payload(request)
    login_hint = _payload_str(payload, "login_hint")
    if not login_hint:
        raise HTTPException(status_code=400, detail="Canvas LTI login requires login_hint")

    return {
        "issuer": _payload_str(payload, "iss"),
        "login_hint": login_hint,
        "target_link_uri": _payload_str(payload, "target_link_uri"),
        "lti_message_hint": _payload_str(payload, "lti_message_hint"),
        "client_id": _payload_str(payload, "client_id"),
    }


def _lti_launch_redirect_uri(platform_id: str) -> str:
    return f"{ISSUER_BASE_URL}/v1/integrations/canvas/lti/platforms/{platform_id}/launch"


def _lti_experience_redirect_uri(platform_id: str) -> str:
    return f"{ISSUER_BASE_URL}/v1/integrations/canvas/lti/platforms/{platform_id}/experience"


def _lti_experience_url(code: str) -> str:
    return f"{CANVAS_LTI_EXPERIENCE_BASE_URL}/canvas/lti/experience?code={quote(code)}"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    value = data.encode("ascii")
    value += b"=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value)


def _json_b64url(value: dict[str, Any]) -> str:
    return _b64url_encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _jwk_uint(jwk: dict[str, Any], field: str) -> int:
    value = jwk.get(field)
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=409, detail=f"Canvas LTI tool signing JWK is missing {field}")
    return int.from_bytes(_b64url_decode(value), "big")


_RSA_PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth"}


def _rsa_jwk_with_kid(jwk: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(jwk)
    if normalized.get("kty") != "RSA" or not normalized.get("n") or not normalized.get("e"):
        raise HTTPException(status_code=409, detail="Canvas LTI tool signing keys must be RSA JWKs")
    if normalized.get("alg") not in {None, "RS256"}:
        raise HTTPException(status_code=409, detail="Canvas LTI tool signing keys must use RS256")
    if not normalized.get("kid"):
        thumbprint_input = json.dumps(
            {"e": normalized["e"], "kty": "RSA", "n": normalized["n"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        normalized["kid"] = _b64url_encode(hashlib.sha256(thumbprint_input).digest())
    normalized["kid"] = str(normalized["kid"])
    normalized["alg"] = "RS256"
    normalized.setdefault("use", "sig")
    return normalized


def _load_tool_signing_jwks() -> list[dict[str, Any]]:
    raw = os.environ.get("CANVAS_LTI_TOOL_PRIVATE_JWKS") or os.environ.get(
        "CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK"
    )
    file_path = os.environ.get("CANVAS_LTI_TOOL_PRIVATE_JWKS_FILE") or os.environ.get(
        "CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK_FILE"
    )
    if not raw and file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except OSError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"Canvas LTI tool signing JWKS file cannot be read: {exc}",
            ) from exc
    if not raw:
        raise HTTPException(
            status_code=409,
            detail="Canvas LTI RS256 tool signing key is not configured",
        )
    try:
        jwk_config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=409, detail="Canvas LTI tool signing JWKS is invalid JSON") from exc
    if not isinstance(jwk_config, dict):
        raise HTTPException(status_code=409, detail="Canvas LTI tool signing JWKS must be a JSON object")

    keys = jwk_config.get("keys")
    if isinstance(keys, list):
        configured_keys = [_rsa_jwk_with_kid(key) for key in keys if isinstance(key, dict)]
    else:
        configured_keys = [_rsa_jwk_with_kid(jwk_config)]
    if not configured_keys:
        raise HTTPException(status_code=409, detail="Canvas LTI tool signing JWKS contains no keys")
    kids = [key["kid"] for key in configured_keys]
    if len(kids) != len(set(kids)):
        raise HTTPException(status_code=409, detail="Canvas LTI tool signing JWKS contains duplicate kid values")
    return configured_keys


def _load_deep_linking_private_jwk() -> dict[str, Any]:
    """Load the active RS256 key (legacy function name retained for callers/tests)."""

    configured_keys = _load_tool_signing_jwks()
    requested_kid = (
        os.environ.get("CANVAS_LTI_TOOL_ACTIVE_KID")
        or os.environ.get("CANVAS_LTI_DEEP_LINKING_KEY_ID")
        or ""
    ).strip()
    private_keys = [key for key in configured_keys if key.get("d")]
    if requested_kid:
        private_keys = [key for key in private_keys if key.get("kid") == requested_kid]
    if len(private_keys) != 1:
        detail = (
            "Canvas LTI tool signing JWKS has no matching active private key"
            if not private_keys
            else "CANVAS_LTI_TOOL_ACTIVE_KID is required when multiple private keys are configured"
        )
        raise HTTPException(status_code=409, detail=detail)
    return private_keys[0]


def _deep_linking_private_key_and_kid() -> tuple[Any, str | None]:
    jwk = _load_deep_linking_private_jwk()
    private_key = rsa.RSAPrivateNumbers(
        p=_jwk_uint(jwk, "p"),
        q=_jwk_uint(jwk, "q"),
        d=_jwk_uint(jwk, "d"),
        dmp1=_jwk_uint(jwk, "dp"),
        dmq1=_jwk_uint(jwk, "dq"),
        iqmp=_jwk_uint(jwk, "qi"),
        public_numbers=rsa.RSAPublicNumbers(
            e=_jwk_uint(jwk, "e"),
            n=_jwk_uint(jwk, "n"),
        ),
    )
    return private_key.private_key(), str(jwk["kid"])


class ToolJwtSigner(Protocol):
    async def sign_jwt(self, payload: dict[str, Any]) -> str: ...

    async def public_jwks(self) -> dict[str, Any]: ...


class LocalJwkToolJwtSigner:
    """Development/test signer. Production key custody must never use this class."""

    async def sign_jwt(self, payload: dict[str, Any]) -> str:
        private_key, kid = _deep_linking_private_key_and_kid()
        header: dict[str, Any] = {"alg": "RS256", "typ": "JWT", "kid": kid}
        signing_input = f"{_json_b64url(header)}.{_json_b64url(payload)}"
        signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{_b64url_encode(signature)}"

    async def public_jwks(self) -> dict[str, Any]:
        active = _load_deep_linking_private_jwk()
        configured = _load_tool_signing_jwks()
        configured.sort(key=lambda key: key.get("kid") != active.get("kid"))
        return {
            "keys": [
                {key: value for key, value in configured_key.items() if key not in _RSA_PRIVATE_JWK_FIELDS}
                for configured_key in configured
            ]
        }


class RemoteKmsToolJwtSigner:
    """Production RS256 signer backed by the registered signing-keys/KMS service."""

    key_purpose = "lti_tool_signing"

    def __init__(self) -> None:
        self.organization_id = os.environ.get("CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID", "").strip()
        self.service_id = os.environ.get("CANVAS_LTI_TOOL_SIGNING_SERVICE_ID", "").strip()
        self.key_reference = os.environ.get("CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE", "").strip() or None
        self.kid = os.environ.get("CANVAS_LTI_TOOL_ACTIVE_KID", "").strip()
        signing_url = os.environ.get("SIGNING_KEYS_INTERNAL_URL", "").strip()
        signing_api_key = (
            os.environ.get("SIGNING_KEYS_INTERNAL_API_KEY", "").strip()
            or os.environ.get("ISSUANCE_API_KEY", "").strip()
        )
        if not all((self.organization_id, self.service_id, self.kid, signing_url, signing_api_key)):
            raise HTTPException(
                status_code=503,
                detail=(
                    "Production Canvas LTI signing requires SIGNING_KEYS_INTERNAL_URL/API key and "
                    "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID/SERVICE_ID/ACTIVE_KID"
                ),
            )

    def _configured_public_jwks(self) -> dict[str, Any]:
        raw = os.environ.get("CANVAS_LTI_TOOL_PUBLIC_JWKS", "").strip()
        if not raw:
            raise HTTPException(status_code=503, detail="CANVAS_LTI_TOOL_PUBLIC_JWKS is required")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=503, detail="CANVAS_LTI_TOOL_PUBLIC_JWKS is invalid JSON") from exc
        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list):
            raise HTTPException(status_code=503, detail="CANVAS_LTI_TOOL_PUBLIC_JWKS must contain keys")
        now = datetime.now(timezone.utc)
        public_keys: list[dict[str, Any]] = []
        for raw_key in keys:
            if not isinstance(raw_key, dict):
                continue
            if _RSA_PRIVATE_JWK_FIELDS.intersection(raw_key):
                raise HTTPException(
                    status_code=503,
                    detail="CANVAS_LTI_TOOL_PUBLIC_JWKS must not contain private key material",
                )
            key = _rsa_jwk_with_kid(raw_key)
            if key["kid"] != self.kid:
                retired_at_raw = raw_key.get("retired_at")
                try:
                    retired_at = datetime.fromisoformat(str(retired_at_raw).replace("Z", "+00:00"))
                except (TypeError, ValueError):
                    continue
                if retired_at.tzinfo is None:
                    retired_at = retired_at.replace(tzinfo=timezone.utc)
                if now > retired_at.astimezone(timezone.utc) + timedelta(days=7):
                    continue
            public_keys.append(
                {name: value for name, value in key.items() if name not in _RSA_PRIVATE_JWK_FIELDS | {"retired_at"}}
            )
        if not any(key.get("kid") == self.kid for key in public_keys):
            raise HTTPException(status_code=503, detail="Active Canvas LTI signing kid is not published")
        return {"keys": sorted(public_keys, key=lambda key: key.get("kid") != self.kid)}

    async def sign_jwt(self, payload: dict[str, Any]) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        signing_input = f"{_json_b64url(header)}.{_json_b64url(payload)}"
        try:
            result = await sign_payload_with_remote_service(
                organization_id=self.organization_id,
                signing_service_id=self.service_id,
                payload=signing_input.encode("ascii"),
                algorithm="RS256",
                key_reference=self.key_reference,
                key_purpose=self.key_purpose,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Canvas LTI remote signing failed: {exc}") from exc
        signature = str(result.get("signature_raw_b64") or result.get("signature_b64") or "").strip()
        if not signature:
            raise HTTPException(status_code=503, detail="Canvas LTI remote signer returned no signature")
        return f"{signing_input}.{signature.rstrip('=')}"

    async def public_jwks(self) -> dict[str, Any]:
        return self._configured_public_jwks()


def _tool_jwt_signer() -> ToolJwtSigner:
    allow_local = os.environ.get("CANVAS_LTI_ALLOW_LOCAL_PRIVATE_JWK", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    environment = os.environ.get("ENVIRONMENT", os.environ.get("APP_ENV", "development")).strip().lower()
    if allow_local and environment not in {"production", "prod"}:
        return LocalJwkToolJwtSigner()
    return RemoteKmsToolJwtSigner()


async def _sign_deep_linking_jwt(payload: dict[str, Any]) -> str:
    return await _tool_jwt_signer().sign_jwt(payload)


async def _lti_tool_signing_challenge_ready() -> bool:
    """Prove the configured KMS signer matches the active published RSA JWK."""

    payload = {
        "iss": "marty:canvas-readiness",
        "aud": "marty:canvas-readiness",
        "iat": int(time.time()),
        "jti": secrets.token_urlsafe(24),
    }
    try:
        signer = _tool_jwt_signer()
        token = await signer.sign_jwt(payload)
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        header = json.loads(_b64url_decode(encoded_header))
        signed_payload = json.loads(_b64url_decode(encoded_payload))
        if (
            not isinstance(header, dict)
            or header.get("alg") != "RS256"
            or not isinstance(header.get("kid"), str)
            or signed_payload != payload
        ):
            return False
        document = await signer.public_jwks()
        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list):
            return False
        matching = [
            key
            for key in keys
            if isinstance(key, dict) and key.get("kid") == header["kid"]
        ]
        if len(matching) != 1:
            return False
        jwk = matching[0]
        if (
            _RSA_PRIVATE_JWK_FIELDS.intersection(jwk)
            or jwk.get("kty") != "RSA"
            or jwk.get("alg") not in {None, "RS256"}
            or jwk.get("use") not in {None, "sig"}
        ):
            return False
        public_key = rsa.RSAPublicNumbers(
            e=_jwk_uint(jwk, "e"),
            n=_jwk_uint(jwk, "n"),
        ).public_key()
        public_key.verify(
            _b64url_decode(encoded_signature),
            f"{encoded_header}.{encoded_payload}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:  # noqa: BLE001 - every signer/configuration failure blocks readiness
        return False


def _expected_lti_trust(platform: CanvasPlatform) -> dict[str, str]:
    if not platform.canvas_base_url:
        raise HTTPException(status_code=409, detail="Canvas platform is missing its HTTPS origin")
    try:
        return canvas_lti_trust_profile(
            platform.canvas_base_url,
            platform.lti_trust_profile,
        )
    except CanvasLtiServiceError as exc:
        raise HTTPException(
            status_code=409,
            detail=f"Canvas LTI trust configuration is not permitted: {exc}",
        ) from exc


def _lti_token_endpoint(platform: CanvasPlatform) -> str:
    metadata = platform.lti_openid_configuration or {}
    endpoint = metadata.get("token_endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise HTTPException(status_code=409, detail="Canvas platform is missing token_endpoint metadata")
    expected = _expected_lti_trust(platform)["token_endpoint"]
    if endpoint.strip() != expected:
        raise HTTPException(status_code=409, detail="Canvas token_endpoint does not match probed metadata")
    return expected


async def _lti_service_client_assertion(platform: CanvasPlatform, token_endpoint: str) -> str:
    if not platform.lti_client_id:
        raise HTTPException(status_code=409, detail="Canvas platform is missing its LTI client ID")
    now = int(time.time())
    return await _sign_deep_linking_jwt(
        {
            "iss": platform.lti_client_id,
            "sub": platform.lti_client_id,
            "aud": token_endpoint,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        }
    )


async def _public_canvas_tool_jwks() -> dict[str, Any]:
    return await _tool_jwt_signer().public_jwks()


def _issue_lti_config_token(platform: CanvasPlatform) -> str:
    token = f"{_b64url_encode(platform.id.encode('utf-8'))}.{secrets.token_urlsafe(32)}"
    config = dict(platform.connection_config or {})
    config.update(
        {
            "lti_config_token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "lti_config_token_status": "active",
            "lti_config_token_issued_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    platform.connection_config = config
    return token


def _revoke_lti_config_token(platform: CanvasPlatform) -> None:
    config = dict(platform.connection_config or {})
    config.pop("lti_config_token_hash", None)
    config["lti_config_token_status"] = "revoked"
    config["lti_config_token_revoked_at"] = datetime.now(timezone.utc).isoformat()
    platform.connection_config = config


def _platform_id_from_lti_config_token(token: str) -> str | None:
    prefix, separator, _secret = token.partition(".")
    if not separator or not prefix or not _secret:
        return None
    try:
        value = _b64url_decode(prefix).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return value.strip() or None


def _canvas_lti_registration(
    platform: CanvasPlatform,
    *,
    config_token: str | None = None,
) -> CanvasLtiRegistrationResponse:
    launch_url = _lti_experience_redirect_uri(platform.id)
    login_url = f"{ISSUER_BASE_URL}/v1/integrations/canvas/lti/platforms/{platform.id}/experience-login"
    jwks_url = f"{ISSUER_BASE_URL}/v1/integrations/canvas/lti/jwks"
    capability_intent = set(
        (platform.connection_config or {}).get("lti_capability_intent") or []
    )
    scopes: list[str] = []
    if "ags" in capability_intent:
        scopes.extend(
            [
                "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
                AGS_RESULT_READ_SCOPE,
            ]
        )
    if "nrps" in capability_intent:
        scopes.append(NRPS_MEMBERSHIP_READ_SCOPE)
    configuration = {
        "tool_id": "marty-portable-canvas-v1",
        "title": "Marty Portable Credentials",
        "description": "Issue externally signed Open Badges from authorized Canvas learning evidence.",
        "target_link_uri": launch_url,
        "oidc_initiation_url": login_url,
        "public_jwk_url": jwks_url,
        # Canvas REST identifiers are not the LTI subject.  Canvas substitutes
        # these values into signed custom claims at launch time, giving the
        # server an authenticated numeric ID for scoped API reads.
        "custom_fields": {
            "canvas_user_id": "$Canvas.user.id",
            "canvas_course_id": "$Canvas.course.id",
            "canvas_account_id": "$Canvas.account.id",
            "canvas_assignment_id": "$Canvas.assignment.id",
        },
        "scopes": scopes,
        "extensions": [
            {
                "platform": "canvas.instructure.com",
                "privacy_level": "public",
                "settings": {
                    "placements": [
                        {"placement": "course_navigation", "message_type": "LtiResourceLinkRequest", "target_link_uri": launch_url},
                        {"placement": "assignment_selection", "message_type": "LtiDeepLinkingRequest", "target_link_uri": launch_url},
                    ]
                },
            }
        ],
    }
    installation = {
        "method": "institution_admin_lti_1_3",
        "login_url": login_url,
        "launch_url": launch_url,
        "jwks_url": jwks_url,
    }
    if config_token:
        installation["config_url"] = (
            f"{ISSUER_BASE_URL}/v1/integrations/canvas/lti/config/{quote(config_token, safe='')}"
        )
    return CanvasLtiRegistrationResponse(
        platform_id=platform.id,
        developer_key_configuration=configuration,
        installation=installation,
    )


def _lti_authorization_endpoint(platform: CanvasPlatform) -> str:
    metadata = platform.lti_openid_configuration or {}
    endpoint = metadata.get("authorization_endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise HTTPException(
            status_code=409,
            detail="Canvas platform is missing LTI authorization_endpoint metadata",
        )
    expected = _expected_lti_trust(platform)[
        "authorization_endpoint"
    ]
    if endpoint.strip() != expected:
        raise HTTPException(
            status_code=409,
            detail="Canvas LTI authorization_endpoint does not match probed metadata",
        )
    return expected


def _validate_lti_ready_platform(platform: CanvasPlatform) -> None:
    if not platform.enabled:
        raise HTTPException(status_code=409, detail="Canvas platform is disabled")
    if not platform.lti_client_id or not platform.lti_deployment_id:
        raise HTTPException(status_code=409, detail="Canvas platform is missing LTI client or deployment configuration")
    if not platform.lti_issuer or not platform.lti_jwks_json:
        raise HTTPException(status_code=409, detail="Canvas platform has not been sandbox-probed or is missing LTI trust metadata")
    expected = _expected_lti_trust(platform)
    metadata = platform.lti_openid_configuration or {}
    observed_endpoints = {
        "issuer": platform.lti_issuer,
        "authorization_endpoint": metadata.get("authorization_endpoint"),
        "token_endpoint": metadata.get("token_endpoint"),
        "jwks_uri": metadata.get("jwks_uri") or platform.lti_jwks_url,
    }
    if any(
        observed and observed != expected[key]
        for key, observed in observed_endpoints.items()
    ):
        raise HTTPException(
            status_code=409,
            detail="Canvas LTI metadata does not match the persisted trust profile",
        )


def _require_portable_canvas_pilot(organization_id: str) -> None:
    if not portable_canvas_enabled_for_organization(organization_id):
        raise HTTPException(
            status_code=404,
            detail="Portable Canvas integration is not enabled for this organization",
        )


async def _record_verified_canvas_launch_identity(
    *,
    platform: CanvasPlatform,
    verified_launch: dict[str, Any],
    repo: IIssuanceRepository,
) -> None:
    """Persist signed account/user identifiers without crossing identity namespaces."""

    signed_account_id = _lti_signed_canvas_identifier(verified_launch, "canvas_account_id")
    if signed_account_id:
        existing = await repo.get_canvas_platform_by_account_id(
            platform.organization_id,
            signed_account_id,
        )
        if existing is not None and existing.id != platform.id:
            raise HTTPException(
                status_code=409,
                detail="Signed Canvas account is already assigned to another platform",
            )
        current = str(platform.canvas_account_id or "")
        if current.startswith("unverified:"):
            platform.canvas_account_id = signed_account_id
        elif current != signed_account_id:
            raise HTTPException(
                status_code=409,
                detail="Signed Canvas account does not match the installed platform",
            )

    subject = _lti_subject(verified_launch)
    canvas_user_id = _lti_canvas_user_id(verified_launch)
    deployment_id = str(
        verified_launch.get("deployment_id") or platform.lti_deployment_id or ""
    ).strip()
    if subject and canvas_user_id and deployment_id:
        identity = await link_verified_canvas_learner_identity(
            repo=repo,
            organization_id=platform.organization_id,
            platform_id=platform.id,
            deployment_id=deployment_id,
            lti_subject=subject,
            canvas_user_id=canvas_user_id,
        )
        verified_launch["identity_mapping_status"] = identity.status.value
    elif subject and deployment_id:
        await record_verified_canvas_lti_subject(
            repo=repo,
            organization_id=platform.organization_id,
            platform_id=platform.id,
            deployment_id=deployment_id,
            lti_subject=subject,
        )
        verified_launch["identity_mapping_status"] = "numeric_id_unavailable"


def _jwks_expiry_from(now: datetime) -> datetime:
    return now + timedelta(minutes=max(1, CANVAS_LTI_JWKS_TTL_MINUTES))


def _apply_canvas_probe(platform: CanvasPlatform, probe: dict[str, Any]) -> None:
    probed_trust_profile = str(probe.get("lti_trust_profile") or "").strip()
    if probed_trust_profile != platform.lti_trust_profile:
        raise HTTPException(
            status_code=409,
            detail="Canvas metadata probe did not use the persisted LTI trust profile",
        )
    expected = _expected_lti_trust(platform)
    if any(
        str(probe.get(key) or "").strip() != expected[key]
        for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")
    ):
        raise HTTPException(
            status_code=409,
            detail="Canvas metadata probe returned endpoints outside the persisted trust profile",
        )
    now = datetime.now(timezone.utc)
    platform.canvas_base_url = probe.get("canvas_base_url") or platform.canvas_base_url
    platform.lti_issuer = probe.get("issuer") or platform.lti_issuer
    platform.lti_jwks_url = probe.get("jwks_uri") or platform.lti_jwks_url
    if probe.get("jwks_json"):
        platform.lti_jwks_json = probe.get("jwks_json")
        platform.lti_jwks_fetched_at = now
        platform.lti_jwks_expires_at = _jwks_expiry_from(now)
    platform.lti_openid_configuration = (
        probe.get("raw_openid_configuration") or platform.lti_openid_configuration
    )
    platform.updated_at = now


async def _refresh_canvas_platform_jwks(
    platform: CanvasPlatform,
    repo: IIssuanceRepository,
) -> tuple[CanvasPlatform, dict[str, Any]]:
    if not platform.canvas_base_url:
        raise HTTPException(status_code=400, detail="Canvas platform requires canvas_base_url before refreshing JWKS")
    try:
        canvas_origin = validate_canvas_origin(platform.canvas_base_url)
        probe = await probe_canvas_lti_platform(
            canvas_origin,
            trust_profile=platform.lti_trust_profile,
        )
    except Exception as exc:  # pragma: no cover - exact binding exception type varies
        raise HTTPException(status_code=400, detail=f"Canvas JWKS refresh failed: {exc}") from exc
    _apply_canvas_probe(platform, probe)
    await repo.save_canvas_platform(platform)
    return platform, probe


def _is_lti_kid_miss(exc: Exception) -> bool:
    return "No JWKS entry found for LTI kid" in str(exc)


def _verify_lti_launch_with_platform(
    *,
    platform: CanvasPlatform,
    id_token: str,
    expected_nonce: str,
) -> dict[str, Any]:
    return verify_canvas_lti_launch(
        id_token=id_token,
        expected_issuer=platform.lti_issuer,
        expected_client_id=platform.lti_client_id,
        expected_deployment_id=platform.lti_deployment_id,
        jwks_json=platform.lti_jwks_json,
        expected_nonce=expected_nonce,
    )


def _as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None and str(item)]
    return [str(value)] if str(value) else []


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = str(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _raw_lti_claim(raw_claims: dict[str, Any], canonical: str, legacy_key: str) -> dict[str, Any]:
    value = raw_claims.get(canonical)
    if not isinstance(value, dict):
        value = raw_claims.get(legacy_key)
    return value if isinstance(value, dict) else {}


def _openid_config_values(key: str, *configs: dict[str, Any] | None) -> list[str]:
    values: list[str] = []
    for config in configs:
        if not isinstance(config, dict):
            continue
        values.extend(_as_string_list(config.get(key)))
    return _unique_strings(values)


def _canvas_fact_types_from_requirements(requirements: list[Any] | None) -> list[str]:
    fact_types: list[str] = []
    for requirement in requirements or []:
        if isinstance(requirement, str):
            fact_types.append(requirement)
            continue
        if not isinstance(requirement, dict):
            continue
        value = (
            requirement.get("fact_type")
            or requirement.get("evidence_type")
            or requirement.get("type")
        )
        if value:
            fact_types.append(str(value))
    return _unique_strings(fact_types)


def _build_lti_capabilities(
    *,
    platform: CanvasPlatform,
    verified_launch: dict[str, Any],
    binding: CanvasProgramBinding,
) -> dict[str, Any]:
    """Negotiate standards capabilities from LTI claims and configured Canvas binding policy."""

    raw_claims = verified_launch.get("raw_claims") if isinstance(verified_launch.get("raw_claims"), dict) else {}
    message_type = str(
        verified_launch.get("message_type")
        or raw_claims.get("https://purl.imsglobal.org/spec/lti/claim/message_type")
        or raw_claims.get("message_type")
        or ""
    )
    deep_linking = _raw_lti_claim(raw_claims, LTI_DEEP_LINKING_SETTINGS_CLAIM, "deep_linking_settings")
    ags = _raw_lti_claim(raw_claims, LTI_AGS_ENDPOINT_CLAIM, "ags_endpoint")
    nrps = _raw_lti_claim(raw_claims, LTI_NRPS_CLAIM, "names_roles_service")
    platform_openid = platform.lti_openid_configuration
    evidence_requirements = binding.evidence_requirements
    if not evidence_requirements:
        evidence_requirements = ["canvas.course_completion"]

    return {
        "message_type": message_type or None,
        "resource_link": message_type == "LtiResourceLinkRequest",
        "deep_linking": bool(deep_linking) or message_type == "LtiDeepLinkingRequest",
        "assignment_grade_services": bool(ags),
        "names_roles": bool(nrps),
        "deep_link_return_url": deep_linking.get("deep_link_return_url"),
        "deep_link_accept_types": _as_string_list(deep_linking.get("accept_types")),
        "deep_link_accept_presentation_document_targets": _as_string_list(
            deep_linking.get("accept_presentation_document_targets")
        ),
        "ags_lineitems_url": ags.get("lineitems"),
        "ags_lineitem_url": ags.get("lineitem"),
        "ags_scopes": _as_string_list(ags.get("scope")),
        "nrps_context_memberships_url": nrps.get("context_memberships_url"),
        "supported_scopes": _openid_config_values("scopes_supported", platform_openid),
        "supported_claims": _openid_config_values("claims_supported", platform_openid),
        "binding_evidence_fact_types": _canvas_fact_types_from_requirements(evidence_requirements),
    }


def _lti_launch_response(
    *,
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
    state: str,
    verified: dict[str, Any],
) -> CanvasLtiLaunchResponse:
    context = verified.get("context")
    lti_capabilities = _build_lti_capabilities(
        platform=platform,
        verified_launch=verified,
        binding=binding,
    )
    return CanvasLtiLaunchResponse(
        organization_id=platform.organization_id,
        canvas_account_id=platform.canvas_account_id,
        canvas_platform_id=platform.id,
        canvas_program_binding_id=binding.id,
        application_template_id=binding.application_template_id,
        credential_template_id=binding.credential_template_id,
        delivery_mode=binding.delivery_mode,
        deployment_profile_id=binding.deployment_profile_id,
        feature_flags=normalize_canvas_feature_flags(binding.feature_flags),
        evidence_requirements=list(binding.evidence_requirements or []),
        state=state,
        issuer=str(verified["issuer"]),
        subject=str(verified["subject"]),
        audience=[str(item) for item in verified.get("audience", [])],
        deployment_id=str(verified["deployment_id"]),
        nonce=verified.get("nonce"),
        issued_at=verified.get("issued_at"),
        expires_at=verified.get("expires_at"),
        message_type=verified.get("message_type"),
        lti_version=verified.get("lti_version"),
        target_link_uri=verified.get("target_link_uri"),
        context=context if isinstance(context, dict) else None,
        roles=[str(item) for item in verified.get("roles", [])],
        learner_identity=verified.get("learner_identity") or {},
        raw_claims=verified.get("raw_claims") or {},
        lti_capabilities=lti_capabilities,
        identity_mapping_status=verified.get("identity_mapping_status"),
    )


def _browser_safe_canvas_context(verified_launch: dict[str, Any]) -> dict[str, Any]:
    context = _lti_canvas_context(verified_launch)
    course_id = _lti_signed_canvas_identifier(verified_launch, "canvas_course_id")
    return {
        key: value
        for key, value in {
            "course_id": course_id or context.get("id") or context.get("context_id"),
            "title": context.get("title"),
            "label": context.get("label"),
        }.items()
        if value is not None and str(value).strip()
    }


def _browser_safe_lti_capabilities(capabilities: dict[str, Any] | None) -> dict[str, Any]:
    values = capabilities if isinstance(capabilities, dict) else {}
    return {
        "resource_link": bool(values.get("resource_link")),
        "deep_linking": bool(values.get("deep_linking")),
        "assignment_grade_services": bool(values.get("assignment_grade_services")),
        "names_roles": bool(values.get("names_roles")),
    }


def _public_lti_launch_response(response: CanvasLtiLaunchResponse) -> CanvasLtiPublicLaunchResponse:
    verified = response.model_dump()
    return CanvasLtiPublicLaunchResponse(
        organization_id=response.organization_id,
        canvas_account_id=response.canvas_account_id,
        canvas_platform_id=response.canvas_platform_id,
        canvas_program_binding_id=response.canvas_program_binding_id,
        application_template_id=response.application_template_id,
        credential_template_id=response.credential_template_id,
        message_type=response.message_type,
        context=_browser_safe_canvas_context(verified),
        roles=[str(role).rsplit("/", 1)[-1] for role in response.roles],
        identity_mapping_status=response.identity_mapping_status,
    )


async def _resolve_lti_program_binding(
    *,
    platform: CanvasPlatform,
    verified: dict[str, Any],
    repo: IIssuanceRepository,
) -> tuple[CanvasPlatform | None, CanvasProgramBinding | None]:
    resolved_platform, resolved_binding = await resolve_canvas_program_binding_for_scope(
        repo=repo,
        organization_id=platform.organization_id,
        canvas_account_id=platform.canvas_account_id,
        actual_scope=lti_verified_launch_to_canvas_scope(
            verified,
            canvas_account_id=platform.canvas_account_id,
        ),
    )
    if resolved_binding is not None:
        return resolved_platform, resolved_binding

    # A staff-only setup launch may select a draft binding so Deep Linking can
    # pin the server-generated resource and Canvas line-item IDs before final
    # activation. Learner launches never receive this fallback.
    message_type = str(
        verified.get("message_type")
        or _lti_raw_claims(verified).get(LTI_MESSAGE_TYPE_CLAIM)
        or ""
    )
    if message_type not in {"LtiDeepLinkingRequest", "LtiResourceLinkRequest"}:
        return resolved_platform, None
    try:
        _require_deep_linking_staff_role(verified)
    except HTTPException:
        return resolved_platform, None
    actual_scope = lti_verified_launch_to_canvas_scope(
        verified,
        canvas_account_id=platform.canvas_account_id,
    )
    custom = _lti_signed_custom_claims(verified)
    requested_binding_id = str(custom.get("canvas_program_binding_id") or "").strip()
    candidates = await repo.list_canvas_program_bindings(
        platform.organization_id,
        platform_id=platform.id,
    )
    candidates = [
        candidate
        for candidate in candidates
        if candidate.archived_at is None
        and (not requested_binding_id or candidate.id == requested_binding_id)
        and canvas_scope_matches(candidate.canvas_scope, actual_scope)
    ]
    if len(candidates) != 1:
        return platform, None
    return platform, candidates[0]


async def _persist_verified_ags_line_item(
    *,
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
    verified_launch: dict[str, Any],
    repo: IIssuanceRepository,
) -> bool:
    raw_claims = _lti_raw_claims(verified_launch)
    custom = _raw_lti_claim(raw_claims, "https://purl.imsglobal.org/spec/lti/claim/custom", "custom")
    ags = _raw_lti_claim(raw_claims, LTI_AGS_ENDPOINT_CLAIM, "ags_endpoint")
    resource_id = str(custom.get("canvas_resource_id") or "").strip()
    requirement_id = str(custom.get("canvas_requirement_id") or "").strip()
    line_item_url = str(ags.get("lineitem") or "").strip()
    if not resource_id or not requirement_id or not line_item_url:
        return False
    if custom.get("canvas_program_binding_id") != binding.id:
        raise HTTPException(status_code=409, detail="Canvas launch resource does not match the selected binding")
    try:
        line_item_url = validate_lti_service_url(line_item_url)
        requirements = validate_canvas_evidence_requirements(list(binding.evidence_requirements or []))
    except (CanvasLtiServiceError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=f"Canvas AGS line item could not be pinned: {exc}") from exc
    matched = False
    updated: list[dict[str, Any]] = []
    for requirement in requirements:
        serialized = requirement.to_dict()
        if (
            requirement.requirement_id == requirement_id
            and requirement.source == CanvasEvidenceSource.AGS_RESULT
            and requirement.scope.resource_id == resource_id
        ):
            serialized["scope"]["line_item_url"] = line_item_url
            matched = True
        updated.append(serialized)
    if not matched:
        raise HTTPException(status_code=409, detail="Canvas launch resource does not match an AGS requirement")
    if updated != list(binding.evidence_requirements or []):
        binding.evidence_requirements = updated
        binding.config_version += 1
        binding.enabled = False
        binding.validated_config_version = None
        binding.readiness_checks = []
        binding.readiness_validated_at = None
        binding.activated_at = None
        binding.credential_template_snapshot = {}
        binding.updated_at = datetime.now(timezone.utc)
        await repo.save_canvas_program_binding(binding)
        return True
    return False


def _require_canvas_feature(binding: CanvasProgramBinding | None, flag: str, detail: str) -> None:
    if binding is not None and not canvas_feature_enabled(binding, flag):
        raise HTTPException(status_code=409, detail=detail)


def _canvas_auto_approval_ready(binding: CanvasProgramBinding) -> bool:
    """Fail closed when activation/readiness changes after a learner launch."""

    return bool(
        binding.auto_approve_on_evidence
        and binding.enabled
        and canvas_feature_enabled(binding, "enable_canvas_evidence")
        and canvas_binding_is_ready_for_activation(binding)
    )


async def _require_lti_session_canvas_feature(
    *,
    repo: IIssuanceRepository,
    session_values: dict[str, Any],
    flag: str,
    detail: str,
) -> None:
    binding_id = session_values.get("canvas_program_binding_id")
    if not binding_id:
        return
    binding = await repo.get_canvas_program_binding(str(binding_id))
    _require_canvas_feature(binding, flag, detail)


def _lti_session_context_values(
    *,
    launch_state: CanvasLtiLaunchState,
    verified_launch: dict[str, Any],
    mip_primitives: dict[str, Any],
) -> dict[str, Any]:
    mip_context = mip_primitives.get("context") if isinstance(mip_primitives.get("context"), dict) else {}
    return {
        "state": (launch_state.metadata or {}).get("launch_state") or launch_state.id,
        "session_id": launch_state.id,
        "organization_id": launch_state.organization_id,
        "canvas_account_id": launch_state.canvas_account_id,
        "canvas_platform_id": (
            mip_context.get("canvas_platform_id")
            or verified_launch.get("canvas_platform_id")
            or launch_state.platform_id
        ),
        "canvas_program_binding_id": mip_context.get("canvas_program_binding_id") or verified_launch.get("canvas_program_binding_id"),
        "application_template_id": mip_context.get("application_template_id") or verified_launch.get("application_template_id"),
        "credential_template_id": mip_context.get("credential_template_id") or verified_launch.get("credential_template_id"),
        "delivery_mode": mip_context.get("delivery_mode") or verified_launch.get("delivery_mode") or "wallet_only",
        "deployment_profile_id": mip_context.get("deployment_profile_id") or verified_launch.get("deployment_profile_id"),
        "feature_flags": mip_context.get("feature_flags") or verified_launch.get("feature_flags") or {},
        "launch_url": (launch_state.metadata or {}).get("launch_url"),
        "application_id": mip_context.get("application_id") or verified_launch.get("application_id"),
        "lti_capabilities": mip_context.get("lti_capabilities") or verified_launch.get("lti_capabilities") or {},
    }


async def _load_verified_lti_experience_session(
    *,
    state: str,
    repo: IIssuanceRepository,
) -> tuple[CanvasLtiLaunchState, dict[str, Any], dict[str, Any], dict[str, Any]]:
    session_hash = hashlib.sha256(state.encode("utf-8")).hexdigest()
    launch_state = await repo.get_canvas_lti_launch_state(session_hash)
    if launch_state is None:
        raise HTTPException(status_code=404, detail="Canvas LTI experience session not found")
    verified_launch = launch_state.metadata.get("verified_launch") if launch_state.metadata else None
    mip_primitives = launch_state.metadata.get("mip_primitives") if launch_state.metadata else None
    if (
        launch_state.status != "session"
        or launch_state.is_expired
        or (launch_state.metadata or {}).get("kind") != "canvas_lti_experience_session"
        or not isinstance(verified_launch, dict)
        or not isinstance(mip_primitives, dict)
    ):
        raise HTTPException(status_code=404, detail="Canvas LTI experience session not found")
    return (
        launch_state,
        verified_launch,
        mip_primitives,
        _lti_session_context_values(
            launch_state=launch_state,
            verified_launch=verified_launch,
            mip_primitives=mip_primitives,
        ),
    )


def _lti_canvas_context(verified_launch: dict[str, Any]) -> dict[str, Any]:
    context = verified_launch.get("context")
    return context if isinstance(context, dict) else {}


def _lti_learner_identity(verified_launch: dict[str, Any]) -> dict[str, Any]:
    learner = verified_launch.get("learner_identity")
    return learner if isinstance(learner, dict) else {}


def _lti_raw_claims(verified_launch: dict[str, Any]) -> dict[str, Any]:
    raw_claims = verified_launch.get("raw_claims")
    return raw_claims if isinstance(raw_claims, dict) else {}


def _lti_subject(verified_launch: dict[str, Any]) -> str | None:
    learner = _lti_learner_identity(verified_launch)
    raw_claims = _lti_raw_claims(verified_launch)
    value = verified_launch.get("subject") or learner.get("subject") or raw_claims.get("sub")
    return str(value) if value is not None and str(value).strip() else None


def _lti_signed_custom_claims(verified_launch: dict[str, Any]) -> dict[str, Any]:
    return _raw_lti_claim(
        _lti_raw_claims(verified_launch),
        "https://purl.imsglobal.org/spec/lti/claim/custom",
        "custom",
    )


def _lti_signed_canvas_identifier(
    verified_launch: dict[str, Any],
    name: str,
) -> str | None:
    value = _lti_signed_custom_claims(verified_launch).get(name)
    return str(value).strip() if value is not None and str(value).strip() else None


def _lti_canvas_user_id(verified_launch: dict[str, Any]) -> str | None:
    """Return only Canvas's signed numeric REST identity, never the opaque LTI subject."""

    return _lti_signed_canvas_identifier(verified_launch, "canvas_user_id")


def _lti_applicant_identifier(
    *,
    verified_launch: dict[str, Any],
    request: CanvasLtiApplicationBootstrapRequest,
) -> str:
    # The opaque, deployment-scoped LTI subject is the canonical applicant
    # identity. Caller input and email are profile attributes only and are
    # never used to join Canvas learners.
    subject = _lti_subject(verified_launch)
    if subject:
        return f"canvas_lti:{subject}"
    return f"canvas_lti_{uuid.uuid4().hex[:8]}"


def _lti_application_form_data(
    *,
    verified_launch: dict[str, Any],
    request: CanvasLtiApplicationBootstrapRequest,
) -> dict[str, Any]:
    learner = _lti_learner_identity(verified_launch)
    raw_claims = _lti_raw_claims(verified_launch)
    canvas_context = _lti_canvas_context(verified_launch)
    signed_course_id = _lti_signed_canvas_identifier(verified_launch, "canvas_course_id")
    form_data = {
        "email": learner.get("email") or raw_claims.get("email"),
        "given_name": learner.get("given_name") or raw_claims.get("given_name"),
        "family_name": learner.get("family_name") or raw_claims.get("family_name"),
        "name": learner.get("name") or raw_claims.get("name"),
        "canvas_subject": _lti_subject(verified_launch),
        "canvas_course_id": signed_course_id or canvas_context.get("id") or canvas_context.get("context_id"),
        "canvas_course_name": canvas_context.get("title") or canvas_context.get("label"),
    }
    caller_data = {
        key: value
        for key, value in (request.applicant_data or {}).items()
        if key not in {"canvas_subject", "canvas_course_id", "canvas_user_id"}
    }
    return {
        key: value
        for key, value in {
            **caller_data,
            **form_data,
        }.items()
        if value is not None
    }


def _lti_application_canvas_context(
    *,
    session_values: dict[str, Any],
    verified_launch: dict[str, Any],
) -> dict[str, Any]:
    canvas_context = _lti_canvas_context(verified_launch)
    canvas_user_id = _lti_canvas_user_id(verified_launch)
    course_id = (
        _lti_signed_canvas_identifier(verified_launch, "canvas_course_id")
        or canvas_context.get("id")
        or canvas_context.get("context_id")
    )
    return {
        "source": "canvas_lti_bootstrap",
        "lti_state": session_values["state"],
        "last_lti_state": session_values["state"],
        "lti_states": [session_values["state"]],
        "canvas_account_id": session_values["canvas_account_id"],
        "canvas_platform_id": session_values.get("canvas_platform_id"),
        "canvas_program_binding_id": session_values.get("canvas_program_binding_id"),
        "deployment_profile_id": session_values.get("deployment_profile_id"),
        "feature_flags": session_values.get("feature_flags") or {},
        "application_template_id": session_values.get("application_template_id"),
        "credential_template_id": session_values.get("credential_template_id"),
        "delivery_mode": session_values.get("delivery_mode") or "wallet_only",
        "canvas_course_id": course_id,
        "canvas_context": canvas_context,
        "lti_subject": _lti_subject(verified_launch),
        "canvas_user_id": canvas_user_id,
        "learner_identity": _lti_learner_identity(verified_launch),
        "roles": verified_launch.get("roles") or [],
        "launch_url": session_values.get("launch_url"),
        "lti_capabilities": session_values.get("lti_capabilities") or {},
    }


def _deep_linking_settings(verified_launch: dict[str, Any]) -> dict[str, Any]:
    return _raw_lti_claim(
        _lti_raw_claims(verified_launch),
        LTI_DEEP_LINKING_SETTINGS_CLAIM,
        "deep_linking_settings",
    )


def _require_deep_linking_staff_role(verified_launch: dict[str, Any]) -> None:
    roles = _as_string_list(verified_launch.get("roles"))
    allowed = {"instructor", "administrator"}
    normalized = {
        role.strip().lower().replace("#", "/").rstrip("/").rsplit("/", 1)[-1]
        for role in roles
        if role.strip()
    }
    if not normalized.intersection(allowed):
        raise HTTPException(
            status_code=403,
            detail="Canvas Deep Linking requires an authenticated Instructor or Administrator role",
        )


def _deep_linking_resource_title(
    binding: CanvasProgramBinding,
    session_values: dict[str, Any],
    verified_launch: dict[str, Any],
) -> str:
    canvas_context = _lti_canvas_context(verified_launch)
    for value in (
        binding.display_name,
        canvas_context.get("title"),
        canvas_context.get("label"),
        session_values.get("credential_template_id"),
        session_values.get("application_template_id"),
    ):
        if value is not None and str(value).strip():
            return str(value).strip()
    return "ElevenID Credential Application"


def _deep_linking_custom_values(
    session_values: dict[str, Any],
    verified_launch: dict[str, Any],
    requirement: CanvasEvidenceRequirement | None = None,
) -> dict[str, str]:
    canvas_context = _lti_canvas_context(verified_launch)
    values = {
        "canvas_account_id": session_values["canvas_account_id"],
        "canvas_platform_id": session_values.get("canvas_platform_id"),
        "canvas_program_binding_id": session_values.get("canvas_program_binding_id"),
        "application_template_id": session_values.get("application_template_id"),
        "credential_template_id": session_values.get("credential_template_id"),
        "canvas_course_id": canvas_context.get("id") or canvas_context.get("context_id"),
    }
    if requirement is not None:
        values.update(
            {
                "canvas_requirement_id": requirement.requirement_id,
                "canvas_resource_id": requirement.scope.resource_id,
            }
        )
    return {
        str(key): str(value)
        for key, value in values.items()
        if key is not None and value is not None and str(key).strip() and str(value).strip()
    }


def _build_deep_linking_content_item(
    *,
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
    session_values: dict[str, Any],
    verified_launch: dict[str, Any],
    requirement: CanvasEvidenceRequirement | None = None,
) -> dict[str, Any]:
    title = _deep_linking_resource_title(binding, session_values, verified_launch)
    item: dict[str, Any] = {
        "type": "ltiResourceLink",
        "title": title,
        "text": "Open the Marty credential application for this course.",
        "url": _lti_experience_redirect_uri(platform.id),
        "custom": _deep_linking_custom_values(session_values, verified_launch, requirement),
    }
    accepted_targets = {
        value.lower()
        for value in _as_string_list(
            _deep_linking_settings(verified_launch).get(
                "accept_presentation_document_targets"
            )
        )
    }
    if "window" in accepted_targets:
        # A standard Deep Linking presentation hint makes the learner launch
        # visible through Canvas's assignment UI and avoids third-party-cookie
        # dependence inside an LMS iframe.
        item["presentation"] = {
            "documentTarget": "window",
            "windowTarget": "_blank",
        }
    if requirement is not None:
        item["lineItem"] = {
            "scoreMaximum": 100,
            "label": title,
            "resourceId": requirement.scope.resource_id,
            "tag": f"marty:{requirement.requirement_id}",
        }
    return item


def _build_deep_linking_jwt_payload(
    *,
    platform: CanvasPlatform,
    verified_launch: dict[str, Any],
    content_items: list[dict[str, Any]],
) -> dict[str, Any]:
    now = int(datetime.now(timezone.utc).timestamp())
    settings = _deep_linking_settings(verified_launch)
    payload: dict[str, Any] = {
        "iss": os.environ.get("CANVAS_LTI_DEEP_LINKING_ISSUER") or platform.lti_client_id,
        "aud": verified_launch.get("issuer") or platform.lti_issuer,
        "iat": now,
        "exp": now + 300,
        "nonce": uuid.uuid4().hex,
        LTI_DEPLOYMENT_ID_CLAIM: verified_launch.get("deployment_id") or platform.lti_deployment_id,
        LTI_MESSAGE_TYPE_CLAIM: "LtiDeepLinkingResponse",
        LTI_VERSION_CLAIM: "1.3.0",
        LTI_DEEP_LINKING_CONTENT_ITEMS_CLAIM: content_items,
    }
    if settings.get("data") is not None:
        payload[LTI_DEEP_LINKING_DATA_CLAIM] = settings["data"]
    return payload


def _application_matches_lti_subject(
    app: Application,
    *,
    session_values: dict[str, Any],
    subject: str | None,
) -> bool:
    if not subject:
        return False
    canvas = app.integration_context.get("canvas") if isinstance(app.integration_context, dict) else None
    if not isinstance(canvas, dict):
        return False
    if canvas.get("canvas_program_binding_id") != session_values.get("canvas_program_binding_id"):
        return False
    return str(canvas.get("lti_subject") or "") == str(subject)


async def _attach_lti_application_to_launch_state(
    *,
    repo: IIssuanceRepository,
    launch_state: CanvasLtiLaunchState,
    verified_launch: dict[str, Any],
    mip_primitives: dict[str, Any],
    app: Application,
    created: bool,
) -> None:
    mip_context = mip_primitives.get("context") if isinstance(mip_primitives.get("context"), dict) else {}
    mip_primitives["context"] = {
        **mip_context,
        "application_id": app.id,
    }
    verified_launch["application_id"] = app.id
    launch_state.metadata = {
        **(launch_state.metadata or {}),
        "verified_launch": verified_launch,
        "mip_primitives": mip_primitives,
        "application_bootstrap": {
            "application_id": app.id,
            "created": created,
            "bootstrapped_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    await repo.save_canvas_lti_launch_state(launch_state)


async def _find_or_create_lti_application(
    *,
    repo: IIssuanceRepository,
    launch_state: CanvasLtiLaunchState,
    verified_launch: dict[str, Any],
    mip_primitives: dict[str, Any],
    session_values: dict[str, Any],
    request: CanvasLtiApplicationBootstrapRequest,
) -> tuple[Application, bool]:
    _require_portable_canvas_pilot(launch_state.organization_id)
    application_template_id = session_values.get("application_template_id")
    if not application_template_id:
        raise HTTPException(status_code=409, detail="Canvas LTI session is not bound to an application template")
    template = await repo.get_application_template(str(application_template_id))
    if template is None:
        raise HTTPException(status_code=404, detail="Bound application template not found")
    if template.organization_id != launch_state.organization_id:
        raise HTTPException(status_code=409, detail="Canvas LTI application template belongs to a different organization")

    existing_apps = sorted(
        await repo.list_applications(
            org_id=launch_state.organization_id,
            template_id=str(application_template_id),
        ),
        key=lambda app: app.created_at,
        reverse=True,
    )
    for app in existing_apps:
        canvas = app.integration_context.get("canvas") if isinstance(app.integration_context, dict) else None
        if isinstance(canvas, dict) and canvas.get("lti_state") == session_values["state"]:
            await _attach_lti_application_to_launch_state(
                repo=repo,
                launch_state=launch_state,
                verified_launch=verified_launch,
                mip_primitives=mip_primitives,
                app=app,
                created=False,
            )
            return app, False

    subject = _lti_subject(verified_launch)
    for app in existing_apps:
        if app.status in {ApplicationStatus.REJECTED, ApplicationStatus.WITHDRAWN}:
            continue
        if _application_matches_lti_subject(app, session_values=session_values, subject=subject):
            canvas = app.integration_context.get("canvas") if isinstance(app.integration_context, dict) else {}
            if not isinstance(canvas, dict):
                canvas = {}
            lti_states = list(canvas.get("lti_states") or [])
            if session_values["state"] not in lti_states:
                lti_states.append(session_values["state"])
            app.integration_context = {
                **(app.integration_context or {}),
                "canvas": {
                    **canvas,
                    "last_lti_state": session_values["state"],
                    "lti_states": lti_states[-10:],
                    "deployment_profile_id": session_values.get("deployment_profile_id"),
                    "feature_flags": session_values.get("feature_flags") or canvas.get("feature_flags") or {},
                    "delivery_mode": session_values.get("delivery_mode") or canvas.get("delivery_mode") or "wallet_only",
                },
                "delivery_mode": session_values.get("delivery_mode") or (app.integration_context or {}).get("delivery_mode") or "wallet_only",
                "delivery": {
                    **(((app.integration_context or {}).get("delivery") or {}) if isinstance((app.integration_context or {}).get("delivery"), dict) else {}),
                    "mode": session_values.get("delivery_mode") or (app.integration_context or {}).get("delivery_mode") or "wallet_only",
                },
            }
            app.updated_at = datetime.now(timezone.utc)
            await repo.save_application(app)
            await _attach_lti_application_to_launch_state(
                repo=repo,
                launch_state=launch_state,
                verified_launch=verified_launch,
                mip_primitives=mip_primitives,
                app=app,
                created=False,
            )
            return app, False

    app = Application(
        organization_id=template.organization_id,
        application_template_id=template.id,
        applicant_identifier=_lti_applicant_identifier(
            verified_launch=verified_launch,
            request=request,
        ),
        form_data=_lti_application_form_data(
            verified_launch=verified_launch,
            request=request,
        ),
        integration_context={
            "canvas": _lti_application_canvas_context(
                session_values=session_values,
                verified_launch=verified_launch,
            ),
            "delivery_mode": session_values.get("delivery_mode") or "wallet_only",
            "delivery": {
                "mode": session_values.get("delivery_mode") or "wallet_only",
            },
        },
    )
    await repo.save_application(app)
    await repo.save_event(
        IssuanceEvent(
            application_id=app.id,
            event_type=EventType.CANVAS_LTI_APPLICATION_BOOTSTRAPPED,
            metadata={
                "organization_id": app.organization_id,
                "source": "canvas_lti_experience",
                "state": session_values["state"],
                "canvas_account_id": launch_state.canvas_account_id,
                "canvas_platform_id": session_values.get("canvas_platform_id"),
                "canvas_program_binding_id": session_values.get("canvas_program_binding_id"),
                "application_template_id": app.application_template_id,
                "credential_template_id": session_values.get("credential_template_id"),
                "subject": subject,
            },
        )
    )
    await _attach_lti_application_to_launch_state(
        repo=repo,
        launch_state=launch_state,
        verified_launch=verified_launch,
        mip_primitives=mip_primitives,
        app=app,
        created=True,
    )
    return app, True


async def _exact_linked_canvas_identity_for_launch(
    *,
    repo: IIssuanceRepository,
    platform: CanvasPlatform,
    verified_launch: dict[str, Any],
) -> CanvasLearnerIdentity | None:
    """Return the one persisted identity that exactly joins both signed IDs."""

    subject = str(_lti_subject(verified_launch) or "").strip()
    canvas_user_id = str(_lti_canvas_user_id(verified_launch) or "").strip()
    deployment_id = str(
        verified_launch.get("deployment_id") or platform.lti_deployment_id or ""
    ).strip()
    if not subject or not canvas_user_id or not deployment_id:
        return None

    by_subject = await repo.get_canvas_learner_identity_by_subject(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        deployment_id=deployment_id,
        lti_subject=subject,
    )
    by_numeric_id = await repo.get_canvas_learner_identity_by_canvas_user(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        deployment_id=deployment_id,
        canvas_user_id=canvas_user_id,
    )
    if (
        by_subject is None
        or by_numeric_id is None
        or by_subject.id != by_numeric_id.id
        or by_subject.status != CanvasLearnerIdentityStatus.LINKED
        or by_subject.lti_subject != subject
        or str(by_subject.canvas_user_id or "").strip() != canvas_user_id
    ):
        return None
    return by_subject


def _canvas_candidate_observation_is_fresh(
    observation: CanvasCandidateObservation,
    *,
    now: datetime,
) -> bool:
    """Require the same verified/fresh observation used by wallet issuance."""

    if str((observation.verification or {}).get("status") or "").upper() != "VERIFIED":
        return False
    try:
        return canvas_evidence_observation_is_fresh(
            observation.observed_at,
            now=now,
        )
    except CanvasIssuanceGuardError:
        # Invalid freshness configuration must fail closed before candidate
        # evidence is copied into the canonical application.
        return False


async def _materialize_canvas_award_candidate_on_launch(
    *,
    repo: IIssuanceRepository,
    app: Application,
    verified_launch: dict[str, Any],
    session_values: dict[str, Any],
) -> None:
    """Move current unsigned candidate observations into the canonical app."""

    if not portable_canvas_enabled_for_organization(app.organization_id):
        return
    binding_id = str(session_values.get("canvas_program_binding_id") or "").strip()
    platform_id = str(session_values.get("canvas_platform_id") or "").strip()
    if not binding_id or not platform_id:
        return
    binding = await repo.get_canvas_program_binding_for_org(app.organization_id, binding_id)
    platform = await repo.get_canvas_platform_for_org(app.organization_id, platform_id)
    if binding is None or platform is None:
        return
    subject = _lti_subject(verified_launch)
    canvas_user_id = _lti_canvas_user_id(verified_launch)
    linked_identity = (
        await _exact_linked_canvas_identity_for_launch(
            repo=repo,
            platform=platform,
            verified_launch=verified_launch,
        )
        if canvas_user_id
        else None
    )
    candidates = await repo.list_canvas_award_candidates(
        app.organization_id,
        binding_id=binding.id,
        limit=500,
    )

    def candidate_matches_launch(value: CanvasAwardCandidate) -> bool:
        if value.state not in {
            CanvasAwardCandidateState.PENDING_CLAIM,
            CanvasAwardCandidateState.ELIGIBLE,
        }:
            return False
        if value.canvas_user_id:
            # Numeric REST evidence may cross into an LTI subject namespace only
            # through the exact, current, non-quarantined persisted identity join.
            return bool(
                linked_identity is not None
                and str(value.canvas_user_id).strip()
                == str(linked_identity.canvas_user_id or "").strip()
                and (not value.lti_subject or value.lti_subject == subject)
                and (
                    not value.learner_identity_id
                    or value.learner_identity_id == linked_identity.id
                )
            )
        return bool(subject and value.lti_subject == subject)

    candidate = next(
        (
            value
            for value in candidates
            if candidate_matches_launch(value)
        ),
        None,
    )
    if candidate is None:
        return
    materialized_at = datetime.now(timezone.utc)
    try:
        candidate_is_fresh = canvas_evidence_observation_is_fresh(
            candidate.observed_at,
            now=materialized_at,
        )
    except CanvasIssuanceGuardError:
        candidate_is_fresh = False
    if not candidate_is_fresh:
        return
    try:
        requirements = validate_canvas_evidence_requirements(
            list(binding.evidence_requirements or [])
        )
    except ValueError:
        return
    by_id = {item.requirement_id: item for item in requirements}
    observations = await repo.list_current_canvas_candidate_observations(
        app.organization_id,
        candidate.id,
    )
    current_observations = {
        observation.requirement_id: observation
        for observation in observations
    }
    required_observations_are_current = all(
        not requirement.required
        or (
            (observation := current_observations.get(requirement.requirement_id))
            is not None
            and _canvas_candidate_observation_is_fresh(
                observation,
                now=materialized_at,
            )
            and _candidate_observation_satisfies(requirement, observation)
        )
        for requirement in requirements
    )
    if not required_observations_are_current:
        return
    observations = [
        observation
        for observation in observations
        if _canvas_candidate_observation_is_fresh(
            observation,
            now=materialized_at,
        )
    ]
    if not observations:
        return
    template = await repo.get_application_template(app.application_template_id)
    if template is None:
        return
    allowed = False
    for observation in observations:
        requirement = by_id.get(observation.requirement_id)
        if requirement is None:
            continue
        fact = _authoritative_canvas_fact(
            app=app,
            platform=platform,
            binding=binding,
            requirement=requirement,
            subject_id=str(subject or candidate.lti_subject or candidate.canvas_user_id or ""),
            assertion=dict(observation.assertion or {}),
            source_payload={
                "candidate_observation_id": observation.id,
                "candidate_payload_hash": observation.payload_hash,
            },
            verification_method=str(
                (observation.verification or {}).get("method")
                or "CANVAS_BACKGROUND_AUTHORITATIVE_READ"
            ),
            observed_at=observation.observed_at,
            effective_at=observation.observed_at,
        )
        _fact_id, _changed, allowed = await _record_canvas_fact_and_policy(
            repo=repo,
            app=app,
            template=template,
            binding=binding,
            fact=fact,
            requirements=requirements,
        )
    candidate.application_id = app.id
    candidate.lti_subject = subject or candidate.lti_subject
    candidate.canvas_user_id = canvas_user_id or candidate.canvas_user_id
    if candidate.canvas_user_id and linked_identity is not None:
        candidate.learner_identity_id = linked_identity.id
    await repo.save_canvas_award_candidate(candidate)
    canvas = (
        app.integration_context.get("canvas")
        if isinstance(app.integration_context, dict)
        else {}
    )
    app.integration_context = {
        **(app.integration_context or {}),
        "canvas": {
            **(canvas if isinstance(canvas, dict) else {}),
            "canvas_award_candidate_id": candidate.id,
            "candidate_materialized_at": materialized_at.isoformat(),
        },
    }
    await repo.save_application(app)
    current_binding = await repo.get_canvas_program_binding_for_org(
        app.organization_id,
        binding.id,
    )
    identity_still_linked = True
    if candidate.canvas_user_id:
        current_identity = await _exact_linked_canvas_identity_for_launch(
            repo=repo,
            platform=platform,
            verified_launch=verified_launch,
        )
        identity_still_linked = bool(
            current_identity is not None
            and linked_identity is not None
            and current_identity.id == linked_identity.id
        )
    if (
        allowed
        and identity_still_linked
        and current_binding is not None
        and _canvas_auto_approval_ready(current_binding)
        and app.status == ApplicationStatus.PENDING
    ):
        try:
            credential_context = credential_context_from_template_snapshot(
                dict(current_binding.credential_template_snapshot or {})
            )
            await approve_application_for_issuance(
                repo=repo,
                app=app,
                template=template,
                reviewer_id="canvas-pending-award-claim",
                review_notes="Learner claimed an eligible Canvas pending award",
                credential_context=credential_context,
                issuer_context_applier=apply_required_remote_issuer_context,
            )
        except (ValueError, RuntimeError):
            # Readiness or KMS drift must leave the claim pending for an
            # administrator; it must never fall back to another issuer/key.
            return


async def _initiate_canvas_lti_login(
    *,
    platform_id: str,
    request: Request,
    repo: IIssuanceRepository,
    redirect_uri: str,
) -> RedirectResponse:
    platform = await repo.get_canvas_platform(platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
    _require_portable_canvas_pilot(platform.organization_id)
    _validate_lti_ready_platform(platform)

    submission = await _parse_lti_login_submission(request)
    if submission["issuer"] and submission["issuer"] != platform.lti_issuer:
        raise HTTPException(status_code=400, detail="Canvas LTI issuer does not match platform")
    if submission["client_id"] and submission["client_id"] != platform.lti_client_id:
        raise HTTPException(status_code=400, detail="Canvas LTI client_id does not match platform")

    launch_state = CanvasLtiLaunchState(
        platform_id=platform.id,
        organization_id=platform.organization_id,
        canvas_account_id=platform.canvas_account_id,
        login_hint=submission["login_hint"],
        target_link_uri=submission["target_link_uri"],
        lti_message_hint=submission["lti_message_hint"],
        redirect_uri=redirect_uri,
        metadata={
            "issuer": submission["issuer"],
            "client_id": submission["client_id"],
            "canvas_platform_id": platform.id,
            "experience_mode": redirect_uri.endswith(f"/lti/platforms/{platform.id}/experience"),
        },
    )
    await repo.save_canvas_lti_launch_state(launch_state)

    params = {
        "scope": "openid",
        "response_type": "id_token",
        "response_mode": "form_post",
        "prompt": "none",
        "client_id": platform.lti_client_id,
        "redirect_uri": redirect_uri,
        "login_hint": launch_state.login_hint,
        "state": launch_state.state,
        "nonce": launch_state.nonce,
    }
    if launch_state.lti_message_hint:
        params["lti_message_hint"] = launch_state.lti_message_hint

    authorization_endpoint = _lti_authorization_endpoint(platform)
    separator = "&" if "?" in authorization_endpoint else "?"
    return RedirectResponse(
        f"{authorization_endpoint}{separator}{urlencode(params)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


async def _verify_canvas_lti_launch_submission(
    *,
    platform_id: str,
    request: Request,
    repo: IIssuanceRepository,
) -> tuple[CanvasPlatform, CanvasLtiLaunchState, CanvasLtiLaunchResponse]:
    platform = await repo.get_canvas_platform(platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
    _require_portable_canvas_pilot(platform.organization_id)
    _validate_lti_ready_platform(platform)

    id_token, state = await _parse_lti_launch_submission(request)
    launch_state = await repo.get_canvas_lti_launch_state(state)
    if launch_state is None or launch_state.platform_id != platform.id:
        raise HTTPException(status_code=400, detail="Canvas LTI state is unknown for this platform")
    if launch_state.status != "pending" or launch_state.is_expired:
        raise HTTPException(status_code=400, detail="Canvas LTI state has expired or already been used")

    consumed_state = await repo.consume_canvas_lti_launch_state(state)
    if consumed_state is None:
        raise HTTPException(status_code=400, detail="Canvas LTI state has expired or already been used")

    try:
        verified = _verify_lti_launch_with_platform(
            platform=platform,
            id_token=id_token,
            expected_nonce=consumed_state.nonce,
        )
    except Exception as exc:  # pragma: no cover - exact binding exception type varies
        if not (_is_lti_kid_miss(exc) and platform.canvas_base_url):
            raise HTTPException(status_code=400, detail=f"Canvas LTI launch verification failed: {exc}") from exc
        try:
            platform, _probe = await _refresh_canvas_platform_jwks(platform, repo)
            verified = _verify_lti_launch_with_platform(
                platform=platform,
                id_token=id_token,
                expected_nonce=consumed_state.nonce,
            )
        except Exception as refresh_exc:  # pragma: no cover - exact binding exception type varies
            raise HTTPException(
                status_code=400,
                detail=f"Canvas LTI launch verification failed after JWKS refresh: {refresh_exc}",
            ) from refresh_exc

    await _record_verified_canvas_launch_identity(
        platform=platform,
        verified_launch=verified,
        repo=repo,
    )
    platform, binding = await _resolve_lti_program_binding(
        platform=platform,
        verified=verified,
        repo=repo,
    )
    if binding is None:
        raise HTTPException(status_code=409, detail="Canvas LTI launch did not match an enabled Canvas program binding")
    _require_canvas_feature(binding, "enable_canvas_lti", "Canvas LTI is disabled for this deployment profile")
    line_item_configuration_changed = await _persist_verified_ags_line_item(
        platform=platform,
        binding=binding,
        verified_launch=verified,
        repo=repo,
    )
    response = _lti_launch_response(
        platform=platform,
        binding=binding,
        state=state,
        verified=verified,
    )
    platform.registration_status = "verified"
    verified_at = datetime.now(timezone.utc)
    snapshot = dict(platform.capability_snapshot or {})
    launches = (
        dict(snapshot.get("verified_binding_launches") or {})
        if isinstance(snapshot.get("verified_binding_launches"), dict)
        else {}
    )
    prior = (
        dict(launches.get(binding.id) or {})
        if isinstance(launches.get(binding.id), dict)
        else {}
    )
    signed_course_id = str(
        _lti_signed_canvas_identifier(verified, "canvas_course_id") or ""
    ).strip()
    try:
        prior_version = int(prior.get("verified_binding_config_version"))
    except (TypeError, ValueError):
        prior_version = -1
    prior_course_id = str(prior.get("verified_course_id") or "").strip()
    can_carry_prior = bool(
        prior.get("verified_binding_id") == binding.id
        and prior_course_id == signed_course_id
        and (
            prior_version == binding.config_version
            or (
                line_item_configuration_changed
                and prior_version == binding.config_version - 1
            )
        )
    )
    launch_capabilities = dict(response.lti_capabilities or {})
    binding_capabilities = prior if can_carry_prior else {}
    # A course-navigation launch can omit AGS while a resource launch can omit
    # NRPS.  Preserve previously verified positive claims for the same binding,
    # course, and configuration instead of letting launch order erase them.
    for key, value in launch_capabilities.items():
        if (
            value is not None
            and value != ""
            and value is not False
            and value != []
        ) or key not in binding_capabilities:
            binding_capabilities[key] = value
    verified_line_items = {
        str(value).strip()
        for value in binding_capabilities.get("verified_ags_line_items", [])
        if str(value).strip()
    }
    current_line_item = str(launch_capabilities.get("ags_lineitem_url") or "").strip()
    if current_line_item:
        verified_line_items.add(current_line_item)
    binding_capabilities.update(
        {
            "verified_binding_id": binding.id,
            "verified_binding_config_version": binding.config_version,
            "verified_course_id": signed_course_id,
            "verified_at": verified_at.isoformat(),
            "verified_ags_line_items": sorted(verified_line_items),
        }
    )
    launches[binding.id] = binding_capabilities
    # Keep the last-launch fields for diagnostics/backward-compatible display,
    # while every authorization decision reads the binding-indexed snapshot.
    platform.capability_snapshot = {
        **launch_capabilities,
        "verified_binding_id": binding.id,
        "verified_binding_config_version": binding.config_version,
        "verified_course_id": signed_course_id,
        "verified_at": verified_at.isoformat(),
        "verified_binding_launches": launches,
    }
    platform.last_validated_at = verified_at
    platform.last_connection_error = None
    await repo.save_canvas_platform(platform)
    return platform, consumed_state, response


@canvas_integration_router.post(
    "/applications/{application_id}/approve",
    response_model=CanvasApplicationApprovalResponse,
    summary="Approve a Canvas application for wallet claim",
    dependencies=[Depends(_verify_management_api_key)],
)
async def approve_canvas_application(
    application_id: str,
    approval: CanvasApplicationApprovalRequest,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasApplicationApprovalResponse:
    """Create a claimable offer only from the active Canvas/KMS snapshot."""

    app, binding, _platform = await _management_canvas_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )
    _require_portable_canvas_pilot(app.organization_id)

    if app.status != ApplicationStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail="Canvas application cannot be approved in its current status",
        )

    template = await repo.get_application_template(app.application_template_id)
    if (
        template is None
        or template.organization_id != app.organization_id
        or template.id != binding.application_template_id
        or not template.credential_template_id
    ):
        raise HTTPException(status_code=404, detail="Canvas application not found")

    try:
        credential_context = await canvas_approval_credential_context(
            repo=repo,
            app=app,
            template=template,
        )
    except CanvasIssuanceGuardError:
        raise HTTPException(
            status_code=409,
            detail="Canvas application is not ready for approval",
        ) from None
    if credential_context is None:
        # The Canvas marker was already checked above; a None result would mean
        # the canonical guard no longer agrees that this is a Canvas workload.
        raise HTTPException(
            status_code=409,
            detail="Canvas application is not ready for approval",
        )

    try:
        transaction = await approve_application_for_issuance(
            repo=repo,
            app=app,
            template=template,
            reviewer_id="canvas-integration-management-api",
            review_notes=(
                approval.review_notes
                or "Approved through Canvas integration operations"
            ),
            credential_context=credential_context,
            issuer_context_applier=apply_required_remote_issuer_context,
        )
    except (RuntimeError, ValueError):
        # KMS/DID or template drift is intentionally exposed only as a stable,
        # non-sensitive conflict response.
        raise HTTPException(
            status_code=409,
            detail="Canvas application is not ready for approval",
        ) from None

    return CanvasApplicationApprovalResponse(
        application_id=app.id,
        status="approved",
        issuance_transaction_id=transaction.id,
    )


@canvas_integration_router.get(
    "/lti/jwks",
    summary="Get Marty public keys for Canvas LTI registration",
)
async def get_canvas_lti_tool_jwks() -> dict[str, Any]:
    return await _public_canvas_tool_jwks()


@canvas_integration_router.get(
    "/lti/config/{token}",
    summary="Get revocable Canvas LTI Developer Key configuration",
)
async def get_public_canvas_lti_config(
    token: str,
    response: Response,
    repo: IIssuanceRepository = Depends(),
) -> dict[str, Any]:
    platform_id = _platform_id_from_lti_config_token(token)
    platform = await repo.get_canvas_platform(platform_id) if platform_id else None
    config = dict(platform.connection_config or {}) if platform is not None else {}
    expected_hash = str(config.get("lti_config_token_hash") or "")
    actual_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if (
        platform is None
        or platform.archived_at is not None
        or config.get("lti_config_token_status") != "active"
        or not expected_hash
        or not hmac.compare_digest(expected_hash, actual_hash)
    ):
        raise HTTPException(status_code=404, detail="Canvas LTI configuration not found")
    response.headers["Cache-Control"] = "no-store"
    return _canvas_lti_registration(platform).developer_key_configuration


@canvas_integration_router.get(
    "/platforms/{platform_id}/registration-config",
    response_model=CanvasLtiRegistrationResponse,
    summary="Get portable Canvas LTI Developer Key configuration",
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_canvas_lti_registration_config(
    platform_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiRegistrationResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    config_token = _issue_lti_config_token(platform)
    await repo.save_canvas_platform(platform)
    return _canvas_lti_registration(platform, config_token=config_token)


@canvas_integration_router.put(
    "/platforms/{platform_id}/lti-installation",
    response_model=CanvasLtiRegistrationResponse,
    summary="Finalize or rotate a Canvas LTI installation",
    dependencies=[Depends(_verify_management_api_key)],
)
async def update_canvas_lti_installation(
    platform_id: str,
    request: CanvasLtiInstallationRequest,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiRegistrationResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    if request.rotate_config_token and request.revoke_config_token:
        raise HTTPException(status_code=400, detail="Rotate and revoke are mutually exclusive")
    client_id = request.lti_client_id.strip()
    deployment_id = request.lti_deployment_id.strip()
    changed = client_id != platform.lti_client_id or deployment_id != platform.lti_deployment_id
    platform.lti_client_id = client_id
    platform.lti_deployment_id = deployment_id
    if changed:
        platform.config_version += 1
        platform.enabled = False
        platform.registration_status = "draft"
        platform.capability_snapshot = {}
        platform.last_validated_at = None
        _revoke_lti_config_token(platform)
    if platform.canvas_base_url:
        try:
            probe = await probe_canvas_lti_platform(
                validate_canvas_origin(platform.canvas_base_url),
                trust_profile=platform.lti_trust_profile,
            )
        except Exception as exc:  # pragma: no cover - transport-specific probe failures
            platform.last_connection_error = str(exc)
            await repo.save_canvas_platform(platform)
            raise HTTPException(status_code=409, detail=f"Canvas LTI metadata probe failed: {exc}") from exc
        _apply_canvas_probe(platform, probe)
        if bool((platform.connection_config or {}).get("enabled_intent")):
            # Platform trust may be enabled after a successful metadata probe;
            # award issuance remains blocked until a binding is separately
            # validated and activated.
            platform.enabled = True
            platform.registration_status = "installed"
    config_token: str | None = None
    if request.revoke_config_token:
        _revoke_lti_config_token(platform)
    elif changed or request.rotate_config_token or not (platform.connection_config or {}).get("lti_config_token_hash"):
        config_token = _issue_lti_config_token(platform)
    await repo.save_canvas_platform(platform)
    if changed:
        await _invalidate_canvas_binding_readiness(repo=repo, platform=platform)
    return _canvas_lti_registration(platform, config_token=config_token)


@canvas_integration_router.get(
    "/platforms/{platform_id}/readiness",
    response_model=CanvasPlatformReadinessResponse,
    summary="Check portable Canvas integration readiness",
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_canvas_platform_readiness(
    platform_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformReadinessResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    bindings = [
        binding
        for binding in await repo.list_canvas_program_bindings(
            platform.organization_id,
            platform_id=platform.id,
        )
        if binding.archived_at is None
    ]
    checks: list[CanvasReadinessCheck] = []
    for binding in bindings:
        _binding, result = await _validate_managed_canvas_binding(
            binding_id=binding.id,
            trusted_organization_id=trusted_organization_id,
            repo=repo,
        )
        checks.extend(result.checks)
    if not bindings:
        now = datetime.now(timezone.utc).isoformat()
        checks.append(
            CanvasReadinessCheck(
                code="program_binding",
                component="bindings",
                status="failed",
                blocking=True,
                remediation="Create and validate at least one portable Canvas program binding.",
                timestamp=now,
            )
        )
    return CanvasPlatformReadinessResponse(
        platform_id=platform.id,
        ready=all(
            not check.blocking or check.status in {"ready", "not_applicable"}
            for check in checks
        ),
        checks=checks,
    )


@canvas_integration_router.post(
    "/platforms/{platform_id}/oauth/authorizations",
    response_model=CanvasOAuthStartResponse,
    summary="Start an organization-scoped Canvas API OAuth connection",
    dependencies=[Depends(_verify_management_api_key)],
)
async def start_canvas_oauth_connection(
    platform_id: str,
    request: CanvasOAuthStartRequest,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasOAuthStartResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    _require_portable_canvas_pilot(platform.organization_id)
    if not platform.canvas_base_url or not platform.canvas_base_url.startswith("https://"):
        raise HTTPException(status_code=409, detail="Canvas OAuth requires a registered HTTPS Canvas base URL")
    try:
        canvas_base_url = validate_canvas_origin(platform.canvas_base_url)
    except CanvasLtiServiceError as exc:
        raise HTTPException(status_code=409, detail="Canvas OAuth platform origin is not trusted") from exc
    existing_connection = await repo.get_canvas_oauth_connection(
        platform.organization_id,
        platform.id,
    )
    if existing_connection is not None:
        raise HTTPException(
            status_code=409,
            detail="Disconnect the existing Canvas OAuth connection before authorizing again",
        )
    secret = await repo.get_integration_secret(request.client_secret_secret_id)
    if (
        secret is None
        or secret.organization_id != platform.organization_id
        or not secret.enabled
        or secret.provider != "canvas"
        or secret.purpose != "oauth_client_secret"
    ):
        raise HTTPException(status_code=404, detail="Canvas OAuth client secret reference was not found")
    client_id = request.client_id.strip()
    if not client_id:
        raise HTTPException(status_code=400, detail="Canvas OAuth client ID is required")
    try:
        capabilities = normalize_canvas_oauth_capabilities(request.capabilities)
        scopes = canvas_oauth_scopes_for_capabilities(capabilities)
    except CanvasOAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    redirect_uri = _canvas_oauth_redirect_uri()
    state = secrets.token_urlsafe(32)
    authorization = CanvasOAuthAuthorization(
        platform_id=platform.id,
        organization_id=platform.organization_id,
        canvas_base_url=canvas_base_url,
        platform_config_version=platform.config_version,
        state_hash=hashlib.sha256(state.encode("utf-8")).hexdigest(),
        client_id=client_id,
        client_secret_ref=secret.secret_ref,
        capabilities=capabilities,
        scopes=scopes,
        redirect_uri=redirect_uri,
    )
    authorization_url = canvas_oauth_authorization_url(
        canvas_base_url=canvas_base_url,
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        scopes=scopes,
    )
    await repo.save_canvas_oauth_authorization(authorization)
    patched = await repo.patch_canvas_platform_connection_config(
        platform.organization_id,
        platform.id,
        expected_config_version=platform.config_version,
        patch={
            "oauth_client_id": client_id,
            "oauth_status": "authorization_pending",
            "oauth_pending_authorization_id": authorization.id,
        },
    )
    if patched is None:
        raise HTTPException(status_code=409, detail="Canvas platform configuration changed")
    return CanvasOAuthStartResponse(
        authorization_url=authorization_url,
        redirect_uri=redirect_uri,
        scopes=scopes,
    )


@canvas_integration_router.get(
    "/oauth/callback",
    summary="Complete a Canvas API OAuth connection",
)
async def complete_canvas_oauth_connection(
    code: str | None = Query(default=None, min_length=1, max_length=4096),
    state: str = Query(..., min_length=32, max_length=512),
    error: str | None = Query(default=None, min_length=1, max_length=256),
    repo: IIssuanceRepository = Depends(),
) -> RedirectResponse:
    authorization_code = code.strip() if isinstance(code, str) else ""
    authorization_error = error.strip() if isinstance(error, str) else ""
    state_hash = hashlib.sha256(state.encode("utf-8")).hexdigest()
    authorization = await repo.consume_canvas_oauth_authorization(state_hash)
    if authorization is None:
        return RedirectResponse(
            _canvas_oauth_completion_url(None, outcome="error", error_code="oauth_state_invalid"),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    platform = await repo.get_canvas_platform(authorization.platform_id)
    if (
        platform is None
        or platform.organization_id != authorization.organization_id
        or platform.archived_at is not None
    ):
        return RedirectResponse(
            _canvas_oauth_completion_url(
                authorization.platform_id,
                outcome="error",
                error_code="oauth_platform_invalid",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    if not portable_canvas_enabled_for_organization(platform.organization_id):
        return RedirectResponse(
            _canvas_oauth_completion_url(
                platform.id,
                outcome="error",
                error_code="oauth_rollout_disabled",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    if authorization_error or not authorization_code:
        return RedirectResponse(
            _canvas_oauth_completion_url(
                platform.id,
                outcome="error",
                error_code="oauth_authorization_denied",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    client_id = authorization.client_id
    client_secret_id = _integration_secret_id_from_ref(
        platform.organization_id,
        authorization.client_secret_ref,
    )
    redirect_uri = authorization.redirect_uri
    scopes = list(authorization.scopes)
    capabilities = list(authorization.capabilities)
    client_secret = (
        await repo.get_integration_secret_value(platform.organization_id, client_secret_id)
        if client_secret_id
        else None
    )
    if (
        not client_id
        or not client_secret
        or not authorization.canvas_base_url
        or platform.canvas_base_url != authorization.canvas_base_url
        or platform.config_version != authorization.platform_config_version
        or redirect_uri != _canvas_oauth_redirect_uri()
    ):
        return RedirectResponse(
            _canvas_oauth_completion_url(
                platform.id,
                outcome="error",
                error_code="oauth_configuration_changed",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    existing_connection = await repo.get_canvas_oauth_connection(
        platform.organization_id,
        platform.id,
    )
    if existing_connection is not None:
        return RedirectResponse(
            _canvas_oauth_completion_url(
                platform.id,
                outcome="error",
                error_code="oauth_authorization_conflict",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    try:
        async with canvas_http_client(timeout=15.0) as client:
            token_bundle = await exchange_canvas_oauth_code(
                client=client,
                canvas_base_url=authorization.canvas_base_url,
                client_id=client_id,
                client_secret=client_secret,
                code=authorization_code,
                redirect_uri=redirect_uri,
            )
    except CanvasOAuthError:
        await repo.patch_canvas_platform_validation_state(
            platform.organization_id,
            platform.id,
            expected_config_version=authorization.platform_config_version,
            last_validated_at=platform.last_validated_at,
            last_connection_error="oauth_token_exchange_failed",
        )
        return RedirectResponse(
            _canvas_oauth_completion_url(
                platform.id,
                outcome="error",
                error_code="oauth_token_exchange_failed",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    patched = await repo.patch_canvas_platform_connection_config(
        platform.organization_id,
        platform.id,
        expected_config_version=authorization.platform_config_version,
        patch={
            "oauth_client_id": client_id,
            "oauth_status": "authorization_completing",
        },
    )
    if patched is None:
        try:
            async with canvas_http_client(timeout=15.0) as client:
                await revoke_canvas_oauth_token(
                    client=client,
                    canvas_base_url=authorization.canvas_base_url,
                    access_token=str(token_bundle["access_token"]),
                )
        except CanvasOAuthError:
            pass
        return RedirectResponse(
            _canvas_oauth_completion_url(
                platform.id,
                outcome="error",
                error_code="oauth_configuration_changed",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    access_secret_id = str(uuid.uuid4())
    access_secret = OrganizationIntegrationSecret(
        id=access_secret_id,
        organization_id=platform.organization_id,
        name=f"Canvas OAuth access token - {platform.id}",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value=str(token_bundle["access_token"]),
        metadata={"platform_id": platform.id, "capabilities": capabilities, "scopes": scopes},
    )
    await repo.save_integration_secret(access_secret)
    refresh_secret: OrganizationIntegrationSecret | None = None
    if token_bundle.get("refresh_token"):
        refresh_secret_id = str(uuid.uuid4())
        refresh_secret = OrganizationIntegrationSecret(
            id=refresh_secret_id,
            organization_id=platform.organization_id,
            name=f"Canvas OAuth refresh token - {platform.id}",
            provider="canvas",
            purpose="oauth_refresh_token",
            secret_value=str(token_bundle["refresh_token"]),
            metadata={"platform_id": platform.id},
        )
        await repo.save_integration_secret(refresh_secret)
    expires_in = token_bundle.get("expires_in")
    token_expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=max(0, int(expires_in)))
        if isinstance(expires_in, (int, float))
        else None
    )
    connection = CanvasOAuthConnection(
        id=existing_connection.id if existing_connection else str(uuid.uuid4()),
        organization_id=platform.organization_id,
        platform_id=platform.id,
        canvas_base_url=authorization.canvas_base_url,
        platform_config_version=authorization.platform_config_version,
        client_id=client_id,
        client_secret_ref=authorization.client_secret_ref,
        capabilities=capabilities,
        scopes=scopes,
        access_token_secret_ref=access_secret.secret_ref,
        refresh_token_secret_ref=(
            refresh_secret.secret_ref if refresh_secret is not None else None
        ),
        token_expires_at=token_expires_at,
        status=CanvasOAuthConnectionStatus.CONNECTED,
    )
    published = await repo.save_canvas_oauth_connection_cas(
        connection,
        expected_updated_at=None,
    )
    if not published:
        for secret_id in (
            access_secret.id,
            refresh_secret.id if refresh_secret is not None else None,
        ):
            if secret_id:
                await repo.delete_integration_secret(secret_id)
        try:
            async with canvas_http_client(timeout=15.0) as client:
                await revoke_canvas_oauth_token(
                    client=client,
                    canvas_base_url=authorization.canvas_base_url,
                    access_token=str(token_bundle["access_token"]),
                )
        except CanvasOAuthError:
            pass
        current_connection = await repo.get_canvas_oauth_connection(
            platform.organization_id,
            platform.id,
        )
        conflict_patch: dict[str, Any] = {"oauth_status": "authorization_conflict"}
        if (
            current_connection is not None
            and current_connection.status == CanvasOAuthConnectionStatus.CONNECTED
        ):
            conflict_patch = {
                "oauth_client_id": current_connection.client_id,
                "oauth_status": "connected",
                "oauth_capabilities": list(current_connection.capabilities),
                "granted_scopes": list(current_connection.scopes),
            }
        await repo.patch_canvas_platform_connection_config(
            platform.organization_id,
            platform.id,
            expected_config_version=authorization.platform_config_version,
            patch=conflict_patch,
            remove_keys=("oauth_pending_authorization_id",),
        )
        return RedirectResponse(
            _canvas_oauth_completion_url(
                platform.id,
                outcome="error",
                error_code="oauth_authorization_conflict",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    connected_platform = await repo.patch_canvas_platform_connection_config(
        platform.organization_id,
        platform.id,
        expected_config_version=authorization.platform_config_version,
        patch={
            "oauth_client_id": client_id,
            "oauth_status": "connected",
            "oauth_capabilities": capabilities,
            "granted_scopes": scopes,
        },
        remove_keys=("oauth_pending_authorization_id",),
    )
    if connected_platform is None:
        await repo.mark_canvas_oauth_reauthorization_required(
            platform.organization_id,
            platform.id,
            expected_updated_at=connection.updated_at,
        )
        return RedirectResponse(
            _canvas_oauth_completion_url(
                platform.id,
                outcome="error",
                error_code="oauth_configuration_changed",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    await repo.patch_canvas_platform_validation_state(
        platform.organization_id,
        platform.id,
        expected_config_version=authorization.platform_config_version,
        last_validated_at=datetime.now(timezone.utc),
        last_connection_error=None,
    )
    return RedirectResponse(
        _canvas_oauth_completion_url(platform.id, outcome="connected"),
        status_code=status.HTTP_303_SEE_OTHER,
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
        },
    )


@canvas_integration_router.delete(
    "/platforms/{platform_id}/oauth",
    response_model=CanvasOAuthConnectionResponse,
    summary="Disconnect an organization-scoped Canvas API connection",
    dependencies=[Depends(_verify_management_api_key)],
)
async def disconnect_canvas_oauth_connection(
    platform_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasOAuthConnectionResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    connection = await repo.get_canvas_oauth_connection(platform.organization_id, platform.id)
    if connection is None:
        await repo.patch_canvas_platform_connection_config(
            platform.organization_id,
            platform.id,
            expected_config_version=platform.config_version,
            patch={
                "oauth_status": "disconnected",
                "granted_scopes": [],
                "oauth_capabilities": [],
            },
            remove_keys=("oauth_pending_authorization_id",),
        )
        return CanvasOAuthConnectionResponse(platform_id=platform.id, status="disconnected", scopes=[])

    lease_owner = f"oauth-revoke:{uuid.uuid4()}"
    leased = await repo.begin_canvas_oauth_revocation(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        expected_updated_at=connection.updated_at,
        lease_owner=lease_owner,
        lease_seconds=60,
    )
    if leased is None:
        raise HTTPException(status_code=409, detail="Canvas OAuth connection changed; retry disconnect")

    access_secret_id = _integration_secret_id_from_ref(
        platform.organization_id,
        leased.access_token_secret_ref,
    )
    access_token = (
        await repo.get_integration_secret_value(platform.organization_id, access_secret_id)
        if access_secret_id
        else None
    )
    try:
        if not leased.canvas_base_url or not access_token:
            raise CanvasOAuthError("Canvas OAuth access token is unavailable for remote revocation")
        async with canvas_http_client(timeout=15.0) as client:
            await revoke_canvas_oauth_token(
                client=client,
                canvas_base_url=leased.canvas_base_url,
                access_token=access_token,
            )
    except CanvasOAuthError as exc:
        delay_seconds = min(3600, 30 * (2 ** min(leased.revoke_retry_count, 7)))
        if exc.retry_after_seconds is not None:
            delay_seconds = max(delay_seconds, exc.retry_after_seconds)
        await repo.reschedule_canvas_oauth_revocation(
            organization_id=platform.organization_id,
            platform_id=platform.id,
            lease_owner=lease_owner,
            retry_at=datetime.now(timezone.utc) + timedelta(seconds=delay_seconds),
            error_code="canvas_oauth_revoke_failed",
        )
        await repo.patch_canvas_platform_connection_config(
            platform.organization_id,
            platform.id,
            expected_config_version=platform.config_version,
            patch={"oauth_status": "revocation_pending"},
            remove_keys=("oauth_pending_authorization_id",),
        )
        return CanvasOAuthConnectionResponse(
            platform_id=platform.id,
            status="revocation_pending",
            scopes=list(leased.scopes),
        )

    completed = await repo.complete_canvas_oauth_revocation(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        lease_owner=lease_owner,
    )
    if not completed:
        raise HTTPException(status_code=409, detail="Canvas OAuth connection changed; retry disconnect")
    for secret_ref in (
        leased.access_token_secret_ref,
        leased.refresh_token_secret_ref,
    ):
        secret_id = _integration_secret_id_from_ref(platform.organization_id, secret_ref)
        if secret_id:
            await repo.delete_integration_secret(secret_id)
    await repo.patch_canvas_platform_connection_config(
        platform.organization_id,
        platform.id,
        expected_config_version=platform.config_version,
        patch={
            "oauth_status": "disconnected",
            "granted_scopes": [],
            "oauth_capabilities": [],
        },
        remove_keys=("oauth_pending_authorization_id",),
    )
    return CanvasOAuthConnectionResponse(platform_id=platform.id, status="disconnected", scopes=[])


@canvas_integration_router.post(
    "/platforms",
    response_model=CanvasPlatformResponse,
    summary="Create Canvas platform",
    dependencies=[Depends(_verify_management_api_key)],
)
async def create_canvas_platform(
    request: CanvasPlatformCreate,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformResponse:
    organization_id = _management_organization_id(trusted_organization_id)
    platform = _platform_from_request(request, organization_id=organization_id)
    await repo.save_canvas_platform(platform)
    return _platform_to_response(platform)


@canvas_integration_router.get(
    "/platforms",
    response_model=list[CanvasPlatformResponse],
    summary="List Canvas platforms",
    dependencies=[Depends(_verify_management_api_key)],
)
async def list_canvas_platforms(
    organization_id: str = Query(...),
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> list[CanvasPlatformResponse]:
    organization_id = _management_organization_id(trusted_organization_id, organization_id)
    platforms = [
        platform
        for platform in await repo.list_canvas_platforms(organization_id)
        if platform.archived_at is None
    ]
    return [_platform_to_response(platform) for platform in platforms]


@canvas_integration_router.get(
    "/platforms/{platform_id}",
    response_model=CanvasPlatformResponse,
    summary="Get Canvas platform",
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_canvas_platform(
    platform_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    return _platform_to_response(platform)


@canvas_integration_router.put(
    "/platforms/{platform_id}",
    response_model=CanvasPlatformResponse,
    summary="Update Canvas platform",
    dependencies=[Depends(_verify_management_api_key)],
)
async def update_canvas_platform(
    platform_id: str,
    request: CanvasPlatformCreate,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    old_version = platform.config_version
    platform = _platform_from_request(
        request,
        organization_id=platform.organization_id,
        existing=platform,
    )
    await repo.save_canvas_platform(platform)
    if platform.config_version != old_version:
        await _invalidate_canvas_binding_readiness(repo=repo, platform=platform)
    return _platform_to_response(platform)


@canvas_integration_router.delete(
    "/platforms/{platform_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Canvas platform",
    dependencies=[Depends(_verify_management_api_key)],
)
async def delete_canvas_platform(
    platform_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> Response:
    # Archival is intentionally idempotent so a caller can retry a revocation
    # CAS conflict after the platform has already been made unusable.  Tenant
    # ownership is still resolved before revealing whether the ID exists.
    if isinstance(trusted_organization_id, str) and trusted_organization_id.strip():
        platform = await repo.get_canvas_platform_for_org(
            trusted_organization_id.strip(),
            platform_id,
        )
    else:  # Direct unit invocation; FastAPI always resolves the trusted dependency.
        platform = await repo.get_canvas_platform(platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")

    queued = await queue_canvas_oauth_revocation(
        repo=repo,
        organization_id=platform.organization_id,
        platform_id=platform.id,
        reason_code="canvas_platform_archived",
    )
    if not queued:
        raise HTTPException(
            status_code=409,
            detail="Canvas OAuth connection changed; retry platform archival",
        )

    if platform.archived_at is None:
        now = datetime.now(timezone.utc)
        platform.enabled = False
        platform.archived_at = now
        platform.registration_status = "archived"
        platform.config_version += 1
        _revoke_lti_config_token(platform)
        connection = await repo.get_canvas_oauth_connection(
            platform.organization_id,
            platform.id,
        )
        platform.connection_config = {
            **(platform.connection_config or {}),
            "oauth_status": (
                "revocation_pending" if connection is not None else "disconnected"
            ),
        }
        platform.connection_config.pop("oauth_pending_authorization_id", None)
        platform.updated_at = now
        await repo.save_canvas_platform(platform)
        for binding in await repo.list_canvas_program_bindings(
            platform.organization_id,
            platform_id=platform.id,
        ):
            binding.enabled = False
            binding.archived_at = now
            binding.updated_at = now
            await repo.save_canvas_program_binding(binding)

        # A callback may have passed its initial platform check immediately
        # before archival.  Connection publication now validates the platform
        # row atomically, but a publication that won the row lock first must be
        # picked up here and moved to the durable revocation queue.
        queued = await queue_canvas_oauth_revocation(
            repo=repo,
            organization_id=platform.organization_id,
            platform_id=platform.id,
            reason_code="canvas_platform_archived",
        )
        if not queued:
            raise HTTPException(
                status_code=409,
                detail="Canvas OAuth connection changed; retry platform archival",
            )

    connection = await repo.get_canvas_oauth_connection(
        platform.organization_id,
        platform.id,
    )
    patched = await repo.patch_canvas_platform_connection_config(
        platform.organization_id,
        platform.id,
        expected_config_version=platform.config_version,
        patch={
            "oauth_status": (
                "revocation_pending" if connection is not None else "disconnected"
            )
        },
        remove_keys=("oauth_pending_authorization_id",),
    )
    if patched is None:
        raise HTTPException(
            status_code=409,
            detail="Canvas platform configuration changed; retry platform archival",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@canvas_integration_router.post(
    "/platforms/{platform_id}/sandbox-probe",
    response_model=CanvasPlatformSandboxProbeResponse,
    summary="Probe Canvas platform sandbox metadata",
    dependencies=[Depends(_verify_management_api_key)],
)
async def probe_canvas_platform_sandbox(
    platform_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformSandboxProbeResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    if not platform.canvas_base_url:
        raise HTTPException(status_code=400, detail="Canvas platform requires canvas_base_url before probing")

    try:
        canvas_origin = validate_canvas_origin(platform.canvas_base_url)
        probe = await probe_canvas_lti_platform(
            canvas_origin,
            trust_profile=platform.lti_trust_profile,
        )
    except Exception as exc:  # pragma: no cover - exact binding exception type varies
        raise HTTPException(status_code=400, detail=f"Canvas sandbox probe failed: {exc}") from exc

    _apply_canvas_probe(platform, probe)
    await repo.save_canvas_platform(platform)
    return CanvasPlatformSandboxProbeResponse(
        platform=_platform_to_response(platform),
        probe=probe,
    )


@canvas_integration_router.post(
    "/platforms/{platform_id}/jwks-refresh",
    response_model=CanvasPlatformJwksRefreshResponse,
    summary="Refresh Canvas platform JWKS metadata",
    dependencies=[Depends(_verify_management_api_key)],
)
async def refresh_canvas_platform_jwks(
    platform_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformJwksRefreshResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )

    platform, probe = await _refresh_canvas_platform_jwks(platform, repo)
    return CanvasPlatformJwksRefreshResponse(
        platform=_platform_to_response(platform),
        probe=probe,
    )


@canvas_integration_router.post(
    "/platforms/{platform_id}/scope-discovery",
    response_model=CanvasScopeDiscoveryResponse,
    summary="Discover Canvas courses and activities for program binding setup",
    dependencies=[Depends(_verify_management_api_key)],
)
async def discover_canvas_scope(
    platform_id: str,
    request: CanvasScopeDiscoveryRequest,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasScopeDiscoveryResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    _require_portable_canvas_pilot(platform.organization_id)
    base_url = _canvas_api_base(platform)
    token = await _canvas_admin_token(platform=platform, repo=repo)
    if not token:
        raise HTTPException(
            status_code=400,
            detail="Canvas scope discovery requires an organization OAuth connection; environment tokens are local compatibility fallbacks",
        )

    course_id = (request.course_id or "").strip() or None
    warnings: list[str] = []
    courses: list[CanvasScopeItem] = []
    assignments: list[CanvasScopeItem] = []
    quizzes: list[CanvasScopeItem] = []
    modules: list[CanvasScopeItem] = []

    async with canvas_http_client(timeout=10.0) as client:
        if request.include_courses:
            courses = _canvas_scope_items(
                await _fetch_canvas_management_collection(
                    client,
                    base_url=base_url,
                    token=token,
                    path="courses",
                    limit=request.limit,
                    repo=repo,
                    platform=platform,
                ),
                "course",
            )
        if course_id:
            quoted_course_id = quote(course_id, safe="")
            if request.include_assignments or request.include_quizzes:
                # Scores for existing assignments, Classic Quizzes, and New
                # Quizzes all come from Assignment Submissions. Discover quiz
                # activities through Assignments so the selected identifier is
                # the assignment ID accepted by that authoritative endpoint;
                # the Classic Quiz API exposes a different quiz ID.
                raw_assignments = await _fetch_canvas_management_collection(
                    client,
                    base_url=base_url,
                    token=token,
                    path=f"courses/{quoted_course_id}/assignments",
                    limit=request.limit,
                    repo=repo,
                    platform=platform,
                )
                quiz_assignments = [
                    item
                    for item in raw_assignments
                    if item.get("is_quiz_assignment") is True or item.get("quiz_id") is not None
                ]
                ordinary_assignments = [
                    item
                    for item in raw_assignments
                    if item.get("is_quiz_assignment") is not True and item.get("quiz_id") is None
                ]
                if request.include_assignments:
                    assignments = _canvas_scope_items(ordinary_assignments, "assignment")
                if request.include_quizzes:
                    quizzes = _canvas_scope_items(quiz_assignments, "quiz")
            if request.include_modules:
                modules = _canvas_scope_items(
                    await _fetch_canvas_management_collection(
                        client,
                        base_url=base_url,
                        token=token,
                        path=f"courses/{quoted_course_id}/modules",
                        limit=request.limit,
                        repo=repo,
                        platform=platform,
                    ),
                    "module",
                )
        elif request.include_assignments or request.include_quizzes or request.include_modules:
            warnings.append("Set course_id and run discovery again to import assignments, quizzes, and modules.")

    return CanvasScopeDiscoveryResponse(
        platform_id=platform.id,
        organization_id=platform.organization_id,
        canvas_base_url=base_url,
        course_id=course_id,
        courses=courses,
        assignments=assignments,
        quizzes=quizzes,
        modules=modules,
        warnings=warnings,
    )


@canvas_integration_router.get(
    "/platforms/{platform_id}/catalog",
    response_model=CanvasScopeDiscoveryResponse,
    summary="Discover Canvas courses and activities through connected OAuth",
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_canvas_catalog(
    platform_id: str,
    course_id: str | None = Query(default=None),
    include_courses: bool = Query(default=True),
    include_assignments: bool = Query(default=True),
    include_quizzes: bool = Query(default=True),
    include_modules: bool = Query(default=True),
    limit: int = Query(default=50, ge=1, le=100),
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasScopeDiscoveryResponse:
    """Read-only counterpart to the legacy scope-discovery POST contract."""

    return await discover_canvas_scope(
        platform_id=platform_id,
        request=CanvasScopeDiscoveryRequest(
            course_id=course_id,
            include_courses=include_courses,
            include_assignments=include_assignments,
            include_quizzes=include_quizzes,
            include_modules=include_modules,
            limit=limit,
        ),
        trusted_organization_id=trusted_organization_id,
        repo=repo,
    )


@canvas_integration_router.post(
    "/platforms/{platform_id}/program-bindings",
    response_model=CanvasProgramBindingResponse,
    summary="Create Canvas program binding",
    dependencies=[Depends(_verify_management_api_key)],
)
async def create_canvas_program_binding(
    platform_id: str,
    request: CanvasProgramBindingCreate,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasProgramBindingResponse:
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    binding = await _validate_program_binding_request(
        platform=platform,
        request=request,
        repo=repo,
    )
    await repo.save_canvas_program_binding(binding)
    return _binding_to_response(binding, platform)


@canvas_integration_router.get(
    "/program-bindings",
    response_model=list[CanvasProgramBindingResponse],
    summary="List Canvas program bindings",
    dependencies=[Depends(_verify_management_api_key)],
)
async def list_canvas_program_bindings(
    organization_id: str = Query(...),
    platform_id: str | None = Query(None),
    application_template_id: str | None = Query(None),
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> list[CanvasProgramBindingResponse]:
    organization_id = _management_organization_id(trusted_organization_id, organization_id)
    platform_filter = platform_id if isinstance(platform_id, str) else None
    template_filter = application_template_id if isinstance(application_template_id, str) else None
    bindings = [
        binding
        for binding in await repo.list_canvas_program_bindings(
            organization_id,
            platform_id=platform_filter,
            application_template_id=template_filter,
        )
        if binding.archived_at is None
    ]
    responses: list[CanvasProgramBindingResponse] = []
    for binding in bindings:
        platform = await repo.get_canvas_platform_for_org(organization_id, binding.platform_id)
        if platform is not None:
            responses.append(_binding_to_response(binding, platform))
    return responses


@canvas_integration_router.get(
    "/program-bindings/{binding_id}",
    response_model=CanvasProgramBindingResponse,
    summary="Get Canvas program binding",
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_canvas_program_binding(
    binding_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasProgramBindingResponse:
    binding = await _management_canvas_binding(
        repo=repo,
        binding_id=binding_id,
        trusted_organization_id=trusted_organization_id,
    )
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=binding.platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    return _binding_to_response(binding, platform)


@canvas_integration_router.put(
    "/program-bindings/{binding_id}",
    response_model=CanvasProgramBindingResponse,
    summary="Update Canvas program binding",
    dependencies=[Depends(_verify_management_api_key)],
)
async def update_canvas_program_binding(
    binding_id: str,
    request: CanvasProgramBindingCreate,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasProgramBindingResponse:
    existing = await _management_canvas_binding(
        repo=repo,
        binding_id=binding_id,
        trusted_organization_id=trusted_organization_id,
    )
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=existing.platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    binding = await _validate_program_binding_request(
        platform=platform,
        request=request,
        repo=repo,
        existing_binding_id=binding_id,
        existing_binding=existing,
    )
    binding.created_at = existing.created_at
    await repo.save_canvas_program_binding(binding)
    return _binding_to_response(binding, platform)


@canvas_integration_router.delete(
    "/program-bindings/{binding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Canvas program binding",
    dependencies=[Depends(_verify_management_api_key)],
)
async def delete_canvas_program_binding(
    binding_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> Response:
    binding = await _management_canvas_binding(
        repo=repo,
        binding_id=binding_id,
        trusted_organization_id=trusted_organization_id,
    )
    binding.enabled = False
    binding.archived_at = datetime.now(timezone.utc)
    binding.updated_at = binding.archived_at
    await repo.save_canvas_program_binding(binding)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _validate_managed_canvas_binding(
    *,
    binding_id: str,
    trusted_organization_id: Any,
    repo: IIssuanceRepository,
) -> tuple[CanvasProgramBinding, CanvasProgramBindingValidationResponse]:
    binding = await _management_canvas_binding(
        repo=repo,
        binding_id=binding_id,
        trusted_organization_id=trusted_organization_id,
    )
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=binding.platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    application_template = await repo.get_application_template(
        binding.application_template_id
    )
    credential_template: dict[str, Any] = {}
    status_profile: dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        try:
            response = await client.get(
                f"{CREDENTIAL_TEMPLATE_SERVICE_URL}/v1/credential-templates/"
                f"{quote(binding.credential_template_id, safe='')}"
            )
            if response.status_code == 200:
                payload = response.json()
                credential_template = payload if isinstance(payload, dict) else {}
        except (httpx.HTTPError, ValueError):
            credential_template = {}
        profile_id = str(credential_template.get("revocation_profile_id") or "").strip()
        if profile_id:
            try:
                response = await client.get(
                    f"{REVOCATION_PROFILE_SERVICE_URL}/v1/revocation-profiles/"
                    f"{quote(profile_id, safe='')}"
                )
                if response.status_code == 200:
                    payload = response.json()
                    status_profile = payload if isinstance(payload, dict) else {}
            except (httpx.HTTPError, ValueError):
                status_profile = {}
    lti_tool_signing_ready = await _lti_tool_signing_challenge_ready()
    readiness = await evaluate_canvas_binding_readiness(
        repo=repo,
        platform=platform,
        binding=binding,
        application_template=application_template,
        credential_template=credential_template,
        credential_status_profile=status_profile,
        lti_tool_signing_ready=lti_tool_signing_ready,
    )
    apply_canvas_readiness_result(binding, readiness)
    await repo.save_canvas_program_binding(binding)
    checks = [CanvasReadinessCheck(**check.to_dict()) for check in readiness.checks]
    return binding, CanvasProgramBindingValidationResponse(
        binding_id=binding.id,
        ready=readiness.ready,
        valid=readiness.ready,
        active=binding.enabled,
        config_version=binding.config_version,
        evaluated_at=readiness.evaluated_at.isoformat(),
        checks=checks,
    )


@canvas_integration_router.post(
    "/program-bindings/{binding_id}/validate",
    response_model=CanvasProgramBindingValidationResponse,
    summary="Validate a Canvas program binding without activating it",
    dependencies=[Depends(_verify_management_api_key)],
)
async def validate_canvas_program_binding(
    binding_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasProgramBindingValidationResponse:
    _binding, result = await _validate_managed_canvas_binding(
        binding_id=binding_id,
        trusted_organization_id=trusted_organization_id,
        repo=repo,
    )
    return result


@canvas_integration_router.post(
    "/program-bindings/{binding_id}/activate",
    response_model=CanvasProgramBindingValidationResponse,
    summary="Activate a Canvas program binding after fail-closed validation",
    dependencies=[Depends(_verify_management_api_key)],
)
async def activate_canvas_program_binding(
    binding_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasProgramBindingValidationResponse:
    managed_binding = await _management_canvas_binding(
        repo=repo,
        binding_id=binding_id,
        trusted_organization_id=trusted_organization_id,
    )
    _require_portable_canvas_pilot(managed_binding.organization_id)
    binding, result = await _validate_managed_canvas_binding(
        binding_id=binding_id,
        trusted_organization_id=trusted_organization_id,
        repo=repo,
    )
    if not result.ready or not canvas_binding_is_ready_for_activation(binding):
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Canvas program binding has blocking readiness checks",
                "checks": [
                    check.model_dump()
                    for check in result.checks
                    if check.blocking and check.status not in {"ready", "not_applicable"}
                ],
            },
        )
    binding.enabled = True
    binding.activated_at = datetime.now(timezone.utc)
    binding.updated_at = binding.activated_at
    await repo.save_canvas_program_binding(binding)
    platform = await _management_canvas_platform(
        repo=repo,
        platform_id=binding.platform_id,
        trusted_organization_id=trusted_organization_id,
    )
    platform.enabled = True
    platform.updated_at = binding.activated_at
    await repo.save_canvas_platform(platform)
    if bool((binding.feature_flags or {}).get("enable_background_awards")):
        verified_capabilities = verified_canvas_binding_capabilities(
            platform,
            binding,
        )
        target_metadata = {
            "created_from": "binding_activation",
            "verified_binding_id": binding.id,
            "verified_binding_config_version": binding.config_version,
            "verified_course_id": verified_capabilities.get("verified_course_id"),
        }
        memberships_url = str(
            verified_capabilities.get("nrps_context_memberships_url") or ""
        ).strip()
        if memberships_url:
            target_metadata["nrps_context_memberships_url"] = memberships_url
        logical_key = f"roster:{binding.id}"
        target = await repo.get_canvas_sync_target_by_logical_key(
            binding.organization_id,
            logical_key,
        )
        if target is None:
            target = CanvasEvidenceSyncTarget(
                organization_id=binding.organization_id,
                platform_id=platform.id,
                binding_id=binding.id,
                target_type=CanvasEvidenceSyncTargetType.BACKGROUND_ROSTER,
                logical_key=logical_key,
                schedule_seconds=15 * 60,
                config_version=binding.config_version,
                metadata=target_metadata,
            )
        else:
            target.platform_id = platform.id
            target.binding_id = binding.id
            target.target_type = CanvasEvidenceSyncTargetType.BACKGROUND_ROSTER
            target.schedule_seconds = 15 * 60
            target.config_version = binding.config_version
            target.enabled = True
            target.updated_at = datetime.now(timezone.utc)
            target.metadata = {
                **(target.metadata if isinstance(target.metadata, dict) else {}),
                **target_metadata,
            }
        await repo.save_canvas_sync_target(target)
        await repo.enqueue_canvas_sync_job(target)
    for app in await repo.list_applications(
        org_id=binding.organization_id,
        template_id=binding.application_template_id,
    ):
        canvas = (
            app.integration_context.get("canvas")
            if isinstance(app.integration_context, dict)
            else None
        )
        if (
            isinstance(canvas, dict)
            and canvas.get("canvas_program_binding_id") == binding.id
            and app.status not in {ApplicationStatus.REJECTED, ApplicationStatus.WITHDRAWN}
        ):
            await enqueue_application_canvas_sync(
                repo=repo,
                organization_id=binding.organization_id,
                application_id=app.id,
            )
    return result.model_copy(update={"active": True})


@canvas_integration_router.post(
    "/program-bindings/{binding_id}/deactivate",
    response_model=CanvasProgramBindingValidationResponse,
    summary="Deactivate a Canvas program binding",
    dependencies=[Depends(_verify_management_api_key)],
)
async def deactivate_canvas_program_binding(
    binding_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasProgramBindingValidationResponse:
    binding, result = await _validate_managed_canvas_binding(
        binding_id=binding_id,
        trusted_organization_id=trusted_organization_id,
        repo=repo,
    )
    binding.enabled = False
    binding.activated_at = None
    binding.updated_at = datetime.now(timezone.utc)
    await repo.save_canvas_program_binding(binding)
    roster_target = await repo.get_canvas_sync_target_by_logical_key(
        binding.organization_id,
        f"roster:{binding.id}",
    )
    if roster_target is not None:
        roster_target.enabled = False
        roster_target.updated_at = datetime.now(timezone.utc)
        await repo.save_canvas_sync_target(roster_target)
    return result.model_copy(update={"active": False})


@canvas_integration_router.post(
    "/canvas-credentials/validate",
    response_model=CanvasCredentialsConfigValidationResult,
    summary="Validate Canvas Credentials provider configuration",
    dependencies=[Depends(_verify_management_api_key)],
)
async def validate_canvas_credentials_provider(
    request: CanvasCredentialsValidationRequest,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasCredentialsConfigValidationResult:
    """Validate Canvas Credentials provider settings without publishing a credential."""

    organization_id = _management_organization_id(trusted_organization_id, request.organization_id)
    canvas_credentials = await _validated_canvas_credentials_input(
        value=request.canvas_credentials,
        organization_id=organization_id,
        repo=repo,
    )
    delivery_record = CredentialDeliveryRecord(
        organization_id=organization_id,
        delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
        delivery_mode="wallet_plus_canvas_mirror",
        status=CredentialDeliveryStatus.PENDING,
        metadata={"canvas_credentials": canvas_credentials},
    )
    return await validate_canvas_credentials_config(
        delivery_record,
        secret_resolver=repo.get_integration_secret_value,
    )


@canvas_integration_router.post(
    "/integration-secrets",
    response_model=CanvasIntegrationSecretResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Canvas integration secret",
    dependencies=[Depends(_verify_management_api_key)],
)
async def create_canvas_integration_secret(
    request: CanvasIntegrationSecretCreate,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasIntegrationSecretResponse:
    """Create an encrypted organization integration secret and return only its reference."""

    organization_id = _management_organization_id(trusted_organization_id, request.organization_id)
    secret = OrganizationIntegrationSecret(
        organization_id=organization_id,
        name=request.name.strip(),
        provider=request.provider.strip() or "canvas_credentials",
        purpose=request.purpose.strip() or "api_token",
        secret_value=request.secret_value,
        metadata=dict(request.metadata or {}),
        enabled=request.enabled,
    )
    if not secret.name:
        raise HTTPException(status_code=400, detail="Secret name is required")
    if not secret.secret_value:
        raise HTTPException(status_code=400, detail="Secret value is required")
    await repo.save_integration_secret(secret)
    stored = await repo.get_integration_secret(secret.id)
    return _secret_to_response(stored or secret)


@canvas_integration_router.get(
    "/integration-secrets",
    response_model=list[CanvasIntegrationSecretResponse],
    summary="List Canvas integration secrets",
    dependencies=[Depends(_verify_management_api_key)],
)
async def list_canvas_integration_secrets(
    organization_id: str = Query(...),
    provider: str | None = Query(default="canvas_credentials"),
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> list[CanvasIntegrationSecretResponse]:
    organization_id = _management_organization_id(trusted_organization_id, organization_id)
    secrets = await repo.list_integration_secrets(organization_id, provider=provider)
    return [_secret_to_response(secret) for secret in secrets]


@canvas_integration_router.put(
    "/integration-secrets/{secret_id}",
    response_model=CanvasIntegrationSecretResponse,
    summary="Update Canvas integration secret",
    dependencies=[Depends(_verify_management_api_key)],
)
async def update_canvas_integration_secret(
    secret_id: str,
    request: CanvasIntegrationSecretUpdate,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasIntegrationSecretResponse:
    secret = await repo.get_integration_secret(secret_id)
    if secret is None or (
        isinstance(trusted_organization_id, str)
        and trusted_organization_id.strip()
        and secret.organization_id != trusted_organization_id.strip()
    ):
        raise HTTPException(status_code=404, detail="Integration secret not found")
    if request.name is not None:
        secret.name = request.name.strip()
    if request.metadata is not None:
        secret.metadata = dict(request.metadata or {})
    if request.enabled is not None:
        secret.enabled = request.enabled
    if request.secret_value is not None:
        secret.secret_value = request.secret_value
        secret.secret_hint = f"...{request.secret_value[-4:]}" if request.secret_value else secret.secret_hint
    await repo.save_integration_secret(secret)
    stored = await repo.get_integration_secret(secret.id)
    return _secret_to_response(stored or secret)


@canvas_integration_router.delete(
    "/integration-secrets/{secret_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Canvas integration secret",
    dependencies=[Depends(_verify_management_api_key)],
)
async def delete_canvas_integration_secret(
    secret_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> Response:
    secret = await repo.get_integration_secret(secret_id)
    if secret is None or (
        isinstance(trusted_organization_id, str)
        and trusted_organization_id.strip()
        and secret.organization_id != trusted_organization_id.strip()
    ):
        raise HTTPException(status_code=404, detail="Integration secret not found")
    await repo.delete_integration_secret(secret_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _canvas_requirement_sources(requirements: list[Any]) -> set[str]:
    try:
        return {
            requirement.source.value
            for requirement in validate_canvas_evidence_requirements(requirements)
        }
    except ValueError:
        return set()


def _portable_fact_event_id(source: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"canvas:{source}:{canonical}"))


def _canvas_evidence_effective_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _canvas_number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


async def _read_canvas_rest_evidence(
    *,
    client: httpx.AsyncClient,
    repo: IIssuanceRepository,
    platform: CanvasPlatform,
    token: str,
    requirement: CanvasEvidenceRequirement,
    canvas_user_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    base = _canvas_api_base(platform)
    scope = requirement.scope.to_dict()
    course_id = requirement.scope.course_id
    user_id = str(canvas_user_id or "").strip()
    fact_type = requirement.fact_type
    if not course_id or not user_id:
        raise CanvasLtiServiceError("Canvas REST evidence requires a course and Canvas user identifier")
    quoted_course = quote(course_id, safe="")
    quoted_user = quote(user_id, safe="")
    params: list[tuple[str, str]] | dict[str, str] | None = None
    if fact_type in {
        CanvasEvidenceFactType.ASSIGNMENT_SCORE,
        CanvasEvidenceFactType.QUIZ_SCORE,
    }:
        activity_id = str(requirement.scope.activity_id or "")
        if not activity_id:
            raise CanvasLtiServiceError("Canvas score evidence requires activity_id")
        # Existing assignments, Classic Quizzes, and New Quizzes all use the
        # authoritative assignment-submission projection. Including assignment
        # supplies the score denominator without a second mutable read.
        path = f"courses/{quoted_course}/assignments/{quote(activity_id, safe='')}/submissions/{quoted_user}"
        params = [("include[]", "assignment")]
    elif fact_type == CanvasEvidenceFactType.MODULE_COMPLETION:
        module_id = str(requirement.scope.module_id or "")
        if not module_id:
            raise CanvasLtiServiceError("Canvas module evidence requires module_id")
        path = f"courses/{quoted_course}/modules/{quote(module_id, safe='')}"
        params = {"student_id": user_id}
    elif fact_type == CanvasEvidenceFactType.COURSE_COMPLETION:
        path = f"courses/{quoted_course}/users/{quoted_user}/progress"
    else:
        raise CanvasLtiServiceError(f"Unsupported Canvas REST evidence fact type: {fact_type.value}")
    try:
        async with client.stream(
            "GET",
            _canvas_collection_url(base, path),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params=params,
            follow_redirects=False,
        ) as response:
            if response.is_redirect:
                raise CanvasLtiServiceError(
                    "Canvas REST evidence endpoint returned a redirect",
                    retryable=False,
                )
            if response.status_code in {401, 403}:
                reauthorization_required = _canvas_rest_oauth_reauthorization_required(response)
                if reauthorization_required:
                    await _mark_rejected_canvas_oauth_token(
                        repo=repo,
                        platform=platform,
                        rejected_access_token=token,
                    )
                raise CanvasLtiServiceError(
                    "Canvas rejected the organization OAuth token or required API scope",
                    reauthorization_required=reauthorization_required,
                )
            if response.status_code == 429:
                raise CanvasLtiServiceError(
                    "Canvas REST evidence was rate limited",
                    retry_after_seconds=parse_canvas_retry_after(
                        response.headers.get("Retry-After")
                    )
                    or 0,
                )
            response.raise_for_status()
            payload = await read_limited_canvas_json_response(
                response,
                label="REST evidence response",
                max_bytes=CANVAS_COLLECTION_PAGE_MAX_BYTES,
            )
    except CanvasLtiServiceError:
        raise
    except httpx.HTTPError as exc:
        raise CanvasLtiServiceError("Canvas REST evidence transport failed") from exc
    if not isinstance(payload, dict):
        # A malformed successful response is an unavailable observation, not a
        # verified negative. Callers preserve the existing evidence head.
        raise CanvasLtiServiceError(
            "Canvas REST evidence returned an unexpected response"
        )
    return payload, scope


def _canvas_rest_assertion(
    fact_type: CanvasEvidenceFactType,
    record: dict[str, Any],
) -> dict[str, Any]:
    assignment = record.get("assignment") if isinstance(record.get("assignment"), dict) else {}
    score = _canvas_number(record.get("score"))
    maximum = _canvas_number(assignment.get("points_possible"))
    score_percent = (score / maximum * 100) if score is not None and maximum not in {None, 0.0} else None
    state = str(record.get("workflow_state") or record.get("state") or "").lower()
    if fact_type == CanvasEvidenceFactType.COURSE_COMPLETION:
        required = int(_canvas_number(record.get("requirement_count")) or 0)
        completed_count = int(_canvas_number(record.get("requirement_completed_count")) or 0)
        completed = required > 0 and completed_count >= required
    elif fact_type == CanvasEvidenceFactType.MODULE_COMPLETION:
        completed = state == "completed" or bool(record.get("completed_at"))
    else:
        completed = bool(record) and state not in {
            "unsubmitted",
            "available",
            "invited",
            "creation_pending",
        }
    return {
        "completed": completed,
        "score": score,
        "score_maximum": maximum,
        "score_percent": score_percent,
        "provider_state": state or None,
        "requirement_count": record.get("requirement_count"),
        "requirement_completed_count": record.get("requirement_completed_count"),
    }


def _authoritative_canvas_fact(
    *,
    app: Application,
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
    requirement: CanvasEvidenceRequirement,
    subject_id: str,
    assertion: dict[str, Any],
    source_payload: dict[str, Any],
    verification_method: str,
    observed_at: datetime | None = None,
    effective_at: datetime | None = None,
) -> EvidenceFact:
    normalized = {
        "requirement_id": requirement.requirement_id,
        "source": requirement.source.value,
        "fact_type": requirement.fact_type.value,
        "scope": requirement.scope.to_dict(),
        "assertion": assertion,
        "payload": source_payload,
    }
    canonical = json.dumps(normalized, separators=(",", ":"), sort_keys=True, default=str)
    payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    logical_material = ":".join(
        [platform.id, binding.id, app.id, requirement.requirement_id, subject_id]
    )
    return EvidenceFact(
        organization_id=app.organization_id,
        application_id=app.id,
        subject_id=subject_id,
        provider="canvas",
        fact_type=requirement.fact_type.value,
        scope=requirement.scope.to_dict(),
        assertion=assertion,
        verification={"status": "VERIFIED", "method": verification_method},
        source={
            "source": requirement.source.value,
            "provider_event_id": _portable_fact_event_id(requirement.source.value, normalized),
        },
        requirement_id=requirement.requirement_id,
        logical_key=hashlib.sha256(logical_material.encode("utf-8")).hexdigest(),
        source_revision=payload_hash,
        payload_hash=payload_hash,
        observed_at=observed_at or datetime.now(timezone.utc),
        effective_at=effective_at,
    )


def _normalized_canvas_rest_source_payload(record: dict[str, Any]) -> dict[str, Any]:
    assignment = record.get("assignment") if isinstance(record.get("assignment"), dict) else {}
    return {
        key: value
        for key, value in {
            "id": record.get("id"),
            "assignment_id": record.get("assignment_id"),
            "score": record.get("score"),
            "grade": record.get("grade"),
            "workflow_state": record.get("workflow_state"),
            "state": record.get("state"),
            "submitted_at": record.get("submitted_at"),
            "graded_at": record.get("graded_at"),
            "updated_at": record.get("updated_at"),
            "completed_at": record.get("completed_at"),
            "points_possible": assignment.get("points_possible"),
            "requirement_count": record.get("requirement_count"),
            "requirement_completed_count": record.get("requirement_completed_count"),
        }.items()
        if value is not None
    }


async def _record_canvas_fact_and_policy(
    *,
    repo: IIssuanceRepository,
    app: Application,
    template: Any,
    binding: CanvasProgramBinding,
    fact: EvidenceFact,
    requirements: list[CanvasEvidenceRequirement],
) -> tuple[str, bool, bool]:
    policy_set = None
    if binding.approval_policy_set_id:
        policy_set = await repo.get_approval_policy_set(
            app.organization_id,
            binding.approval_policy_set_id,
        )
    result = await record_authoritative_canvas_evidence_revision(
        repo=repo,
        app=app,
        template=template,
        binding=binding,
        fact=fact,
        requirements=requirements,
        policy_set=policy_set,
    )
    return result.evidence_fact.id, result.inserted, result.policy_decision.allowed


async def _synchronize_authoritative_canvas_application(
    *,
    repo: IIssuanceRepository,
    app: Application,
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
) -> dict[str, Any]:
    """Read every typed requirement; NRPS is deliberately not issuance evidence."""

    try:
        requirements = validate_canvas_evidence_requirements(
            list(binding.evidence_requirements or [])
        )
    except ValueError as exc:
        raise CanvasSyncProcessingError(
            "canvas_requirements_invalid",
            "Canvas evidence requirements are invalid",
            retryable=False,
        ) from exc
    template = await repo.get_application_template(app.application_template_id)
    if template is None or template.organization_id != app.organization_id:
        raise CanvasSyncProcessingError(
            "canvas_application_template_unavailable",
            "Canvas application template is unavailable",
            retryable=False,
        )
    canvas_context = (
        app.integration_context.get("canvas")
        if isinstance(app.integration_context, dict)
        else None
    )
    canvas_context = dict(canvas_context) if isinstance(canvas_context, dict) else {}
    subject = str(canvas_context.get("lti_subject") or "").strip()
    if not subject:
        raise CanvasSyncProcessingError(
            "canvas_lti_identity_missing",
            "Canvas application has no verified LTI subject",
            retryable=False,
        )

    deployment_id = str(platform.lti_deployment_id or "").strip()
    identity = await repo.get_canvas_learner_identity_by_subject(
        organization_id=app.organization_id,
        platform_id=platform.id,
        deployment_id=deployment_id,
        lti_subject=subject,
    )
    numeric_user_id = (
        str(identity.canvas_user_id).strip()
        if identity is not None
        and identity.status == CanvasLearnerIdentityStatus.LINKED
        and identity.canvas_user_id
        else ""
    )

    created: list[str] = []
    reused: list[str] = []
    checked: list[str] = []
    warnings: list[str] = []
    previous_allowed = canvas_context.get("last_evidence_policy_allowed")
    final_allowed = previous_allowed if isinstance(previous_allowed, bool) else False
    ags_token: str | None = None
    oauth_token: str | None = None
    token_endpoint: str | None = None
    client_assertion: str | None = None
    retry_after_seconds: int | None = None
    oauth_reauthorization_required = False
    async with canvas_http_client(timeout=15.0) as client:
        for requirement in requirements:
            try:
                if requirement.source == CanvasEvidenceSource.AGS_RESULT:
                    line_item_url = str(requirement.scope.line_item_url or "").strip()
                    if not line_item_url:
                        raise CanvasLtiServiceError("AGS requirement has no verified line-item URL")
                    line_item_url = validate_lti_service_url(line_item_url)
                    if ags_token is None:
                        token_endpoint = _lti_token_endpoint(platform)
                        client_assertion = await _lti_service_client_assertion(
                            platform,
                            token_endpoint,
                        )
                        token = await request_lti_access_token(
                            client=client,
                            token_endpoint=token_endpoint,
                            client_id=str(platform.lti_client_id or ""),
                            client_assertion=client_assertion,
                            scopes=[AGS_RESULT_READ_SCOPE],
                            platform_issuer=platform.lti_issuer or platform.canvas_base_url or "",
                        )
                        ags_token = token.value
                    results = await read_ags_results(
                        client=client,
                        results_url=f"{line_item_url.rstrip('/')}/results",
                        access_token=ags_token,
                        platform_issuer=platform.lti_issuer or platform.canvas_base_url or "",
                        user_id=subject,
                    )
                    result = results[0] if results else {}
                    score = _canvas_number(result.get("resultScore"))
                    maximum = _canvas_number(result.get("resultMaximum"))
                    score_percent = (
                        score / maximum * 100
                        if score is not None and maximum not in {None, 0.0}
                        else None
                    )
                    status_value = str(result.get("resultStatus") or "")
                    assertion = {
                        "completed": bool(result)
                        and status_value.lower() not in {"notready", "failed"},
                        "score": score,
                        "score_maximum": maximum,
                        "score_percent": score_percent,
                        "result_status": status_value or None,
                    }
                    source_payload = {
                        key: value
                        for key, value in {
                            "id": result.get("id"),
                            "resultScore": result.get("resultScore"),
                            "resultMaximum": result.get("resultMaximum"),
                            "resultStatus": result.get("resultStatus"),
                            "timestamp": result.get("timestamp"),
                        }.items()
                        if value is not None
                    }
                    fact = _authoritative_canvas_fact(
                        app=app,
                        platform=platform,
                        binding=binding,
                        requirement=requirement,
                        subject_id=subject,
                        assertion=assertion,
                        source_payload=source_payload,
                        verification_method="LTI_AGS_RESULT_READ",
                        effective_at=_canvas_evidence_effective_at(result.get("timestamp")),
                    )
                else:
                    if not numeric_user_id:
                        reason = (
                            "verified Canvas identity is quarantined"
                            if identity is not None
                            and identity.status == CanvasLearnerIdentityStatus.QUARANTINED
                            else "verified numeric Canvas identity is unavailable"
                        )
                        raise CanvasLtiServiceError(reason)
                    if oauth_token is None:
                        oauth_token = await _canvas_oauth_access_token(
                            platform=platform,
                            repo=repo,
                        )
                    if not oauth_token:
                        raise CanvasLtiServiceError(
                            "Canvas REST OAuth connection requires reauthorization"
                        )
                    record, _scope = await _read_canvas_rest_evidence(
                        client=client,
                        repo=repo,
                        platform=platform,
                        token=oauth_token,
                        requirement=requirement,
                        canvas_user_id=numeric_user_id,
                    )
                    source_payload = _normalized_canvas_rest_source_payload(record)
                    effective = (
                        record.get("updated_at")
                        or record.get("graded_at")
                        or record.get("completed_at")
                    )
                    fact = _authoritative_canvas_fact(
                        app=app,
                        platform=platform,
                        binding=binding,
                        requirement=requirement,
                        subject_id=subject,
                        assertion=_canvas_rest_assertion(requirement.fact_type, record),
                        source_payload=source_payload,
                        verification_method="CANVAS_OAUTH_API_READ",
                        effective_at=_canvas_evidence_effective_at(effective),
                    )
                fact_id, inserted, final_allowed = await _record_canvas_fact_and_policy(
                    repo=repo,
                    app=app,
                    template=template,
                    binding=binding,
                    fact=fact,
                    requirements=requirements,
                )
                checked.append(requirement.requirement_id)
                (created if inserted else reused).append(fact_id)
            except CanvasLtiServiceError as exc:
                # Authoritative read failures never replace the current head.
                warnings.append(f"{requirement.requirement_id}: {str(exc)[:240]}")
                oauth_reauthorization_required = (
                    oauth_reauthorization_required or exc.reauthorization_required
                )
                if exc.retry_after_seconds is not None:
                    retry_after_seconds = max(
                        retry_after_seconds or 0,
                        exc.retry_after_seconds,
                    )
            except (HTTPException, ValueError) as exc:
                # Authoritative read failures never replace the current head.
                warnings.append(f"{requirement.requirement_id}: {str(exc)[:240]}")

    now = datetime.now(timezone.utc)
    patched_platform = await repo.patch_canvas_platform_validation_state(
        app.organization_id,
        platform.id,
        expected_config_version=platform.config_version,
        last_validated_at=now,
        last_connection_error=(
            "oauth_reauthorization_required"
            if oauth_reauthorization_required
            else None if checked else "canvas_authoritative_reads_failed"
        ),
    )
    if patched_platform is None:
        raise CanvasSyncProcessingError(
            "canvas_platform_reconfigured",
            "Canvas platform configuration changed during synchronization",
            retryable=True,
        )
    patched_app = await repo.patch_application_integration_context(
        app.organization_id,
        app.id,
        patch={
            "canvas": {
                "last_evidence_sync_at": now.isoformat(),
                "last_evidence_policy_allowed": final_allowed,
                "last_evidence_requirements_checked": checked,
            }
        },
    )
    if patched_app is None:
        raise CanvasSyncProcessingError(
            "canvas_application_unavailable",
            "Canvas application became unavailable during synchronization",
            retryable=False,
        )
    if retry_after_seconds is not None:
        raise CanvasSyncProcessingError(
            "canvas_rate_limited",
            "Canvas rate limited one or more authoritative evidence reads",
            retryable=True,
            retry_after_seconds=retry_after_seconds,
        )
    return {
        "application_id": app.id,
        "sources_checked": checked,
        "facts_created": created,
        "facts_reused": reused,
        "warnings": warnings,
        "policy_allowed": final_allowed,
    }


def _canvas_candidate_key(
    *,
    platform_id: str,
    binding_id: str,
    canvas_user_id: str | None,
    lti_subject: str | None,
) -> str:
    namespace = "canvas_user" if canvas_user_id else "lti_subject"
    identifier = str(canvas_user_id or lti_subject or "").strip()
    return hashlib.sha256(
        f"{platform_id}:{binding_id}:{namespace}:{identifier}".encode("utf-8")
    ).hexdigest()


def _candidate_observation_satisfies(
    requirement: CanvasEvidenceRequirement,
    observation: CanvasCandidateObservation | None,
) -> bool:
    if observation is None:
        return False
    assertion = observation.assertion or {}
    if requirement.pass_rule.min_score_percent is not None:
        score = _canvas_number(assertion.get("score_percent"))
        return score is not None and score >= requirement.pass_rule.min_score_percent
    if requirement.pass_rule.completed is True:
        return assertion.get("completed") is True
    return False


async def _process_background_canvas_roster(
    *,
    repo: IIssuanceRepository,
    target: CanvasEvidenceSyncTarget,
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
) -> dict[str, Any]:
    """Evaluate an unsigned roster and produce pending-claim candidates."""

    requirements = validate_canvas_evidence_requirements(
        list(binding.evidence_requirements or [])
    )
    rest_requirements = [
        item for item in requirements if item.source == CanvasEvidenceSource.CANVAS_REST
    ]
    ags_requirements = [
        item for item in requirements if item.source == CanvasEvidenceSource.AGS_RESULT
    ]
    mixed_sources = bool(rest_requirements and ags_requirements)
    try:
        batch_size = int(os.environ.get("CANVAS_BACKGROUND_ROSTER_BATCH_SIZE", "500"))
        roster_limit = int(os.environ.get("CANVAS_BACKGROUND_ROSTER_MAX_SIZE", "5000"))
    except ValueError as exc:
        raise CanvasSyncProcessingError(
            "canvas_roster_configuration_invalid",
            "Canvas roster bounds are invalid",
            retryable=False,
        ) from exc
    batch_size = max(1, min(batch_size, 2000))
    roster_limit = max(batch_size, min(roster_limit, 10000))
    base = _canvas_api_base(platform)
    oauth_token = await _canvas_oauth_access_token(platform=platform, repo=repo)
    numeric_users: dict[str, dict[str, Any]] = {}
    opaque_subjects: set[str] = set()
    bulk_course_progress: dict[tuple[str, str], dict[str, Any]] = {}
    async with canvas_http_client(timeout=20.0) as client:
        if rest_requirements:
            if not oauth_token:
                raise CanvasSyncProcessingError(
                    "canvas_roster_oauth_unavailable",
                    "Canvas background roster OAuth requires reauthorization",
                    retryable=True,
                )
            course_ids = sorted({item.scope.course_id for item in rest_requirements})
            for course_id in course_ids:
                path = (
                    f"courses/{quote(course_id, safe='')}/users?"
                    + urlencode({"enrollment_type[]": "student"})
                )
                users = await _fetch_canvas_api_collection(
                    client,
                    base_url=base,
                    token=oauth_token,
                    path=path,
                    limit=roster_limit,
                    require_complete=True,
                    repo=repo,
                    platform=platform,
                )
                for user in users:
                    user_id = str(user.get("id") or "").strip()
                    if user_id:
                        # Retain no email/name; only the numeric Canvas identity
                        # participates in candidate matching.
                        numeric_users[user_id] = {"id": user_id}
            progress_course_ids = sorted(
                {
                    item.scope.course_id
                    for item in rest_requirements
                    if item.fact_type == CanvasEvidenceFactType.COURSE_COMPLETION
                }
            )
            for course_id in progress_course_ids:
                progress_rows = await _fetch_canvas_api_collection(
                    client,
                    base_url=base,
                    token=oauth_token,
                    path=f"courses/{quote(course_id, safe='')}/bulk_user_progress",
                    limit=roster_limit,
                    require_complete=True,
                    repo=repo,
                    platform=platform,
                )
                for progress in progress_rows:
                    user_id = str(
                        progress.get("user_id")
                        or progress.get("userId")
                        or ""
                    ).strip()
                    if user_id:
                        bulk_course_progress[(course_id, user_id)] = progress

        nrps_token: str | None = None
        if ags_requirements:
            target_metadata = target.metadata if isinstance(target.metadata, dict) else {}
            memberships_url = str(
                target_metadata.get("nrps_context_memberships_url") or ""
            ).strip()
            if (
                target_metadata.get("verified_binding_id") != binding.id
                or target_metadata.get("verified_binding_config_version")
                != binding.config_version
            ):
                memberships_url = ""
            if not memberships_url:
                raise CanvasSyncProcessingError(
                    "canvas_nrps_roster_unavailable",
                    "Canvas NRPS roster URL is unavailable",
                    retryable=True,
                )
            token_endpoint = _lti_token_endpoint(platform)
            client_assertion = await _lti_service_client_assertion(platform, token_endpoint)
            token = await request_lti_access_token(
                client=client,
                token_endpoint=token_endpoint,
                client_id=str(platform.lti_client_id or ""),
                client_assertion=client_assertion,
                scopes=[NRPS_MEMBERSHIP_READ_SCOPE],
                platform_issuer=platform.lti_issuer or platform.canvas_base_url or "",
            )
            nrps_token = token.value
            members = await read_nrps_memberships(
                client=client,
                memberships_url=memberships_url,
                access_token=nrps_token,
                platform_issuer=platform.lti_issuer or platform.canvas_base_url or "",
                limit=roster_limit,
            )
            for member in members:
                subject = str(member.get("user_id") or member.get("userId") or "").strip()
                if subject and str(member.get("status") or "active").lower() == "active":
                    opaque_subjects.add(subject)

        existing = {
            candidate.candidate_key: candidate
            for candidate in await repo.list_canvas_award_candidates(
                target.organization_id,
                binding_id=binding.id,
                limit=roster_limit,
            )
        }
        candidate_inputs: list[tuple[str | None, str | None, Any | None]] = []
        if rest_requirements:
            for user_id in sorted(numeric_users):
                identity = await repo.get_canvas_learner_identity_by_canvas_user(
                    organization_id=target.organization_id,
                    platform_id=platform.id,
                    deployment_id=str(platform.lti_deployment_id or ""),
                    canvas_user_id=user_id,
                )
                subject = (
                    identity.lti_subject
                    if identity is not None
                    and identity.status == CanvasLearnerIdentityStatus.LINKED
                    else None
                )
                candidate_inputs.append((user_id, subject, identity))
        else:
            candidate_inputs.extend(
                (None, subject, None) for subject in sorted(opaque_subjects)
            )

        try:
            cursor = int((target.metadata or {}).get("roster_cursor") or 0)
        except (TypeError, ValueError):
            cursor = 0
        if cursor < 0 or cursor >= len(candidate_inputs):
            cursor = 0
        candidate_batch = candidate_inputs[cursor : cursor + batch_size]

        candidates_seen = 0
        pending_claim = 0
        identity_link_required = 0
        observations_written = 0
        ags_token: str | None = None
        for canvas_user_id, lti_subject, identity in candidate_batch:
            key = _canvas_candidate_key(
                platform_id=platform.id,
                binding_id=binding.id,
                canvas_user_id=canvas_user_id,
                lti_subject=lti_subject,
            )
            candidate = existing.get(key) or CanvasAwardCandidate(
                organization_id=target.organization_id,
                platform_id=platform.id,
                binding_id=binding.id,
                candidate_key=key,
            )
            candidate.canvas_user_id = canvas_user_id
            candidate.lti_subject = lti_subject
            candidate.learner_identity_id = identity.id if identity is not None else None
            candidate.observed_at = datetime.now(timezone.utc)
            if candidate.state not in {
                CanvasAwardCandidateState.CLAIMED,
                CanvasAwardCandidateState.DISMISSED,
            }:
                candidate.state = (
                    CanvasAwardCandidateState.IDENTITY_LINK_REQUIRED
                    if mixed_sources
                    and (
                        identity is None
                        or identity.status != CanvasLearnerIdentityStatus.LINKED
                        or not lti_subject
                        or lti_subject not in opaque_subjects
                    )
                    else CanvasAwardCandidateState.OBSERVED
                )
            await repo.save_canvas_award_candidate(candidate)
            candidates_seen += 1
            if candidate.state == CanvasAwardCandidateState.IDENTITY_LINK_REQUIRED:
                identity_link_required += 1
                continue

            for requirement in requirements:
                try:
                    if requirement.source == CanvasEvidenceSource.CANVAS_REST:
                        if requirement.fact_type == CanvasEvidenceFactType.COURSE_COMPLETION:
                            # The hosted background contract uses Canvas's bulk
                            # course-progress projection. A successful collection
                            # read with no user row is a verified negative.
                            record = dict(
                                bulk_course_progress.get(
                                    (
                                        requirement.scope.course_id,
                                        str(canvas_user_id or ""),
                                    ),
                                    {},
                                )
                            )
                        else:
                            record, _scope = await _read_canvas_rest_evidence(
                                client=client,
                                repo=repo,
                                platform=platform,
                                token=oauth_token,
                                requirement=requirement,
                                canvas_user_id=str(canvas_user_id or ""),
                            )
                        assertion = _canvas_rest_assertion(
                            requirement.fact_type,
                            record,
                        )
                        payload = _normalized_canvas_rest_source_payload(record)
                        method = "CANVAS_OAUTH_API_READ"
                    else:
                        line_item_url = validate_lti_service_url(
                            str(requirement.scope.line_item_url or "")
                        )
                        if ags_token is None:
                            token_endpoint = _lti_token_endpoint(platform)
                            assertion_jwt = await _lti_service_client_assertion(
                                platform,
                                token_endpoint,
                            )
                            token = await request_lti_access_token(
                                client=client,
                                token_endpoint=token_endpoint,
                                client_id=str(platform.lti_client_id or ""),
                                client_assertion=assertion_jwt,
                                scopes=[AGS_RESULT_READ_SCOPE],
                                platform_issuer=platform.lti_issuer
                                or platform.canvas_base_url
                                or "",
                            )
                            ags_token = token.value
                        results = await read_ags_results(
                            client=client,
                            results_url=f"{line_item_url.rstrip('/')}/results",
                            access_token=ags_token,
                            platform_issuer=platform.lti_issuer
                            or platform.canvas_base_url
                            or "",
                            user_id=lti_subject,
                        )
                        result = results[0] if results else {}
                        score = _canvas_number(result.get("resultScore"))
                        maximum = _canvas_number(result.get("resultMaximum"))
                        assertion = {
                            "completed": bool(result)
                            and str(result.get("resultStatus") or "").lower()
                            not in {"notready", "failed"},
                            "score": score,
                            "score_maximum": maximum,
                            "score_percent": (
                                score / maximum * 100
                                if score is not None and maximum not in {None, 0.0}
                                else None
                            ),
                        }
                        payload = {
                            key: value
                            for key, value in {
                                "resultScore": result.get("resultScore"),
                                "resultMaximum": result.get("resultMaximum"),
                                "resultStatus": result.get("resultStatus"),
                                "timestamp": result.get("timestamp"),
                            }.items()
                            if value is not None
                        }
                        method = "LTI_AGS_RESULT_READ"
                    canonical = json.dumps(
                        {"assertion": assertion, "payload": payload},
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    )
                    observation = CanvasCandidateObservation(
                        organization_id=target.organization_id,
                        candidate_id=candidate.id,
                        requirement_id=requirement.requirement_id,
                        logical_key=requirement.requirement_id,
                        assertion=assertion,
                        verification={"status": "VERIFIED", "method": method},
                        payload_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                    )
                    _stored, changed = await repo.save_canvas_candidate_observation(
                        observation
                    )
                    observations_written += int(changed)
                except CanvasLtiServiceError as exc:
                    if exc.retry_after_seconds is not None:
                        raise
                    # Preserve the previous current observation on a failed read.
                    continue
                except (HTTPException, ValueError):
                    # Preserve the previous current observation on any failed read.
                    continue

            current = {
                observation.requirement_id: observation
                for observation in await repo.list_current_canvas_candidate_observations(
                    target.organization_id,
                    candidate.id,
                )
            }
            allowed = all(
                not requirement.required
                or _candidate_observation_satisfies(
                    requirement,
                    current.get(requirement.requirement_id),
                )
                for requirement in requirements
            )
            if (
                allowed
                and candidate.state
                not in {
                    CanvasAwardCandidateState.CLAIMED,
                    CanvasAwardCandidateState.DISMISSED,
                }
            ):
                candidate.state = CanvasAwardCandidateState.PENDING_CLAIM
                pending_claim += 1
                await repo.save_canvas_award_candidate(candidate)

    next_cursor = cursor + len(candidate_batch)
    if next_cursor >= len(candidate_inputs):
        next_cursor = 0
    target.metadata = {
        **(target.metadata if isinstance(target.metadata, dict) else {}),
        "roster_cursor": next_cursor,
        "roster_size": len(candidate_inputs),
        "roster_cycle_completed_at": (
            datetime.now(timezone.utc).isoformat() if next_cursor == 0 else None
        ),
    }
    target.updated_at = datetime.now(timezone.utc)
    if next_cursor:
        # Finish a bounded large-roster cycle promptly instead of waiting a
        # full 15-minute cadence between batches.
        target.next_run_at = target.updated_at + timedelta(minutes=1)
    await repo.save_canvas_sync_target(target)
    return {
        "candidates_seen": candidates_seen,
        "pending_claim": pending_claim,
        "identity_link_required": identity_link_required,
        "observations_written": observations_written,
        "roster_remaining": max(0, len(candidate_inputs) - next_cursor)
        if next_cursor
        else 0,
    }


async def process_authoritative_canvas_sync_target(
    repo: IIssuanceRepository,
    target: CanvasEvidenceSyncTarget,
) -> dict[str, Any]:
    """Worker hook for application/drift reads; it never approves or signs."""

    if not portable_canvas_enabled_for_organization(target.organization_id):
        # Keep due targets intact while the global/pilot kill switch is off,
        # but perform no Canvas network read and create no award observation.
        return {"no_change": True}

    # The worker wrapper performs the same validation. Keep the authoritative
    # hook independently fail-closed for direct invocations and future workers.
    await validate_canvas_sync_target(repo=repo, target=target)

    if target.target_type == CanvasEvidenceSyncTargetType.ISSUED_DRIFT:
        drift_until = _canvas_evidence_effective_at(
            (target.metadata or {}).get("drift_until")
        )
        if drift_until is not None and drift_until <= datetime.now(timezone.utc):
            target.enabled = False
            target.updated_at = datetime.now(timezone.utc)
            await repo.save_canvas_sync_target(target)
            return {"application_id": target.application_id, "no_change": True}
    if target.target_type == CanvasEvidenceSyncTargetType.BACKGROUND_ROSTER:
        platform = await repo.get_canvas_platform_for_org(
            target.organization_id,
            target.platform_id,
        )
        binding = await repo.get_canvas_program_binding_for_org(
            target.organization_id,
            target.binding_id,
        )
        if platform is None or binding is None:
            raise CanvasSyncProcessingError(
                "canvas_sync_resources_unavailable",
                "Canvas synchronization resources are unavailable",
                retryable=False,
            )
        try:
            return await _process_background_canvas_roster(
                repo=repo,
                target=target,
                platform=platform,
                binding=binding,
            )
        except CanvasLtiServiceError as exc:
            raise CanvasSyncProcessingError(
                "canvas_rate_limited"
                if exc.retry_after_seconds is not None
                else "canvas_authoritative_read_failed",
                "Canvas background evidence could not be read",
                retryable=exc.retryable,
                retry_after_seconds=exc.retry_after_seconds,
            ) from exc
    if target.target_type not in {
        CanvasEvidenceSyncTargetType.LEARNER_APPLICATION,
        CanvasEvidenceSyncTargetType.ISSUED_DRIFT,
    }:
        raise CanvasSyncProcessingError(
            "canvas_sync_target_type_unsupported",
            "Canvas target type has no authoritative processor",
            retryable=False,
        )
    app = await repo.get_application(str(target.application_id or ""))
    platform = await repo.get_canvas_platform_for_org(
        target.organization_id,
        target.platform_id,
    )
    binding = await repo.get_canvas_program_binding_for_org(
        target.organization_id,
        target.binding_id,
    )
    if app is None or platform is None or binding is None:
        raise CanvasSyncProcessingError(
            "canvas_sync_resources_unavailable",
            "Canvas synchronization resources are unavailable",
            retryable=False,
        )
    result = await _synchronize_authoritative_canvas_application(
        repo=repo,
        app=app,
        platform=platform,
        binding=binding,
    )
    if not result["sources_checked"]:
        raise CanvasSyncProcessingError(
            "canvas_authoritative_reads_failed",
            "No authoritative Canvas evidence requirement could be read",
            retryable=True,
        )
    # Do not return warning/provider text in durable job results.
    return {
        "application_id": app.id,
        "config_version": target.config_version,
        "requirements_checked": len(result["sources_checked"]),
        "facts_created": len(result["facts_created"]),
        "facts_reused": len(result["facts_reused"]),
        "policy_allowed": bool(result["policy_allowed"]),
    }


def _canvas_lti_public_job_status(job: CanvasEvidenceSyncJob) -> str:
    return {
        CanvasEvidenceSyncJobStatus.QUEUED: "queued",
        CanvasEvidenceSyncJobStatus.LEASED: "running",
        CanvasEvidenceSyncJobStatus.RETRY: "retrying",
        CanvasEvidenceSyncJobStatus.SUCCEEDED: "succeeded",
        CanvasEvidenceSyncJobStatus.DEAD_LETTER: "failed",
        CanvasEvidenceSyncJobStatus.CANCELLED: "cancelled",
    }[job.status]


async def _current_lti_application_scope(
    *,
    state: str,
    repo: IIssuanceRepository,
) -> tuple[Application, CanvasProgramBinding, CanvasPlatform]:
    """Resolve the application exclusively from the verified experience session.

    Every relationship is checked again with organization-scoped repository
    lookups.  This endpoint intentionally has no application, organization,
    platform, binding, candidate, target, or job identifier supplied by the
    browser.
    """

    launch_state, _verified, _mip, session = await _load_verified_lti_experience_session(
        state=state,
        repo=repo,
    )
    application_id = str(session.get("application_id") or "").strip()
    binding_id = str(session.get("canvas_program_binding_id") or "").strip()
    platform_id = str(session.get("canvas_platform_id") or "").strip()
    if not application_id:
        raise HTTPException(
            status_code=409,
            detail="Bootstrap the Canvas application before synchronizing evidence",
        )
    if not binding_id or not platform_id:
        raise HTTPException(status_code=404, detail="Canvas application context was not found")

    app = await repo.get_application(application_id)
    if app is None or app.organization_id != launch_state.organization_id:
        raise HTTPException(status_code=404, detail="Canvas application context was not found")

    canvas_context = (
        app.integration_context.get("canvas")
        if isinstance(app.integration_context, dict)
        else None
    )
    session_state = str(session.get("state") or "")
    application_lti_states = {
        str(value)
        for value in (
            [
                canvas_context.get("lti_state"),
                canvas_context.get("last_lti_state"),
                *(canvas_context.get("lti_states") or []),
            ]
            if isinstance(canvas_context, dict)
            else []
        )
        if value is not None and str(value)
    }
    if (
        not isinstance(canvas_context, dict)
        or str(canvas_context.get("canvas_platform_id") or "") != platform_id
        or str(canvas_context.get("canvas_program_binding_id") or "") != binding_id
        or session_state not in application_lti_states
    ):
        raise HTTPException(status_code=404, detail="Canvas application context was not found")

    binding = await repo.get_canvas_program_binding_for_org(
        launch_state.organization_id,
        binding_id,
    )
    platform = await repo.get_canvas_platform_for_org(
        launch_state.organization_id,
        platform_id,
    )
    if (
        binding is None
        or platform is None
        or binding.platform_id != platform.id
        or binding.application_template_id != app.application_template_id
    ):
        raise HTTPException(status_code=404, detail="Canvas application context was not found")
    _require_portable_canvas_pilot(app.organization_id)
    return app, binding, platform


async def _canvas_lti_application_evidence_status(
    *,
    repo: IIssuanceRepository,
    app: Application,
    binding: CanvasProgramBinding,
    platform: CanvasPlatform,
) -> CanvasLtiApplicationEvidenceStatusResponse:
    try:
        requirements = validate_canvas_evidence_requirements(
            list(binding.evidence_requirements or [])
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail="Canvas evidence configuration is unavailable",
        ) from exc

    configured_requirement_ids = {
        requirement.requirement_id for requirement in requirements
    }
    required_requirement_ids = {
        requirement.requirement_id
        for requirement in requirements
        if requirement.required
    }
    current_facts = await repo.list_current_evidence_facts_for_application(
        app.id,
        organization_id=app.organization_id,
    )
    authoritative_facts = [
        fact
        for fact in current_facts
        if fact.provider == "canvas"
        and fact.requirement_id in configured_requirement_ids
        and str((fact.source or {}).get("source") or "")
        in {source.value for source in CanvasEvidenceSource}
    ]
    authoritative_ids = {
        str(fact.requirement_id)
        for fact in authoritative_facts
        if fact.requirement_id
    }
    verified_facts = [
        fact
        for fact in authoritative_facts
        if str((fact.verification or {}).get("status") or "").upper() == "VERIFIED"
    ]
    verified_ids = {
        str(fact.requirement_id)
        for fact in verified_facts
        if fact.requirement_id
    }

    target = await repo.get_canvas_sync_target_by_logical_key(
        app.organization_id,
        f"application:{app.id}",
    )
    if (
        target is not None
        and (
            target.application_id != app.id
            or target.binding_id != binding.id
            or target.platform_id != platform.id
            or target.config_version != binding.config_version
        )
    ):
        # A malformed/colliding target is never exposed through a learner
        # session and cannot be used to infer another application's state.
        target = None
    jobs = (
        await repo.list_canvas_sync_jobs(
            app.organization_id,
            target_id=target.id,
            limit=25,
        )
        if target is not None
        else []
    )
    latest_job = jobs[0] if jobs else None
    latest_success = next(
        (
            job
            for job in jobs
            if job.status == CanvasEvidenceSyncJobStatus.SUCCEEDED
            and (job.result or {}).get("config_version") == binding.config_version
        ),
        None,
    )
    current_config_verified_ids = verified_ids if latest_success is not None else set()

    public_job = (
        CanvasLtiEvidenceJobStatus(
            job_id=latest_job.id,
            status=_canvas_lti_public_job_status(latest_job),
            requested_at=latest_job.created_at.isoformat(),
            completed_at=(
                latest_job.completed_at.isoformat()
                if latest_job.completed_at is not None
                else None
            ),
        )
        if latest_job is not None
        else None
    )
    active_job = latest_job is not None and latest_job.status in {
        CanvasEvidenceSyncJobStatus.QUEUED,
        CanvasEvidenceSyncJobStatus.LEASED,
        CanvasEvidenceSyncJobStatus.RETRY,
    }
    if not required_requirement_ids:
        evidence_status = "not_required"
    elif required_requirement_ids.issubset(current_config_verified_ids):
        evidence_status = "verified"
    elif active_job and not authoritative_ids:
        evidence_status = "syncing"
    elif authoritative_ids:
        evidence_status = "partial"
    else:
        evidence_status = "not_observed"

    last_observed_at = max(
        (fact.observed_at for fact in authoritative_facts),
        default=None,
    )
    policy_status = "not_evaluated"
    if latest_success is not None and isinstance(
        (latest_success.result or {}).get("policy_allowed"),
        bool,
    ):
        policy_status = (
            "permitted"
            if latest_success.result["policy_allowed"]
            else "not_permitted"
        )

    claim_status = "not_available"
    unsigned = False
    available = False
    if app.credential_id:
        claim_status = "claimed"
    else:
        canvas_context = (
            app.integration_context.get("canvas")
            if isinstance(app.integration_context, dict)
            else {}
        )
        candidate_id = str(
            (canvas_context if isinstance(canvas_context, dict) else {}).get(
                "canvas_award_candidate_id"
            )
            or ""
        ).strip()
        candidate = (
            await repo.get_canvas_award_candidate_for_org(
                app.organization_id,
                candidate_id,
            )
            if candidate_id
            else None
        )
        candidate_is_scoped = bool(
            candidate is not None
            and candidate.application_id == app.id
            and candidate.binding_id == binding.id
            and candidate.platform_id == platform.id
        )
        if candidate_is_scoped and candidate.state == CanvasAwardCandidateState.CLAIMED:
            claim_status = "claimed"
        elif app.status == ApplicationStatus.APPROVED:
            claim_status = "ready_to_claim"
            unsigned = True
            available = True
        elif candidate_is_scoped and candidate.state == CanvasAwardCandidateState.PENDING_CLAIM:
            claim_status = "pending_claim"
            unsigned = True

    return CanvasLtiApplicationEvidenceStatusResponse(
        application_status=(
            app.status.value if hasattr(app.status, "value") else str(app.status)
        ),
        sync=public_job,
        evidence=CanvasLtiEvidenceSummary(
            required_count=len(required_requirement_ids),
            current_authoritative_count=len(authoritative_ids),
            verified_authoritative_count=len(current_config_verified_ids),
            verified_required_count=len(
                required_requirement_ids.intersection(current_config_verified_ids)
            ),
            status=evidence_status,
            last_observed_at=(
                last_observed_at.isoformat()
                if last_observed_at is not None
                else None
            ),
        ),
        policy=CanvasLtiEvidencePolicyStatus(status=policy_status),
        claim=CanvasLtiClaimStatus(
            status=claim_status,
            unsigned=unsigned,
            available=available,
        ),
    )


@canvas_integration_router.post(
    "/lti/experience-sessions/current/evidence-sync",
    response_model=CanvasLtiApplicationEvidenceStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue authoritative Canvas evidence synchronization for this learner",
)
async def sync_canvas_lti_evidence(
    state: Annotated[str, Depends(_lti_session_bearer_token)],
    response: Response,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiApplicationEvidenceStatusResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    app, binding, platform = await _current_lti_application_scope(
        state=state,
        repo=repo,
    )
    try:
        await enqueue_application_canvas_sync(
            repo=repo,
            organization_id=app.organization_id,
            application_id=app.id,
        )
    except CanvasSyncNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Canvas application context was not found") from exc
    except CanvasSyncConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": "Canvas synchronization is unavailable"},
        ) from exc
    return await _canvas_lti_application_evidence_status(
        repo=repo,
        app=app,
        binding=binding,
        platform=platform,
    )


@canvas_integration_router.get(
    "/lti/experience-sessions/current/evidence-status",
    response_model=CanvasLtiApplicationEvidenceStatusResponse,
    summary="Get browser-safe authoritative Canvas evidence status for this learner",
)
async def get_canvas_lti_evidence_status(
    state: Annotated[str, Depends(_lti_session_bearer_token)],
    response: Response,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiApplicationEvidenceStatusResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    app, binding, platform = await _current_lti_application_scope(
        state=state,
        repo=repo,
    )
    return await _canvas_lti_application_evidence_status(
        repo=repo,
        app=app,
        binding=binding,
        platform=platform,
    )


@canvas_integration_router.post(
    "/evidence-events",
    response_model=CanvasEvidenceEventResponse,
    summary="Process Canvas evidence event",
)
async def process_canvas_evidence_event_route(
    request: Request,
    response: Response,
    repo: IIssuanceRepository = Depends(),
) -> CanvasEvidenceEventResponse:
    """Validate signed Canvas evidence and attach it to an ElevenID application."""

    if not legacy_canvas_event_ingest_enabled():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Legacy Canvas event ingestion is disabled; use portable synchronization",
        )
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "Wed, 14 Oct 2026 00:00:00 GMT"
    response.headers["Link"] = '</docs/canvas-portable-integration>; rel="deprecation"'
    raw_body = await request.body()
    return await process_canvas_evidence_event(
        raw_body=raw_body,
        headers=request.headers,
        repo=repo,
        issuer_context_applier=apply_required_remote_issuer_context,
    )


@canvas_integration_router.post(
    "/ags/score-events",
    response_model=CanvasEvidenceEventResponse,
    summary="Process Canvas AGS score as MIP evidence",
)
async def process_canvas_ags_score_event_route(
    request: Request,
    response: Response,
    repo: IIssuanceRepository = Depends(),
) -> CanvasEvidenceEventResponse:
    """Validate a signed Canvas AGS score payload and emit normalized evidence facts."""

    if not legacy_canvas_event_ingest_enabled():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Legacy Canvas AGS event ingestion is disabled",
        )
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "Wed, 14 Oct 2026 00:00:00 GMT"
    raw_body = await request.body()
    return await process_canvas_ags_score_event(
        raw_body=raw_body,
        headers=request.headers,
        repo=repo,
        issuer_context_applier=apply_required_remote_issuer_context,
    )


@canvas_integration_router.post(
    "/nrps/membership-events",
    response_model=CanvasEvidenceEventResponse,
    summary="Process Canvas NRPS membership as MIP evidence",
)
async def process_canvas_nrps_membership_event_route(
    request: Request,
    response: Response,
    repo: IIssuanceRepository = Depends(),
) -> CanvasEvidenceEventResponse:
    """Validate a signed Canvas NRPS membership payload and emit normalized evidence facts."""

    if not legacy_canvas_event_ingest_enabled():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Legacy Canvas NRPS event ingestion is disabled",
        )
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "Wed, 14 Oct 2026 00:00:00 GMT"
    raw_body = await request.body()
    return await process_canvas_nrps_membership_event(
        raw_body=raw_body,
        headers=request.headers,
        repo=repo,
        issuer_context_applier=apply_required_remote_issuer_context,
    )


@canvas_integration_router.get(
    "/evidence-events/{canvas_account_id}/{provider_event_id}",
    response_model=CanvasEvidenceEventStatusResponse,
    summary="Get Canvas evidence event status",
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_canvas_evidence_event_status(
    canvas_account_id: str,
    provider_event_id: str,
    trusted_organization_id: str = Depends(_trusted_canvas_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> CanvasEvidenceEventStatusResponse:
    """Read the replay-safe receipt and recorded response for a Canvas evidence event."""

    receipt = await repo.get_canvas_event_receipt(provider_event_id, canvas_account_id)
    if receipt is None or (
        isinstance(trusted_organization_id, str)
        and trusted_organization_id.strip()
        and receipt.organization_id != trusted_organization_id.strip()
    ):
        raise HTTPException(status_code=404, detail="Canvas evidence event receipt not found")

    response_payload = receipt.issuance_response if isinstance(receipt.issuance_response, dict) else {}
    return CanvasEvidenceEventStatusResponse(
        id=receipt.id,
        provider_event_id=receipt.provider_event_id,
        canvas_account_id=receipt.canvas_account_id,
        organization_id=receipt.organization_id,
        credential_template_id=receipt.credential_template_id,
        application_id=response_payload.get("application_id"),
        status=receipt.status,
        payload_hash=receipt.payload_hash,
        issuance_transaction_id=receipt.issuance_transaction_id,
        error_summary=receipt.error_summary,
        first_seen_at=receipt.first_seen_at.isoformat(),
        last_seen_at=receipt.last_seen_at.isoformat(),
        response=response_payload,
        evidence_facts=response_payload.get("evidence_facts") or [],
        policy_decision=response_payload.get("policy_decision"),
    )


@canvas_integration_router.post(
    "/lti/platforms/{platform_id}/login",
    summary="Initiate Canvas LTI OIDC login",
)
async def initiate_canvas_lti_login_route(
    platform_id: str,
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> RedirectResponse:
    return await _initiate_canvas_lti_login(
        platform_id=platform_id,
        request=request,
        repo=repo,
        redirect_uri=_lti_launch_redirect_uri(platform_id),
    )


@canvas_integration_router.post(
    "/lti/platforms/{platform_id}/experience-login",
    summary="Initiate Canvas LTI login for ElevenID experience",
)
async def initiate_canvas_lti_experience_login_route(
    platform_id: str,
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> RedirectResponse:
    return await _initiate_canvas_lti_login(
        platform_id=platform_id,
        request=request,
        repo=repo,
        redirect_uri=_lti_experience_redirect_uri(platform_id),
    )


@canvas_integration_router.post(
    "/lti/platforms/{platform_id}/launch",
    response_model=CanvasLtiPublicLaunchResponse,
    summary="Verify Canvas LTI launch",
)
async def verify_canvas_lti_launch_route(
    platform_id: str,
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiPublicLaunchResponse:
    _connector, _consumed_state, response = await _verify_canvas_lti_launch_submission(
        platform_id=platform_id,
        request=request,
        repo=repo,
    )
    return _public_lti_launch_response(response)


@canvas_integration_router.post(
    "/lti/platforms/{platform_id}/experience",
    summary="Verify Canvas LTI launch and redirect to ElevenID experience",
)
async def launch_canvas_lti_experience_route(
    platform_id: str,
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> RedirectResponse:
    platform, consumed_state, verified_response = await _verify_canvas_lti_launch_submission(
        platform_id=platform_id,
        request=request,
        repo=repo,
    )
    experience_code = CanvasLtiLaunchState(
        platform_id=platform.id,
        organization_id=platform.organization_id,
        canvas_account_id=platform.canvas_account_id,
        redirect_uri=consumed_state.redirect_uri,
        expires_at=datetime.now(timezone.utc)
        + timedelta(seconds=max(1, CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS)),
    )
    launch_url = _lti_experience_url(experience_code.state)
    mip_experience = canvas_lti_launch_to_mip_experience(
        platform,
        state=consumed_state.state,
        verified_launch=verified_response.model_dump(),
        launch_url=launch_url,
    )
    mip_primitives = mip_experience.to_dict()
    mip_primitives["context"] = {
        **(mip_primitives.get("context") or {}),
        "canvas_platform_id": verified_response.canvas_platform_id,
        "canvas_program_binding_id": verified_response.canvas_program_binding_id,
        "application_template_id": verified_response.application_template_id,
        "credential_template_id": verified_response.credential_template_id,
        "delivery_mode": verified_response.delivery_mode,
        "deployment_profile_id": verified_response.deployment_profile_id,
        "feature_flags": verified_response.feature_flags,
        "evidence_requirements": verified_response.evidence_requirements,
        "lti_capabilities": verified_response.lti_capabilities,
    }
    experience_code.metadata = {
        "kind": "canvas_lti_experience_code",
        "launch_state": consumed_state.state,
        "verified_launch": verified_response.model_dump(),
        "mip_primitives": mip_primitives,
        "launch_url": launch_url,
    }
    await repo.save_canvas_lti_launch_state(experience_code)
    consumed_state.metadata = {
        **(consumed_state.metadata or {}),
        "experience_code_id": experience_code.id,
        "experience_code_expires_at": experience_code.expires_at.isoformat(),
    }
    await repo.save_canvas_lti_launch_state(consumed_state)
    return RedirectResponse(launch_url, status_code=status.HTTP_303_SEE_OTHER)


@canvas_integration_router.post(
    "/lti/experience-sessions/exchange",
    response_model=CanvasLtiExperienceCodeExchangeResponse,
    summary="Exchange a one-time Canvas LTI experience code for a short-lived session",
)
async def exchange_canvas_lti_experience_code_route(
    request: CanvasLtiExperienceCodeExchangeRequest,
    response: Response,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiExperienceCodeExchangeResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    code = request.code.strip()
    consumed_code = await repo.consume_canvas_lti_launch_state(code)
    metadata = consumed_code.metadata if consumed_code is not None else {}
    if consumed_code is None or metadata.get("kind") != "canvas_lti_experience_code":
        raise HTTPException(
            status_code=400,
            detail="Canvas LTI experience code has expired, is invalid, or was already used",
        )

    now = datetime.now(timezone.utc)
    session_token = secrets.token_urlsafe(32)
    expires_at = now + timedelta(minutes=max(1, CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES))
    session = CanvasLtiLaunchState(
        platform_id=consumed_code.platform_id,
        organization_id=consumed_code.organization_id,
        canvas_account_id=consumed_code.canvas_account_id,
        state=hashlib.sha256(session_token.encode("utf-8")).hexdigest(),
        redirect_uri=consumed_code.redirect_uri,
        status="session",
        metadata={
            **metadata,
            "kind": "canvas_lti_experience_session",
            "experience_code_id": consumed_code.id,
            "session_created_at": now.isoformat(),
        },
        expires_at=expires_at,
        consumed_at=now,
    )
    await repo.save_canvas_lti_launch_state(session)

    # Retain an audit pointer but remove launch claims from the spent code.
    consumed_code.metadata = {
        "kind": "canvas_lti_experience_code_consumed",
        "launch_state": metadata.get("launch_state"),
        "session_id": session.id,
        "exchanged_at": now.isoformat(),
    }
    await repo.save_canvas_lti_launch_state(consumed_code)
    return CanvasLtiExperienceCodeExchangeResponse(
        session_token=session_token,
        expires_at=expires_at.isoformat(),
    )


@canvas_integration_router.get(
    "/lti/experience-sessions/current",
    response_model=CanvasLtiExperienceSessionResponse,
    summary="Get verified Canvas-launched ElevenID experience context",
)
async def get_canvas_lti_experience_session_route(
    state: Annotated[str, Depends(_lti_session_bearer_token)],
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiExperienceSessionResponse:
    launch_state, verified_launch, _mip_primitives, session_values = await _load_verified_lti_experience_session(
        state=state,
        repo=repo,
    )
    learner = _lti_learner_identity(verified_launch)
    display_name = str(learner.get("name") or "").strip() or None
    learner_key = hashlib.sha256(
        ":".join(
            [
                str(session_values.get("canvas_platform_id") or ""),
                str(verified_launch.get("deployment_id") or ""),
                str(_lti_subject(verified_launch) or ""),
            ]
        ).encode("utf-8")
    ).hexdigest()
    return CanvasLtiExperienceSessionResponse(
        organization_id=session_values["organization_id"],
        canvas_account_id=session_values["canvas_account_id"],
        canvas_platform_id=session_values["canvas_platform_id"],
        canvas_program_binding_id=session_values.get("canvas_program_binding_id"),
        application_template_id=session_values.get("application_template_id"),
        credential_template_id=session_values.get("credential_template_id"),
        application_id=session_values.get("application_id"),
        status=launch_state.status,
        lti_capabilities=_browser_safe_lti_capabilities(
            session_values.get("lti_capabilities")
        ),
        canvas_context=_browser_safe_canvas_context(verified_launch),
        roles=[
            str(role).rstrip("/").rsplit("/", 1)[-1]
            for role in (verified_launch.get("roles") or [])
        ],
        learner_display_name=display_name,
        learner_key=learner_key,
        identity_mapping_status=verified_launch.get("identity_mapping_status"),
    )


@canvas_integration_router.post(
    "/lti/experience-sessions/current/bootstrap",
    response_model=CanvasLtiApplicationBootstrapResponse,
    summary="Bootstrap or resume an issuance application from Canvas LTI context",
)
async def bootstrap_canvas_lti_experience_application_route(
    state: Annotated[str, Depends(_lti_session_bearer_token)],
    request: CanvasLtiApplicationBootstrapRequest,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiApplicationBootstrapResponse:
    launch_state, verified_launch, mip_primitives, session_values = await _load_verified_lti_experience_session(
        state=state,
        repo=repo,
    )
    await _require_lti_session_canvas_feature(
        repo=repo,
        session_values=session_values,
        flag="enable_canvas_lti",
        detail="Canvas LTI is disabled for this deployment profile",
    )
    app, created = await _find_or_create_lti_application(
        repo=repo,
        launch_state=launch_state,
        verified_launch=verified_launch,
        mip_primitives=mip_primitives,
        session_values=session_values,
        request=request,
    )
    await _materialize_canvas_award_candidate_on_launch(
        repo=repo,
        app=app,
        verified_launch=verified_launch,
        session_values=session_values,
    )
    app = await repo.get_application(app.id) or app
    try:
        await enqueue_application_canvas_sync(
            repo=repo,
            organization_id=app.organization_id,
            application_id=app.id,
        )
    except CanvasSyncServiceError:
        # The learner experience can continue when durable enqueue is
        # temporarily unavailable; readiness/operations expose the worker gap.
        pass
    return CanvasLtiApplicationBootstrapResponse(
        application_id=app.id,
        application_status=app.status.value,
        created=created,
        organization_id=app.organization_id,
        application_template_id=app.application_template_id,
        credential_template_id=session_values.get("credential_template_id"),
        canvas_account_id=launch_state.canvas_account_id,
        canvas_platform_id=session_values.get("canvas_platform_id"),
        canvas_program_binding_id=session_values.get("canvas_program_binding_id"),
        canvas_context={
            **_browser_safe_canvas_context(verified_launch),
            "identity_mapping_status": verified_launch.get("identity_mapping_status"),
        },
    )


@canvas_integration_router.post(
    "/lti/experience-sessions/current/deep-linking-response",
    response_model=CanvasLtiDeepLinkingResponse,
    summary="Create a signed Canvas LTI Deep Linking response",
)
async def create_canvas_lti_deep_linking_response_route(
    state: Annotated[str, Depends(_lti_session_bearer_token)],
    request: CanvasLtiDeepLinkingRequest,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiDeepLinkingResponse:
    launch_state, verified_launch, _mip_primitives, session_values = await _load_verified_lti_experience_session(
        state=state,
        repo=repo,
    )
    _require_portable_canvas_pilot(str(session_values.get("organization_id") or ""))
    await _require_lti_session_canvas_feature(
        repo=repo,
        session_values=session_values,
        flag="enable_canvas_deep_linking",
        detail="Canvas Deep Linking is disabled for this deployment profile",
    )
    _require_deep_linking_staff_role(verified_launch)
    platform = await repo.get_canvas_platform(session_values["canvas_platform_id"])
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
    binding_id = session_values.get("canvas_program_binding_id")
    binding = await repo.get_canvas_program_binding(str(binding_id)) if binding_id else None
    if (
        binding is None
        or binding.organization_id != platform.organization_id
        or binding.platform_id != platform.id
    ):
        raise HTTPException(status_code=409, detail="Canvas Deep Linking session is not bound to this platform")

    capabilities = session_values.get("lti_capabilities") if isinstance(session_values.get("lti_capabilities"), dict) else {}
    settings = _deep_linking_settings(verified_launch)
    if not capabilities.get("deep_linking") and not settings:
        raise HTTPException(status_code=409, detail="Canvas LTI session was not launched with Deep Linking")

    accept_types = _as_string_list(capabilities.get("deep_link_accept_types") or settings.get("accept_types"))
    if accept_types and "ltiResourceLink" not in accept_types:
        raise HTTPException(status_code=409, detail="Canvas Deep Linking launch does not accept LTI resource links")

    return_url = capabilities.get("deep_link_return_url") or settings.get("deep_link_return_url")
    if not isinstance(return_url, str) or not return_url.strip():
        raise HTTPException(status_code=409, detail="Canvas Deep Linking return URL is missing")
    return_url = return_url.strip()
    try:
        return_url = validate_lti_service_url(return_url)
    except CanvasLtiServiceError as exc:
        raise HTTPException(status_code=409, detail="Canvas Deep Linking return URL is not trusted") from exc

    try:
        requirements = validate_canvas_evidence_requirements(list(binding.evidence_requirements or []))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=f"Canvas binding evidence requirements are invalid: {exc}") from exc
    ags_requirements = [
        requirement
        for requirement in requirements
        if requirement.source == CanvasEvidenceSource.AGS_RESULT
    ]
    content_items = [
        _build_deep_linking_content_item(
            platform=platform,
            binding=binding,
            session_values=session_values,
            verified_launch=verified_launch,
            requirement=requirement,
        )
        for requirement in (ags_requirements or [None])
    ]
    jwt = await _sign_deep_linking_jwt(
        _build_deep_linking_jwt_payload(
            platform=platform,
            verified_launch=verified_launch,
            content_items=content_items,
        )
    )

    launch_state.metadata = {
        **(launch_state.metadata or {}),
        "deep_linking_response": {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "deep_link_return_url": return_url,
            "content_items": content_items,
        },
    }
    await repo.save_canvas_lti_launch_state(launch_state)

    return CanvasLtiDeepLinkingResponse(
        canvas_platform_id=platform.id,
        organization_id=platform.organization_id,
        canvas_account_id=platform.canvas_account_id,
        deep_link_return_url=return_url,
        content_items=content_items,
        jwt=jwt,
        form_post={
            "method": "POST",
            "action": return_url,
            "fields": {"JWT": jwt},
        },
    )
