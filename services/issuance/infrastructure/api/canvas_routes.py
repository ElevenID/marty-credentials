"""Canvas integration routes for issuance."""

from __future__ import annotations

import base64
import json
import os
import uuid
from typing import Any
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import RedirectResponse

from issuance.application.mip_integration_primitives import (
    canvas_lti_launch_to_mip_experience,
)
from issuance.application.canvas_runtime import (
    canvas_feature_enabled,
    lti_verified_launch_to_canvas_scope,
    normalize_canvas_feature_flags,
    resolve_canvas_program_binding_for_scope,
)
from issuance.application.rust_integration import (
    canvas_normalize_base_url,
    canvas_probe_lti_platform,
    verify_canvas_lti_launch,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    IssuanceEvent,
    EventType,
    CanvasLtiLaunchState,
    CanvasPlatform,
    CanvasProgramBinding,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.canvas_credentials_adapter import (
    CanvasEvidenceEventResponse,
    process_canvas_ags_score_event,
    process_canvas_evidence_event,
    process_canvas_nrps_membership_event,
)
from issuance.infrastructure.api.routes import (
    _verify_management_api_key,
    apply_remote_issuer_context,
)


canvas_integration_router = APIRouter(prefix="/v1/integrations/canvas", tags=["canvas-integrations"])
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "http://localhost:8000").rstrip("/")
CANVAS_LTI_EXPERIENCE_BASE_URL = (
    os.environ.get("CANVAS_LTI_EXPERIENCE_BASE_URL")
    or os.environ.get("UI_BASE_URL")
    or ISSUER_BASE_URL
).rstrip("/")
CANVAS_LTI_JWKS_TTL_MINUTES = int(os.environ.get("CANVAS_LTI_JWKS_TTL_MINUTES", "1440"))
LTI_MESSAGE_TYPE_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/message_type"
LTI_VERSION_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/version"
LTI_DEPLOYMENT_ID_CLAIM = "https://purl.imsglobal.org/spec/lti/claim/deployment_id"
LTI_DEEP_LINKING_SETTINGS_CLAIM = "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings"
LTI_DEEP_LINKING_CONTENT_ITEMS_CLAIM = "https://purl.imsglobal.org/spec/lti-dl/claim/content_items"
LTI_DEEP_LINKING_DATA_CLAIM = "https://purl.imsglobal.org/spec/lti-dl/claim/data"
LTI_AGS_ENDPOINT_CLAIM = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"
LTI_NRPS_CLAIM = "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice"


class CanvasPlatformCreate(BaseModel):
    organization_id: str
    canvas_account_id: str
    display_name: str | None = None
    canvas_base_url: str | None = None
    lti_client_id: str | None = None
    lti_deployment_id: str | None = None
    lti_issuer: str | None = None
    lti_jwks_url: str | None = None
    lti_jwks_json: dict[str, Any] | None = None
    lti_jwks_fetched_at: datetime | None = None
    lti_jwks_expires_at: datetime | None = None
    lti_openid_configuration: dict[str, Any] | None = None
    enabled: bool = True


class CanvasPlatformResponse(BaseModel):
    id: str
    organization_id: str
    canvas_account_id: str
    display_name: str | None = None
    canvas_base_url: str | None = None
    lti_client_id: str | None = None
    lti_deployment_id: str | None = None
    lti_issuer: str | None = None
    lti_jwks_url: str | None = None
    lti_jwks_json: dict[str, Any] | None = None
    lti_jwks_fetched_at: str | None = None
    lti_jwks_expires_at: str | None = None
    lti_openid_configuration: dict[str, Any] | None = None
    enabled: bool
    created_at: str
    updated_at: str


class CanvasProgramBindingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_template_id: str
    credential_template_id: str | None = None
    display_name: str | None = None
    flow_mode: str = "elevenid_orchestrated_canvas_evidence"
    direct_issue_enabled: bool = False
    auto_approve_on_evidence: bool = False
    evidence_requirements: list[Any] = Field(default_factory=lambda: ["canvas.course_completion"])
    canvas_scope: dict[str, Any] = Field(default_factory=dict)
    delivery_mode: str = "wallet_only"
    issuer_mode: str = "org_managed"
    approval_policy_set_id: str | None = None
    deployment_profile_id: str | None = None
    feature_flags: dict[str, bool] = Field(default_factory=dict)
    canvas_credentials: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


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
    evidence_requirements: list[Any]
    canvas_scope: dict[str, Any]
    delivery_mode: str
    issuer_mode: str
    approval_policy_set_id: str | None = None
    deployment_profile_id: str | None = None
    feature_flags: dict[str, bool] = Field(default_factory=dict)
    canvas_credentials: dict[str, Any] = Field(default_factory=dict)
    enabled: bool
    created_at: str
    updated_at: str


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


class CanvasLtiExperienceSessionResponse(BaseModel):
    state: str
    organization_id: str
    canvas_account_id: str
    canvas_platform_id: str
    canvas_program_binding_id: str | None = None
    application_template_id: str | None = None
    credential_template_id: str | None = None
    status: str
    launch_url: str | None = None
    verified_launch: dict[str, Any]
    mip_primitives: dict[str, Any]
    application_id: str | None = None
    lti_capabilities: dict[str, Any] = Field(default_factory=dict)


class CanvasLtiApplicationBootstrapRequest(BaseModel):
    applicant_identifier: str | None = None
    applicant_data: dict[str, Any] = Field(default_factory=dict)


class CanvasLtiApplicationBootstrapResponse(BaseModel):
    state: str
    application_id: str
    application_status: str
    created: bool
    organization_id: str
    application_template_id: str
    credential_template_id: str | None = None
    canvas_account_id: str
    canvas_platform_id: str | None = None
    canvas_program_binding_id: str | None = None
    subject: str | None = None
    canvas_context: dict[str, Any] = Field(default_factory=dict)


class CanvasLtiDeepLinkingRequest(BaseModel):
    title: str | None = None
    text: str | None = None
    custom: dict[str, Any] = Field(default_factory=dict)
    line_item: dict[str, Any] | None = None


class CanvasLtiDeepLinkingResponse(BaseModel):
    state: str
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


def _normalize_canvas_base_url_or_none(canvas_base_url: str | None) -> str | None:
    if canvas_base_url is None:
        return None
    value = canvas_base_url.strip()
    if not value:
        return None
    try:
        return canvas_normalize_base_url(value)
    except Exception as exc:  # pragma: no cover - exact binding exception type varies
        raise HTTPException(status_code=400, detail=f"Invalid Canvas base URL: {exc}") from exc


def _platform_from_request(request: CanvasPlatformCreate, existing: CanvasPlatform | None = None) -> CanvasPlatform:
    platform = existing or CanvasPlatform()
    now = datetime.now(timezone.utc)
    platform.organization_id = request.organization_id
    platform.canvas_account_id = request.canvas_account_id
    platform.display_name = request.display_name
    platform.canvas_base_url = _normalize_canvas_base_url_or_none(request.canvas_base_url)
    platform.lti_client_id = request.lti_client_id
    platform.lti_deployment_id = request.lti_deployment_id
    platform.lti_issuer = request.lti_issuer
    platform.lti_jwks_url = request.lti_jwks_url
    platform.lti_jwks_json = request.lti_jwks_json
    platform.lti_jwks_fetched_at = request.lti_jwks_fetched_at
    platform.lti_jwks_expires_at = request.lti_jwks_expires_at
    if platform.lti_jwks_json and platform.lti_jwks_fetched_at is None:
        platform.lti_jwks_fetched_at = now
        platform.lti_jwks_expires_at = _jwks_expiry_from(now)
    platform.lti_openid_configuration = request.lti_openid_configuration
    platform.enabled = request.enabled
    platform.updated_at = now
    return platform


def _platform_to_response(platform: CanvasPlatform) -> CanvasPlatformResponse:
    return CanvasPlatformResponse(
        id=platform.id,
        organization_id=platform.organization_id,
        canvas_account_id=platform.canvas_account_id,
        display_name=platform.display_name,
        canvas_base_url=platform.canvas_base_url,
        lti_client_id=platform.lti_client_id,
        lti_deployment_id=platform.lti_deployment_id,
        lti_issuer=platform.lti_issuer,
        lti_jwks_url=platform.lti_jwks_url,
        lti_jwks_json=platform.lti_jwks_json,
        lti_jwks_fetched_at=platform.lti_jwks_fetched_at.isoformat() if platform.lti_jwks_fetched_at else None,
        lti_jwks_expires_at=platform.lti_jwks_expires_at.isoformat() if platform.lti_jwks_expires_at else None,
        lti_openid_configuration=platform.lti_openid_configuration,
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
        evidence_requirements=binding.evidence_requirements or [],
        canvas_scope=binding.canvas_scope or {},
        delivery_mode=binding.delivery_mode,
        issuer_mode=binding.issuer_mode,
        approval_policy_set_id=binding.approval_policy_set_id,
        deployment_profile_id=binding.deployment_profile_id,
        feature_flags=normalize_canvas_feature_flags(binding.feature_flags),
        canvas_credentials=binding.canvas_credentials or {},
        enabled=binding.enabled,
        created_at=binding.created_at.isoformat(),
        updated_at=binding.updated_at.isoformat(),
    )


async def _validate_program_binding_request(
    *,
    platform: CanvasPlatform,
    request: CanvasProgramBindingCreate,
    repo: IIssuanceRepository,
    existing_binding_id: str | None = None,
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

    binding = CanvasProgramBinding()
    if existing_binding_id:
        binding.id = existing_binding_id
    binding.organization_id = platform.organization_id
    binding.platform_id = platform.id
    binding.application_template_id = request.application_template_id
    binding.credential_template_id = credential_template_id
    binding.display_name = request.display_name
    binding.flow_mode = request.flow_mode or "elevenid_orchestrated_canvas_evidence"
    binding.direct_issue_enabled = request.direct_issue_enabled
    binding.auto_approve_on_evidence = request.auto_approve_on_evidence
    binding.evidence_requirements = list(request.evidence_requirements or [])
    binding.canvas_scope = dict(request.canvas_scope or {})
    binding.delivery_mode = request.delivery_mode or "wallet_only"
    binding.issuer_mode = request.issuer_mode or "org_managed"
    binding.approval_policy_set_id = request.approval_policy_set_id or template.approval_policy_set_id
    binding.deployment_profile_id = request.deployment_profile_id
    binding.feature_flags = feature_flags
    binding.canvas_credentials = dict(request.canvas_credentials or {})
    binding.enabled = request.enabled
    return binding


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


def _lti_experience_url(state: str) -> str:
    return f"{CANVAS_LTI_EXPERIENCE_BASE_URL}/canvas/lti/experience?state={quote(state)}"


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
        raise HTTPException(status_code=409, detail=f"Canvas LTI Deep Linking private JWK is missing {field}")
    return int.from_bytes(_b64url_decode(value), "big")


def _load_deep_linking_private_jwk() -> dict[str, Any]:
    raw = os.environ.get("CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK")
    file_path = os.environ.get("CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK_FILE")
    if not raw and file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except OSError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"Canvas LTI Deep Linking private JWK file cannot be read: {exc}",
            ) from exc
    if not raw:
        raise HTTPException(
            status_code=409,
            detail="Canvas LTI Deep Linking signing key is not configured",
        )
    try:
        jwk_config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=409, detail="Canvas LTI Deep Linking private JWK is invalid JSON") from exc
    if not isinstance(jwk_config, dict):
        raise HTTPException(status_code=409, detail="Canvas LTI Deep Linking private JWK must be a JSON object")

    keys = jwk_config.get("keys")
    if isinstance(keys, list):
        requested_kid = os.environ.get("CANVAS_LTI_DEEP_LINKING_KEY_ID")
        private_keys = [key for key in keys if isinstance(key, dict) and key.get("d")]
        if requested_kid:
            private_keys = [key for key in private_keys if key.get("kid") == requested_kid]
        if not private_keys:
            raise HTTPException(status_code=409, detail="Canvas LTI Deep Linking JWKS has no matching private key")
        jwk_config = private_keys[0]
    return jwk_config


def _deep_linking_private_key_and_kid() -> tuple[Any, str | None]:
    jwk = _load_deep_linking_private_jwk()
    if jwk.get("kty") != "EC" or jwk.get("crv") not in {"P-256", "prime256v1", "secp256r1"}:
        raise HTTPException(status_code=409, detail="Canvas LTI Deep Linking private JWK must be an EC P-256 key")
    private_value = _jwk_uint(jwk, "d")
    public_numbers = ec.EllipticCurvePublicNumbers(
        _jwk_uint(jwk, "x"),
        _jwk_uint(jwk, "y"),
        ec.SECP256R1(),
    )
    private_key = ec.EllipticCurvePrivateNumbers(private_value, public_numbers).private_key()
    kid = os.environ.get("CANVAS_LTI_DEEP_LINKING_KEY_ID") or jwk.get("kid")
    return private_key, str(kid) if kid else None


def _sign_deep_linking_jwt(payload: dict[str, Any]) -> str:
    private_key, kid = _deep_linking_private_key_and_kid()
    header: dict[str, Any] = {"alg": "ES256", "typ": "JWT"}
    if kid:
        header["kid"] = kid
    signing_input = f"{_json_b64url(header)}.{_json_b64url(payload)}"
    der_signature = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input}.{_b64url_encode(raw_signature)}"


def _lti_authorization_endpoint(platform: CanvasPlatform) -> str:
    metadata = platform.lti_openid_configuration or {}
    endpoint = metadata.get("authorization_endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise HTTPException(
            status_code=409,
            detail="Canvas platform is missing LTI authorization_endpoint metadata",
        )
    return endpoint.strip()


def _validate_lti_ready_platform(platform: CanvasPlatform) -> None:
    if not platform.enabled:
        raise HTTPException(status_code=409, detail="Canvas platform is disabled")
    if not platform.lti_client_id or not platform.lti_deployment_id:
        raise HTTPException(status_code=409, detail="Canvas platform is missing LTI client or deployment configuration")
    if not platform.lti_issuer or not platform.lti_jwks_json:
        raise HTTPException(status_code=409, detail="Canvas platform has not been sandbox-probed or is missing LTI trust metadata")


def _jwks_expiry_from(now: datetime) -> datetime:
    return now + timedelta(minutes=max(1, CANVAS_LTI_JWKS_TTL_MINUTES))


def _apply_canvas_probe(platform: CanvasPlatform, probe: dict[str, Any]) -> None:
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
        probe = canvas_probe_lti_platform(platform.canvas_base_url)
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
    )


async def _resolve_lti_program_binding(
    *,
    platform: CanvasPlatform,
    verified: dict[str, Any],
    repo: IIssuanceRepository,
) -> tuple[CanvasPlatform | None, CanvasProgramBinding | None]:
    return await resolve_canvas_program_binding_for_scope(
        repo=repo,
        organization_id=platform.organization_id,
        canvas_account_id=platform.canvas_account_id,
        actual_scope=lti_verified_launch_to_canvas_scope(
            verified,
            canvas_account_id=platform.canvas_account_id,
        ),
    )


def _require_canvas_feature(binding: CanvasProgramBinding | None, flag: str, detail: str) -> None:
    if binding is not None and not canvas_feature_enabled(binding, flag):
        raise HTTPException(status_code=409, detail=detail)


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
        "state": launch_state.state,
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
    launch_state = await repo.get_canvas_lti_launch_state(state)
    if launch_state is None:
        raise HTTPException(status_code=404, detail="Canvas LTI experience session not found")
    verified_launch = launch_state.metadata.get("verified_launch") if launch_state.metadata else None
    mip_primitives = launch_state.metadata.get("mip_primitives") if launch_state.metadata else None
    if launch_state.status != "consumed" or not isinstance(verified_launch, dict) or not isinstance(mip_primitives, dict):
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


def _lti_applicant_identifier(
    *,
    verified_launch: dict[str, Any],
    request: CanvasLtiApplicationBootstrapRequest,
) -> str:
    learner = _lti_learner_identity(verified_launch)
    raw_claims = _lti_raw_claims(verified_launch)
    for value in (
        request.applicant_identifier,
        request.applicant_data.get("email"),
        learner.get("email"),
        raw_claims.get("email"),
        _lti_subject(verified_launch),
    ):
        if value is not None and str(value).strip():
            return str(value).strip()
    return f"canvas_lti_{uuid.uuid4().hex[:8]}"


def _lti_application_form_data(
    *,
    verified_launch: dict[str, Any],
    request: CanvasLtiApplicationBootstrapRequest,
) -> dict[str, Any]:
    learner = _lti_learner_identity(verified_launch)
    raw_claims = _lti_raw_claims(verified_launch)
    canvas_context = _lti_canvas_context(verified_launch)
    form_data = {
        "email": learner.get("email") or raw_claims.get("email"),
        "given_name": learner.get("given_name") or raw_claims.get("given_name"),
        "family_name": learner.get("family_name") or raw_claims.get("family_name"),
        "name": learner.get("name") or raw_claims.get("name"),
        "canvas_subject": _lti_subject(verified_launch),
        "canvas_course_id": canvas_context.get("id") or canvas_context.get("context_id"),
        "canvas_course_name": canvas_context.get("title") or canvas_context.get("label"),
    }
    return {
        key: value
        for key, value in {
            **form_data,
            **(request.applicant_data or {}),
        }.items()
        if value is not None
    }


def _lti_application_canvas_context(
    *,
    session_values: dict[str, Any],
    verified_launch: dict[str, Any],
) -> dict[str, Any]:
    canvas_context = _lti_canvas_context(verified_launch)
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
        "canvas_course_id": canvas_context.get("id") or canvas_context.get("context_id"),
        "canvas_context": canvas_context,
        "canvas_user_id": _lti_subject(verified_launch),
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


def _deep_linking_resource_title(
    request: CanvasLtiDeepLinkingRequest,
    session_values: dict[str, Any],
    verified_launch: dict[str, Any],
) -> str:
    canvas_context = _lti_canvas_context(verified_launch)
    for value in (
        request.title,
        canvas_context.get("title"),
        canvas_context.get("label"),
        session_values.get("credential_template_id"),
        session_values.get("application_template_id"),
    ):
        if value is not None and str(value).strip():
            return str(value).strip()
    return "ElevenID Credential Application"


def _deep_linking_custom_values(
    request: CanvasLtiDeepLinkingRequest,
    session_values: dict[str, Any],
    verified_launch: dict[str, Any],
) -> dict[str, str]:
    canvas_context = _lti_canvas_context(verified_launch)
    defaults = {
        "canvas_lti_state": session_values["state"],
        "canvas_account_id": session_values["canvas_account_id"],
        "canvas_platform_id": session_values.get("canvas_platform_id"),
        "canvas_program_binding_id": session_values.get("canvas_program_binding_id"),
        "application_template_id": session_values.get("application_template_id"),
        "credential_template_id": session_values.get("credential_template_id"),
        "canvas_course_id": canvas_context.get("id") or canvas_context.get("context_id"),
    }
    values = {
        **defaults,
        **(request.custom or {}),
    }
    return {
        str(key): str(value)
        for key, value in values.items()
        if key is not None and value is not None and str(key).strip() and str(value).strip()
    }


def _build_deep_linking_content_item(
    *,
    platform: CanvasPlatform,
    request: CanvasLtiDeepLinkingRequest,
    session_values: dict[str, Any],
    verified_launch: dict[str, Any],
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "type": "ltiResourceLink",
        "title": _deep_linking_resource_title(request, session_values, verified_launch),
        "url": _lti_experience_redirect_uri(platform.id),
        "custom": _deep_linking_custom_values(request, session_values, verified_launch),
    }
    if request.text is not None and str(request.text).strip():
        item["text"] = str(request.text).strip()
    if request.line_item:
        item["lineItem"] = request.line_item
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
    return str(canvas.get("canvas_user_id") or "") == str(subject)


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
        if isinstance(canvas, dict) and canvas.get("lti_state") == launch_state.state:
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
            if launch_state.state not in lti_states:
                lti_states.append(launch_state.state)
            app.integration_context = {
                **(app.integration_context or {}),
                "canvas": {
                    **canvas,
                    "last_lti_state": launch_state.state,
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
                "state": launch_state.state,
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

    platform, binding = await _resolve_lti_program_binding(
        platform=platform,
        verified=verified,
        repo=repo,
    )
    if binding is None:
        raise HTTPException(status_code=409, detail="Canvas LTI launch did not match an enabled Canvas program binding")
    _require_canvas_feature(binding, "enable_canvas_lti", "Canvas LTI is disabled for this deployment profile")
    response = _lti_launch_response(
        platform=platform,
        binding=binding,
        state=state,
        verified=verified,
    )
    return platform, consumed_state, response


@canvas_integration_router.post(
    "/platforms",
    response_model=CanvasPlatformResponse,
    summary="Create Canvas platform",
    dependencies=[Depends(_verify_management_api_key)],
)
async def create_canvas_platform(
    request: CanvasPlatformCreate,
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformResponse:
    existing = await repo.get_canvas_platform_by_account_id(request.organization_id, request.canvas_account_id)
    if existing is not None:
        raise HTTPException(status_code=409, detail="Canvas platform already exists for this organization and account")
    platform = _platform_from_request(request)
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
    repo: IIssuanceRepository = Depends(),
) -> list[CanvasPlatformResponse]:
    platforms = await repo.list_canvas_platforms(organization_id)
    return [_platform_to_response(platform) for platform in platforms]


@canvas_integration_router.get(
    "/platforms/{platform_id}",
    response_model=CanvasPlatformResponse,
    summary="Get Canvas platform",
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_canvas_platform(
    platform_id: str,
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformResponse:
    platform = await repo.get_canvas_platform(platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
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
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformResponse:
    platform = await repo.get_canvas_platform(platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
    existing = await repo.get_canvas_platform_by_account_id(request.organization_id, request.canvas_account_id)
    if existing is not None and existing.id != platform_id:
        raise HTTPException(status_code=409, detail="Canvas platform already exists for this organization and account")
    platform = _platform_from_request(request, existing=platform)
    await repo.save_canvas_platform(platform)
    return _platform_to_response(platform)


@canvas_integration_router.delete(
    "/platforms/{platform_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Canvas platform",
    dependencies=[Depends(_verify_management_api_key)],
)
async def delete_canvas_platform(
    platform_id: str,
    repo: IIssuanceRepository = Depends(),
) -> Response:
    platform = await repo.get_canvas_platform(platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
    await repo.delete_canvas_platform(platform_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@canvas_integration_router.post(
    "/platforms/{platform_id}/sandbox-probe",
    response_model=CanvasPlatformSandboxProbeResponse,
    summary="Probe Canvas platform sandbox metadata",
    dependencies=[Depends(_verify_management_api_key)],
)
async def probe_canvas_platform_sandbox(
    platform_id: str,
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformSandboxProbeResponse:
    platform = await repo.get_canvas_platform(platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
    if not platform.canvas_base_url:
        raise HTTPException(status_code=400, detail="Canvas platform requires canvas_base_url before probing")

    try:
        probe = canvas_probe_lti_platform(platform.canvas_base_url)
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
    repo: IIssuanceRepository = Depends(),
) -> CanvasPlatformJwksRefreshResponse:
    platform = await repo.get_canvas_platform(platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")

    platform, probe = await _refresh_canvas_platform_jwks(platform, repo)
    return CanvasPlatformJwksRefreshResponse(
        platform=_platform_to_response(platform),
        probe=probe,
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
    repo: IIssuanceRepository = Depends(),
) -> CanvasProgramBindingResponse:
    platform = await repo.get_canvas_platform(platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
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
    repo: IIssuanceRepository = Depends(),
) -> list[CanvasProgramBindingResponse]:
    platform_filter = platform_id if isinstance(platform_id, str) else None
    template_filter = application_template_id if isinstance(application_template_id, str) else None
    bindings = await repo.list_canvas_program_bindings(
        organization_id,
        platform_id=platform_filter,
        application_template_id=template_filter,
    )
    responses: list[CanvasProgramBindingResponse] = []
    for binding in bindings:
        platform = await repo.get_canvas_platform(binding.platform_id)
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
    repo: IIssuanceRepository = Depends(),
) -> CanvasProgramBindingResponse:
    binding = await repo.get_canvas_program_binding(binding_id)
    if binding is None:
        raise HTTPException(status_code=404, detail="Canvas program binding not found")
    platform = await repo.get_canvas_platform(binding.platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
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
    repo: IIssuanceRepository = Depends(),
) -> CanvasProgramBindingResponse:
    existing = await repo.get_canvas_program_binding(binding_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Canvas program binding not found")
    platform = await repo.get_canvas_platform(existing.platform_id)
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")
    binding = await _validate_program_binding_request(
        platform=platform,
        request=request,
        repo=repo,
        existing_binding_id=binding_id,
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
    repo: IIssuanceRepository = Depends(),
) -> Response:
    binding = await repo.get_canvas_program_binding(binding_id)
    if binding is None:
        raise HTTPException(status_code=404, detail="Canvas program binding not found")
    await repo.delete_canvas_program_binding(binding_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@canvas_integration_router.post(
    "/evidence-events",
    response_model=CanvasEvidenceEventResponse,
    summary="Process Canvas evidence event",
)
async def process_canvas_evidence_event_route(
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> CanvasEvidenceEventResponse:
    """Validate signed Canvas evidence and attach it to an ElevenID application."""

    raw_body = await request.body()
    return await process_canvas_evidence_event(
        raw_body=raw_body,
        headers=request.headers,
        repo=repo,
        issuer_context_applier=apply_remote_issuer_context,
    )


@canvas_integration_router.post(
    "/ags/score-events",
    response_model=CanvasEvidenceEventResponse,
    summary="Process Canvas AGS score as MIP evidence",
)
async def process_canvas_ags_score_event_route(
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> CanvasEvidenceEventResponse:
    """Validate a signed Canvas AGS score payload and emit normalized evidence facts."""

    raw_body = await request.body()
    return await process_canvas_ags_score_event(
        raw_body=raw_body,
        headers=request.headers,
        repo=repo,
        issuer_context_applier=apply_remote_issuer_context,
    )


@canvas_integration_router.post(
    "/nrps/membership-events",
    response_model=CanvasEvidenceEventResponse,
    summary="Process Canvas NRPS membership as MIP evidence",
)
async def process_canvas_nrps_membership_event_route(
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> CanvasEvidenceEventResponse:
    """Validate a signed Canvas NRPS membership payload and emit normalized evidence facts."""

    raw_body = await request.body()
    return await process_canvas_nrps_membership_event(
        raw_body=raw_body,
        headers=request.headers,
        repo=repo,
        issuer_context_applier=apply_remote_issuer_context,
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
    repo: IIssuanceRepository = Depends(),
) -> CanvasEvidenceEventStatusResponse:
    """Read the replay-safe receipt and recorded response for a Canvas evidence event."""

    receipt = await repo.get_canvas_event_receipt(provider_event_id, canvas_account_id)
    if receipt is None:
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
    response_model=CanvasLtiLaunchResponse,
    summary="Verify Canvas LTI launch",
)
async def verify_canvas_lti_launch_route(
    platform_id: str,
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiLaunchResponse:
    _connector, _consumed_state, response = await _verify_canvas_lti_launch_submission(
        platform_id=platform_id,
        request=request,
        repo=repo,
    )
    return response


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
    launch_url = _lti_experience_url(consumed_state.state)
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
    consumed_state.metadata = {
        **(consumed_state.metadata or {}),
        "verified_launch": verified_response.model_dump(),
        "mip_primitives": mip_primitives,
        "launch_url": launch_url,
    }
    await repo.save_canvas_lti_launch_state(consumed_state)
    return RedirectResponse(launch_url, status_code=status.HTTP_303_SEE_OTHER)


@canvas_integration_router.get(
    "/lti/experience-sessions/{state}",
    response_model=CanvasLtiExperienceSessionResponse,
    summary="Get verified Canvas-launched ElevenID experience context",
)
async def get_canvas_lti_experience_session_route(
    state: str,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiExperienceSessionResponse:
    launch_state, verified_launch, mip_primitives, session_values = await _load_verified_lti_experience_session(
        state=state,
        repo=repo,
    )
    return CanvasLtiExperienceSessionResponse(
        state=session_values["state"],
        organization_id=session_values["organization_id"],
        canvas_account_id=session_values["canvas_account_id"],
        canvas_platform_id=session_values["canvas_platform_id"],
        canvas_program_binding_id=session_values.get("canvas_program_binding_id"),
        application_template_id=session_values.get("application_template_id"),
        credential_template_id=session_values.get("credential_template_id"),
        application_id=session_values.get("application_id"),
        status=launch_state.status,
        launch_url=session_values.get("launch_url"),
        verified_launch=verified_launch,
        mip_primitives=mip_primitives,
        lti_capabilities=session_values.get("lti_capabilities") or {},
    )


@canvas_integration_router.post(
    "/lti/experience-sessions/{state}/bootstrap",
    response_model=CanvasLtiApplicationBootstrapResponse,
    summary="Bootstrap or resume an issuance application from Canvas LTI context",
)
async def bootstrap_canvas_lti_experience_application_route(
    state: str,
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
    canvas_context = _lti_application_canvas_context(
        session_values={
            **session_values,
            "application_id": app.id,
        },
        verified_launch=verified_launch,
    )
    return CanvasLtiApplicationBootstrapResponse(
        state=launch_state.state,
        application_id=app.id,
        application_status=app.status.value,
        created=created,
        organization_id=app.organization_id,
        application_template_id=app.application_template_id,
        credential_template_id=session_values.get("credential_template_id"),
        canvas_account_id=launch_state.canvas_account_id,
        canvas_platform_id=session_values.get("canvas_platform_id"),
        canvas_program_binding_id=session_values.get("canvas_program_binding_id"),
        subject=_lti_subject(verified_launch),
        canvas_context=canvas_context,
    )


@canvas_integration_router.post(
    "/lti/experience-sessions/{state}/deep-linking-response",
    response_model=CanvasLtiDeepLinkingResponse,
    summary="Create a signed Canvas LTI Deep Linking response",
)
async def create_canvas_lti_deep_linking_response_route(
    state: str,
    request: CanvasLtiDeepLinkingRequest,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiDeepLinkingResponse:
    launch_state, verified_launch, _mip_primitives, session_values = await _load_verified_lti_experience_session(
        state=state,
        repo=repo,
    )
    await _require_lti_session_canvas_feature(
        repo=repo,
        session_values=session_values,
        flag="enable_canvas_deep_linking",
        detail="Canvas Deep Linking is disabled for this deployment profile",
    )
    platform = await repo.get_canvas_platform(session_values["canvas_platform_id"])
    if platform is None:
        raise HTTPException(status_code=404, detail="Canvas platform not found")

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

    content_items = [
        _build_deep_linking_content_item(
            platform=platform,
            request=request,
            session_values=session_values,
            verified_launch=verified_launch,
        )
    ]
    jwt = _sign_deep_linking_jwt(
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
        state=launch_state.state,
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
