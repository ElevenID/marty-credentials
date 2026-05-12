"""Canvas integration routes for issuance."""

from __future__ import annotations

import os
from typing import Any
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from starlette.responses import RedirectResponse

from issuance.application.mip_integration_primitives import (
    canvas_connector_to_mip_binding,
    canvas_evidence_flow_to_mip_plan,
    canvas_lti_launch_to_mip_experience,
)
from issuance.application.rust_integration import (
    canvas_normalize_base_url,
    canvas_probe_lti_platform,
    verify_canvas_lti_launch,
)
from issuance.domain.entities import CanvasConnectorConfig, CanvasLtiLaunchState
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.canvas_credentials_adapter import (
    CanvasCredentialEventResponse,
    CanvasEvidenceEventResponse,
    process_canvas_credential_event,
    process_canvas_evidence_event,
)
from issuance.infrastructure.api.routes import _verify_management_api_key, initiate_issuance


canvas_integration_router = APIRouter(prefix="/v1/integrations/canvas", tags=["canvas-integrations"])
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "http://localhost:8000").rstrip("/")
CANVAS_LTI_EXPERIENCE_BASE_URL = (
    os.environ.get("CANVAS_LTI_EXPERIENCE_BASE_URL")
    or os.environ.get("UI_BASE_URL")
    or ISSUER_BASE_URL
).rstrip("/")
CANVAS_LTI_JWKS_TTL_MINUTES = int(os.environ.get("CANVAS_LTI_JWKS_TTL_MINUTES", "1440"))


class CanvasConnectorCreate(BaseModel):
    organization_id: str
    canvas_account_id: str
    credential_template_id: str
    application_template_id: str | None = None
    flow_mode: str = "elevenid_orchestrated_canvas_evidence"
    direct_issue_enabled: bool = False
    auto_approve_on_evidence: bool = False
    evidence_requirements: list[str] = Field(default_factory=lambda: ["canvas.course_completion"])
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


class CanvasConnectorResponse(BaseModel):
    id: str
    organization_id: str
    canvas_account_id: str
    credential_template_id: str
    application_template_id: str | None = None
    flow_mode: str
    direct_issue_enabled: bool
    auto_approve_on_evidence: bool
    evidence_requirements: list[str]
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
    mip_primitives: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class CanvasSandboxProbeResponse(BaseModel):
    connector: CanvasConnectorResponse
    probe: dict[str, Any]


class CanvasJwksRefreshResponse(BaseModel):
    connector: CanvasConnectorResponse
    refreshed: bool = True
    probe: dict[str, Any]


class CanvasEvidenceFlowRequest(BaseModel):
    application_id: str | None = None
    application_template_id: str | None = None
    canvas_course_id: str | None = None
    canvas_user_id: str | None = None
    evidence_requirements: list[str] | None = None
    auto_issue_on_completion: bool = False


class CanvasEvidenceFlowResponse(BaseModel):
    connector: CanvasConnectorResponse
    flow: dict[str, Any]


class CanvasLtiLaunchResponse(BaseModel):
    connector_id: str
    organization_id: str
    canvas_account_id: str
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


class CanvasLtiExperienceSessionResponse(BaseModel):
    state: str
    connector_id: str
    organization_id: str
    canvas_account_id: str
    status: str
    launch_url: str | None = None
    verified_launch: dict[str, Any]
    mip_primitives: dict[str, Any]


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


def _connector_from_request(request: CanvasConnectorCreate, existing: CanvasConnectorConfig | None = None) -> CanvasConnectorConfig:
    connector = existing or CanvasConnectorConfig()
    now = datetime.now(timezone.utc)
    connector.organization_id = request.organization_id
    connector.canvas_account_id = request.canvas_account_id
    connector.credential_template_id = request.credential_template_id
    connector.application_template_id = request.application_template_id
    connector.flow_mode = request.flow_mode or "elevenid_orchestrated_canvas_evidence"
    connector.direct_issue_enabled = request.direct_issue_enabled
    connector.auto_approve_on_evidence = request.auto_approve_on_evidence
    connector.evidence_requirements = list(request.evidence_requirements or [])
    connector.display_name = request.display_name
    connector.canvas_base_url = _normalize_canvas_base_url_or_none(request.canvas_base_url)
    connector.lti_client_id = request.lti_client_id
    connector.lti_deployment_id = request.lti_deployment_id
    connector.lti_issuer = request.lti_issuer
    connector.lti_jwks_url = request.lti_jwks_url
    connector.lti_jwks_json = request.lti_jwks_json
    connector.lti_jwks_fetched_at = request.lti_jwks_fetched_at
    connector.lti_jwks_expires_at = request.lti_jwks_expires_at
    if connector.lti_jwks_json and connector.lti_jwks_fetched_at is None:
        connector.lti_jwks_fetched_at = now
        connector.lti_jwks_expires_at = _jwks_expiry_from(now)
    connector.lti_openid_configuration = request.lti_openid_configuration
    connector.enabled = request.enabled
    connector.updated_at = now
    return connector


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


def _lti_launch_redirect_uri(connector_id: str) -> str:
    return f"{ISSUER_BASE_URL}/v1/integrations/canvas/lti/launch/{connector_id}"


def _lti_experience_redirect_uri(connector_id: str) -> str:
    return f"{ISSUER_BASE_URL}/v1/integrations/canvas/lti/experience/{connector_id}"


def _lti_experience_url(state: str) -> str:
    return f"{CANVAS_LTI_EXPERIENCE_BASE_URL}/canvas/lti/experience?state={quote(state)}"


def _lti_authorization_endpoint(connector: CanvasConnectorConfig) -> str:
    metadata = connector.lti_openid_configuration or {}
    endpoint = metadata.get("authorization_endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise HTTPException(
            status_code=409,
            detail="Canvas connector is missing LTI authorization_endpoint metadata",
        )
    return endpoint.strip()


def _validate_lti_ready_connector(connector: CanvasConnectorConfig) -> None:
    if not connector.enabled:
        raise HTTPException(status_code=409, detail="Canvas connector is disabled")
    if not connector.lti_client_id or not connector.lti_deployment_id:
        raise HTTPException(status_code=409, detail="Canvas connector is missing LTI client or deployment configuration")
    if not connector.lti_issuer or not connector.lti_jwks_json:
        raise HTTPException(status_code=409, detail="Canvas connector has not been sandbox-probed or is missing LTI trust metadata")


def _jwks_expiry_from(now: datetime) -> datetime:
    return now + timedelta(minutes=max(1, CANVAS_LTI_JWKS_TTL_MINUTES))


def _apply_canvas_probe(connector: CanvasConnectorConfig, probe: dict[str, Any]) -> None:
    now = datetime.now(timezone.utc)
    connector.canvas_base_url = probe.get("canvas_base_url") or connector.canvas_base_url
    connector.lti_issuer = probe.get("issuer") or connector.lti_issuer
    connector.lti_jwks_url = probe.get("jwks_uri") or connector.lti_jwks_url
    if probe.get("jwks_json"):
        connector.lti_jwks_json = probe.get("jwks_json")
        connector.lti_jwks_fetched_at = now
        connector.lti_jwks_expires_at = _jwks_expiry_from(now)
    connector.lti_openid_configuration = (
        probe.get("raw_openid_configuration") or connector.lti_openid_configuration
    )
    connector.updated_at = now


async def _refresh_canvas_connector_jwks(
    connector: CanvasConnectorConfig,
    repo: IIssuanceRepository,
) -> tuple[CanvasConnectorConfig, dict[str, Any]]:
    if not connector.canvas_base_url:
        raise HTTPException(status_code=400, detail="Canvas connector requires canvas_base_url before refreshing JWKS")
    try:
        probe = canvas_probe_lti_platform(connector.canvas_base_url)
    except Exception as exc:  # pragma: no cover - exact binding exception type varies
        raise HTTPException(status_code=400, detail=f"Canvas JWKS refresh failed: {exc}") from exc
    _apply_canvas_probe(connector, probe)
    await repo.save_canvas_connector(connector)
    return connector, probe


def _is_lti_kid_miss(exc: Exception) -> bool:
    return "No JWKS entry found for LTI kid" in str(exc)


def _verify_lti_launch_with_connector(
    *,
    connector: CanvasConnectorConfig,
    id_token: str,
    expected_nonce: str,
) -> dict[str, Any]:
    return verify_canvas_lti_launch(
        id_token=id_token,
        expected_issuer=connector.lti_issuer,
        expected_client_id=connector.lti_client_id,
        expected_deployment_id=connector.lti_deployment_id,
        jwks_json=connector.lti_jwks_json,
        expected_nonce=expected_nonce,
    )


def _connector_to_response(connector: CanvasConnectorConfig) -> CanvasConnectorResponse:
    return CanvasConnectorResponse(
        id=connector.id,
        organization_id=connector.organization_id,
        canvas_account_id=connector.canvas_account_id,
        credential_template_id=connector.credential_template_id,
        application_template_id=connector.application_template_id,
        flow_mode=connector.flow_mode,
        direct_issue_enabled=connector.direct_issue_enabled,
        auto_approve_on_evidence=connector.auto_approve_on_evidence,
        evidence_requirements=connector.evidence_requirements or [],
        display_name=connector.display_name,
        canvas_base_url=connector.canvas_base_url,
        lti_client_id=connector.lti_client_id,
        lti_deployment_id=connector.lti_deployment_id,
        lti_issuer=connector.lti_issuer,
        lti_jwks_url=connector.lti_jwks_url,
        lti_jwks_json=connector.lti_jwks_json,
        lti_jwks_fetched_at=connector.lti_jwks_fetched_at.isoformat() if connector.lti_jwks_fetched_at else None,
        lti_jwks_expires_at=connector.lti_jwks_expires_at.isoformat() if connector.lti_jwks_expires_at else None,
        lti_openid_configuration=connector.lti_openid_configuration,
        enabled=connector.enabled,
        mip_primitives=canvas_connector_to_mip_binding(connector).to_dict(),
        created_at=connector.created_at.isoformat(),
        updated_at=connector.updated_at.isoformat(),
    )


def _lti_launch_response(
    *,
    connector: CanvasConnectorConfig,
    state: str,
    verified: dict[str, Any],
) -> CanvasLtiLaunchResponse:
    context = verified.get("context")
    return CanvasLtiLaunchResponse(
        connector_id=connector.id,
        organization_id=connector.organization_id,
        canvas_account_id=connector.canvas_account_id,
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
    )


async def _initiate_canvas_lti_login(
    *,
    connector_id: str,
    request: Request,
    repo: IIssuanceRepository,
    redirect_uri: str,
) -> RedirectResponse:
    connector = await repo.get_canvas_connector(connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Canvas connector not found")
    _validate_lti_ready_connector(connector)

    submission = await _parse_lti_login_submission(request)
    if submission["issuer"] and submission["issuer"] != connector.lti_issuer:
        raise HTTPException(status_code=400, detail="Canvas LTI issuer does not match connector")
    if submission["client_id"] and submission["client_id"] != connector.lti_client_id:
        raise HTTPException(status_code=400, detail="Canvas LTI client_id does not match connector")

    launch_state = CanvasLtiLaunchState(
        connector_id=connector.id,
        organization_id=connector.organization_id,
        canvas_account_id=connector.canvas_account_id,
        login_hint=submission["login_hint"],
        target_link_uri=submission["target_link_uri"],
        lti_message_hint=submission["lti_message_hint"],
        redirect_uri=redirect_uri,
        metadata={
            "issuer": submission["issuer"],
            "client_id": submission["client_id"],
            "experience_mode": redirect_uri.endswith(f"/lti/experience/{connector.id}"),
        },
    )
    await repo.save_canvas_lti_launch_state(launch_state)

    params = {
        "scope": "openid",
        "response_type": "id_token",
        "response_mode": "form_post",
        "prompt": "none",
        "client_id": connector.lti_client_id,
        "redirect_uri": redirect_uri,
        "login_hint": launch_state.login_hint,
        "state": launch_state.state,
        "nonce": launch_state.nonce,
    }
    if launch_state.lti_message_hint:
        params["lti_message_hint"] = launch_state.lti_message_hint

    authorization_endpoint = _lti_authorization_endpoint(connector)
    separator = "&" if "?" in authorization_endpoint else "?"
    return RedirectResponse(
        f"{authorization_endpoint}{separator}{urlencode(params)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


async def _verify_canvas_lti_launch_submission(
    *,
    connector_id: str,
    request: Request,
    repo: IIssuanceRepository,
) -> tuple[CanvasConnectorConfig, CanvasLtiLaunchState, CanvasLtiLaunchResponse]:
    connector = await repo.get_canvas_connector(connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Canvas connector not found")
    _validate_lti_ready_connector(connector)

    id_token, state = await _parse_lti_launch_submission(request)
    launch_state = await repo.get_canvas_lti_launch_state(state)
    if launch_state is None or launch_state.connector_id != connector.id:
        raise HTTPException(status_code=400, detail="Canvas LTI state is unknown for this connector")
    if launch_state.status != "pending" or launch_state.is_expired:
        raise HTTPException(status_code=400, detail="Canvas LTI state has expired or already been used")

    consumed_state = await repo.consume_canvas_lti_launch_state(state)
    if consumed_state is None:
        raise HTTPException(status_code=400, detail="Canvas LTI state has expired or already been used")

    try:
        verified = _verify_lti_launch_with_connector(
            connector=connector,
            id_token=id_token,
            expected_nonce=consumed_state.nonce,
        )
    except Exception as exc:  # pragma: no cover - exact binding exception type varies
        if not (_is_lti_kid_miss(exc) and connector.canvas_base_url):
            raise HTTPException(status_code=400, detail=f"Canvas LTI launch verification failed: {exc}") from exc
        try:
            connector, _probe = await _refresh_canvas_connector_jwks(connector, repo)
            verified = _verify_lti_launch_with_connector(
                connector=connector,
                id_token=id_token,
                expected_nonce=consumed_state.nonce,
            )
        except Exception as refresh_exc:  # pragma: no cover - exact binding exception type varies
            raise HTTPException(
                status_code=400,
                detail=f"Canvas LTI launch verification failed after JWKS refresh: {refresh_exc}",
            ) from refresh_exc

    response = _lti_launch_response(connector=connector, state=state, verified=verified)
    return connector, consumed_state, response


@canvas_integration_router.post(
    "/connectors",
    response_model=CanvasConnectorResponse,
    summary="Create Canvas connector",
    dependencies=[Depends(_verify_management_api_key)],
)
async def create_canvas_connector(
    request: CanvasConnectorCreate,
    repo: IIssuanceRepository = Depends(),
) -> CanvasConnectorResponse:
    connector = _connector_from_request(request)
    await repo.save_canvas_connector(connector)
    return _connector_to_response(connector)


@canvas_integration_router.get(
    "/connectors",
    response_model=list[CanvasConnectorResponse],
    summary="List Canvas connectors",
    dependencies=[Depends(_verify_management_api_key)],
)
async def list_canvas_connectors(
    organization_id: str = Query(...),
    repo: IIssuanceRepository = Depends(),
) -> list[CanvasConnectorResponse]:
    connectors = await repo.list_canvas_connectors(organization_id)
    return [_connector_to_response(connector) for connector in connectors]


@canvas_integration_router.get(
    "/connectors/{connector_id}",
    response_model=CanvasConnectorResponse,
    summary="Get Canvas connector",
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_canvas_connector(
    connector_id: str,
    repo: IIssuanceRepository = Depends(),
) -> CanvasConnectorResponse:
    connector = await repo.get_canvas_connector(connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Canvas connector not found")
    return _connector_to_response(connector)


@canvas_integration_router.put(
    "/connectors/{connector_id}",
    response_model=CanvasConnectorResponse,
    summary="Update Canvas connector",
    dependencies=[Depends(_verify_management_api_key)],
)
async def update_canvas_connector(
    connector_id: str,
    request: CanvasConnectorCreate,
    repo: IIssuanceRepository = Depends(),
) -> CanvasConnectorResponse:
    connector = await repo.get_canvas_connector(connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Canvas connector not found")

    connector = _connector_from_request(request, existing=connector)
    await repo.save_canvas_connector(connector)
    return _connector_to_response(connector)


@canvas_integration_router.post(
    "/connectors/{connector_id}/sandbox-probe",
    response_model=CanvasSandboxProbeResponse,
    summary="Probe Canvas sandbox metadata",
    dependencies=[Depends(_verify_management_api_key)],
)
async def probe_canvas_connector_sandbox(
    connector_id: str,
    repo: IIssuanceRepository = Depends(),
) -> CanvasSandboxProbeResponse:
    connector = await repo.get_canvas_connector(connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Canvas connector not found")
    if not connector.canvas_base_url:
        raise HTTPException(status_code=400, detail="Canvas connector requires canvas_base_url before probing")

    try:
        probe = canvas_probe_lti_platform(connector.canvas_base_url)
    except Exception as exc:  # pragma: no cover - exact binding exception type varies
        raise HTTPException(status_code=400, detail=f"Canvas sandbox probe failed: {exc}") from exc

    _apply_canvas_probe(connector, probe)
    await repo.save_canvas_connector(connector)
    return CanvasSandboxProbeResponse(
        connector=_connector_to_response(connector),
        probe=probe,
    )


@canvas_integration_router.post(
    "/connectors/{connector_id}/jwks-refresh",
    response_model=CanvasJwksRefreshResponse,
    summary="Refresh Canvas connector JWKS metadata",
    dependencies=[Depends(_verify_management_api_key)],
)
async def refresh_canvas_connector_jwks(
    connector_id: str,
    repo: IIssuanceRepository = Depends(),
) -> CanvasJwksRefreshResponse:
    connector = await repo.get_canvas_connector(connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Canvas connector not found")

    connector, probe = await _refresh_canvas_connector_jwks(connector, repo)
    return CanvasJwksRefreshResponse(
        connector=_connector_to_response(connector),
        probe=probe,
    )


@canvas_integration_router.post(
    "/connectors/{connector_id}/evidence-flow",
    response_model=CanvasEvidenceFlowResponse,
    summary="Plan ElevenID-orchestrated Canvas evidence flow",
    dependencies=[Depends(_verify_management_api_key)],
)
async def plan_canvas_evidence_flow(
    connector_id: str,
    request: CanvasEvidenceFlowRequest,
    repo: IIssuanceRepository = Depends(),
) -> CanvasEvidenceFlowResponse:
    connector = await repo.get_canvas_connector(connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Canvas connector not found")
    if not connector.enabled:
        raise HTTPException(status_code=409, detail="Canvas connector is disabled")

    plan = canvas_evidence_flow_to_mip_plan(
        connector,
        application_id=request.application_id,
        application_template_id=request.application_template_id or connector.application_template_id,
        canvas_course_id=request.canvas_course_id,
        canvas_user_id=request.canvas_user_id,
        evidence_requirements=request.evidence_requirements or connector.evidence_requirements or ["canvas.course_completion"],
        auto_issue_on_completion=(request.auto_issue_on_completion and connector.direct_issue_enabled),
    )
    return CanvasEvidenceFlowResponse(
        connector=_connector_to_response(connector),
        flow=plan.to_dict(),
    )


@canvas_integration_router.delete(
    "/connectors/{connector_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Canvas connector",
    dependencies=[Depends(_verify_management_api_key)],
)
async def delete_canvas_connector(
    connector_id: str,
    repo: IIssuanceRepository = Depends(),
) -> Response:
    connector = await repo.get_canvas_connector(connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Canvas connector not found")
    await repo.delete_canvas_connector(connector_id)
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
    )


@canvas_integration_router.post(
    "/credential-events",
    response_model=CanvasCredentialEventResponse,
    summary="Process Canvas credential event",
)
async def process_canvas_credential_event_route(
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> CanvasCredentialEventResponse:
    """Validate and convert a signed Canvas completion event into wallet issuance."""

    raw_body = await request.body()
    return await process_canvas_credential_event(
        raw_body=raw_body,
        headers=request.headers,
        repo=repo,
        issue_credential=initiate_issuance,
        http_request=request,
    )


@canvas_integration_router.post(
    "/lti/login/{connector_id}",
    summary="Initiate Canvas LTI OIDC login",
)
async def initiate_canvas_lti_login_route(
    connector_id: str,
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> RedirectResponse:
    return await _initiate_canvas_lti_login(
        connector_id=connector_id,
        request=request,
        repo=repo,
        redirect_uri=_lti_launch_redirect_uri(connector_id),
    )


@canvas_integration_router.post(
    "/lti/experience-login/{connector_id}",
    summary="Initiate Canvas LTI login for ElevenID experience",
)
async def initiate_canvas_lti_experience_login_route(
    connector_id: str,
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> RedirectResponse:
    return await _initiate_canvas_lti_login(
        connector_id=connector_id,
        request=request,
        repo=repo,
        redirect_uri=_lti_experience_redirect_uri(connector_id),
    )


@canvas_integration_router.post(
    "/lti/launch/{connector_id}",
    response_model=CanvasLtiLaunchResponse,
    summary="Verify Canvas LTI launch",
)
async def verify_canvas_lti_launch_route(
    connector_id: str,
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> CanvasLtiLaunchResponse:
    _connector, _consumed_state, response = await _verify_canvas_lti_launch_submission(
        connector_id=connector_id,
        request=request,
        repo=repo,
    )
    return response


@canvas_integration_router.post(
    "/lti/experience/{connector_id}",
    summary="Verify Canvas LTI launch and redirect to ElevenID experience",
)
async def launch_canvas_lti_experience_route(
    connector_id: str,
    request: Request,
    repo: IIssuanceRepository = Depends(),
) -> RedirectResponse:
    connector, consumed_state, verified_response = await _verify_canvas_lti_launch_submission(
        connector_id=connector_id,
        request=request,
        repo=repo,
    )
    launch_url = _lti_experience_url(consumed_state.state)
    mip_experience = canvas_lti_launch_to_mip_experience(
        connector,
        state=consumed_state.state,
        verified_launch=verified_response.model_dump(),
        launch_url=launch_url,
    )
    consumed_state.metadata = {
        **(consumed_state.metadata or {}),
        "verified_launch": verified_response.model_dump(),
        "mip_primitives": mip_experience.to_dict(),
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
    launch_state = await repo.get_canvas_lti_launch_state(state)
    if launch_state is None:
        raise HTTPException(status_code=404, detail="Canvas LTI experience session not found")
    verified_launch = launch_state.metadata.get("verified_launch") if launch_state.metadata else None
    mip_primitives = launch_state.metadata.get("mip_primitives") if launch_state.metadata else None
    if launch_state.status != "consumed" or not isinstance(verified_launch, dict) or not isinstance(mip_primitives, dict):
        raise HTTPException(status_code=404, detail="Canvas LTI experience session not found")
    return CanvasLtiExperienceSessionResponse(
        state=launch_state.state,
        connector_id=launch_state.connector_id,
        organization_id=launch_state.organization_id,
        canvas_account_id=launch_state.canvas_account_id,
        status=launch_state.status,
        launch_url=launch_state.metadata.get("launch_url"),
        verified_launch=verified_launch,
        mip_primitives=mip_primitives,
    )
