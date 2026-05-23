"""Unit tests for Canvas sandbox hardening and LTI launch routes."""

from __future__ import annotations

import base64
import json
import os
import sys
from urllib.parse import parse_qs, urlparse
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from starlette.requests import Request

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_SERVICES = os.path.join(_REPO_ROOT, "services")

if _SERVICES not in sys.path:
    sys.path.insert(0, _SERVICES)

for _module_name in (
    "status_list",
    "status_list.infrastructure",
    "status_list.infrastructure.security",
    "status_list.infrastructure.security.encryption",
):
    sys.modules.setdefault(_module_name, MagicMock())

from issuance.domain.entities import (
    ApplicationTemplate,
    CanvasPlatform,
    CanvasProgramBinding,
    EventType,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes


def _json_request(payload: dict[str, object], path: str = "/v1/integrations/canvas/lti/launch/test") -> Request:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [(b"content-type", b"application/json")],
        },
        receive,
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    value = data.encode("ascii")
    value += b"=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value)


def _private_p256_jwk(kid: str = "tool-key-1") -> tuple[dict[str, str], object]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.private_numbers()
    public = numbers.public_numbers
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "x": _b64url(public.x.to_bytes(32, "big")),
        "y": _b64url(public.y.to_bytes(32, "big")),
        "d": _b64url(numbers.private_value.to_bytes(32, "big")),
    }
    return jwk, private_key.public_key()


def _jwt_payload(token: str) -> dict[str, object]:
    return json.loads(_b64url_decode(token.split(".")[1]))


def _verify_es256_jwt_signature(token: str, public_key: object) -> None:
    header, payload, signature = token.split(".")
    raw_signature = _b64url_decode(signature)
    der_signature = utils.encode_dss_signature(
        int.from_bytes(raw_signature[:32], "big"),
        int.from_bytes(raw_signature[32:], "big"),
    )
    public_key.verify(der_signature, f"{header}.{payload}".encode("ascii"), ec.ECDSA(hashes.SHA256()))


@pytest.mark.asyncio
async def test_create_canvas_program_binding_persists_canvas_credentials_config() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-provider-config",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
    )
    template = ApplicationTemplate(
        id="application-template-provider-config",
        organization_id="org-123",
        credential_template_id="credential-template-provider-config",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_application_template(template)

    response = await canvas_routes.create_canvas_program_binding(
        platform.id,
        request=canvas_routes.CanvasProgramBindingCreate(
            application_template_id=template.id,
            credential_template_id=template.credential_template_id,
            delivery_mode="wallet_plus_canvas_mirror",
            canvas_credentials={
                "provider": "badgr_api",
                "api_base_url": "https://api.canvascredentials.example",
                "issuer_id": "issuer-1",
                "badgeclass_id": "badgeclass-1",
                "api_token_env": "CANVAS_CREDENTIALS_TOKEN_ORG_123",
            },
        ),
        repo=repo,
    )
    stored = await repo.get_canvas_program_binding(response.id)

    assert response.canvas_credentials["provider"] == "badgr_api"
    assert response.canvas_credentials["api_token_env"] == "CANVAS_CREDENTIALS_TOKEN_ORG_123"
    assert stored is not None
    assert stored.canvas_credentials == response.canvas_credentials


@pytest.mark.asyncio
async def test_probe_canvas_platform_sandbox_persists_rust_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
    )
    await repo.save_canvas_platform(platform)

    monkeypatch.setattr(
        canvas_routes,
        "canvas_probe_lti_platform",
        lambda base_url: {
            "canvas_base_url": base_url,
            "issuer": "https://canvas.example.edu",
            "jwks_uri": "https://canvas.example.edu/jwks",
            "jwks_json": {"keys": [{"kid": "canvas-kid"}]},
            "raw_openid_configuration": {
                "issuer": "https://canvas.example.edu",
                "jwks_uri": "https://canvas.example.edu/jwks",
            },
        },
    )

    response = await canvas_routes.probe_canvas_platform_sandbox(platform.id, repo=repo)
    stored = await repo.get_canvas_platform(platform.id)

    assert response.platform.id == platform.id
    assert response.probe["issuer"] == "https://canvas.example.edu"
    assert stored is not None
    assert stored.lti_issuer == "https://canvas.example.edu"
    assert stored.lti_jwks_url == "https://canvas.example.edu/jwks"
    assert stored.lti_jwks_json == {"keys": [{"kid": "canvas-kid"}]}
    assert stored.lti_jwks_fetched_at is not None
    assert stored.lti_jwks_expires_at is not None
    assert stored.lti_jwks_expires_at > stored.lti_jwks_fetched_at


@pytest.mark.asyncio
async def test_verify_canvas_lti_launch_route_returns_identity_context(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-identity",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
            "scopes_supported": [
                "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
                "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
            ],
            "claims_supported": [
                canvas_routes.LTI_AGS_ENDPOINT_CLAIM,
                canvas_routes.LTI_NRPS_CLAIM,
            ],
        },
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-identity",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id="application-template-identity",
        credential_template_id="credential-template-identity",
        evidence_requirements=["canvas.course_completion"],
        canvas_scope={"course_id": "course-101"},
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)

    login_response = await canvas_routes.initiate_canvas_lti_login_route(
        platform.id,
        request=_json_request(
            {
                "iss": "https://canvas.example.edu",
                "login_hint": "login-hint-123",
                "target_link_uri": "https://tool.example.edu/launch",
                "lti_message_hint": "message-hint-123",
                "client_id": "client-123",
            },
            path="/v1/integrations/canvas/lti/login/test",
        ),
        repo=repo,
    )
    location = login_response.headers["location"]
    params = parse_qs(urlparse(location).query)
    state = params["state"][0]
    nonce = params["nonce"][0]

    monkeypatch.setattr(
        canvas_routes,
        "verify_canvas_lti_launch",
        lambda **kwargs: {
            "issuer": kwargs["expected_issuer"],
            "subject": "student-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "issued_at": 1700000000,
            "expires_at": 1700000300,
            "message_type": "LtiResourceLinkRequest",
            "lti_version": "1.3.0",
            "target_link_uri": "https://tool.example.edu/launch",
            "context": {"id": "course-101", "label": "PORTABLE101"},
            "roles": ["Learner"],
            "learner_identity": {"subject": "student-123", "issuer": kwargs["expected_issuer"]},
            "raw_claims": {
                "sub": "student-123",
                canvas_routes.LTI_DEEP_LINKING_SETTINGS_CLAIM: {
                    "deep_link_return_url": "https://canvas.example.edu/deep-link-return",
                    "accept_types": ["ltiResourceLink"],
                },
                canvas_routes.LTI_AGS_ENDPOINT_CLAIM: {
                    "lineitems": "https://canvas.example.edu/api/lti/courses/101/line_items",
                    "scope": ["https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"],
                },
                canvas_routes.LTI_NRPS_CLAIM: {
                    "context_memberships_url": "https://canvas.example.edu/api/lti/courses/101/names_and_roles",
                },
            },
        },
    )

    response = await canvas_routes.verify_canvas_lti_launch_route(
        platform.id,
        request=_json_request(
            {
                "id_token": "header.payload.signature",
                "state": state,
            }
        ),
        repo=repo,
    )

    assert response.verified is True
    assert response.canvas_platform_id == platform.id
    assert response.organization_id == "org-123"
    assert response.canvas_account_id == "canvas-acct-1"
    assert response.subject == "student-123"
    assert response.nonce == nonce
    assert response.state == state
    assert response.context == {"id": "course-101", "label": "PORTABLE101"}
    assert response.roles == ["Learner"]
    assert response.learner_identity["subject"] == "student-123"
    assert response.lti_capabilities["resource_link"] is True
    assert response.lti_capabilities["deep_linking"] is True
    assert response.lti_capabilities["assignment_grade_services"] is True
    assert response.lti_capabilities["names_roles"] is True
    assert response.lti_capabilities["binding_evidence_fact_types"] == ["canvas.course_completion"]
    assert "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem" in response.lti_capabilities["supported_scopes"]


@pytest.mark.asyncio
async def test_canvas_lti_experience_launch_redirects_and_persists_session(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-lti",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        display_name="Canvas Tenant",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-lti",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id="application-template-lti",
        credential_template_id="credential-template-lti",
        evidence_requirements=["canvas.course_completion"],
        canvas_scope={"course_id": "course-101"},
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    monkeypatch.setattr(canvas_routes, "CANVAS_LTI_EXPERIENCE_BASE_URL", "https://app.example.edu")

    login_response = await canvas_routes.initiate_canvas_lti_experience_login_route(
        platform.id,
        request=_json_request(
            {
                "iss": "https://canvas.example.edu",
                "login_hint": "login-hint-123",
                "target_link_uri": "https://tool.example.edu/launch",
                "client_id": "client-123",
            },
            path="/v1/integrations/canvas/lti/experience-login/test",
        ),
        repo=repo,
    )
    login_params = parse_qs(urlparse(login_response.headers["location"]).query)
    state = login_params["state"][0]
    nonce = login_params["nonce"][0]
    assert login_params["redirect_uri"][0].endswith(f"/v1/integrations/canvas/lti/platforms/{platform.id}/experience")

    monkeypatch.setattr(
        canvas_routes,
        "verify_canvas_lti_launch",
        lambda **kwargs: {
            "issuer": kwargs["expected_issuer"],
            "subject": "student-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "message_type": "LtiResourceLinkRequest",
            "lti_version": "1.3.0",
            "context": {"id": "course-101", "title": "Portable Trust 101"},
            "roles": ["Learner"],
            "learner_identity": {"subject": "student-123", "issuer": kwargs["expected_issuer"]},
            "raw_claims": {
                "sub": "student-123",
                canvas_routes.LTI_AGS_ENDPOINT_CLAIM: {
                    "lineitem": "https://canvas.example.edu/api/lti/courses/101/line_items/1",
                    "scope": ["https://purl.imsglobal.org/spec/lti-ags/scope/score"],
                },
            },
        },
    )

    launch_response = await canvas_routes.launch_canvas_lti_experience_route(
        platform.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )
    session = await canvas_routes.get_canvas_lti_experience_session_route(state, repo=repo)

    assert launch_response.status_code == 303
    assert launch_response.headers["location"] == f"https://app.example.edu/canvas/lti/experience?state={state}"
    assert session.state == state
    assert session.status == "consumed"
    assert session.verified_launch["nonce"] == nonce
    assert session.verified_launch["subject"] == "student-123"
    assert session.canvas_platform_id == platform.id
    assert session.canvas_program_binding_id == binding.id
    assert session.application_template_id == "application-template-lti"
    assert session.credential_template_id == "credential-template-lti"
    assert session.mip_primitives["protocol"] == "ELEVENID_EXPERIENCE"
    assert session.mip_primitives["source"]["event_type"] == "canvas.lti_launch"
    assert session.mip_primitives["context"]["canvas_program_binding_id"] == binding.id
    assert session.lti_capabilities["assignment_grade_services"] is True
    assert session.mip_primitives["context"]["lti_capabilities"]["assignment_grade_services"] is True


@pytest.mark.asyncio
async def test_canvas_lti_deep_linking_response_signs_lti_resource_link(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-deep-link",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-deep-link",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id="application-template-deep-link",
        credential_template_id="credential-template-deep-link",
        evidence_requirements=["canvas.assignment_score"],
        canvas_scope={"course_id": "course-101"},
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    jwk, public_key = _private_p256_jwk()
    monkeypatch.setenv("CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK", json.dumps(jwk))
    monkeypatch.setattr(canvas_routes, "ISSUER_BASE_URL", "https://issuer.example.com")
    monkeypatch.setattr(canvas_routes, "CANVAS_LTI_EXPERIENCE_BASE_URL", "https://app.example.edu")

    login_response = await canvas_routes.initiate_canvas_lti_experience_login_route(
        platform.id,
        request=_json_request(
            {
                "iss": "https://canvas.example.edu",
                "login_hint": "login-hint-123",
                "target_link_uri": "https://issuer.example.com/deep-link",
                "client_id": "client-123",
            },
            path="/v1/integrations/canvas/lti/experience-login/test",
        ),
        repo=repo,
    )
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    monkeypatch.setattr(
        canvas_routes,
        "verify_canvas_lti_launch",
        lambda **kwargs: {
            "issuer": kwargs["expected_issuer"],
            "subject": "instructor-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "message_type": "LtiDeepLinkingRequest",
            "lti_version": "1.3.0",
            "context": {"id": "course-101", "title": "Portable Trust 101"},
            "roles": ["Instructor"],
            "learner_identity": {"subject": "instructor-123"},
            "raw_claims": {
                "sub": "instructor-123",
                canvas_routes.LTI_DEEP_LINKING_SETTINGS_CLAIM: {
                    "deep_link_return_url": "https://canvas.example.edu/deep-link-return",
                    "accept_types": ["ltiResourceLink"],
                    "accept_presentation_document_targets": ["iframe"],
                    "data": "opaque-canvas-data",
                },
            },
        },
    )

    await canvas_routes.launch_canvas_lti_experience_route(
        platform.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )
    response = await canvas_routes.create_canvas_lti_deep_linking_response_route(
        state,
        request=canvas_routes.CanvasLtiDeepLinkingRequest(
            title="Portable Trust Credential",
            text="Apply for the credential inside ElevenID.",
            custom={"launch_kind": "credential_application"},
        ),
        repo=repo,
    )

    _verify_es256_jwt_signature(response.jwt, public_key)
    header = json.loads(_b64url_decode(response.jwt.split(".")[0]))
    payload = _jwt_payload(response.jwt)
    stored_state = await repo.get_canvas_lti_launch_state(state)

    assert header["kid"] == "tool-key-1"
    assert response.deep_link_return_url == "https://canvas.example.edu/deep-link-return"
    assert response.form_post["method"] == "POST"
    assert response.form_post["action"] == "https://canvas.example.edu/deep-link-return"
    assert response.form_post["fields"]["JWT"] == response.jwt
    assert payload["iss"] == "client-123"
    assert payload["aud"] == "https://canvas.example.edu"
    assert payload[canvas_routes.LTI_MESSAGE_TYPE_CLAIM] == "LtiDeepLinkingResponse"
    assert payload[canvas_routes.LTI_DEEP_LINKING_DATA_CLAIM] == "opaque-canvas-data"
    assert payload[canvas_routes.LTI_DEPLOYMENT_ID_CLAIM] == "deployment-xyz"
    content_item = payload[canvas_routes.LTI_DEEP_LINKING_CONTENT_ITEMS_CLAIM][0]
    assert content_item == response.content_items[0]
    assert content_item["type"] == "ltiResourceLink"
    assert content_item["url"] == f"https://issuer.example.com/v1/integrations/canvas/lti/platforms/{platform.id}/experience"
    assert content_item["title"] == "Portable Trust Credential"
    assert content_item["custom"]["canvas_lti_state"] == state
    assert content_item["custom"]["canvas_program_binding_id"] == binding.id
    assert content_item["custom"]["credential_template_id"] == "credential-template-deep-link"
    assert content_item["custom"]["launch_kind"] == "credential_application"
    assert stored_state is not None
    assert stored_state.metadata["deep_linking_response"]["content_items"][0] == content_item


@pytest.mark.asyncio
async def test_canvas_lti_bootstrap_creates_and_replays_issuance_application(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-bootstrap",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )
    template = ApplicationTemplate(
        id="application-template-bootstrap",
        organization_id="org-123",
        credential_template_id="credential-template-bootstrap",
        evidence_requirements=["canvas.course_completion"],
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-bootstrap",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id=template.id,
        credential_template_id="credential-template-bootstrap",
        evidence_requirements=["canvas.course_completion"],
        canvas_scope={"course_id": "course-101"},
    )
    await repo.save_canvas_platform(platform)
    await repo.save_application_template(template)
    await repo.save_canvas_program_binding(binding)
    monkeypatch.setattr(canvas_routes, "CANVAS_LTI_EXPERIENCE_BASE_URL", "https://app.example.edu")

    login_response = await canvas_routes.initiate_canvas_lti_experience_login_route(
        platform.id,
        request=_json_request(
            {
                "iss": "https://canvas.example.edu",
                "login_hint": "login-hint-123",
                "target_link_uri": "https://tool.example.edu/launch",
                "client_id": "client-123",
            },
            path="/v1/integrations/canvas/lti/experience-login/test",
        ),
        repo=repo,
    )
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    monkeypatch.setattr(
        canvas_routes,
        "verify_canvas_lti_launch",
        lambda **kwargs: {
            "issuer": kwargs["expected_issuer"],
            "subject": "student-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "message_type": "LtiResourceLinkRequest",
            "lti_version": "1.3.0",
            "context": {"id": "course-101", "title": "Portable Trust 101"},
            "roles": ["Learner"],
            "learner_identity": {
                "subject": "student-123",
                "email": "ada@example.com",
                "given_name": "Ada",
                "family_name": "Lovelace",
            },
            "raw_claims": {"sub": "student-123", "email": "ada@example.com"},
        },
    )

    await canvas_routes.launch_canvas_lti_experience_route(
        platform.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )

    first = await canvas_routes.bootstrap_canvas_lti_experience_application_route(
        state,
        request=canvas_routes.CanvasLtiApplicationBootstrapRequest(
            applicant_identifier="ada@example.com",
            applicant_data={"email": "ada@example.com"},
        ),
        repo=repo,
    )
    second = await canvas_routes.bootstrap_canvas_lti_experience_application_route(
        state,
        request=canvas_routes.CanvasLtiApplicationBootstrapRequest(
            applicant_identifier="ada@example.com",
            applicant_data={"email": "ada@example.com"},
        ),
        repo=repo,
    )
    app = await repo.get_application(first.application_id)
    session = await canvas_routes.get_canvas_lti_experience_session_route(state, repo=repo)
    events = await repo.list_events_for_application(first.application_id)

    assert first.created is True
    assert second.created is False
    assert second.application_id == first.application_id
    assert app is not None
    assert app.application_template_id == template.id
    assert app.form_data["email"] == "ada@example.com"
    assert app.integration_context["canvas"]["lti_state"] == state
    assert app.integration_context["canvas"]["canvas_program_binding_id"] == binding.id
    assert session.application_id == first.application_id
    assert session.mip_primitives["context"]["application_id"] == first.application_id
    assert [event.event_type for event in events] == [EventType.CANVAS_LTI_APPLICATION_BOOTSTRAPPED]


@pytest.mark.asyncio
async def test_verify_canvas_lti_launch_rejects_reused_state(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-reuse",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-reuse",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id="application-template-reuse",
        credential_template_id="credential-template-reuse",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)

    login_response = await canvas_routes.initiate_canvas_lti_login_route(
        platform.id,
        request=_json_request(
            {"login_hint": "login-hint-123"},
            path="/v1/integrations/canvas/lti/login/test",
        ),
        repo=repo,
    )
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    monkeypatch.setattr(
        canvas_routes,
        "verify_canvas_lti_launch",
        lambda **kwargs: {
            "issuer": kwargs["expected_issuer"],
            "subject": "student-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "roles": ["Learner"],
            "learner_identity": {"subject": "student-123"},
            "raw_claims": {"sub": "student-123"},
        },
    )

    first = await canvas_routes.verify_canvas_lti_launch_route(
        platform.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )

    assert first.verified is True

    with pytest.raises(Exception) as exc_info:
        await canvas_routes.verify_canvas_lti_launch_route(
            platform.id,
            request=_json_request({"id_token": "header.payload.signature", "state": state}),
            repo=repo,
        )

    assert getattr(exc_info.value, "status_code", None) == 400


@pytest.mark.asyncio
async def test_verify_canvas_lti_launch_refreshes_jwks_on_kid_miss(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-jwks",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "old-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-jwks",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id="application-template-jwks",
        credential_template_id="credential-template-jwks",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)

    login_response = await canvas_routes.initiate_canvas_lti_login_route(
        platform.id,
        request=_json_request(
            {"login_hint": "login-hint-123"},
            path="/v1/integrations/canvas/lti/login/test",
        ),
        repo=repo,
    )
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    monkeypatch.setattr(
        canvas_routes,
        "canvas_probe_lti_platform",
        lambda base_url: {
            "canvas_base_url": base_url,
            "issuer": "https://canvas.example.edu",
            "jwks_uri": "https://canvas.example.edu/jwks",
            "jwks_json": {"keys": [{"kid": "new-kid"}]},
            "raw_openid_configuration": {
                "issuer": "https://canvas.example.edu",
                "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
                "jwks_uri": "https://canvas.example.edu/jwks",
            },
        },
    )

    calls = {"count": 0}

    def fake_verify(**kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise Exception("No JWKS entry found for LTI kid new-kid")
        assert kwargs["jwks_json"] == {"keys": [{"kid": "new-kid"}]}
        return {
            "issuer": kwargs["expected_issuer"],
            "subject": "student-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "roles": ["Learner"],
            "learner_identity": {"subject": "student-123"},
            "raw_claims": {"sub": "student-123"},
        }

    monkeypatch.setattr(canvas_routes, "verify_canvas_lti_launch", fake_verify)

    response = await canvas_routes.verify_canvas_lti_launch_route(
        platform.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )
    stored = await repo.get_canvas_platform(platform.id)

    assert response.verified is True
    assert calls["count"] == 2
    assert stored is not None
    assert stored.lti_jwks_json == {"keys": [{"kid": "new-kid"}]}
    assert stored.lti_jwks_fetched_at is not None
