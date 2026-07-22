"""Unit tests for Canvas sandbox hardening and LTI launch routes."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

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

from issuance.application import canvas_evidence_revisions
from issuance.application.canvas_sync_jobs import complete_canvas_sync_job
from issuance.application.evidence_policy import EvidencePolicyDecision
from issuance.domain.entities import (
    ApplicationTemplate,
    CanvasEventReceipt,
    CanvasEvidenceRequirement,
    CanvasOAuthConnection,
    CanvasOAuthConnectionStatus,
    CanvasPlatform,
    CanvasProgramBinding,
    EventType,
    OrganizationIntegrationSecret,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes


@pytest.fixture(autouse=True)
def _enable_local_canvas_tool_signer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_LTI_ALLOW_LOCAL_PRIVATE_JWK", "true")
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1,org-123")
    monkeypatch.setenv("APP_ENV", "test")


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


def _rsa_uint(value: int) -> str:
    return _b64url(value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big"))


def test_canvas_lti_endpoints_are_exactly_pinned_to_documented_hosted_profile() -> None:
    platform = CanvasPlatform(
        id="endpoint-pinning-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://school.canvas.example",
        lti_openid_configuration={
            "authorization_endpoint": "https://attacker.example/authorize",
            "token_endpoint": "https://school.canvas.example/login/oauth2/token",
        },
    )
    with pytest.raises(HTTPException) as authorization_error:
        canvas_routes._lti_authorization_endpoint(platform)
    assert authorization_error.value.status_code == 409

    platform.lti_openid_configuration = {
        "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
        "token_endpoint": "https://attacker.example/token",
    }
    with pytest.raises(HTTPException) as token_error:
        canvas_routes._lti_token_endpoint(platform)
    assert token_error.value.status_code == 409


def test_canvas_route_auth_matrix_defaults_to_management_or_lti_session_auth() -> None:
    intentionally_public = {
        "get_canvas_lti_tool_jwks",
        "get_public_canvas_lti_config",
        "initiate_canvas_lti_login_route",
        "verify_canvas_lti_launch_route",
        "initiate_canvas_lti_experience_login_route",
        "launch_canvas_lti_experience_route",
        "complete_canvas_oauth_connection",
        "exchange_canvas_lti_experience_code_route",
    }
    session_authenticated = {
        "get_canvas_lti_experience_session_route",
        "bootstrap_canvas_lti_experience_application_route",
        "create_canvas_lti_deep_linking_response_route",
        "sync_canvas_lti_evidence",
        "get_canvas_lti_evidence_status",
    }
    disabled_legacy_ingest = {
        "process_canvas_evidence_event_route",
        "process_canvas_ags_score_event_route",
        "process_canvas_nrps_membership_event_route",
    }

    for route in canvas_routes.canvas_integration_router.routes:
        endpoint_name = route.endpoint.__name__
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        if endpoint_name in intentionally_public:
            assert canvas_routes._verify_management_api_key not in dependencies
        elif endpoint_name in session_authenticated:
            assert canvas_routes._lti_session_bearer_token in dependencies
        elif endpoint_name in disabled_legacy_ingest:
            continue
        else:
            assert canvas_routes._verify_management_api_key in dependencies, route.path
            assert canvas_routes._trusted_canvas_organization_id in dependencies, route.path


@pytest.mark.asyncio
async def test_legacy_canvas_event_routes_return_gone_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CANVAS_LEGACY_EVENT_INGEST_ENABLED", raising=False)
    repo = InMemoryIssuanceRepository()
    for handler in (
        canvas_routes.process_canvas_evidence_event_route,
        canvas_routes.process_canvas_ags_score_event_route,
        canvas_routes.process_canvas_nrps_membership_event_route,
    ):
        with pytest.raises(HTTPException) as disabled:
            await handler(
                request=_json_request({}),
                response=Response(),
                repo=repo,
            )
        assert disabled.value.status_code == 410


def _private_rsa_jwk(kid: str = "tool-key-1") -> tuple[dict[str, str], object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.private_numbers()
    public = numbers.public_numbers
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "n": _rsa_uint(public.n),
        "e": _rsa_uint(public.e),
        "d": _rsa_uint(numbers.d),
        "p": _rsa_uint(numbers.p),
        "q": _rsa_uint(numbers.q),
        "dp": _rsa_uint(numbers.dmp1),
        "dq": _rsa_uint(numbers.dmq1),
        "qi": _rsa_uint(numbers.iqmp),
    }
    return jwk, private_key.public_key()


def _jwt_payload(token: str) -> dict[str, object]:
    return json.loads(_b64url_decode(token.split(".")[1]))


def _verify_rs256_jwt_signature(token: str, public_key: object) -> None:
    header, payload, signature = token.split(".")
    public_key.verify(
        _b64url_decode(signature),
        f"{header}.{payload}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


async def _exchange_experience_code(response, repo: InMemoryIssuanceRepository) -> tuple[str, str]:
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    exchanged = await canvas_routes.exchange_canvas_lti_experience_code_route(
        canvas_routes.CanvasLtiExperienceCodeExchangeRequest(code=code),
        response=Response(),
        repo=repo,
    )
    return code, exchanged.session_token


@pytest.mark.asyncio
async def test_canvas_registration_config_exposes_public_jwks_and_standard_placements(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(id="portable-platform", organization_id="org-1", canvas_account_id="account-1")
    await repo.save_canvas_platform(platform)
    jwk, _public_key = _private_rsa_jwk()
    retiring_jwk, _retiring_public_key = _private_rsa_jwk("tool-key-retiring")
    retiring_public_jwk = {
        key: value
        for key, value in retiring_jwk.items()
        if key not in {"d", "p", "q", "dp", "dq", "qi"}
    }
    monkeypatch.setenv(
        "CANVAS_LTI_TOOL_PRIVATE_JWKS",
        json.dumps({"keys": [retiring_public_jwk, jwk]}),
    )
    monkeypatch.setenv("CANVAS_LTI_TOOL_ACTIVE_KID", "tool-key-1")
    monkeypatch.setattr(canvas_routes, "ISSUER_BASE_URL", "https://issuer.example.edu")

    registration = await canvas_routes.get_canvas_lti_registration_config(platform.id, repo=repo)
    public_jwks = await canvas_routes.get_canvas_lti_tool_jwks()

    assert registration.installation["method"] == "institution_admin_lti_1_3"
    assert registration.developer_key_configuration["public_jwk_url"].endswith("/v1/integrations/canvas/lti/jwks")
    placements = registration.developer_key_configuration["extensions"][0]["settings"]["placements"]
    assert {item["message_type"] for item in placements} == {"LtiResourceLinkRequest", "LtiDeepLinkingRequest"}
    assert public_jwks["keys"][0]["kid"] == "tool-key-1"
    assert {key["kid"] for key in public_jwks["keys"]} == {"tool-key-1", "tool-key-retiring"}
    assert all(key["alg"] == "RS256" and "d" not in key for key in public_jwks["keys"])
    assert registration.developer_key_configuration["custom_fields"]["canvas_user_id"] == "$Canvas.user.id"
    assert registration.developer_key_configuration["custom_fields"]["canvas_course_id"] == "$Canvas.course.id"


@pytest.mark.asyncio
async def test_canvas_registration_config_token_rotates_and_is_publicly_revocable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="config-token-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
    )
    await repo.save_canvas_platform(platform)
    jwk, _public_key = _private_rsa_jwk()
    monkeypatch.setenv("CANVAS_LTI_TOOL_PRIVATE_JWKS", json.dumps(jwk))
    monkeypatch.setattr(canvas_routes, "ISSUER_BASE_URL", "https://issuer.example.edu")

    first = await canvas_routes.get_canvas_lti_registration_config(
        platform.id,
        trusted_organization_id="org-1",
        repo=repo,
    )
    first_token = first.installation["config_url"].rsplit("/", 1)[-1]
    public_config = await canvas_routes.get_public_canvas_lti_config(
        first_token,
        response=Response(),
        repo=repo,
    )
    assert public_config["public_jwk_url"].endswith("/lti/jwks")

    second = await canvas_routes.get_canvas_lti_registration_config(
        platform.id,
        trusted_organization_id="org-1",
        repo=repo,
    )
    assert second.installation["config_url"] != first.installation["config_url"]
    with pytest.raises(HTTPException, match="not found"):
        await canvas_routes.get_public_canvas_lti_config(first_token, response=Response(), repo=repo)

    await canvas_routes.update_canvas_lti_installation(
        platform.id,
        canvas_routes.CanvasLtiInstallationRequest(
            lti_client_id="client-1",
            lti_deployment_id="deployment-1",
            revoke_config_token=True,
        ),
        trusted_organization_id="org-1",
        repo=repo,
    )
    second_token = second.installation["config_url"].rsplit("/", 1)[-1]
    with pytest.raises(HTTPException, match="not found"):
        await canvas_routes.get_public_canvas_lti_config(second_token, response=Response(), repo=repo)


@pytest.mark.asyncio
async def test_production_canvas_tool_signer_rejects_local_private_jwk(monkeypatch: pytest.MonkeyPatch) -> None:
    jwk, _public_key = _private_rsa_jwk()
    monkeypatch.setenv("CANVAS_LTI_TOOL_PRIVATE_JWKS", json.dumps(jwk))
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SIGNING_KEYS_INTERNAL_URL", raising=False)
    monkeypatch.delenv("SIGNING_KEYS_INTERNAL_API_KEY", raising=False)
    with pytest.raises(HTTPException, match="Production Canvas LTI signing"):
        await canvas_routes.get_canvas_lti_tool_jwks()


@pytest.mark.asyncio
async def test_production_canvas_tool_signer_uses_issuer_profile_and_did(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def sign(**kwargs):
        captured.update(kwargs)
        return {"signature_raw_b64": "c2ln"}

    monkeypatch.setenv("CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID", "system-tools")
    issuer_did = "did:web:issuer.example:canvas"
    kid = f"{issuer_did}#lti-tool-rs256"
    monkeypatch.setenv("CANVAS_LTI_TOOL_ISSUER_PROFILE_ID", "canvas-lti-profile")
    monkeypatch.setenv("CANVAS_LTI_TOOL_ISSUER_DID", issuer_did)
    monkeypatch.setenv("CANVAS_LTI_TOOL_ACTIVE_KID", kid)
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_URL", "http://gateway/internal/signing-keys")
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "service-secret")
    monkeypatch.setattr(canvas_routes, "sign_payload_with_issuer_profile", sign)

    token = await canvas_routes.IssuerProfileToolJwtSigner().sign_jwt(
        {"iss": "client-123", "aud": "https://canvas.example.edu/login/oauth2/token"}
    )

    assert token.endswith(".c2ln")
    assert captured["issuer_profile_id"] == "canvas-lti-profile"
    assert captured["expected_issuer_did"] == issuer_did
    assert captured["expected_verification_method_id"] == kid
    assert captured["algorithm"] == "RS256"
    assert "signing_service_id" not in captured
    assert "key_reference" not in captured


@pytest.mark.asyncio
async def test_production_canvas_tool_signer_rejects_kid_outside_issuer_did(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID", "system-tools")
    monkeypatch.setenv("CANVAS_LTI_TOOL_ISSUER_PROFILE_ID", "canvas-lti-profile")
    monkeypatch.setenv("CANVAS_LTI_TOOL_ISSUER_DID", "did:web:issuer.example:canvas")
    monkeypatch.setenv("CANVAS_LTI_TOOL_ACTIVE_KID", "did:web:other.example#key-1")
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_URL", "http://gateway/internal/signing-keys")
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "service-secret")

    with pytest.raises(HTTPException, match="verification method"):
        canvas_routes.IssuerProfileToolJwtSigner()


@pytest.mark.asyncio
async def test_production_canvas_tool_jwks_rejects_private_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_jwk, _public_key = _private_rsa_jwk("canvas-lti-kid")
    monkeypatch.setenv("CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID", "system-tools")
    issuer_did = "did:web:issuer.example:canvas"
    kid = f"{issuer_did}#lti-tool-rs256"
    private_jwk["kid"] = kid
    monkeypatch.setenv("CANVAS_LTI_TOOL_ISSUER_PROFILE_ID", "canvas-lti-profile")
    monkeypatch.setenv("CANVAS_LTI_TOOL_ISSUER_DID", issuer_did)
    monkeypatch.setenv("CANVAS_LTI_TOOL_ACTIVE_KID", kid)
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_URL", "http://gateway/internal/signing-keys")
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "service-secret")
    monkeypatch.setenv(
        "CANVAS_LTI_TOOL_PUBLIC_JWKS",
        json.dumps({"keys": [private_jwk]}),
    )

    with pytest.raises(HTTPException, match="must not contain private key material"):
        await canvas_routes.IssuerProfileToolJwtSigner().public_jwks()


@pytest.mark.asyncio
async def test_lti_tool_readiness_challenge_requires_signer_to_match_published_jwk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_jwk, _public_key = _private_rsa_jwk("canvas-lti-active")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("CANVAS_LTI_ALLOW_LOCAL_PRIVATE_JWK", "true")
    monkeypatch.setenv("CANVAS_LTI_TOOL_PRIVATE_JWKS", json.dumps(private_jwk))
    monkeypatch.setenv("CANVAS_LTI_TOOL_ACTIVE_KID", "canvas-lti-active")

    assert await canvas_routes._lti_tool_signing_challenge_ready() is True

    other_private_jwk, _other_public_key = _private_rsa_jwk("canvas-lti-active")
    other_public_jwk = {
        key: value
        for key, value in other_private_jwk.items()
        if key not in canvas_routes._RSA_PRIVATE_JWK_FIELDS
    }

    async def mismatched_jwks(_self) -> dict[str, object]:
        return {"keys": [other_public_jwk]}

    monkeypatch.setattr(
        canvas_routes.LocalJwkToolJwtSigner,
        "public_jwks",
        mismatched_jwks,
    )
    assert await canvas_routes._lti_tool_signing_challenge_ready() is False


@pytest.mark.asyncio
async def test_canvas_lti_service_client_assertion_is_rs256_with_active_kid(monkeypatch: pytest.MonkeyPatch) -> None:
    jwk, public_key = _private_rsa_jwk("active-rsa-key")
    monkeypatch.setenv("CANVAS_LTI_TOOL_PRIVATE_JWKS", json.dumps(jwk))
    platform = CanvasPlatform(id="platform", lti_client_id="client-123")

    assertion = await canvas_routes._lti_service_client_assertion(
        platform,
        "https://canvas.example.edu/login/oauth2/token",
    )

    _verify_rs256_jwt_signature(assertion, public_key)
    header = json.loads(_b64url_decode(assertion.split(".")[0]))
    payload = _jwt_payload(assertion)
    assert header == {"alg": "RS256", "kid": "active-rsa-key", "typ": "JWT"}
    assert payload["iss"] == payload["sub"] == "client-123"
    assert payload["aud"] == "https://canvas.example.edu/login/oauth2/token"
    assert payload["exp"] - payload["iat"] == 300
    assert payload["jti"]


@pytest.mark.asyncio
async def test_verified_ags_line_item_change_invalidates_binding_readiness() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-ags-pin",
        organization_id="org-123",
        canvas_account_id="account-123",
    )
    binding = CanvasProgramBinding(
        id="binding-ags-pin",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        evidence_requirements=[
            {
                "requirement_id": "score-1",
                "source": "ags_result",
                "fact_type": "canvas.assignment_score",
                "scope": {
                    "course_id": "course-1",
                    "resource_id": "marty:binding-ags-pin:score-1",
                    "line_item_url": "https://canvas.example.edu/api/lti/courses/1/line_items/old",
                },
                "pass_rule": {"min_score_percent": 80},
                "required": True,
            }
        ],
        config_version=4,
        validated_config_version=4,
        readiness_checks=[{"code": "ready", "status": "ready", "blocking": True}],
        credential_template_snapshot={"id": "credential-template-1"},
        enabled=True,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)

    await canvas_routes._persist_verified_ags_line_item(
        platform=platform,
        binding=binding,
        verified_launch={
            "raw_claims": {
                "custom": {
                    "canvas_program_binding_id": binding.id,
                    "canvas_requirement_id": "score-1",
                    "canvas_resource_id": "marty:binding-ags-pin:score-1",
                },
                "ags_endpoint": {
                    "lineitem": "https://canvas.example.edu/api/lti/courses/1/line_items/new"
                },
            }
        },
        repo=repo,
    )

    stored = await repo.get_canvas_program_binding(binding.id)
    assert stored is not None
    assert stored.config_version == 5
    assert stored.enabled is False
    assert stored.validated_config_version is None
    assert stored.readiness_checks == []
    assert stored.credential_template_snapshot == {}
    assert stored.evidence_requirements[0]["scope"]["line_item_url"].endswith("/new")


def test_canvas_auto_approval_requires_active_current_readiness() -> None:
    binding = CanvasProgramBinding(
        id="binding-auto-approval",
        organization_id="org-123",
        platform_id="platform-123",
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        auto_approve_on_evidence=True,
        enabled=True,
        config_version=3,
        validated_config_version=3,
        readiness_checks=[
            {"code": "kms", "status": "ready", "blocking": True},
        ],
        readiness_validated_at=datetime.now(timezone.utc),
        credential_template_snapshot={"id": "credential-template-1"},
    )

    assert canvas_routes._canvas_auto_approval_ready(binding) is True

    binding.enabled = False
    assert canvas_routes._canvas_auto_approval_ready(binding) is False
    binding.enabled = True
    binding.config_version += 1
    assert canvas_routes._canvas_auto_approval_ready(binding) is False
    binding.validated_config_version = binding.config_version
    binding.feature_flags = {"enable_canvas_evidence": False}
    assert canvas_routes._canvas_auto_approval_ready(binding) is False


def test_canvas_deep_linking_contract_rejects_browser_owned_content_and_learner_role() -> None:
    with pytest.raises(ValueError):
        canvas_routes.CanvasLtiDeepLinkingRequest.model_validate(
            {"custom": {"binding": "attacker"}, "line_item": {"scoreMaximum": 100}}
        )
    with pytest.raises(HTTPException, match="Instructor or Administrator"):
        canvas_routes._require_deep_linking_staff_role({"roles": ["Learner"]})
    canvas_routes._require_deep_linking_staff_role(
        {"roles": ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"]}
    )


def test_canvas_experience_session_uses_bearer_header_not_url_path() -> None:
    paths = {route.path for route in canvas_routes.canvas_integration_router.routes}
    assert not any("experience-sessions/{state}" in path for path in paths)
    assert "/v1/integrations/canvas/lti/experience-sessions/current" in paths
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", b"Bearer opaque-session-token")],
        }
    )
    assert canvas_routes._lti_session_bearer_token(request) == "opaque-session-token"



@pytest.mark.asyncio
async def test_canvas_oauth_connection_stores_tokens_in_org_secret_not_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="oauth-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
    )
    client_secret = OrganizationIntegrationSecret(
        id="oauth-client-secret",
        organization_id="org-1",
        name="Canvas API client secret",
        provider="canvas",
        purpose="oauth_client_secret",
        secret_value="client-secret-value",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_integration_secret(client_secret)
    monkeypatch.setenv("CANVAS_OAUTH_COMPLETION_REDIRECT_URL", "https://app.example.edu/integrations/canvas")
    monkeypatch.setattr(canvas_routes, "ISSUER_BASE_URL", "https://issuer.example.edu")

    start = await canvas_routes.start_canvas_oauth_connection(
        platform.id,
        request=canvas_routes.CanvasOAuthStartRequest(
            client_id="canvas-api-client",
            client_secret_secret_id=client_secret.id,
            capabilities=["catalog"],
        ),
        repo=repo,
    )
    state = parse_qs(urlparse(start.authorization_url).query)["state"][0]

    async def fake_exchange(**_kwargs):
        return {"access_token": "access-token", "refresh_token": "refresh-token", "expires_in": 3600}

    monkeypatch.setattr(canvas_routes, "exchange_canvas_oauth_code", fake_exchange)
    complete = await canvas_routes.complete_canvas_oauth_connection(code="code", state=state, repo=repo)
    stored = await repo.get_canvas_platform(platform.id)
    connection = await repo.get_canvas_oauth_connection("org-1", platform.id)
    assert connection is not None
    access_secret_id = connection.access_token_secret_ref.rsplit("/", 1)[-1]
    refresh_secret_id = connection.refresh_token_secret_ref.rsplit("/", 1)[-1]

    assert complete.status_code == 303
    assert complete.headers["location"].startswith(
        "https://app.example.edu/integrations/canvas?outcome=connected&platform_id=oauth-platform"
    )
    assert "access-token" not in complete.headers["location"]
    assert complete.headers["cache-control"] == "no-store"
    assert stored.connection_config["oauth_status"] == "connected"
    assert stored.connection_config["oauth_capabilities"] == ["catalog"]
    assert "url:GET|/api/v1/courses" in stored.connection_config["granted_scopes"]
    assert await repo.get_integration_secret_value("org-1", access_secret_id) == "access-token"
    assert await repo.get_integration_secret_value("org-1", refresh_secret_id) == "refresh-token"
    assert connection.client_id == "canvas-api-client"
    assert connection.client_secret_ref == client_secret.secret_ref
    assert "access-token" not in json.dumps(stored.connection_config)
    replay = await canvas_routes.complete_canvas_oauth_connection(code="replay", state=state, repo=repo)
    assert replay.status_code == 303
    assert "error_code=oauth_state_invalid" in replay.headers["location"]


@pytest.mark.asyncio
async def test_canvas_oauth_callback_refuses_platform_changed_after_authorization_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="oauth-origin-snapshot-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
    )
    client_secret = OrganizationIntegrationSecret(
        id="oauth-origin-snapshot-secret",
        organization_id="org-1",
        provider="canvas",
        purpose="oauth_client_secret",
        secret_value="client-secret",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_integration_secret(client_secret)
    monkeypatch.setenv(
        "CANVAS_OAUTH_COMPLETION_REDIRECT_URL",
        "https://app.example.edu/integrations/canvas",
    )
    monkeypatch.setattr(canvas_routes, "ISSUER_BASE_URL", "https://issuer.example.edu")
    started = await canvas_routes.start_canvas_oauth_connection(
        platform.id,
        request=canvas_routes.CanvasOAuthStartRequest(
            client_id="canvas-client",
            client_secret_secret_id=client_secret.id,
            capabilities=["catalog"],
        ),
        repo=repo,
    )
    state = parse_qs(urlparse(started.authorization_url).query)["state"][0]
    platform.canvas_base_url = "https://other-canvas.example.edu"
    platform.config_version += 1
    await repo.save_canvas_platform(platform)

    async def forbidden_exchange(**_kwargs):
        raise AssertionError("A client secret must never be sent after the Canvas origin changes")

    monkeypatch.setattr(canvas_routes, "exchange_canvas_oauth_code", forbidden_exchange)
    completed = await canvas_routes.complete_canvas_oauth_connection(
        code="authorization-code",
        state=state,
        repo=repo,
    )

    assert completed.status_code == 303
    assert "error_code=oauth_configuration_changed" in completed.headers["location"]
    assert await repo.get_canvas_oauth_connection("org-1", platform.id) is None


@pytest.mark.asyncio
async def test_canvas_oauth_rejects_wrong_secret_purpose_and_redirects_denial_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="oauth-security-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
    )
    wrong_secret = OrganizationIntegrationSecret(
        id="credentials-token",
        organization_id="org-1",
        provider="canvas_credentials",
        purpose="api_token",
        secret_value="not-an-oauth-client-secret",
    )
    client_secret = OrganizationIntegrationSecret(
        id="oauth-client-secret-security",
        organization_id="org-1",
        provider="canvas",
        purpose="oauth_client_secret",
        secret_value="client-secret",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_integration_secret(wrong_secret)
    await repo.save_integration_secret(client_secret)
    monkeypatch.setenv(
        "CANVAS_OAUTH_COMPLETION_REDIRECT_URL",
        "https://app.example.edu/integrations/canvas",
    )
    monkeypatch.setattr(canvas_routes, "ISSUER_BASE_URL", "https://issuer.example.edu")

    with pytest.raises(HTTPException) as rejected:
        await canvas_routes.start_canvas_oauth_connection(
            platform.id,
            request=canvas_routes.CanvasOAuthStartRequest(
                client_id="canvas-client",
                client_secret_secret_id=wrong_secret.id,
                capabilities=["catalog"],
            ),
            repo=repo,
        )
    assert rejected.value.status_code == 404

    started = await canvas_routes.start_canvas_oauth_connection(
        platform.id,
        request=canvas_routes.CanvasOAuthStartRequest(
            client_id="canvas-client",
            client_secret_secret_id=client_secret.id,
            capabilities=["catalog"],
        ),
        repo=repo,
    )
    state = parse_qs(urlparse(started.authorization_url).query)["state"][0]
    denied = await canvas_routes.complete_canvas_oauth_connection(
        code=None,
        state=state,
        error="access_denied",
        repo=repo,
    )
    assert denied.status_code == 303
    assert "error_code=oauth_authorization_denied" in denied.headers["location"]
    assert "access_denied" not in denied.headers["location"]
    replay = await canvas_routes.complete_canvas_oauth_connection(
        code="replay",
        state=state,
        repo=repo,
    )
    assert "error_code=oauth_state_invalid" in replay.headers["location"]


@pytest.mark.asyncio
async def test_canvas_event_status_rechecks_trusted_organization() -> None:
    repo = InMemoryIssuanceRepository()
    await repo.save_canvas_event_receipt(
        CanvasEventReceipt(
            provider_event_id="event-owned-by-org-1",
            organization_id="org-1",
            canvas_account_id="account-1",
            credential_template_id="template-1",
            payload_hash="payload-hash",
        )
    )

    with pytest.raises(HTTPException) as foreign:
        await canvas_routes.get_canvas_evidence_event_status(
            "account-1",
            "event-owned-by-org-1",
            trusted_organization_id="org-2",
            repo=repo,
        )
    assert foreign.value.status_code == 404

    owned = await canvas_routes.get_canvas_evidence_event_status(
        "account-1",
        "event-owned-by-org-1",
        trusted_organization_id="org-1",
        repo=repo,
    )
    assert owned.organization_id == "org-1"


@pytest.mark.asyncio
async def test_canvas_oauth_access_token_refreshes_expired_org_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    client_secret = OrganizationIntegrationSecret(
        id="refresh-client-secret",
        organization_id="org-1",
        name="Canvas client secret",
        provider="canvas",
        purpose="oauth_client_secret",
        secret_value="client-secret",
    )
    access_secret = OrganizationIntegrationSecret(
        id="access-token-secret",
        organization_id="org-1",
        name="Canvas OAuth access token",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value="expired",
    )
    refresh_secret = OrganizationIntegrationSecret(
        id="refresh-token-secret",
        organization_id="org-1",
        name="Canvas OAuth refresh token",
        provider="canvas",
        purpose="oauth_refresh_token",
        secret_value="refresh",
    )
    platform = CanvasPlatform(
        id="refresh-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_integration_secret(client_secret)
    await repo.save_integration_secret(access_secret)
    await repo.save_integration_secret(refresh_secret)
    await repo.save_canvas_oauth_connection(
        CanvasOAuthConnection(
            organization_id="org-1",
            platform_id=platform.id,
            canvas_base_url=str(platform.canvas_base_url),
            platform_config_version=platform.config_version,
            client_id="client-id",
            client_secret_ref=client_secret.secret_ref,
            capabilities=["catalog"],
            scopes=canvas_routes.canvas_oauth_scopes_for_capabilities(["catalog"]),
            access_token_secret_ref=access_secret.secret_ref,
            refresh_token_secret_ref=refresh_secret.secret_ref,
            token_expires_at=datetime.fromtimestamp(1, tz=timezone.utc),
            status=CanvasOAuthConnectionStatus.CONNECTED,
        )
    )

    async def fake_refresh(**_kwargs):
        return {"access_token": "fresh", "refresh_token": "refresh", "obtained_at": 9999999999, "expires_in": 3600}

    monkeypatch.setattr(canvas_routes, "refresh_canvas_oauth_token", fake_refresh)
    value = await canvas_routes._canvas_oauth_access_token(platform=platform, repo=repo)

    assert value == "fresh"
    stored_connection = await repo.get_canvas_oauth_connection("org-1", platform.id)
    assert stored_connection is not None
    refreshed_access_id = stored_connection.access_token_secret_ref.rsplit("/", 1)[-1]
    assert refreshed_access_id != access_secret.id
    assert await repo.get_integration_secret_value("org-1", refreshed_access_id) == "fresh"
    assert await repo.get_integration_secret_value("org-1", access_secret.id) is None


@pytest.mark.asyncio
async def test_canvas_oauth_refresh_cas_failure_does_not_overwrite_current_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="refresh-cas-platform",
        organization_id="org-1",
        canvas_base_url="https://canvas.example.edu",
    )
    client_secret = OrganizationIntegrationSecret(
        id="refresh-cas-client",
        organization_id="org-1",
        provider="canvas",
        purpose="oauth_client_secret",
        secret_value="client-secret",
    )
    access_secret = OrganizationIntegrationSecret(
        id="refresh-cas-access",
        organization_id="org-1",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value="current-access-token",
    )
    refresh_secret = OrganizationIntegrationSecret(
        id="refresh-cas-refresh",
        organization_id="org-1",
        provider="canvas",
        purpose="oauth_refresh_token",
        secret_value="current-refresh-token",
    )
    await repo.save_canvas_platform(platform)
    for secret in (client_secret, access_secret, refresh_secret):
        await repo.save_integration_secret(secret)
    await repo.save_canvas_oauth_connection(
        CanvasOAuthConnection(
            organization_id="org-1",
            platform_id=platform.id,
            canvas_base_url=str(platform.canvas_base_url),
            platform_config_version=platform.config_version,
            client_id="client-id",
            client_secret_ref=client_secret.secret_ref,
            access_token_secret_ref=access_secret.secret_ref,
            refresh_token_secret_ref=refresh_secret.secret_ref,
            token_expires_at=datetime.fromtimestamp(1, tz=timezone.utc),
        )
    )

    async def fake_refresh(**_kwargs):
        return {
            "access_token": "stale-refreshed-access",
            "refresh_token": "stale-refreshed-refresh",
            "expires_in": 3600,
        }

    async def fail_completion(**_kwargs):
        return None

    monkeypatch.setattr(canvas_routes, "refresh_canvas_oauth_token", fake_refresh)
    monkeypatch.setattr(repo, "complete_canvas_oauth_refresh", fail_completion)
    value = await canvas_routes._canvas_oauth_access_token(platform=platform, repo=repo)

    assert value == ""
    assert (
        await repo.get_integration_secret_value("org-1", access_secret.id)
        == "current-access-token"
    )
    assert (
        await repo.get_integration_secret_value("org-1", refresh_secret.id)
        == "current-refresh-token"
    )
    assert all(
        secret.secret_value not in {"stale-refreshed-access", "stale-refreshed-refresh"}
        for secret in repo._integration_secrets.values()
    )


@pytest.mark.asyncio
async def test_canvas_oauth_token_fails_closed_when_platform_snapshot_changes() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="oauth-snapshot-mismatch",
        organization_id="org-1",
        canvas_base_url="https://new-canvas.example.edu",
        config_version=2,
    )
    access_secret = OrganizationIntegrationSecret(
        id="snapshot-mismatch-access",
        organization_id="org-1",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value="must-not-be-returned",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_integration_secret(access_secret)
    await repo.save_canvas_oauth_connection(
        CanvasOAuthConnection(
            organization_id="org-1",
            platform_id=platform.id,
            canvas_base_url="https://old-canvas.example.edu",
            platform_config_version=1,
            access_token_secret_ref=access_secret.secret_ref,
        )
    )

    assert await canvas_routes._canvas_oauth_access_token(platform=platform, repo=repo) == ""
    connection = await repo.get_canvas_oauth_connection("org-1", platform.id)
    assert connection is not None
    assert connection.status == CanvasOAuthConnectionStatus.REAUTHORIZATION_REQUIRED
    assert (
        await repo.get_integration_secret_value("org-1", access_secret.id)
        == "must-not-be-returned"
    )


@pytest.mark.asyncio
async def test_canvas_oauth_disconnect_revokes_against_pinned_connection_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="oauth-pinned-revoke",
        organization_id="org-1",
        canvas_base_url="https://edited-canvas.example.edu",
        config_version=2,
    )
    access_secret = OrganizationIntegrationSecret(
        id="pinned-revoke-access",
        organization_id="org-1",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value="access-token",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_integration_secret(access_secret)
    await repo.save_canvas_oauth_connection(
        CanvasOAuthConnection(
            organization_id="org-1",
            platform_id=platform.id,
            canvas_base_url="https://authorized-canvas.example.edu",
            platform_config_version=1,
            access_token_secret_ref=access_secret.secret_ref,
            scopes=["url:GET|/api/v1/courses"],
        )
    )
    calls: list[tuple[str, str]] = []

    async def fake_revoke(*, client, canvas_base_url, access_token):
        calls.append((canvas_base_url, access_token))

    monkeypatch.setattr(canvas_routes, "revoke_canvas_oauth_token", fake_revoke)
    disconnected = await canvas_routes.disconnect_canvas_oauth_connection(
        platform.id,
        repo=repo,
    )

    assert disconnected.status == "disconnected"
    assert calls == [("https://authorized-canvas.example.edu", "access-token")]
    assert await repo.get_canvas_oauth_connection("org-1", platform.id) is None
    assert await repo.get_integration_secret_value("org-1", access_secret.id) is None


@pytest.mark.asyncio
async def test_canvas_platform_archival_queues_oauth_revocation_and_is_idempotent() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="archive-oauth-platform",
        organization_id="org-1",
        canvas_base_url="https://canvas.example.edu",
        config_version=3,
        enabled=True,
        registration_status="active",
        connection_config={"oauth_status": "connected"},
    )
    binding = CanvasProgramBinding(
        id="archive-oauth-binding",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        enabled=True,
    )
    connection = CanvasOAuthConnection(
        organization_id="org-1",
        platform_id=platform.id,
        canvas_base_url="https://canvas.example.edu",
        platform_config_version=platform.config_version,
        access_token_secret_ref="org_secret://org-1/access-token",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    await repo.save_canvas_oauth_connection(connection)

    archived = await canvas_routes.delete_canvas_platform(
        platform.id,
        trusted_organization_id="org-1",
        repo=repo,
    )

    assert archived.status_code == 204
    stored_platform = await repo.get_canvas_platform(platform.id)
    stored_binding = await repo.get_canvas_program_binding(binding.id)
    queued = await repo.get_canvas_oauth_connection("org-1", platform.id)
    assert stored_platform is not None
    assert stored_platform.archived_at is not None
    assert stored_platform.enabled is False
    assert stored_platform.config_version == 4
    assert stored_platform.connection_config["oauth_status"] == "revocation_pending"
    assert stored_binding is not None
    assert stored_binding.archived_at is not None
    assert stored_binding.enabled is False
    assert queued is not None
    assert queued.status == CanvasOAuthConnectionStatus.REVOCATION_PENDING
    assert queued.revoke_retry_at is not None
    assert queued.refresh_lease_owner is None

    retried = await canvas_routes.delete_canvas_platform(
        platform.id,
        trusted_organization_id="org-1",
        repo=repo,
    )
    assert retried.status_code == 204
    assert (await repo.get_canvas_platform(platform.id)).config_version == 4


@pytest.mark.asyncio
async def test_canvas_platform_archival_fails_before_mutation_on_revocation_cas_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="archive-conflict-platform",
        organization_id="org-1",
        canvas_base_url="https://canvas.example.edu",
        enabled=True,
    )
    await repo.save_canvas_platform(platform)

    async def fail_queue(**_kwargs):
        return False

    monkeypatch.setattr(canvas_routes, "queue_canvas_oauth_revocation", fail_queue)
    with pytest.raises(HTTPException) as conflict:
        await canvas_routes.delete_canvas_platform(
            platform.id,
            trusted_organization_id="org-1",
            repo=repo,
        )

    assert conflict.value.status_code == 409
    stored = await repo.get_canvas_platform(platform.id)
    assert stored is not None
    assert stored.archived_at is None
    assert stored.enabled is True


@pytest.mark.asyncio
async def test_oauth_connection_cas_rejects_archived_or_reconfigured_platform() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="oauth-publish-platform-snapshot",
        organization_id="org-1",
        canvas_base_url="https://canvas.example.edu",
        config_version=2,
    )
    await repo.save_canvas_platform(platform)

    stale = CanvasOAuthConnection(
        organization_id="org-1",
        platform_id=platform.id,
        canvas_base_url="https://canvas.example.edu",
        platform_config_version=1,
        access_token_secret_ref="org_secret://org-1/stale-access",
    )
    assert not await repo.save_canvas_oauth_connection_cas(
        stale,
        expected_updated_at=None,
    )

    platform.archived_at = datetime.now(timezone.utc)
    await repo.save_canvas_platform(platform)
    archived = CanvasOAuthConnection(
        organization_id="org-1",
        platform_id=platform.id,
        canvas_base_url="https://canvas.example.edu",
        platform_config_version=platform.config_version,
        access_token_secret_ref="org_secret://org-1/archived-access",
    )
    assert not await repo.save_canvas_oauth_connection_cas(
        archived,
        expected_updated_at=None,
    )
    assert await repo.get_canvas_oauth_connection("org-1", platform.id) is None


@pytest.mark.asyncio
async def test_canvas_rest_assignment_evidence_uses_scoped_org_token_and_lti_user() -> None:
    platform = CanvasPlatform(
        id="rest-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
    )
    requirement = CanvasEvidenceRequirement.from_mapping(
        {
            "requirement_id": "assignment-55",
            "source": "canvas_rest",
            "fact_type": "canvas.assignment_score",
            "scope": {"course_id": "101", "activity_id": "55"},
            "pass_rule": {"min_score_percent": 80},
        }
    )

    def handler(request):
        assert request.headers["authorization"] == "Bearer org-oauth-token"
        assert request.url.path == "/api/v1/courses/101/assignments/55/submissions/777"
        return httpx.Response(
            200,
            json={
                "id": "submission-1",
                "user_id": "777",
                "score": 45,
                "workflow_state": "graded",
                "assignment": {"points_possible": 50},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        record, scope = await canvas_routes._read_canvas_rest_evidence(
            client=client,
            repo=InMemoryIssuanceRepository(),
            platform=platform,
            token="org-oauth-token",
            requirement=requirement,
            canvas_user_id="777",
        )

    assertion = canvas_routes._canvas_rest_assertion(requirement.fact_type, record)
    assert scope["activity_id"] == "55"
    assert assertion["score_percent"] == 90
    assert assertion["completed"] is True


@pytest.mark.asyncio
async def test_canvas_rest_invalid_access_token_marks_connection_for_reauthorization() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="invalid-token-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
    )
    access_secret = OrganizationIntegrationSecret(
        id="invalid-access-token-secret",
        organization_id="org-1",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value="invalid-access-token",
    )
    connection = CanvasOAuthConnection(
        organization_id="org-1",
        platform_id=platform.id,
        canvas_base_url=str(platform.canvas_base_url),
        platform_config_version=platform.config_version,
        client_id="client-id",
        access_token_secret_ref=access_secret.secret_ref,
        status=CanvasOAuthConnectionStatus.CONNECTED,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_integration_secret(access_secret)
    await repo.save_canvas_oauth_connection(connection)
    requirement = CanvasEvidenceRequirement.from_mapping(
        {
            "requirement_id": "course-completion-invalid-token",
            "source": "canvas_rest",
            "fact_type": "canvas.course_completion",
            "scope": {"course_id": "101"},
            "pass_rule": {"completed": True},
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(canvas_routes.CanvasLtiServiceError) as rejected:
            await canvas_routes._read_canvas_rest_evidence(
                client=client,
                repo=repo,
                platform=platform,
                token="invalid-access-token",
                requirement=requirement,
                canvas_user_id="777",
            )

    assert rejected.value.reauthorization_required is True
    stored = await repo.get_canvas_oauth_connection("org-1", platform.id)
    assert stored is not None
    assert stored.status == CanvasOAuthConnectionStatus.REAUTHORIZATION_REQUIRED
    assert stored.reauthorization_required is True


@pytest.mark.asyncio
async def test_canvas_readiness_reports_missing_oauth_for_rest_evidence() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="readiness-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        lti_client_id="client-1",
        lti_deployment_id="deployment-1",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "canvas"}]},
        registration_status="verified",
    )
    binding = CanvasProgramBinding(
        id="readiness-binding",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id="application-1",
        credential_template_id="credential-1",
        evidence_requirements=[{
            "requirement_id": "course-completion",
            "source": "canvas_rest",
            "fact_type": "canvas.course_completion",
            "scope": {"course_id": "101"},
            "pass_rule": {"completed": True},
        }],
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)

    missing = await canvas_routes.get_canvas_platform_readiness(platform.id, repo=repo)
    access_secret = OrganizationIntegrationSecret(
        id="readiness-access-token",
        organization_id="org-1",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value="access-token",
    )
    await repo.save_integration_secret(access_secret)
    await repo.save_canvas_oauth_connection(
        CanvasOAuthConnection(
            organization_id="org-1",
            platform_id=platform.id,
            canvas_base_url=str(platform.canvas_base_url or ""),
            platform_config_version=platform.config_version,
            client_id="client-id",
            client_secret_ref="org_secret://org-1/client-secret",
            capabilities=["course_completion"],
            scopes=canvas_routes.canvas_oauth_scopes_for_capabilities(["course_completion"]),
            access_token_secret_ref=access_secret.secret_ref,
        )
    )
    ready = await canvas_routes.get_canvas_platform_readiness(platform.id, repo=repo)

    assert missing.ready is False
    assert next(check for check in missing.checks if check.code == "oauth_connection").status == "failed"
    assert next(check for check in ready.checks if check.code == "oauth_connection").status == "ready"
    assert next(check for check in ready.checks if check.code == "oauth_least_privilege_grant").status == "ready"


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
    token_secret = OrganizationIntegrationSecret(
        id="canvas-credentials-token",
        organization_id="org-123",
        name="Canvas Credentials API token",
        provider="canvas_credentials",
        purpose="api_token",
        secret_value="secret-token",
    )
    await repo.save_integration_secret(token_secret)

    response = await canvas_routes.create_canvas_program_binding(
        platform.id,
        request=canvas_routes.CanvasProgramBindingCreate(
            application_template_id=template.id,
            credential_template_id=template.credential_template_id,
            delivery_mode="wallet_plus_canvas_mirror",
            canvas_scope={"course_id": "course-101"},
            evidence_requirements=[{
                "requirement_id": "course-completion",
                "source": "canvas_rest",
                "fact_type": "canvas.course_completion",
                "scope": {"course_id": "course-101"},
                "pass_rule": {"completed": True},
            }],
            canvas_credentials={
                "provider": "badgr_api",
                "api_base_url": "https://api.badgr.io",
                "issuer_id": "issuer-1",
                "badgeclass_id": "badgeclass-1",
                "api_token_secret_id": token_secret.id,
            },
        ),
        repo=repo,
    )
    stored = await repo.get_canvas_program_binding(response.id)

    assert response.canvas_credentials["provider"] == "badgr_api"
    assert response.canvas_credentials["api_token_secret_id"] == token_secret.id
    assert stored is not None
    assert stored.canvas_credentials == response.canvas_credentials


@pytest.mark.parametrize(
    "unsafe_selector",
    [
        {"api_token": "inline-secret"},
        {"api_token_env": "INTEGRATION_SECRET_MASTER_KEY"},
        {"api_token_file": "C:/secrets/internal-api-key"},
        {"validation_url_template": "https://attacker.example/{badgeclass_id}"},
    ],
)
def test_canvas_credentials_input_rejects_caller_secret_and_url_selectors(
    unsafe_selector: dict[str, str],
) -> None:
    with pytest.raises(ValueError):
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-1",
            evidence_requirements=[{
                "requirement_id": "course-completion",
                "source": "canvas_rest",
                "fact_type": "canvas.course_completion",
                "scope": {"course_id": "course-101"},
                "pass_rule": {"completed": True},
            }],
            canvas_credentials={
                "provider": "badgr_api",
                "api_token_secret_id": "managed-secret",
                **unsafe_selector,
            },
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe_url",
    [
        "http://api.badgr.io",
        "https://127.0.0.1",
        "https://169.254.169.254/latest/meta-data",
        "https://attacker.example",
        "https://api.badgr.io@attacker.example",
        "https://api.badgr.io:not-a-port",
    ],
)
async def test_canvas_binding_rejects_untrusted_credentials_api_origins(
    unsafe_url: str,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="credentials-origin-platform",
        organization_id="org-123",
        canvas_account_id="account-1",
    )
    template = ApplicationTemplate(
        id="credentials-origin-template",
        organization_id="org-123",
        credential_template_id="credential-template-1",
    )
    secret = OrganizationIntegrationSecret(
        id="credentials-origin-secret",
        organization_id="org-123",
        provider="canvas_credentials",
        purpose="api_token",
        secret_value="secret-token",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_application_template(template)
    await repo.save_integration_secret(secret)

    with pytest.raises(HTTPException) as exc_info:
        await canvas_routes.create_canvas_program_binding(
            platform.id,
            canvas_routes.CanvasProgramBindingCreate(
                application_template_id=template.id,
                evidence_requirements=[{
                    "requirement_id": "course-completion",
                    "source": "canvas_rest",
                    "fact_type": "canvas.course_completion",
                    "scope": {"course_id": "course-101"},
                    "pass_rule": {"completed": True},
                }],
                canvas_credentials={
                    "provider": "badgr_api",
                    "api_base_url": unsafe_url,
                    "api_token_secret_id": secret.id,
                },
            ),
            trusted_organization_id="org-123",
            repo=repo,
        )

    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_canvas_binding_generates_ags_ids_and_fails_closed_before_readiness() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="activation-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
        lti_client_id="client-1",
        lti_deployment_id="deployment-1",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "canvas"}]},
    )
    template = ApplicationTemplate(
        id="activation-template",
        organization_id="org-1",
        credential_template_id="credential-template-1",
    )
    await repo.save_canvas_platform(platform)
    await repo.save_application_template(template)

    created = await canvas_routes.create_canvas_program_binding(
        platform.id,
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id=template.id,
            canvas_scope={"course_id": "101"},
            evidence_requirements=[
                {
                    "source": "ags_result",
                    "fact_type": "canvas.assignment_score",
                    "scope": {"course_id": "101"},
                    "pass_rule": {"min_score_percent": 80},
                }
            ],
        ),
        trusted_organization_id="org-1",
        repo=repo,
    )
    requirement = created.evidence_requirements[0]
    assert created.enabled is False
    assert requirement["requirement_id"].startswith("canvas_req_")
    assert requirement["scope"]["resource_id"].startswith(f"marty:{created.id}:")

    validation = await canvas_routes.validate_canvas_program_binding(
        created.id,
        trusted_organization_id="org-1",
        repo=repo,
    )
    assert validation.valid is False
    with pytest.raises(HTTPException) as activation_error:
        await canvas_routes.activate_canvas_program_binding(
            created.id,
            trusted_organization_id="org-1",
            repo=repo,
        )
    assert activation_error.value.status_code == 409
    assert (await repo.get_canvas_program_binding(created.id)).enabled is False
    deactivated = await canvas_routes.deactivate_canvas_program_binding(
        created.id,
        trusted_organization_id="org-1",
        repo=repo,
    )
    assert deactivated.active is False

    with pytest.raises(HTTPException) as exc_info:
        await canvas_routes.get_canvas_program_binding(
            created.id,
            trusted_organization_id="org-2",
            repo=repo,
        )
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_canvas_integration_secret_can_validate_canvas_credentials_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    monkeypatch.setenv("CANVAS_CREDENTIALS_PUBLISH_URL", "https://canvas-bridge.example/publish")

    secret = await canvas_routes.create_canvas_integration_secret(
        canvas_routes.CanvasIntegrationSecretCreate(
            organization_id="org-1",
            name="Canvas Credentials API token",
            provider="canvas_credentials",
            purpose="api_token",
            secret_value="canvas-secret-token",
        ),
        repo=repo,
    )

    assert secret.secret_ref == f"org_secret://org-1/{secret.id}"
    assert secret.secret_hint == "...oken"
    assert await repo.get_integration_secret_value("org-1", secret.id) == "canvas-secret-token"

    validation = await canvas_routes.validate_canvas_credentials_provider(
        request=canvas_routes.CanvasCredentialsValidationRequest(
            organization_id="org-1",
            canvas_credentials={
                "provider": "bridge",
                "api_token_secret_id": secret.id,
            }
        ),
        repo=repo,
    )

    assert validation.ok is True
    assert validation.token_configured is True


@pytest.mark.asyncio
async def test_validate_canvas_credentials_provider_reports_missing_bridge_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CANVAS_CREDENTIALS_PUBLISH_URL", raising=False)
    repo = InMemoryIssuanceRepository()
    secret = OrganizationIntegrationSecret(
        id="bridge-token",
        organization_id="org-1",
        name="Canvas bridge token",
        provider="canvas_credentials",
        purpose="api_token",
        secret_value="bridge-secret",
    )
    await repo.save_integration_secret(secret)

    response = await canvas_routes.validate_canvas_credentials_provider(
        request=canvas_routes.CanvasCredentialsValidationRequest(
            organization_id="org-1",
            canvas_credentials={
                "provider": "bridge",
                "api_token_secret_id": secret.id,
            },
        ),
        repo=repo,
    )

    assert response.ok is False
    assert response.provider == "bridge"
    assert "CANVAS_CREDENTIALS_PUBLISH_URL" in response.error


@pytest.mark.asyncio
async def test_discover_canvas_scope_uses_organization_oauth_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-discovery",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
    )
    await repo.save_canvas_platform(platform)
    access_secret = OrganizationIntegrationSecret(
        id="discovery-access-token",
        organization_id="org-123",
        provider="canvas",
        purpose="oauth_access_token",
        secret_value="canvas-token",
    )
    await repo.save_integration_secret(access_secret)
    await repo.save_canvas_oauth_connection(
        CanvasOAuthConnection(
            organization_id="org-123",
            platform_id=platform.id,
            canvas_base_url=str(platform.canvas_base_url),
            platform_config_version=platform.config_version,
            client_id="client-id",
            client_secret_ref="org_secret://org-123/client-secret",
            capabilities=["catalog"],
            scopes=canvas_routes.canvas_oauth_scopes_for_capabilities(["catalog"]),
            access_token_secret_ref=access_secret.secret_ref,
        )
    )
    calls: list[str] = []

    async def fake_fetch(
        _client,
        *,
        base_url: str,
        token: str,
        path: str,
        limit: int,
        **_kwargs,
    ) -> list[dict[str, object]]:
        assert base_url == "https://canvas.example.edu"
        assert token == "canvas-token"
        assert limit == 25
        calls.append(path)
        if path == "courses":
            return [{"id": 101, "name": "Interoperability 101"}]
        if path == "courses/101/assignments":
            return [
                {"id": 201, "name": "Badge assignment", "points_possible": 100, "published": True},
                {
                    "id": 302,
                    "name": "Badge Classic Quiz",
                    "quiz_id": 301,
                    "points_possible": 100,
                },
                {
                    "id": 303,
                    "name": "Badge New Quiz",
                    "is_quiz_assignment": True,
                    "points_possible": 100,
                },
            ]
        if path == "courses/101/modules":
            return [{"id": 401, "name": "Badge module", "workflow_state": "available"}]
        return []

    monkeypatch.setattr(canvas_routes, "_fetch_canvas_api_collection", fake_fetch)

    response = await canvas_routes.discover_canvas_scope(
        platform.id,
        request=canvas_routes.CanvasScopeDiscoveryRequest(
            course_id="101",
            limit=25,
        ),
        trusted_organization_id="org-123",
        repo=repo,
    )

    assert calls == [
        "courses",
        "courses/101/assignments",
        "courses/101/modules",
    ]
    assert response.courses[0].id == "101"
    assert response.assignments[0].name == "Badge assignment"
    assert [item.id for item in response.quizzes] == ["302", "303"]
    assert response.quizzes[0].name == "Badge Classic Quiz"
    assert response.modules[0].published is True


@pytest.mark.asyncio
async def test_discover_canvas_scope_requires_secret_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-discovery-no-token",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
    )
    await repo.save_canvas_platform(platform)
    monkeypatch.delenv("CANVAS_ADMIN_API_TOKEN", raising=False)
    monkeypatch.delenv("CANVAS_ADMIN_API_TOKEN_FILE", raising=False)

    with pytest.raises(HTTPException) as exc:
        await canvas_routes.discover_canvas_scope(
            platform.id,
            request=canvas_routes.CanvasScopeDiscoveryRequest(course_id="101"),
            trusted_organization_id="org-123",
            repo=repo,
        )

    assert exc.value.status_code == 400
    assert "organization OAuth connection" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_probe_canvas_platform_sandbox_persists_pinned_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
    )
    await repo.save_canvas_platform(platform)

    monkeypatch.setattr(
        canvas_routes,
        "probe_canvas_lti_platform",
        AsyncMock(return_value={
            "canvas_base_url": "https://canvas.example.edu",
            "lti_trust_profile": "hosted_global",
            "issuer": "https://canvas.instructure.com",
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
            "token_endpoint": "https://canvas.example.edu/login/oauth2/token",
            "jwks_uri": "https://sso.canvaslms.com/api/lti/security/jwks",
            "jwks_json": {"keys": [{"kid": "canvas-kid"}]},
            "raw_openid_configuration": {
                "issuer": "https://canvas.instructure.com",
                "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
                "token_endpoint": "https://canvas.example.edu/login/oauth2/token",
                "jwks_uri": "https://sso.canvaslms.com/api/lti/security/jwks",
            },
        }),
    )

    response = await canvas_routes.probe_canvas_platform_sandbox(platform.id, repo=repo)
    stored = await repo.get_canvas_platform(platform.id)

    assert response.platform.id == platform.id
    assert response.probe["issuer"] == "https://canvas.instructure.com"
    assert stored is not None
    assert stored.lti_issuer == "https://canvas.instructure.com"
    assert stored.lti_jwks_url == "https://sso.canvaslms.com/api/lti/security/jwks"
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
        canvas_base_url="https://canvas.example.edu",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
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
                "iss": "https://canvas.instructure.com",
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
    assert params["nonce"][0]

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
    assert response.context == {"course_id": "course-101", "label": "PORTABLE101"}
    assert response.roles == ["Learner"]
    public_payload = response.model_dump()
    for private_field in (
        "subject",
        "nonce",
        "state",
        "learner_identity",
        "raw_claims",
        "lti_capabilities",
        "target_link_uri",
    ):
        assert private_field not in public_payload


@pytest.mark.asyncio
async def test_canvas_lti_experience_launch_redirects_and_persists_session(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-lti",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
        display_name="Canvas Tenant",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
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
                "iss": "https://canvas.instructure.com",
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
    assert login_params["nonce"][0]
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
    code, session_token = await _exchange_experience_code(launch_response, repo)
    session = await canvas_routes.get_canvas_lti_experience_session_route(session_token, repo=repo)

    assert launch_response.status_code == 303
    assert launch_response.headers["location"] == f"https://app.example.edu/canvas/lti/experience?code={code}"
    assert session.status == "session"
    assert session.canvas_platform_id == platform.id
    assert session.canvas_program_binding_id == binding.id
    assert session.application_template_id == "application-template-lti"
    assert session.credential_template_id == "credential-template-lti"
    assert session.canvas_context == {
        "course_id": "course-101",
        "title": "Portable Trust 101",
    }
    assert session.lti_capabilities["assignment_grade_services"] is True
    assert session.learner_key
    assert session.identity_mapping_status == "numeric_id_unavailable"
    for private_field in ("state", "verified_launch", "mip_primitives", "subject", "nonce"):
        assert private_field not in session.model_dump()
    with pytest.raises(HTTPException, match="already used"):
        await canvas_routes.exchange_canvas_lti_experience_code_route(
            canvas_routes.CanvasLtiExperienceCodeExchangeRequest(code=code),
            response=Response(),
            repo=repo,
        )
    with pytest.raises(HTTPException, match="not found"):
        await canvas_routes.get_canvas_lti_experience_session_route(state, repo=repo)


@pytest.mark.asyncio
async def test_canvas_lti_deep_linking_response_signs_lti_resource_link(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-deep-link",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
        },
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-deep-link",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id="application-template-deep-link",
        credential_template_id="credential-template-deep-link",
        display_name="Portable Trust Credential",
        evidence_requirements=[
            {
                "requirement_id": "assignment-score",
                "source": "ags_result",
                "fact_type": "canvas.assignment_score",
                "scope": {"course_id": "course-101", "resource_id": "marty:assignment-score"},
                "pass_rule": {"min_score_percent": 80},
            }
        ],
        canvas_scope={"course_id": "course-101"},
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    jwk, public_key = _private_rsa_jwk()
    monkeypatch.setenv("CANVAS_LTI_TOOL_PRIVATE_JWKS", json.dumps(jwk))
    monkeypatch.setattr(canvas_routes, "ISSUER_BASE_URL", "https://issuer.example.com")
    monkeypatch.setattr(canvas_routes, "CANVAS_LTI_EXPERIENCE_BASE_URL", "https://app.example.edu")

    login_response = await canvas_routes.initiate_canvas_lti_experience_login_route(
        platform.id,
        request=_json_request(
            {
                "iss": "https://canvas.instructure.com",
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
                    "accept_presentation_document_targets": ["iframe", "window"],
                    "data": "opaque-canvas-data",
                },
            },
        },
    )

    launch = await canvas_routes.launch_canvas_lti_experience_route(
        platform.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )
    _code, session_token = await _exchange_experience_code(launch, repo)
    response = await canvas_routes.create_canvas_lti_deep_linking_response_route(
        session_token,
        request=canvas_routes.CanvasLtiDeepLinkingRequest(),
        repo=repo,
    )

    _verify_rs256_jwt_signature(response.jwt, public_key)
    header = json.loads(_b64url_decode(response.jwt.split(".")[0]))
    payload = _jwt_payload(response.jwt)
    stored_state = await repo.get_canvas_lti_launch_state(
        hashlib.sha256(session_token.encode("utf-8")).hexdigest()
    )

    assert header["kid"] == "tool-key-1"
    assert header["alg"] == "RS256"
    assert response.deep_link_return_url == "https://canvas.example.edu/deep-link-return"
    assert response.form_post["method"] == "POST"
    assert response.form_post["action"] == "https://canvas.example.edu/deep-link-return"
    assert response.form_post["fields"]["JWT"] == response.jwt
    assert payload["iss"] == "client-123"
    assert payload["aud"] == "https://canvas.instructure.com"
    assert payload[canvas_routes.LTI_MESSAGE_TYPE_CLAIM] == "LtiDeepLinkingResponse"
    assert payload[canvas_routes.LTI_DEEP_LINKING_DATA_CLAIM] == "opaque-canvas-data"
    assert payload[canvas_routes.LTI_DEPLOYMENT_ID_CLAIM] == "deployment-xyz"
    content_item = payload[canvas_routes.LTI_DEEP_LINKING_CONTENT_ITEMS_CLAIM][0]
    assert content_item == response.content_items[0]
    assert content_item["type"] == "ltiResourceLink"
    assert content_item["url"] == f"https://issuer.example.com/v1/integrations/canvas/lti/platforms/{platform.id}/experience"
    assert content_item["title"] == "Portable Trust Credential"
    assert content_item["custom"]["canvas_program_binding_id"] == binding.id
    assert content_item["custom"]["credential_template_id"] == "credential-template-deep-link"
    assert "canvas_lti_state" not in content_item["custom"]
    assert content_item["presentation"] == {
        "documentTarget": "window",
        "windowTarget": "_blank",
    }
    assert content_item["lineItem"]["resourceId"] == "marty:assignment-score"
    assert content_item["lineItem"]["tag"] == "marty:assignment-score"
    assert stored_state is not None
    assert stored_state.metadata["deep_linking_response"]["content_items"][0] == content_item


@pytest.mark.asyncio
async def test_canvas_lti_bootstrap_creates_and_replays_issuance_application(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-bootstrap",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
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
                "iss": "https://canvas.instructure.com",
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

    launch = await canvas_routes.launch_canvas_lti_experience_route(
        platform.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )
    _code, session_token = await _exchange_experience_code(launch, repo)

    first = await canvas_routes.bootstrap_canvas_lti_experience_application_route(
        session_token,
        request=canvas_routes.CanvasLtiApplicationBootstrapRequest(
            applicant_identifier="ada@example.com",
            applicant_data={"email": "ada@example.com"},
        ),
        repo=repo,
    )
    second = await canvas_routes.bootstrap_canvas_lti_experience_application_route(
        session_token,
        request=canvas_routes.CanvasLtiApplicationBootstrapRequest(
            applicant_identifier="ada@example.com",
            applicant_data={"email": "ada@example.com"},
        ),
        repo=repo,
    )
    app = await repo.get_application(first.application_id)
    session = await canvas_routes.get_canvas_lti_experience_session_route(session_token, repo=repo)
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
    assert "mip_primitives" not in session.model_dump()
    assert [event.event_type for event in events] == [EventType.CANVAS_LTI_APPLICATION_BOOTSTRAPPED]


@pytest.mark.asyncio
async def test_canvas_lti_evidence_sync_is_durable_and_worker_reads_ags(monkeypatch: pytest.MonkeyPatch) -> None:
    def deterministic_policy(**kwargs) -> EvidencePolicyDecision:
        return EvidencePolicyDecision(
            allowed=bool(kwargs["facts"]),
            engine="deterministic_test_policy",
        )

    # This test exercises durable AGS synchronization, not optional package
    # discovery. Keep its decision stable whether marty_common is installed or
    # was imported by another test module earlier in the process.
    monkeypatch.setattr(
        canvas_evidence_revisions,
        "evaluate_application_evidence_policy",
        deterministic_policy,
    )
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-portable-ags",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
            "token_endpoint": "https://canvas.example.edu/login/oauth2/token",
        },
    )
    requirement = {
        "requirement_id": "assignment-score",
        "source": "ags_result",
        "fact_type": "canvas.assignment_score",
        "scope": {
            "course_id": "course-101",
            "line_item_url": "https://canvas.example.edu/api/lti/courses/101/line_items/1",
        },
        "pass_rule": {"min_score_percent": 80},
    }
    template = ApplicationTemplate(
        id="application-template-portable-ags",
        organization_id="org-123",
        credential_template_id="credential-template-portable-ags",
        evidence_requirements=[requirement],
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-portable-ags",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id=template.id,
        credential_template_id="credential-template-portable-ags",
        evidence_requirements=[requirement],
        canvas_scope={"course_id": "course-101"},
    )
    await repo.save_canvas_platform(platform)
    await repo.save_application_template(template)
    await repo.save_canvas_program_binding(binding)
    jwk, _public_key = _private_rsa_jwk()
    monkeypatch.setenv("CANVAS_LTI_TOOL_PRIVATE_JWKS", json.dumps(jwk))
    monkeypatch.setattr(canvas_routes, "CANVAS_LTI_EXPERIENCE_BASE_URL", "https://app.example.edu")

    login = await canvas_routes.initiate_canvas_lti_experience_login_route(
        platform.id,
        request=_json_request({"iss": platform.lti_issuer, "login_hint": "hint", "client_id": platform.lti_client_id}),
        repo=repo,
    )
    state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
    monkeypatch.setattr(
        canvas_routes,
        "verify_canvas_lti_launch",
        lambda **kwargs: {
            "issuer": platform.lti_issuer,
            "subject": "student-123",
            "audience": [platform.lti_client_id],
            "deployment_id": platform.lti_deployment_id,
            "nonce": kwargs["expected_nonce"],
            "message_type": "LtiResourceLinkRequest",
            "lti_version": "1.3.0",
            "context": {"id": "course-101"},
            "roles": ["Learner"],
            "learner_identity": {"subject": "student-123", "email": "ada@example.com"},
            "raw_claims": {
                "sub": "student-123",
                canvas_routes.LTI_AGS_ENDPOINT_CLAIM: {
                    "lineitem": "https://canvas.example.edu/api/lti/courses/101/line_items/1",
                    "scope": [canvas_routes.AGS_RESULT_READ_SCOPE],
                },
            },
        },
    )
    launch = await canvas_routes.launch_canvas_lti_experience_route(
        platform.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )
    _code, session_token = await _exchange_experience_code(launch, repo)
    bootstrap = await canvas_routes.bootstrap_canvas_lti_experience_application_route(
        session_token,
        request=canvas_routes.CanvasLtiApplicationBootstrapRequest(
            applicant_identifier="ada@example.com",
            applicant_data={"email": "ada@example.com"},
        ),
        repo=repo,
    )

    async def fake_token(**_kwargs):
        return type("Token", (), {"value": "service-token"})()

    async def fake_results(**kwargs):
        assert kwargs["user_id"] == "student-123"
        return [{"id": "result-1", "userId": "student-123", "resultScore": 92, "resultMaximum": 100, "resultStatus": "FullyGraded"}]

    monkeypatch.setattr(canvas_routes, "request_lti_access_token", fake_token)
    monkeypatch.setattr(canvas_routes, "read_ags_results", fake_results)

    queued = await canvas_routes.sync_canvas_lti_evidence(
        session_token,
        response=Response(),
        repo=repo,
    )
    assert queued.sync is not None
    assert queued.sync.status == "queued"
    assert queued.evidence.status == "syncing"

    leased = await repo.lease_canvas_sync_jobs(
        worker_id="canvas-test-worker",
        limit=1,
    )
    assert len(leased) == 1
    target = await repo.get_canvas_sync_target_for_org("org-123", leased[0].target_id)
    assert target is not None
    first = await canvas_routes.process_authoritative_canvas_sync_target(repo, target)
    await complete_canvas_sync_job(
        repo=repo,
        job=leased[0],
        worker_id="canvas-test-worker",
        target_config_version=target.config_version,
        result=first,
    )

    queued_again = await canvas_routes.sync_canvas_lti_evidence(
        session_token,
        response=Response(),
        repo=repo,
    )
    assert queued_again.sync is not None
    assert queued_again.sync.status == "queued"
    leased_again = await repo.lease_canvas_sync_jobs(
        worker_id="canvas-test-worker",
        limit=1,
    )
    assert len(leased_again) == 1
    second = await canvas_routes.process_authoritative_canvas_sync_target(repo, target)
    await complete_canvas_sync_job(
        repo=repo,
        job=leased_again[0],
        worker_id="canvas-test-worker",
        target_config_version=target.config_version,
        result=second,
    )
    browser_status = await canvas_routes.get_canvas_lti_evidence_status(
        session_token,
        response=Response(),
        repo=repo,
    )
    facts = await repo.list_evidence_facts_for_application(bootstrap.application_id)
    heads = await repo.list_evidence_fact_heads_for_application(bootstrap.application_id)
    events = await repo.list_events_for_application(bootstrap.application_id)

    assert first["requirements_checked"] == 1
    assert first["facts_created"] == 1
    assert second["facts_reused"] == 1
    assert browser_status.sync is not None
    assert browser_status.sync.status == "succeeded"
    assert browser_status.evidence.status == "verified"
    assert browser_status.evidence.verified_authoritative_count == 1
    assert browser_status.evidence.verified_required_count == 1
    assert browser_status.policy.status == "permitted"
    assert len(facts) == 1
    assert facts[0].assertion["score_percent"] == 92
    assert facts[0].requirement_id == "assignment-score"
    assert facts[0].verification["status"] == "VERIFIED"
    assert facts[0].verification["method"] == "LTI_AGS_RESULT_READ"
    assert facts[0].payload_hash
    assert facts[0].source_revision == facts[0].payload_hash
    assert len(heads) == 1
    assert heads[0].fact_id == facts[0].id
    browser_payload = browser_status.model_dump()
    assert set(browser_payload) == {
        "application_status",
        "sync",
        "evidence",
        "policy",
        "claim",
    }
    serialized_browser_payload = json.dumps(browser_payload)
    for secret_or_raw_field in (
        "service-token",
        "student-123",
        "raw_claims",
        "assertion",
        "payload_hash",
        "line_item_url",
        "organization_id",
        "application_id",
    ):
        assert secret_or_raw_field not in serialized_browser_payload

    binding.config_version += 1
    await repo.save_canvas_program_binding(binding)
    stale_configuration = await canvas_routes.get_canvas_lti_evidence_status(
        session_token,
        response=Response(),
        repo=repo,
    )
    assert stale_configuration.evidence.status == "partial"
    assert stale_configuration.evidence.verified_authoritative_count == 0
    assert stale_configuration.evidence.verified_required_count == 0
    assert stale_configuration.policy.status == "not_evaluated"
    binding.config_version -= 1
    await repo.save_canvas_program_binding(binding)

    fact_events = [
        event for event in events if event.event_type == EventType.EVIDENCE_FACT_CREATED
    ]
    assert [event.metadata["fact_id"] for event in fact_events] == [facts[0].id]

    app = await repo.get_application(bootstrap.application_id)
    assert app is not None
    candidate = canvas_routes.CanvasAwardCandidate(
        organization_id=app.organization_id,
        platform_id=platform.id,
        binding_id=binding.id,
        candidate_key="portable-pending-claim",
        lti_subject="student-123",
        state=canvas_routes.CanvasAwardCandidateState.PENDING_CLAIM,
        application_id=app.id,
    )
    await repo.save_canvas_award_candidate(candidate)
    app.integration_context["canvas"]["canvas_award_candidate_id"] = candidate.id
    await repo.save_application(app)
    pending_claim = await canvas_routes.get_canvas_lti_evidence_status(
        session_token,
        response=Response(),
        repo=repo,
    )
    assert pending_claim.claim.status == "pending_claim"
    assert pending_claim.claim.unsigned is True
    assert pending_claim.claim.available is False
    assert candidate.id not in pending_claim.model_dump_json()

    app.status = canvas_routes.ApplicationStatus.APPROVED
    await repo.save_application(app)
    ready_to_claim = await canvas_routes.get_canvas_lti_evidence_status(
        session_token,
        response=Response(),
        repo=repo,
    )
    assert ready_to_claim.claim.status == "ready_to_claim"
    assert ready_to_claim.claim.unsigned is True
    assert ready_to_claim.claim.available is True

    # Even a corrupted server-side session/application join cannot cross the
    # organization boundary; the browser has no identifier with which to
    # select another application.
    app.organization_id = "foreign-org"
    await repo.save_application(app)
    with pytest.raises(HTTPException) as foreign_scope:
        await canvas_routes.get_canvas_lti_evidence_status(
            session_token,
            response=Response(),
            repo=repo,
        )
    assert foreign_scope.value.status_code == 404


@pytest.mark.asyncio
async def test_quarantined_numeric_identity_cannot_materialize_background_candidate() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-quarantined-candidate",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        lti_deployment_id="deployment-xyz",
        enabled=True,
    )
    template = ApplicationTemplate(
        id="application-template-quarantined-candidate",
        organization_id="org-123",
        credential_template_id="credential-template-quarantined-candidate",
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-quarantined-candidate",
        organization_id="org-123",
        platform_id=platform.id,
        application_template_id=template.id,
        credential_template_id=template.credential_template_id,
        evidence_requirements=[
            {
                "requirement_id": "assignment-score",
                "source": "canvas_rest",
                "fact_type": "canvas.assignment_score",
                "scope": {"course_id": "course-101", "activity_id": "assignment-7"},
                "pass_rule": {"min_score_percent": 80},
                "required": True,
            }
        ],
        canvas_scope={"course_id": "course-101"},
        enabled=True,
    )
    app = canvas_routes.Application(
        id="application-quarantined-candidate",
        organization_id="org-123",
        application_template_id=template.id,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_application_template(template)
    await repo.save_canvas_program_binding(binding)
    await repo.save_application(app)

    original_identity = await canvas_routes.link_verified_canvas_learner_identity(
        repo=repo,
        organization_id="org-123",
        platform_id=platform.id,
        deployment_id=platform.lti_deployment_id,
        lti_subject="student-original",
        canvas_user_id="42",
    )
    candidate = canvas_routes.CanvasAwardCandidate(
        organization_id="org-123",
        platform_id=platform.id,
        binding_id=binding.id,
        learner_identity_id=original_identity.id,
        candidate_key="canvas-user:42",
        canvas_user_id="42",
        lti_subject="student-original",
        state=canvas_routes.CanvasAwardCandidateState.PENDING_CLAIM,
    )
    await repo.save_canvas_award_candidate(candidate)
    await repo.save_canvas_candidate_observation(
        canvas_routes.CanvasCandidateObservation(
            organization_id="org-123",
            candidate_id=candidate.id,
            requirement_id="assignment-score",
            logical_key="assignment-score",
            assertion={"completed": True, "score_percent": 95},
            verification={"status": "VERIFIED", "method": "CANVAS_OAUTH_API_READ"},
            payload_hash="candidate-payload-95",
        )
    )

    conflicting_identity = await canvas_routes.link_verified_canvas_learner_identity(
        repo=repo,
        organization_id="org-123",
        platform_id=platform.id,
        deployment_id=platform.lti_deployment_id,
        lti_subject="student-conflict",
        canvas_user_id="42",
    )
    assert conflicting_identity.status == canvas_routes.CanvasLearnerIdentityStatus.QUARANTINED

    verified_launch = {
        "subject": "student-conflict",
        "deployment_id": platform.lti_deployment_id,
        "raw_claims": {
            "https://purl.imsglobal.org/spec/lti/claim/custom": {
                "canvas_user_id": "42",
            }
        },
    }
    await canvas_routes._materialize_canvas_award_candidate_on_launch(
        repo=repo,
        app=app,
        verified_launch=verified_launch,
        session_values={
            "canvas_platform_id": platform.id,
            "canvas_program_binding_id": binding.id,
        },
    )

    stored_candidate = (
        await repo.list_canvas_award_candidates("org-123", binding_id=binding.id)
    )[0]
    assert stored_candidate.application_id is None
    assert stored_candidate.lti_subject == "student-original"
    assert await repo.list_evidence_facts_for_application(app.id) == []


@pytest.mark.asyncio
async def test_verify_canvas_lti_launch_rejects_reused_state(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-reuse",
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        canvas_base_url="https://canvas.example.edu",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
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
        lti_issuer="https://canvas.instructure.com",
        lti_jwks_json={"keys": [{"kid": "old-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
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
        "probe_canvas_lti_platform",
        AsyncMock(return_value={
            "canvas_base_url": "https://canvas.example.edu",
            "lti_trust_profile": "hosted_global",
            "issuer": "https://canvas.instructure.com",
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
            "token_endpoint": "https://canvas.example.edu/login/oauth2/token",
            "jwks_uri": "https://sso.canvaslms.com/api/lti/security/jwks",
            "jwks_json": {"keys": [{"kid": "new-kid"}]},
            "raw_openid_configuration": {
                "issuer": "https://canvas.instructure.com",
                "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
                "token_endpoint": "https://canvas.example.edu/login/oauth2/token",
                "jwks_uri": "https://sso.canvaslms.com/api/lti/security/jwks",
            },
        }),
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
