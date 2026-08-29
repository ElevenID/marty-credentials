"""Language-neutral behavior floor for the native Canvas/LTI migration."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

from issuance.application.canvas_lti_services import canvas_lti_trust_profile  # noqa: E402
from issuance.domain.entities import CanvasLtiLaunchState, CanvasPlatform  # noqa: E402
from issuance.infrastructure.adapters.memory_repository import (  # noqa: E402
    InMemoryIssuanceRepository,
)
from issuance.infrastructure.api import canvas_routes  # noqa: E402

CONTRACT = json.loads(
    (ROOT / "contracts/issuance-canvas-lti-foundation.json").read_text(encoding="utf-8")
)


def _route_authentication(route) -> str:
    dependencies = {dependency.call for dependency in route.dependant.dependencies}
    if canvas_routes._lti_session_bearer_token in dependencies:
        return "lti-session-bearer"
    assert canvas_routes._verify_management_api_key not in dependencies
    assert canvas_routes._trusted_canvas_organization_id not in dependencies
    return CONTRACT_ROUTE_AUTH[route.endpoint.__name__]


CONTRACT_ROUTE_AUTH = {
    route["operation"]: route["authentication"] for route in CONTRACT["scope"]["routes"]
}


def _json_request(payload: dict[str, object], path: str) -> Request:
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


def _ready_platform() -> CanvasPlatform:
    trust = CONTRACT["hosted_global_trust"]
    return CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url=trust["canvas_origin"],
        lti_client_id="client-1",
        lti_deployment_id="deployment-1",
        lti_issuer=trust["issuer"],
        lti_jwks_url=trust["jwks_uri"],
        lti_jwks_json={"keys": []},
        lti_openid_configuration={
            "authorization_endpoint": trust["authorization_endpoint"],
            "token_endpoint": trust["token_endpoint"],
            "jwks_uri": trust["jwks_uri"],
        },
    )


def test_canvas_lti_route_and_authentication_surface_is_frozen() -> None:
    expected = {
        (route["method"], route["path"], route["operation"], route["authentication"])
        for route in CONTRACT["scope"]["routes"]
    }
    observed = set()
    for route in canvas_routes.canvas_integration_router.routes:
        if not route.path.startswith(CONTRACT["scope"]["route_prefix"]):
            continue
        methods = set(route.methods) - {"HEAD", "OPTIONS"}
        assert len(methods) == 1
        observed.add(
            (
                methods.pop(),
                route.path,
                route.endpoint.__name__,
                _route_authentication(route),
            )
        )

    assert CONTRACT["schema"] == "marty.issuance-canvas-lti-foundation/v1"
    assert len(observed) == CONTRACT["scope"]["route_count"] == 12
    assert observed == expected


def test_canvas_hosted_global_trust_profile_is_exact() -> None:
    expected = CONTRACT["hosted_global_trust"]
    observed = canvas_lti_trust_profile(expected["canvas_origin"], expected["profile"])
    assert observed == {
        "trust_profile": expected["profile"],
        "environment": expected["environment"],
        "issuer": expected["issuer"],
        "authorization_endpoint": expected["authorization_endpoint"],
        "jwks_uri": expected["jwks_uri"],
        "token_endpoint": expected["token_endpoint"],
    }

    platform = CanvasPlatform(
        canvas_base_url=expected["canvas_origin"],
        lti_openid_configuration={
            "authorization_endpoint": "https://attacker.example/authorize",
            "token_endpoint": expected["token_endpoint"],
        },
    )
    with pytest.raises(HTTPException) as rejected:
        canvas_routes._lti_authorization_endpoint(platform)
    assert rejected.value.status_code == expected["metadata_drift_status"]


def test_canvas_registration_shape_is_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(canvas_routes, "ISSUER_BASE_URL", "https://issuer.example.edu")
    registration_contract = CONTRACT["registration"]
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
    )
    registration = canvas_routes._canvas_lti_registration(
        platform, config_token="opaque.config-token"
    )
    configuration = registration.developer_key_configuration
    installation = registration.installation

    assert configuration["tool_id"] == registration_contract["tool_id"]
    assert installation["method"] == registration_contract["installation_method"]
    assert configuration["custom_fields"] == registration_contract["server_owned_custom_fields"]
    extension = configuration["extensions"][0]
    assert extension["platform"] == registration_contract["platform"]
    assert extension["privacy_level"] == registration_contract["privacy_level"]
    assert [
        {"placement": item["placement"], "message_type": item["message_type"]}
        for item in extension["settings"]["placements"]
    ] == registration_contract["placements"]
    assert installation["config_url"].endswith(
        "/v1/integrations/canvas/lti/config/opaque.config-token"
    )


@pytest.mark.asyncio
async def test_canvas_lti_login_redirect_replays_the_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = _ready_platform()
    await repo.save_canvas_platform(platform)
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", platform.organization_id)
    monkeypatch.setattr(canvas_routes, "ISSUER_BASE_URL", "https://issuer.example.edu")

    response = await canvas_routes.initiate_canvas_lti_login_route(
        platform.id,
        _json_request(
            {
                "iss": platform.lti_issuer,
                "client_id": platform.lti_client_id,
                "login_hint": "opaque-login-hint",
                "target_link_uri": "https://issuer.example.edu/experience",
                "lti_message_hint": "opaque-message-hint",
            },
            f"/v1/integrations/canvas/lti/platforms/{platform.id}/login",
        ),
        repo,
    )
    assert response.status_code == CONTRACT["login"]["success"]["status_code"]
    location = urlparse(response.headers["location"])
    assert (
        f"{location.scheme}://{location.netloc}{location.path}"
        == CONTRACT["hosted_global_trust"]["authorization_endpoint"]
    )
    parameters = parse_qs(location.query)
    for key, value in CONTRACT["login"]["success"]["authorization_parameters"].items():
        assert parameters[key] == [value]
    assert parameters["client_id"] == [platform.lti_client_id]
    assert parameters["login_hint"] == ["opaque-login-hint"]
    assert parameters["lti_message_hint"] == ["opaque-message-hint"]
    assert len(parameters["state"][0]) == 43
    assert len(parameters["nonce"][0]) == 43
    stored = await repo.get_canvas_lti_launch_state(parameters["state"][0])
    assert stored is not None
    assert stored.nonce == parameters["nonce"][0]
    assert stored.platform_id == platform.id
    assert stored.status == "pending"

    missing_hint = next(
        failure
        for failure in CONTRACT["login"]["failures"]
        if failure["name"] == "login_hint_missing"
    )
    with pytest.raises(HTTPException) as rejected:
        await canvas_routes.initiate_canvas_lti_login_route(
            platform.id,
            _json_request({}, f"/v1/integrations/canvas/lti/platforms/{platform.id}/login"),
            repo,
        )
    assert (rejected.value.status_code, rejected.value.detail) == (
        missing_hint["status_code"],
        missing_hint["detail"],
    )


@pytest.mark.asyncio
async def test_canvas_experience_exchange_replays_the_contract() -> None:
    repo = InMemoryIssuanceRepository()
    code = CanvasLtiLaunchState(
        state="c" * 43,
        platform_id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
        metadata={"kind": "canvas_lti_experience_code", "launch_state": "launch-1"},
    )
    await repo.save_canvas_lti_launch_state(code)
    http_response = Response()
    exchanged = await canvas_routes.exchange_canvas_lti_experience_code_route(
        canvas_routes.CanvasLtiExperienceCodeExchangeRequest(code=code.state),
        http_response,
        repo,
    )
    assert {
        key: http_response.headers[key] for key in CONTRACT["experience"]["exchange_cache_headers"]
    } == CONTRACT["experience"]["exchange_cache_headers"]
    assert len(exchanged.session_token) == 43
    session_digest = hashlib.sha256(exchanged.session_token.encode("utf-8")).hexdigest()
    assert await repo.get_canvas_lti_launch_state(exchanged.session_token) is None
    session = await repo.get_canvas_lti_launch_state(session_digest)
    assert session is not None
    assert session.status == "session"
    expires_at = datetime.fromisoformat(exchanged.expires_at)
    remaining_minutes = (expires_at - datetime.now(UTC)).total_seconds() / 60
    assert (
        CONTRACT["experience"]["session_ttl_minutes"] - 1
        < remaining_minutes
        <= CONTRACT["experience"]["session_ttl_minutes"]
    )

    invalid = CONTRACT["experience"]["invalid_code"]
    with pytest.raises(HTTPException) as replayed:
        await canvas_routes.exchange_canvas_lti_experience_code_route(
            canvas_routes.CanvasLtiExperienceCodeExchangeRequest(code=code.state),
            Response(),
            repo,
        )
    assert (replayed.value.status_code, replayed.value.detail) == (
        invalid["status_code"],
        invalid["detail"],
    )


def test_canvas_lti_security_and_lifetime_constants_are_frozen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CONTRACT["launch"]["jwt"]["algorithm_policy"] == ("protected-header-and-matching-jwk")
    assert CONTRACT["launch"]["jwt"]["algorithm_compatibility"] == (
        "preserve-marty-oid4vci-verifier-set"
    )
    assert sorted(canvas_routes._RSA_PRIVATE_JWK_FIELDS) == sorted(
        CONTRACT["tool_signing"]["private_jwk_fields_forbidden"]
    )
    assert (
        CONTRACT["experience"]["code_ttl_seconds"]
        == canvas_routes.CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS
    )
    assert (
        CONTRACT["experience"]["session_ttl_minutes"]
        == canvas_routes.CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES
    )
    assert CONTRACT["session_authentication"]["token_in_url"] is False
    assert CONTRACT["session_authentication"]["plaintext_persisted"] is False

    monkeypatch.delenv("CANVAS_LEGACY_EVENT_INGEST_ENABLED", raising=False)
    assert CONTRACT["legacy_event_ingest"] == {
        "default": "disabled",
        "status_code": 410,
        "operations": [
            "process_canvas_evidence_event_route",
            "process_canvas_ags_score_event_route",
            "process_canvas_nrps_membership_event_route",
        ],
    }


def test_canvas_config_token_is_platform_bound_and_fail_closed() -> None:
    platform = CanvasPlatform(id="platform-1")
    token = canvas_routes._issue_lti_config_token(platform)
    prefix, secret = token.split(".", 1)
    assert prefix and secret
    assert canvas_routes._platform_id_from_lti_config_token(token) == platform.id
    assert len(secret) == 43
    assert platform.connection_config["lti_config_token_status"] == "active"
    assert len(platform.connection_config["lti_config_token_hash"]) == 64
    assert token not in json.dumps(platform.connection_config)
    assert canvas_routes._platform_id_from_lti_config_token("not-a-token") is None

    canvas_routes._revoke_lti_config_token(platform)
    assert "lti_config_token_hash" not in platform.connection_config
    assert platform.connection_config["lti_config_token_status"] == "revoked"
