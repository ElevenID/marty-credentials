"""Language-neutral behavior floor for the native Canvas/LTI migration."""

from __future__ import annotations

import hashlib
import inspect
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

from issuance.application.canvas_lti_services import canvas_lti_trust_profile  # noqa: E402
from issuance.application.mip_integration_primitives import (  # noqa: E402
    canvas_lti_experience_exchange_metadata,
    canvas_lti_experience_handoff,
)
from issuance.domain.entities import (  # noqa: E402
    CanvasLtiLaunchState,
    CanvasPlatform,
    CanvasProgramBinding,
)
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
    assert (
        session.platform_id,
        session.organization_id,
        session.canvas_account_id,
        session.redirect_uri,
    ) == (
        code.platform_id,
        code.organization_id,
        code.canvas_account_id,
        code.redirect_uri,
    )
    assert session.metadata["kind"] == "canvas_lti_experience_session"
    assert session.metadata["experience_code_id"] == code.id
    spent_code = await repo.get_canvas_lti_launch_state(code.state)
    assert spent_code is not None
    assert spent_code.metadata["kind"] == "canvas_lti_experience_code_consumed"
    assert "verified_launch" not in spent_code.metadata
    assert "mip_primitives" not in spent_code.metadata
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


def test_canvas_experience_exchange_metadata_replays_the_complete_contract() -> None:
    policy = CONTRACT["experience"]["exchange"]
    vector = policy["vector"]
    session_metadata, spent_code_metadata = canvas_lti_experience_exchange_metadata(
        vector["code_metadata"],
        experience_code_id=vector["experience_code_id"],
        session_id=vector["session_id"],
        session_created_at=vector["session_created_at"],
    )

    assert hashlib.sha256(vector["session_token"].encode("utf-8")).hexdigest() == vector[
        "expected_session_state"
    ]
    assert session_metadata == vector["expected_session_metadata"]
    assert spent_code_metadata == vector["expected_spent_code_metadata"]
    assert vector["expected_response"] == {
        "session_token": vector["session_token"],
        "expires_at": vector["session_expires_at"],
    }
    assert policy["request"]["schema_failure_status"] == 422
    assert policy["persistence_order"] == ["session", "redacted-spent-code"]
    assert policy["response_after_both_persistence_writes"] is True
    assert len(policy["ordered_stages"]) == 11


@pytest.mark.asyncio
async def test_canvas_experience_current_session_replays_the_complete_contract() -> None:
    policy = CONTRACT["experience"]["session_current"]
    vector = policy["vector"]
    stored = vector["stored_session"]
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/integrations/canvas/lti/experience-sessions/current",
            "headers": [(b"authorization", vector["authorization"].encode("ascii"))],
        }
    )
    token = canvas_routes._lti_session_bearer_token(request)
    assert token == vector["normalized_token"]
    assert hashlib.sha256(token.encode("utf-8")).hexdigest() == vector["expected_state_digest"]

    repo = InMemoryIssuanceRepository()
    session = CanvasLtiLaunchState(
        id=stored["id"],
        state=vector["expected_state_digest"],
        platform_id=stored["platform_id"],
        organization_id=stored["organization_id"],
        canvas_account_id=stored["canvas_account_id"],
        status=stored["status"],
        metadata=stored["metadata"],
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
    )
    await repo.save_canvas_lti_launch_state(session)
    response = await canvas_routes.get_canvas_lti_experience_session_route(token, repo=repo)

    assert response.model_dump(mode="json") == vector["expected_response"]
    assert response.learner_key == vector["expected_learner_key"]
    assert await repo.get_canvas_lti_launch_state(token) is None
    for field in policy["browser_safe"]["private_response_fields_forbidden"]:
        assert field not in response.model_dump(mode="json")

    missing = policy["lookup"]["failure"]
    with pytest.raises(HTTPException) as unknown:
        await canvas_routes.get_canvas_lti_experience_session_route("unknown-token", repo=repo)
    assert (unknown.value.status_code, unknown.value.detail) == (
        missing["status_code"],
        missing["detail"],
    )

    invalid_conditions = policy["lookup"]["required"][1:]
    for condition in invalid_conditions:
        invalid_repo = InMemoryIssuanceRepository()
        invalid_token = f"invalid-session-token-{condition}"
        metadata = json.loads(json.dumps(stored["metadata"]))
        status = "session"
        expires_at = datetime(2099, 1, 1, tzinfo=UTC)
        if condition == "status-session":
            status = "pending"
        elif condition == "unexpired":
            expires_at = datetime(2000, 1, 1, tzinfo=UTC)
        elif condition == "kind-canvas-lti-experience-session":
            metadata["kind"] = "canvas_lti_experience_code"
        elif condition == "verified-launch-object":
            metadata["verified_launch"] = []
        elif condition == "mip-primitives-object":
            metadata["mip_primitives"] = None
        else:  # pragma: no cover - contract additions must add an explicit mutation
            raise AssertionError(f"unhandled session condition: {condition}")
        await invalid_repo.save_canvas_lti_launch_state(
            CanvasLtiLaunchState(
                state=hashlib.sha256(invalid_token.encode("utf-8")).hexdigest(),
                platform_id=stored["platform_id"],
                organization_id=stored["organization_id"],
                canvas_account_id=stored["canvas_account_id"],
                status=status,
                metadata=metadata,
                expires_at=expires_at,
            )
        )
        with pytest.raises(HTTPException) as invalid:
            await canvas_routes.get_canvas_lti_experience_session_route(
                invalid_token,
                repo=invalid_repo,
            )
        assert (invalid.value.status_code, invalid.value.detail) == (
            missing["status_code"],
            missing["detail"],
        )


def test_canvas_experience_current_session_bearer_failures_match_the_contract() -> None:
    failure = CONTRACT["experience"]["session_current"]["authentication"]["failure"]
    headers = [
        [],
        [(b"authorization", b"Bearer")],
        [(b"authorization", b"Basic token")],
        [(b"authorization", b"Bearer   ")],
    ]
    for values in headers:
        request = Request(
            {"type": "http", "method": "GET", "path": "/", "headers": values}
        )
        with pytest.raises(HTTPException) as rejected:
            canvas_routes._lti_session_bearer_token(request)
        assert (rejected.value.status_code, rejected.value.detail, rejected.value.headers) == (
            failure["status_code"],
            failure["detail"],
            failure["headers"],
        )


def test_canvas_experience_callback_handoff_replays_the_contract() -> None:
    policy = CONTRACT["experience"]["callback"]
    vector = policy["handoff_vector"]
    code_metadata, consumed_metadata = canvas_lti_experience_handoff(
        SimpleNamespace(**vector["platform"]),
        launch_state=vector["launch_state"],
        verified_launch=vector["verified_launch"],
        launch_url=vector["launch_url"],
        existing_launch_metadata=vector["existing_launch_metadata"],
        experience_code_id=vector["experience_code_id"],
        experience_code_expires_at=vector["experience_code_expires_at"],
    )

    assert code_metadata == {
        "kind": policy["code_record"]["metadata_kind"],
        "launch_state": vector["launch_state"],
        "verified_launch": vector["verified_launch"],
        "mip_primitives": vector["expected_mip_primitives"],
        "launch_url": vector["launch_url"],
    }
    assert consumed_metadata == vector["expected_consumed_state_metadata"]
    assert policy["redirect_only_after_both_persistence_writes"] is True


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


@pytest.mark.asyncio
async def test_canvas_lti_launch_submission_failures_replay_the_contract() -> None:
    failures = {
        failure["name"]: failure for failure in CONTRACT["launch"]["submission"]["failures"]
    }
    cases = [
        ("id_token_missing", {"state": "state-1"}),
        ("state_missing", {"id_token": "header.payload.signature"}),
        ("id_token_missing", {"id_token": 7, "state": "state-1"}),
        ("state_missing", {"id_token": "header.payload.signature", "state": False}),
    ]
    for failure_name, payload in cases:
        with pytest.raises(HTTPException) as rejected:
            await canvas_routes._parse_lti_launch_submission(
                _json_request(payload, "/v1/integrations/canvas/lti/platforms/platform-1/launch")
            )
        expected = failures[failure_name]
        assert (rejected.value.status_code, rejected.value.detail) == (
            expected["status_code"],
            expected["detail"],
        )


def test_canvas_lti_public_launch_projection_replays_the_contract() -> None:
    vector = CONTRACT["launch"]["public_response_vector"]
    platform = CanvasPlatform(**vector["platform"])
    binding = CanvasProgramBinding(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        **vector["binding"],
    )
    private_response = canvas_routes._lti_launch_response(
        platform=platform,
        binding=binding,
        state="private-state",
        verified=vector["verified"],
    )
    public_response = canvas_routes._public_lti_launch_response(private_response).model_dump()

    assert public_response == vector["expected"]
    for field in CONTRACT["launch"]["private_response_fields"]:
        assert field not in public_response


@pytest.mark.asyncio
async def test_canvas_lti_identity_mapping_replays_the_contract() -> None:
    identity_contract = CONTRACT["launch"]["identity_mapping"]
    cases = {case["name"]: case for case in identity_contract["cases"]}
    repo = InMemoryIssuanceRepository()
    values = {
        "organization_id": "org-1",
        "platform_id": "platform-1",
        "deployment_id": "deployment-1",
    }

    subject_case = cases["subject_is_recorded_before_numeric_id_is_available"]
    subject_only = await canvas_routes.record_verified_canvas_lti_subject(
        repo=repo,
        lti_subject=subject_case["subject"],
        **values,
    )
    assert subject_only.status.value == subject_case["expected_status"]
    assert subject_only.canvas_user_id == subject_case["canvas_user_id"]

    enrich_case = cases["subject_only_record_is_enriched_in_place"]
    linked = await canvas_routes.link_verified_canvas_learner_identity(
        repo=repo,
        lti_subject=enrich_case["subject"],
        canvas_user_id=enrich_case["canvas_user_id"],
        **values,
    )
    if enrich_case["preserve_subject_record_id"]:
        assert linked.id == subject_only.id
    assert linked.status.value == enrich_case["expected_status"]

    repeated_case = cases["same_verified_pair_is_idempotent"]
    repeated = await canvas_routes.link_verified_canvas_learner_identity(
        repo=repo,
        lti_subject=repeated_case["subject"],
        canvas_user_id=repeated_case["canvas_user_id"],
        **values,
    )
    if repeated_case["preserve_subject_record_id"]:
        assert repeated.id == subject_only.id
    assert repeated.status.value == repeated_case["expected_status"]

    conflict_case = cases["numeric_id_cannot_move_to_another_subject"]
    conflict = await canvas_routes.link_verified_canvas_learner_identity(
        repo=repo,
        lti_subject=conflict_case["subject"],
        canvas_user_id=conflict_case["canvas_user_id"],
        **values,
    )
    assert conflict.status.value == conflict_case["expected_status"]
    assert linked.status.value == conflict_case["existing_status"]
    assert conflict.conflict_reason == conflict_case["reason"]

    for name in (
        "quarantined_pair_cannot_reactivate",
        "quarantined_numeric_id_cannot_move_to_a_third_subject",
    ):
        sticky_case = cases[name]
        sticky = await canvas_routes.link_verified_canvas_learner_identity(
            repo=repo,
            lti_subject=sticky_case["subject"],
            canvas_user_id=sticky_case["canvas_user_id"],
            **values,
        )
        assert sticky.status.value == sticky_case["expected_status"]

    identities = list(repo._canvas_learner_identities.values())
    assert len(identities) == 3
    assert all(
        identity.status.value == identity_contract["conflict"]["stored_status"]
        for identity in identities
    )

    link_parameters = inspect.signature(
        canvas_routes.link_verified_canvas_learner_identity
    ).parameters
    assert identity_contract["forbidden_join_fields"] == ["email"]
    assert "email" not in link_parameters


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
