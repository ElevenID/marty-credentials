"""Language-neutral behavior floor for native Canvas management migration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from issuance.application import canvas_lti_services
from issuance.application.application_approval import CredentialContext
from issuance.domain.entities import (
    Application,
    ApplicationTemplate,
    CanvasEventReceipt,
    CanvasPlatform,
    CanvasProgramBinding,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes
from pydantic import ValidationError
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-canvas-management.json").read_text(encoding="utf-8")
)
LTI_CONTRACT = json.loads(
    (ROOT / "contracts/issuance-canvas-lti-foundation.json").read_text(encoding="utf-8")
)
OAUTH_CONTRACT = json.loads(
    (ROOT / "contracts/issuance-canvas-oauth-lifecycle.json").read_text(encoding="utf-8")
)


def _route_tuple(route: dict[str, object]) -> tuple[str, str, str]:
    return str(route["method"]), str(route["path"]), str(route["operation"])


def _request(*, headers: list[tuple[bytes, bytes]] | None = None, body: bytes = b"") -> Request:
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
            "path": "/v1/integrations/canvas",
            "headers": headers or [],
        },
        receive,
    )


def _completion_requirement(course_id: str) -> canvas_routes.CanvasEvidenceRequirementInput:
    return canvas_routes.CanvasEvidenceRequirementInput(
        source="canvas_rest",
        fact_type="canvas.course_completion",
        scope=canvas_routes.CanvasEvidenceScopeInput(course_id=course_id),
        pass_rule=canvas_routes.CanvasEvidencePassRuleInput(completed=True),
    )


def test_canvas_management_route_surface_and_authentication_are_complete() -> None:
    assert CONTRACT["schema"] == "marty.issuance-canvas-management/v1"
    management_routes = {_route_tuple(route) for route in CONTRACT["scope"]["routes"]}
    assert len(management_routes) == CONTRACT["scope"]["route_count"] == 31

    # These three contracts partition the complete canvas_routes.py HTTP surface.
    # The public config route is intentionally shared by the LTI and management
    # contracts because this slice owns its token lifecycle and the LTI slice owns
    # its registration representation.
    expected_complete_surface = management_routes | {
        _route_tuple(route)
        for route in [*LTI_CONTRACT["scope"]["routes"], *OAUTH_CONTRACT["scope"]["routes"]]
    }
    observed_complete_surface: set[tuple[str, str, str]] = set()
    observed_by_operation = {}
    for route in canvas_routes.canvas_integration_router.routes:
        methods = set(route.methods) - {"HEAD", "OPTIONS"}
        assert len(methods) == 1
        item = (methods.pop(), route.path, route.endpoint.__name__)
        observed_complete_surface.add(item)
        observed_by_operation[route.endpoint.__name__] = route
    assert observed_complete_surface == expected_complete_surface

    for expected in CONTRACT["scope"]["routes"]:
        route = observed_by_operation[expected["operation"]]
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        authentication = expected["authentication"]
        if authentication == "management-api-key-and-trusted-organization":
            assert canvas_routes._verify_management_api_key in dependencies
            assert canvas_routes._trusted_canvas_organization_id in dependencies
        elif authentication == "public-revocable-token":
            assert canvas_routes._verify_management_api_key not in dependencies
            assert canvas_routes._trusted_canvas_organization_id not in dependencies
        else:
            assert authentication == "default-disabled-legacy-ingest"


def test_canvas_management_request_ownership_is_exact_and_fail_closed() -> None:
    ownership = CONTRACT["request_ownership"]
    assert ownership["extra_fields"] == "forbidden"
    for model_name, expected_fields in ownership["models"].items():
        model = getattr(canvas_routes, model_name)
        assert list(model.model_fields) == expected_fields
        assert model.model_config.get("extra") == "forbid"

    platform_payload = {"canvas_base_url": "https://canvas.example.edu"}
    for field in ownership["server_owned_platform_fields"]:
        with pytest.raises(ValidationError):
            canvas_routes.CanvasPlatformCreate.model_validate(
                {**platform_payload, field: "caller-owned"}
            )

    binding_payload = {
        "application_template_id": "application-template-1",
        "evidence_requirements": [
            {
                "source": "canvas_rest",
                "fact_type": "canvas.course_completion",
                "scope": {"course_id": "course-1"},
                "pass_rule": {"completed": True},
            }
        ],
    }
    for field in ownership["server_owned_binding_fields"]:
        with pytest.raises(ValidationError):
            canvas_routes.CanvasProgramBindingCreate.model_validate(
                {**binding_payload, field: "caller-owned"}
            )

    assert (
        list(
            canvas_routes.CanvasEvidenceRequirementInput.model_fields["source"].annotation.__args__
        )
        == ownership["allowed_evidence_sources"]
    )
    assert (
        list(
            canvas_routes.CanvasEvidenceRequirementInput.model_fields[
                "fact_type"
            ].annotation.__args__
        )
        == ownership["allowed_fact_types"]
    )
    assert (
        list(
            canvas_routes.CanvasProgramBindingCreate.model_fields[
                "delivery_mode"
            ].annotation.__args__
        )
        == ownership["allowed_delivery_modes"]
    )


def test_canvas_management_trusted_organization_boundary_is_exact() -> None:
    boundary = CONTRACT["management_boundary"]
    with pytest.raises(HTTPException) as missing:
        canvas_routes._trusted_canvas_organization_id(_request())
    assert (missing.value.status_code, missing.value.detail) == (
        boundary["missing_organization"]["status_code"],
        boundary["missing_organization"]["detail"],
    )

    trusted = canvas_routes._trusted_canvas_organization_id(
        _request(headers=[(b"x-organization-id", b"  org-1  ")])
    )
    assert trusted == "org-1"
    with pytest.raises(HTTPException) as forged:
        canvas_routes._management_organization_id(trusted, "org-2")
    assert (forged.value.status_code, forged.value.detail) == (
        boundary["claimed_organization_mismatch"]["status_code"],
        boundary["claimed_organization_mismatch"]["detail"],
    )


@pytest.mark.asyncio
async def test_platform_and_binding_configuration_replay_the_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", "")
    monkeypatch.setattr(
        canvas_lti_services.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    repo = InMemoryIssuanceRepository()
    platform_policy = CONTRACT["platform_lifecycle"]["create"]
    platform = await canvas_routes.create_canvas_platform(
        canvas_routes.CanvasPlatformCreate(
            display_name="Canvas Production",
            canvas_base_url="https://canvas.example.edu",
            lti_client_id="client-1",
            lti_deployment_id="deployment-1",
            enabled=True,
        ),
        trusted_organization_id="org-1",
        repo=repo,
    )
    assert platform.organization_id == "org-1"
    assert platform.canvas_account_id.startswith(platform_policy["canvas_account_id_prefix"])
    assert platform.enabled is platform_policy["enabled_before_successful_probe"]
    assert (
        platform.connection_config["enabled_intent"] is platform_policy["enabled_intent_persisted"]
    )
    assert platform.registration_status == platform_policy["initial_registration_status"]
    assert platform.config_version == platform_policy["initial_config_version"]

    await repo.save_application_template(
        ApplicationTemplate(
            id="application-template-1",
            organization_id="org-1",
            name="Canvas badge",
            credential_template_id="credential-template-1",
            status="ACTIVE",
        )
    )
    binding = await canvas_routes.create_canvas_program_binding(
        platform.id,
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-1",
            canvas_scope={"course_id": "course-1"},
            evidence_requirements=[_completion_requirement("course-1")],
        ),
        trusted_organization_id="org-1",
        repo=repo,
    )
    binding_policy = CONTRACT["program_binding"]
    assert binding.flow_mode == binding_policy["flow_mode"]
    assert binding.direct_issue_enabled is binding_policy["direct_issue_enabled"]
    assert binding.issuer_mode == binding_policy["issuer_mode"]
    assert binding.enabled is binding_policy["created_enabled"]
    assert binding.evidence_requirements[0]["requirement_id"].startswith(
        binding_policy["generated_requirement_id_prefix"]
    )

    stored_binding = await repo.get_canvas_program_binding(binding.id)
    assert stored_binding is not None
    stored_binding.enabled = True
    stored_binding.validated_config_version = stored_binding.config_version
    stored_binding.readiness_checks = [{"status": "ready"}]
    stored_binding.readiness_validated_at = stored_binding.updated_at
    stored_binding.activated_at = stored_binding.updated_at
    await repo.save_canvas_program_binding(stored_binding)

    updated = await canvas_routes.update_canvas_platform(
        platform.id,
        canvas_routes.CanvasPlatformCreate(
            display_name="Canvas Production",
            canvas_base_url="https://canvas.example.edu",
            lti_client_id="client-2",
            lti_deployment_id="deployment-1",
            enabled=True,
        ),
        trusted_organization_id="org-1",
        repo=repo,
    )
    assert updated.config_version == platform.config_version + 1
    invalidated = await repo.get_canvas_program_binding(binding.id)
    assert invalidated is not None
    for field in CONTRACT["platform_lifecycle"]["configuration_change"]["binding_fields_cleared"]:
        expected = False if field == "enabled" else ([] if field == "readiness_checks" else None)
        assert getattr(invalidated, field) == expected

    with pytest.raises(HTTPException) as foreign:
        await canvas_routes.get_canvas_platform(
            platform.id,
            trusted_organization_id="org-foreign",
            repo=repo,
        )
    assert foreign.value.status_code == CONTRACT["management_boundary"]["hidden_resource_status"]


@pytest.mark.asyncio
async def test_public_registration_token_is_digest_only_revocable_and_no_store() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-token",
        organization_id="org-1",
        canvas_account_id="account-1",
    )
    token = canvas_routes._issue_lti_config_token(platform)
    assert token not in json.dumps(platform.connection_config)
    await repo.save_canvas_platform(platform)

    http_response = Response()
    configuration = await canvas_routes.get_public_canvas_lti_config(
        token,
        response=http_response,
        repo=repo,
    )
    assert configuration["tool_id"] == "marty-portable-canvas-v1"
    assert (
        http_response.headers["Cache-Control"]
        == CONTRACT["registration"]["public_config"]["cache_control"]
    )

    canvas_routes._revoke_lti_config_token(platform)
    await repo.save_canvas_platform(platform)
    failure = CONTRACT["registration"]["public_config"]["invalid_revoked_archived_or_unknown"]
    with pytest.raises(HTTPException) as revoked:
        await canvas_routes.get_public_canvas_lti_config(
            token,
            response=Response(),
            repo=repo,
        )
    assert (revoked.value.status_code, revoked.value.detail) == (
        failure["status_code"],
        failure["detail"],
    )


@pytest.mark.asyncio
async def test_integration_secret_reference_and_tenant_privacy_replay_the_contract() -> None:
    repo = InMemoryIssuanceRepository()
    policy = CONTRACT["integration_secrets"]
    secret = await canvas_routes.create_canvas_integration_secret(
        canvas_routes.CanvasIntegrationSecretCreate(
            organization_id="org-1",
            name="Canvas Credentials token",
            provider="canvas_credentials",
            purpose="api_token",
            secret_value="super-secret-token",
        ),
        trusted_organization_id="org-1",
        repo=repo,
    )
    assert secret.secret_ref == policy["reference_format"].format(
        organization_id="org-1", secret_id=secret.id
    )
    assert secret.secret_hint == "...oken"
    serialized = secret.model_dump(mode="json")
    assert set(serialized).isdisjoint(policy["response_forbidden_fields"])
    assert "super-secret-token" not in json.dumps(serialized)
    assert await repo.get_integration_secret_value("org-1", secret.id) == "super-secret-token"

    with pytest.raises(HTTPException) as foreign:
        await canvas_routes.update_canvas_integration_secret(
            secret.id,
            canvas_routes.CanvasIntegrationSecretUpdate(name="stolen"),
            trusted_organization_id="org-foreign",
            repo=repo,
        )
    assert foreign.value.status_code == policy["wrong_tenant_status"]


@pytest.mark.asyncio
async def test_application_approval_uses_canonical_guard_and_redacts_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
    )
    binding = CanvasProgramBinding(
        id="binding-1",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id="template-1",
        credential_template_id="credential-template-1",
    )
    template = ApplicationTemplate(
        id="template-1",
        organization_id="org-1",
        name="Canvas badge",
        credential_template_id="credential-template-1",
        status="ACTIVE",
    )
    application = Application(
        id="application-1",
        organization_id="org-1",
        application_template_id=template.id,
        integration_context={
            "canvas": {
                "canvas_platform_id": platform.id,
                "canvas_program_binding_id": binding.id,
            }
        },
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    await repo.save_application_template(template)
    await repo.save_application(application)
    monkeypatch.setattr(canvas_routes, "_require_portable_canvas_pilot", lambda _org: None)

    policy = CONTRACT["application_approval"]
    captured: dict[str, object] = {}

    async def guard(**_kwargs):
        return CredentialContext(credential_type="OpenBadgeCredential")

    async def approve(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(id="transaction-1")

    monkeypatch.setattr(canvas_routes, "canvas_approval_credential_context", guard)
    monkeypatch.setattr(canvas_routes, "approve_application_for_issuance", approve)
    response = await canvas_routes.approve_canvas_application(
        application.id,
        canvas_routes.CanvasApplicationApprovalRequest(),
        trusted_organization_id="org-1",
        repo=repo,
    )
    assert response.status == policy["success"]["status"]
    assert captured["reviewer_id"] == policy["reviewer_id"]
    assert captured["review_notes"] == policy["default_review_notes"]
    assert captured["issuer_context_applier"] is canvas_routes.apply_required_remote_issuer_context

    async def signing_failure(**_kwargs):
        raise RuntimeError("remote signer bearer secret")

    monkeypatch.setattr(canvas_routes, "approve_application_for_issuance", signing_failure)
    failure = policy["not_ready"]
    with pytest.raises(HTTPException) as rejected:
        await canvas_routes.approve_canvas_application(
            application.id,
            canvas_routes.CanvasApplicationApprovalRequest(),
            trusted_organization_id="org-1",
            repo=repo,
        )
    assert (rejected.value.status_code, rejected.value.detail) == (
        failure["status_code"],
        failure["detail"],
    )
    assert "secret" not in str(rejected.value.detail).lower()


@pytest.mark.asyncio
async def test_legacy_ingest_and_event_status_replay_the_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = CONTRACT["legacy_ingest"]
    monkeypatch.delenv(legacy["environment_switch"], raising=False)
    repo = InMemoryIssuanceRepository()
    for operation in legacy["routes"]:
        handler = getattr(canvas_routes, operation)
        with pytest.raises(HTTPException) as gone:
            await handler(request=_request(body=b"{}"), response=Response(), repo=repo)
        assert gone.value.status_code == legacy["disabled_status_code"]

    await repo.save_canvas_event_receipt(
        CanvasEventReceipt(
            provider_event_id="event-1",
            organization_id="org-1",
            canvas_account_id="account-1",
            credential_template_id="credential-template-1",
            payload_hash="payload-hash",
            issuance_response={
                "evidence_facts": [{"type": "canvas.course_completion"}],
                "policy_decision": {"permitted": True},
            },
        )
    )
    failure = CONTRACT["event_status"]["missing_or_foreign"]
    with pytest.raises(HTTPException) as hidden:
        await canvas_routes.get_canvas_evidence_event_status(
            "account-1", "event-1", trusted_organization_id="org-foreign", repo=repo
        )
    assert (hidden.value.status_code, hidden.value.detail) == (
        failure["status_code"],
        failure["detail"],
    )
    owned = await canvas_routes.get_canvas_evidence_event_status(
        "account-1", "event-1", trusted_organization_id="org-1", repo=repo
    )
    serialized = owned.model_dump(mode="json")
    assert set(CONTRACT["event_status"]["response_includes"]).issubset(serialized)
    assert owned.replay_available is True
