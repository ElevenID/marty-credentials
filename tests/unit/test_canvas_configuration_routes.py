"""Tests for Canvas platform and program binding configuration APIs."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

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

from issuance.application import canvas_lti_services
from issuance.domain.entities import ApplicationTemplate
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes


def test_private_canvas_origin_requires_exact_operator_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "https://canvas.internal.example"
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("CANVAS_ALLOW_PRIVATE_BASE_URLS", "false")
    monkeypatch.setenv("CANVAS_PRIVATE_ORIGIN_ALLOWLIST", origin)
    monkeypatch.setattr(
        canvas_lti_services.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("10.10.0.8", 443))],
    )

    assert canvas_routes._normalize_canvas_base_url_or_none(origin) == origin

    monkeypatch.setenv("CANVAS_PRIVATE_ORIGIN_ALLOWLIST", "")
    with pytest.raises(HTTPException) as exc_info:
        canvas_routes._normalize_canvas_base_url_or_none(origin)
    assert exc_info.value.status_code == 400
    assert "exact CANVAS_PRIVATE_ORIGIN_ALLOWLIST" in str(exc_info.value.detail)


async def _save_template(
    repo: InMemoryIssuanceRepository,
    *,
    template_id: str,
    credential_template_id: str,
) -> ApplicationTemplate:
    template = ApplicationTemplate(
        id=template_id,
        organization_id="org-123",
        name=template_id,
        credential_template_id=credential_template_id,
        evidence_requirements=["canvas.course_completion"],
    )
    await repo.save_application_template(template)
    return template


def _course_completion_requirement(course_id: str) -> canvas_routes.CanvasEvidenceRequirementInput:
    return canvas_routes.CanvasEvidenceRequirementInput(
        source="canvas_rest",
        fact_type="canvas.course_completion",
        scope=canvas_routes.CanvasEvidenceScopeInput(course_id=course_id),
        pass_rule=canvas_routes.CanvasEvidencePassRuleInput(completed=True),
    )


async def _create_platform(
    repo: InMemoryIssuanceRepository,
    *,
    display_name: str | None = None,
) -> canvas_routes.CanvasPlatformResponse:
    return await canvas_routes.create_canvas_platform(
        canvas_routes.CanvasPlatformCreate(
            display_name=display_name,
            canvas_base_url="https://canvas.example.edu",
            lti_client_id="canvas-client-1",
            lti_deployment_id="canvas-deployment-1",
            enabled=True,
        ),
        trusted_organization_id="org-123",
        repo=repo,
    )


@pytest.mark.asyncio
async def test_platform_persists_operator_selected_self_managed_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "https://canvas-test.elevenidllc.com"
    monkeypatch.setenv("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", origin)
    monkeypatch.setattr(
        canvas_lti_services.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    repo = InMemoryIssuanceRepository()

    response = await canvas_routes.create_canvas_platform(
        canvas_routes.CanvasPlatformCreate(
            canvas_base_url=origin,
            lti_client_id="canvas-client-1",
            lti_deployment_id="deployment-1",
            enabled=True,
        ),
        trusted_organization_id="org-123",
        repo=repo,
    )
    stored = await repo.get_canvas_platform(response.id)

    assert response.lti_trust_profile == "self_managed_same_origin"
    assert stored is not None
    assert stored.lti_trust_profile == "self_managed_same_origin"

    stored.lti_issuer = origin
    stored.enabled = True
    stored.lti_jwks_url = f"{origin}/api/lti/security/jwks"
    stored.lti_jwks_json = {"keys": [{"kid": "canvas-key"}]}
    stored.lti_openid_configuration = {
        "issuer": origin,
        "authorization_endpoint": f"{origin}/api/lti/authorize_redirect",
        "token_endpoint": f"{origin}/login/oauth2/token",
        "jwks_uri": f"{origin}/api/lti/security/jwks",
    }
    assert canvas_routes._lti_authorization_endpoint(stored) == (
        f"{origin}/api/lti/authorize_redirect"
    )
    assert canvas_routes._lti_token_endpoint(stored) == (
        f"{origin}/login/oauth2/token"
    )

    monkeypatch.setenv("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", "")
    with pytest.raises(HTTPException) as exc_info:
        canvas_routes._validate_lti_ready_platform(stored)
    assert exc_info.value.status_code == 409
    assert "not permitted" in str(exc_info.value.detail)


async def test_canvas_platform_supports_multiple_program_bindings() -> None:
    repo = InMemoryIssuanceRepository()
    await _save_template(repo, template_id="application-template-1", credential_template_id="credential-template-1")
    await _save_template(repo, template_id="application-template-2", credential_template_id="credential-template-2")

    platform = await _create_platform(repo, display_name="Canvas Production")

    first = await canvas_routes.create_canvas_program_binding(
        platform.id,
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-1",
            canvas_scope={"course_id": "course-101"},
            evidence_requirements=[_course_completion_requirement("course-101")],
            auto_approve_on_evidence=True,
        ),
        trusted_organization_id="org-123",
        repo=repo,
    )
    second = await canvas_routes.create_canvas_program_binding(
        platform.id,
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-2",
            canvas_scope={"course_id": "course-202"},
            evidence_requirements=[_course_completion_requirement("course-202")],
            delivery_mode="wallet_plus_canvas_mirror",
            deployment_profile_id="deployment-profile-1",
            feature_flags={
                "enable_canvas_evidence": True,
                "enable_canvas_lti": True,
                "enable_canvas_mirror_publish": True,
            },
        ),
        trusted_organization_id="org-123",
        repo=repo,
    )

    bindings = await canvas_routes.list_canvas_program_bindings(
        organization_id="org-123",
        platform_id=platform.id,
        trusted_organization_id="org-123",
        repo=repo,
    )

    assert platform.organization_id == "org-123"
    assert platform.canvas_account_id.startswith("unverified:")
    assert platform.enabled is False
    assert platform.connection_config["enabled_intent"] is True
    assert {binding.id for binding in bindings} == {first.id, second.id}
    assert first.credential_template_id == "credential-template-1"
    assert first.auto_approve_on_evidence is True
    assert first.canvas_scope == {"course_id": "course-101"}
    assert first.enabled is False
    assert first.direct_issue_enabled is False
    assert first.issuer_mode == "org_managed"
    assert first.evidence_requirements[0]["requirement_id"].startswith("canvas_req_")
    assert second.credential_template_id == "credential-template-2"
    assert second.delivery_mode == "wallet_plus_canvas_mirror"
    assert second.deployment_profile_id == "deployment-profile-1"
    assert second.feature_flags == {
        "enable_canvas_evidence": True,
        "enable_canvas_lti": True,
        "enable_canvas_mirror_publish": True,
    }


async def test_canvas_program_binding_rejects_duplicate_template_scope() -> None:
    repo = InMemoryIssuanceRepository()
    await _save_template(repo, template_id="application-template-1", credential_template_id="credential-template-1")
    platform = await _create_platform(repo)

    request = canvas_routes.CanvasProgramBindingCreate(
        application_template_id="application-template-1",
        canvas_scope={"course_id": "course-101"},
        evidence_requirements=[_course_completion_requirement("course-101")],
    )
    await canvas_routes.create_canvas_program_binding(
        platform.id,
        request,
        trusted_organization_id="org-123",
        repo=repo,
    )

    with pytest.raises(HTTPException) as exc_info:
        await canvas_routes.create_canvas_program_binding(
            platform.id,
            request,
            trusted_organization_id="org-123",
            repo=repo,
        )

    assert exc_info.value.status_code == 409


async def test_canvas_program_binding_rejects_legacy_caller_controls() -> None:
    repo = InMemoryIssuanceRepository()
    await _save_template(repo, template_id="application-template-1", credential_template_id="credential-template-1")
    platform = await _create_platform(repo)

    for field_name, value in (
        ("deprecated_canvas_field", "legacy-value"),
        ("canvas_account_id", "spoofed-account"),
        ("flow_mode", "direct_canvas_issue"),
        ("direct_issue_enabled", True),
        ("issuer_mode", "canvas_managed"),
        ("enabled", True),
    ):
        with pytest.raises(ValidationError):
            canvas_routes.CanvasProgramBindingCreate(
                application_template_id="application-template-1",
                evidence_requirements=[_course_completion_requirement("course-101")],
                **{field_name: value},
            )

    with pytest.raises(ValidationError):
        canvas_routes.CanvasProgramBindingCreate(application_template_id="application-template-1")

    binding = await canvas_routes.create_canvas_program_binding(
        platform.id,
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-1",
            auto_approve_on_evidence=True,
            canvas_scope={"course_id": "course-101"},
            evidence_requirements=[_course_completion_requirement("course-101")],
        ),
        trusted_organization_id="org-123",
        repo=repo,
    )
    assert binding.canvas_account_id == platform.canvas_account_id
    assert binding.credential_template_id == "credential-template-1"
    assert binding.direct_issue_enabled is False
    assert binding.flow_mode == "elevenid_orchestrated_canvas_evidence"


def test_canvas_management_models_reject_untyped_or_cross_purpose_inputs() -> None:
    with pytest.raises(ValidationError):
        canvas_routes.CanvasPlatformCreate(
            canvas_base_url="https://canvas.example.edu",
            lti_trust_profile="self_managed_same_origin",
        )
    with pytest.raises(ValidationError):
        canvas_routes.CanvasEvidenceRequirementInput(
            source="custom_webhook",
            fact_type="canvas.course_completion",
            scope={"course_id": "course-101"},
            pass_rule={"completed": True},
        )
    with pytest.raises(ValidationError):
        canvas_routes.CanvasEvidenceRequirementInput(
            source="canvas_rest",
            fact_type="arbitrary.fact",
            scope={"course_id": "course-101"},
            pass_rule={"completed": True},
        )
    with pytest.raises(ValidationError):
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-1",
            canvas_scope={"internal_service_url": "https://attacker.example"},
            evidence_requirements=[_course_completion_requirement("course-101")],
        )
    with pytest.raises(ValidationError):
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-1",
            delivery_mode="direct_canvas_issue",
            evidence_requirements=[_course_completion_requirement("course-101")],
        )
    with pytest.raises(ValidationError):
        canvas_routes.CanvasIntegrationSecretCreate(
            organization_id="org-123",
            name="purpose-confused secret",
            provider="canvas_credentials",
            purpose="oauth_client_secret",
            secret_value="secret",
        )


async def test_canvas_program_binding_rejects_profile_disabled_required_modes() -> None:
    repo = InMemoryIssuanceRepository()
    await _save_template(repo, template_id="application-template-1", credential_template_id="credential-template-1")
    platform = await _create_platform(repo)

    with pytest.raises(HTTPException) as exc_info:
        await canvas_routes.create_canvas_program_binding(
            platform.id,
            canvas_routes.CanvasProgramBindingCreate(
                application_template_id="application-template-1",
                canvas_scope={"course_id": "course-101"},
                evidence_requirements=[_course_completion_requirement("course-101")],
                delivery_mode="wallet_plus_canvas_mirror",
                deployment_profile_id="deployment-profile-1",
                feature_flags={
                    "enable_canvas_evidence": True,
                    "enable_canvas_mirror_publish": False,
                },
            ),
            trusted_organization_id="org-123",
            repo=repo,
        )

    assert exc_info.value.status_code == 409
    assert "enable_canvas_mirror_publish" in str(exc_info.value.detail)


async def test_canvas_platform_rejects_caller_owned_trust_fields_and_scopes_reads_by_org() -> None:
    repo = InMemoryIssuanceRepository()
    with pytest.raises(ValidationError):
        canvas_routes.CanvasPlatformCreate(
            organization_id="attacker-org",
            canvas_account_id="spoofed-account",
            canvas_base_url="https://canvas.example.edu",
        )

    platform = await _create_platform(repo)
    with pytest.raises(HTTPException) as exc_info:
        await canvas_routes.get_canvas_platform(
            platform.id,
            trusted_organization_id="another-org",
            repo=repo,
        )

    assert exc_info.value.status_code == 404
