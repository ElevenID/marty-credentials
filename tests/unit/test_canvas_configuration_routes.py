"""Tests for Canvas platform and program binding configuration APIs."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

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

from issuance.domain.entities import ApplicationTemplate
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes


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


async def test_canvas_platform_supports_multiple_program_bindings_for_same_account() -> None:
    repo = InMemoryIssuanceRepository()
    await _save_template(repo, template_id="application-template-1", credential_template_id="credential-template-1")
    await _save_template(repo, template_id="application-template-2", credential_template_id="credential-template-2")

    platform = await canvas_routes.create_canvas_platform(
        canvas_routes.CanvasPlatformCreate(
            organization_id="org-123",
            canvas_account_id="canvas-account-1",
            display_name="Canvas Production",
            canvas_base_url="https://canvas.example.edu",
        ),
        repo=repo,
    )

    first = await canvas_routes.create_canvas_program_binding(
        platform.id,
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-1",
            canvas_scope={"course_id": "course-101"},
            auto_approve_on_evidence=True,
        ),
        repo=repo,
    )
    second = await canvas_routes.create_canvas_program_binding(
        platform.id,
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-2",
            canvas_scope={"course_id": "course-202"},
            delivery_mode="wallet_plus_canvas_mirror",
            deployment_profile_id="deployment-profile-1",
            feature_flags={
                "enable_canvas_evidence": True,
                "enable_canvas_lti": True,
                "enable_canvas_mirror_publish": True,
            },
        ),
        repo=repo,
    )

    bindings = await canvas_routes.list_canvas_program_bindings(
        organization_id="org-123",
        platform_id=platform.id,
        repo=repo,
    )

    assert platform.canvas_account_id == "canvas-account-1"
    assert {binding.id for binding in bindings} == {first.id, second.id}
    assert first.credential_template_id == "credential-template-1"
    assert first.auto_approve_on_evidence is True
    assert first.canvas_scope == {"course_id": "course-101"}
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
    platform = await canvas_routes.create_canvas_platform(
        canvas_routes.CanvasPlatformCreate(
            organization_id="org-123",
            canvas_account_id="canvas-account-1",
        ),
        repo=repo,
    )

    request = canvas_routes.CanvasProgramBindingCreate(
        application_template_id="application-template-1",
        canvas_scope={"course_id": "course-101"},
    )
    await canvas_routes.create_canvas_program_binding(platform.id, request, repo=repo)

    with pytest.raises(HTTPException) as exc_info:
        await canvas_routes.create_canvas_program_binding(platform.id, request, repo=repo)

    assert exc_info.value.status_code == 409


async def test_canvas_program_binding_rejects_legacy_connector_payload() -> None:
    repo = InMemoryIssuanceRepository()
    await _save_template(repo, template_id="application-template-1", credential_template_id="credential-template-1")
    platform = await canvas_routes.create_canvas_platform(
        canvas_routes.CanvasPlatformCreate(
            organization_id="org-123",
            canvas_account_id="canvas-account-1",
        ),
        repo=repo,
    )

    with pytest.raises(Exception):
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-1",
            deprecated_canvas_field="legacy-value",
            auto_approve_on_evidence=True,
        )

    binding = await canvas_routes.create_canvas_program_binding(
        platform.id,
        canvas_routes.CanvasProgramBindingCreate(
            application_template_id="application-template-1",
            auto_approve_on_evidence=True,
        ),
        repo=repo,
    )
    assert binding.canvas_account_id == "canvas-account-1"
    assert binding.credential_template_id == "credential-template-1"


async def test_canvas_program_binding_rejects_profile_disabled_required_modes() -> None:
    repo = InMemoryIssuanceRepository()
    await _save_template(repo, template_id="application-template-1", credential_template_id="credential-template-1")
    platform = await canvas_routes.create_canvas_platform(
        canvas_routes.CanvasPlatformCreate(
            organization_id="org-123",
            canvas_account_id="canvas-account-1",
        ),
        repo=repo,
    )

    with pytest.raises(HTTPException) as exc_info:
        await canvas_routes.create_canvas_program_binding(
            platform.id,
            canvas_routes.CanvasProgramBindingCreate(
                application_template_id="application-template-1",
                delivery_mode="wallet_plus_canvas_mirror",
                deployment_profile_id="deployment-profile-1",
                feature_flags={
                    "enable_canvas_evidence": True,
                    "enable_canvas_mirror_publish": False,
                },
            ),
            repo=repo,
        )

    assert exc_info.value.status_code == 409
    assert "enable_canvas_mirror_publish" in str(exc_info.value.detail)
