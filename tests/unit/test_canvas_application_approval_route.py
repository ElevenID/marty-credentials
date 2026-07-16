from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from issuance.application.application_approval import CredentialContext
from issuance.application.canvas_issuance_guard import CanvasIssuanceGuardError
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    CanvasPlatform,
    CanvasProgramBinding,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes
from issuance.infrastructure.api.canvas_routes import canvas_integration_router
from issuance.infrastructure.api.routes import _verify_management_api_key


async def _client_and_data(monkeypatch: pytest.MonkeyPatch):
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-1",
        organization_id="org-1",
        canvas_account_id="account-1",
        enabled=True,
    )
    binding = CanvasProgramBinding(
        id="binding-1",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id="template-1",
        credential_template_id="credential-template-1",
        enabled=True,
    )
    template = ApplicationTemplate(
        id="template-1",
        organization_id="org-1",
        name="Canvas badge application",
        credential_template_id="credential-template-1",
        status="ACTIVE",
    )
    application = Application(
        id="application-1",
        organization_id="org-1",
        application_template_id=template.id,
        integration_context={
            "canvas": {
                "canvas_account_id": platform.canvas_account_id,
                "canvas_platform_id": platform.id,
                "canvas_program_binding_id": binding.id,
                "application_template_id": template.id,
                "credential_template_id": binding.credential_template_id,
                "lti_subject": "opaque-learner-subject",
            }
        },
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    await repo.save_application_template(template)
    await repo.save_application(application)

    monkeypatch.setattr(
        canvas_routes,
        "_require_portable_canvas_pilot",
        lambda _organization_id: None,
    )

    app = FastAPI()
    app.include_router(canvas_integration_router)
    app.dependency_overrides[IIssuanceRepository] = lambda: repo
    app.dependency_overrides[_verify_management_api_key] = (
        lambda: "test-management-key"
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )
    return client, repo, application, template, binding, platform


@pytest.mark.asyncio
async def test_canvas_application_approval_is_owned_and_uses_canonical_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _repo, application, _template, _binding, _platform = (
        await _client_and_data(monkeypatch)
    )
    credential_context = CredentialContext(
        credential_type="OpenBadgeCredential",
        credential_payload_format="w3c_vcdm_v2_jwt",
        revocation_profile_id="status-profile-1",
        issuer_profile_id="issuer-profile-1",
        issuer_key_id="kms-key-1",
    )
    captured: dict[str, object] = {}

    async def _guard(**kwargs):
        captured["guard"] = kwargs
        return credential_context

    async def _approve(**kwargs):
        captured["approval"] = kwargs
        kwargs["app"].status = ApplicationStatus.APPROVED
        kwargs["app"].issuance_transaction_id = "transaction-1"
        return SimpleNamespace(id="transaction-1")

    monkeypatch.setattr(canvas_routes, "canvas_approval_credential_context", _guard)
    monkeypatch.setattr(canvas_routes, "approve_application_for_issuance", _approve)

    async with client:
        response = await client.post(
            f"/v1/integrations/canvas/applications/{application.id}/approve",
            headers={"X-Organization-ID": "org-1"},
            json={"review_notes": "Evidence verified by the pilot administrator"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "application_id": application.id,
        "status": "approved",
        "issuance_transaction_id": "transaction-1",
    }
    assert captured["guard"]["app"] is application
    approval = captured["approval"]
    assert approval["app"] is application
    assert approval["credential_context"] is credential_context
    assert approval["reviewer_id"] == "canvas-integration-management-api"
    assert approval["review_notes"] == "Evidence verified by the pilot administrator"
    assert approval["issuer_context_applier"] is canvas_routes.apply_required_remote_issuer_context


@pytest.mark.asyncio
async def test_canvas_application_approval_hides_foreign_and_non_canvas_applications(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, repo, application, template, _binding, _platform = (
        await _client_and_data(monkeypatch)
    )
    approvals = 0

    async def _approve(**_kwargs):
        nonlocal approvals
        approvals += 1
        return SimpleNamespace(id="must-not-be-created")

    monkeypatch.setattr(canvas_routes, "approve_application_for_issuance", _approve)

    async with client:
        foreign = await client.post(
            f"/v1/integrations/canvas/applications/{application.id}/approve",
            headers={"X-Organization-ID": "org-foreign"},
            json={},
        )
        assert foreign.status_code == 404

        non_canvas = Application(
            id="ordinary-application",
            organization_id="org-1",
            application_template_id=template.id,
        )
        await repo.save_application(non_canvas)
        ordinary = await client.post(
            f"/v1/integrations/canvas/applications/{non_canvas.id}/approve",
            headers={"X-Organization-ID": "org-1"},
            json={},
        )
        assert ordinary.status_code == 404

        forged_tenant = await client.post(
            f"/v1/integrations/canvas/applications/{application.id}/approve",
            headers={"X-Organization-ID": "org-1"},
            json={"organization_id": "org-foreign"},
        )
        assert forged_tenant.status_code == 422

    assert approvals == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_stage", ["readiness", "signing"])
async def test_canvas_application_approval_fails_closed_without_leaking_errors(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    client, _repo, application, _template, _binding, _platform = (
        await _client_and_data(monkeypatch)
    )

    async def _guard(**_kwargs):
        if failure_stage == "readiness":
            raise CanvasIssuanceGuardError("kms_private_reference_secret")
        return CredentialContext(credential_type="OpenBadgeCredential")

    async def _approve(**_kwargs):
        raise RuntimeError("remote signer bearer secret")

    monkeypatch.setattr(canvas_routes, "canvas_approval_credential_context", _guard)
    monkeypatch.setattr(canvas_routes, "approve_application_for_issuance", _approve)

    async with client:
        response = await client.post(
            f"/v1/integrations/canvas/applications/{application.id}/approve",
            headers={"X-Organization-ID": "org-1"},
            json={},
        )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Canvas application is not ready for approval"
    }
    serialized = response.text.lower()
    assert "private_reference" not in serialized
    assert "bearer secret" not in serialized


@pytest.mark.asyncio
async def test_canvas_application_approval_requires_trusted_organization_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _repo, application, _template, _binding, _platform = (
        await _client_and_data(monkeypatch)
    )

    async with client:
        response = await client.post(
            f"/v1/integrations/canvas/applications/{application.id}/approve",
            json={},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "X-Organization-ID is required for Canvas management"
    )
