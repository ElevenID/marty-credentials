from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from fastapi import FastAPI
from issuance.domain.entities import (
    Application,
    CanvasAwardCandidate,
    CanvasAwardCandidateState,
    CanvasEvidenceSyncJobStatus,
    CanvasPlatform,
    CanvasProgramBinding,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api.canvas_operations_routes import canvas_operations_router
from issuance.infrastructure.api.routes import _verify_management_api_key


@pytest.fixture(autouse=True)
def _enable_canvas_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")


async def _client_and_data():
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
    application = Application(
        id="application-1",
        organization_id="org-1",
        application_template_id="template-1",
        integration_context={
            "canvas": {
                "canvas_platform_id": platform.id,
                "canvas_program_binding_id": binding.id,
            }
        },
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    await repo.save_application(application)
    app = FastAPI()
    app.include_router(canvas_operations_router)
    app.dependency_overrides[IIssuanceRepository] = lambda: repo
    app.dependency_overrides[_verify_management_api_key] = lambda: "test-internal-key"
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )
    return client, repo, application, platform, binding


def test_canvas_operations_route_auth_matrix_requires_management_key() -> None:
    for route in canvas_operations_router.routes:
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        assert _verify_management_api_key in dependencies, route.path
        # Operational handlers resolve X-Organization-ID from the Request and
        # scope every repository lookup to it.
        assert route.dependant.request_param_name == "request", route.path


@pytest.mark.asyncio
async def test_enqueue_get_and_list_are_organization_scoped() -> None:
    client, repo, application, _platform, _binding = await _client_and_data()
    async with client:
        missing_header = await client.post(
            f"/v1/integrations/canvas/applications/{application.id}/canvas-sync",
            json={},
        )
        assert missing_header.status_code == 400

        first = await client.post(
            f"/v1/integrations/canvas/applications/{application.id}/canvas-sync",
            headers={"X-Organization-ID": "org-1"},
            json={},
        )
        assert first.status_code == 202
        job_id = first.json()["id"]
        second = await client.post(
            f"/v1/integrations/canvas/applications/{application.id}/canvas-sync",
            headers={"X-Organization-ID": "org-1"},
            json={},
        )
        assert second.status_code == 202
        assert second.json()["id"] == job_id

        foreign = await client.get(
            f"/v1/integrations/canvas/canvas-sync-jobs/{job_id}",
            headers={"X-Organization-ID": "org-foreign"},
        )
        assert foreign.status_code == 404

        forged_query = await client.get(
            "/v1/integrations/canvas/canvas-sync-jobs",
            headers={"X-Organization-ID": "org-1"},
            params={"organization_id": "org-foreign"},
        )
        assert forged_query.status_code == 404

        listed = await client.get(
            "/v1/integrations/canvas/canvas-sync-jobs",
            headers={"X-Organization-ID": "org-1"},
            params={"organization_id": "org-1"},
        )
        assert listed.status_code == 200
        assert [item["id"] for item in listed.json()] == [job_id]

    assert len(await repo.list_canvas_sync_jobs("org-1")) == 1


@pytest.mark.asyncio
async def test_job_retry_is_dead_letter_only_and_redacts_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")
    client, repo, application, _platform, _binding = await _client_and_data()
    async with client:
        created = await client.post(
            f"/v1/integrations/canvas/applications/{application.id}/canvas-sync",
            headers={"X-Organization-ID": "org-1"},
            json={},
        )
        job = await repo.get_canvas_sync_job_for_org("org-1", created.json()["id"])
        assert job is not None
        job.status = CanvasEvidenceSyncJobStatus.DEAD_LETTER
        job.last_error_code = "canvas_sync_failed"
        job.last_error_summary = "Bearer super-secret-access-token"
        job.result = {"facts_changed": 1, "provider_payload": {"token": "secret"}}
        job.completed_at = datetime.now(UTC)
        await repo.save_canvas_sync_job(job)

        fetched = await client.get(
            f"/v1/integrations/canvas/canvas-sync-jobs/{job.id}",
            headers={"X-Organization-ID": "org-1"},
        )
        assert fetched.status_code == 200
        assert "super-secret" not in fetched.json()["last_error_summary"]
        assert fetched.json()["result"] == {"facts_changed": 1}

        foreign = await client.post(
            f"/v1/integrations/canvas/canvas-sync-jobs/{job.id}/retry",
            headers={"X-Organization-ID": "org-foreign"},
            json={},
        )
        assert foreign.status_code == 404

        retried = await client.post(
            f"/v1/integrations/canvas/canvas-sync-jobs/{job.id}/retry",
            headers={"X-Organization-ID": "org-1"},
            json={},
        )
        assert retried.status_code == 202
        assert retried.json()["status"] == "queued"

        retry_again = await client.post(
            f"/v1/integrations/canvas/canvas-sync-jobs/{job.id}/retry",
            headers={"X-Organization-ID": "org-1"},
            json={},
        )
        assert retry_again.status_code == 409

        queued = await repo.get_canvas_sync_job_for_org("org-1", job.id)
        assert queued is not None
        queued.status = CanvasEvidenceSyncJobStatus.DEAD_LETTER
        queued.completed_at = datetime.now(UTC)
        await repo.save_canvas_sync_job(queued)
        foreign_resolve = await client.post(
            f"/v1/integrations/canvas/canvas-sync-jobs/{job.id}/resolve",
            headers={"X-Organization-ID": "org-foreign"},
            json={},
        )
        assert foreign_resolve.status_code == 404
        resolved = await client.post(
            f"/v1/integrations/canvas/canvas-sync-jobs/{job.id}/resolve",
            headers={"X-Organization-ID": "org-1"},
            json={},
        )
        assert resolved.status_code == 200
        assert resolved.json()["status"] == "cancelled"


@pytest.mark.asyncio
async def test_candidate_and_review_apis_hide_foreign_and_identity_fields() -> None:
    client, repo, application, platform, binding = await _client_and_data()
    candidate = CanvasAwardCandidate(
        id="candidate-1",
        organization_id="org-1",
        platform_id=platform.id,
        binding_id=binding.id,
        candidate_key="numeric-user:99",
        canvas_user_id="99",
        lti_subject="opaque-subject",
        state=CanvasAwardCandidateState.PENDING_CLAIM,
    )
    foreign_candidate = CanvasAwardCandidate(
        id="candidate-foreign",
        organization_id="org-foreign",
        platform_id="foreign-platform",
        binding_id="foreign-binding",
        candidate_key="numeric-user:100",
    )
    review = EvidencePolicyReview(
        id="review-1",
        organization_id="org-1",
        application_id=application.id,
        credential_id="credential-1",
        binding_id=binding.id,
    )
    await repo.save_canvas_award_candidate(candidate)
    await repo.save_canvas_award_candidate(foreign_candidate)
    await repo.save_evidence_policy_review(review)

    async with client:
        candidates = await client.get(
            "/v1/integrations/canvas/canvas-award-candidates",
            headers={"X-Organization-ID": "org-1"},
            params={"organization_id": "org-1", "status": "pending_claim"},
        )
        assert candidates.status_code == 200
        assert [item["id"] for item in candidates.json()] == [candidate.id]
        assert "canvas_user_id" not in candidates.json()[0]
        assert "lti_subject" not in candidates.json()[0]
        assert "candidate_key" not in candidates.json()[0]

        reviews = await client.get(
            "/v1/integrations/canvas/evidence-policy-reviews",
            headers={"X-Organization-ID": "org-1"},
            params={"organization_id": "org-1", "status": "open"},
        )
        assert reviews.status_code == 200
        assert [item["id"] for item in reviews.json()] == [review.id]

        dismissed = await client.post(
            f"/v1/integrations/canvas/evidence-policy-reviews/{review.id}/resolve",
            headers={
                "X-Organization-ID": "org-1",
                "X-Authenticated-User-ID": "admin-1",
            },
            json={"action": "dismiss", "note": "Reviewed with registrar"},
        )
        assert dismissed.status_code == 200
        assert dismissed.json()["status"] == EvidencePolicyReviewStatus.DISMISSED.value
        assert dismissed.json()["resolved_by"] == "admin-1"

        duplicate = await client.post(
            f"/v1/integrations/canvas/evidence-policy-reviews/{review.id}/resolve",
            headers={"X-Organization-ID": "org-1"},
            json={"action": "dismiss"},
        )
        assert duplicate.status_code == 409
