from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
import pytest
from issuance.application.canvas_lti_services import CanvasLtiServiceError
from issuance.domain.entities import (
    Application,
    ApplicationTemplate,
    CanvasAwardCandidateState,
    CanvasEvidenceSyncTarget,
    CanvasEvidenceSyncTargetType,
    CanvasLearnerIdentity,
    CanvasLearnerIdentityStatus,
    CanvasPlatform,
    CanvasProgramBinding,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes


@pytest.fixture(autouse=True)
def _enable_portable_canvas_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")


@asynccontextmanager
async def _unused_canvas_client(*args, **kwargs):
    yield object()


def _background_target(platform: CanvasPlatform, binding: CanvasProgramBinding) -> CanvasEvidenceSyncTarget:
    capabilities = platform.capability_snapshot or {}
    return CanvasEvidenceSyncTarget(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        binding_id=binding.id,
        target_type=CanvasEvidenceSyncTargetType.BACKGROUND_ROSTER,
        logical_key=f"background:{binding.id}",
        config_version=binding.config_version,
        metadata={
            "verified_binding_id": binding.id,
            "verified_binding_config_version": binding.config_version,
            "nrps_context_memberships_url": capabilities.get(
                "nrps_context_memberships_url"
            ),
        },
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("progress_rows", "expected_state", "expected_completed"),
    [
        (
            [{"user_id": 7, "requirement_count": 3, "requirement_completed_count": 3}],
            CanvasAwardCandidateState.PENDING_CLAIM,
            True,
        ),
        ([], CanvasAwardCandidateState.OBSERVED, False),
    ],
)
async def test_background_course_completion_uses_bulk_progress_and_records_verified_negative(
    monkeypatch: pytest.MonkeyPatch,
    progress_rows: list[dict[str, int]],
    expected_state: CanvasAwardCandidateState,
    expected_completed: bool,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-bulk-progress",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
        lti_deployment_id="deployment-1",
    )
    requirement = {
        "requirement_id": "course-complete",
        "source": "canvas_rest",
        "fact_type": "canvas.course_completion",
        "scope": {"course_id": "42"},
        "pass_rule": {"completed": True},
        "required": True,
    }
    binding = CanvasProgramBinding(
        id="canvas-binding-bulk-progress",
        organization_id=platform.organization_id,
        platform_id=platform.id,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        evidence_requirements=[requirement],
    )
    paths: list[str] = []

    async def fetch_collection(client, *, path: str, **kwargs):
        paths.append(path)
        if path.endswith("/users?enrollment_type%5B%5D=student"):
            return [{"id": 7, "name": "must not persist", "email": "must-not-match@example.edu"}]
        if path.endswith("/bulk_user_progress"):
            return progress_rows
        raise AssertionError(f"unexpected Canvas collection path: {path}")

    async def fail_per_user_progress(**kwargs):
        raise AssertionError("background course completion must not use per-user progress")

    monkeypatch.setattr(canvas_routes, "canvas_http_client", _unused_canvas_client)
    monkeypatch.setattr(canvas_routes, "validate_canvas_origin", lambda value: value.rstrip("/"))
    monkeypatch.setattr(canvas_routes, "_canvas_oauth_access_token", lambda **kwargs: _async_value("oauth-token"))
    monkeypatch.setattr(canvas_routes, "_fetch_canvas_api_collection", fetch_collection)
    monkeypatch.setattr(canvas_routes, "_read_canvas_rest_evidence", fail_per_user_progress)

    result = await canvas_routes._process_background_canvas_roster(
        repo=repo,
        target=_background_target(platform, binding),
        platform=platform,
        binding=binding,
    )

    candidates = await repo.list_canvas_award_candidates(
        platform.organization_id,
        binding_id=binding.id,
    )
    observations = await repo.list_current_canvas_candidate_observations(
        platform.organization_id,
        candidates[0].id,
    )
    assert paths == [
        "courses/42/users?enrollment_type%5B%5D=student",
        "courses/42/bulk_user_progress",
    ]
    assert candidates[0].state == expected_state
    assert candidates[0].canvas_user_id == "7"
    assert candidates[0].lti_subject is None
    assert observations[0].assertion["completed"] is expected_completed
    assert observations[0].verification == {
        "status": "VERIFIED",
        "method": "CANVAS_OAUTH_API_READ",
    }
    assert result["pending_claim"] == int(expected_completed)


async def _async_value(value):
    return value


@pytest.mark.asyncio
async def test_mixed_background_evidence_requires_verified_identity_join_before_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-mixed",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
        lti_issuer="https://canvas.example.edu",
        lti_client_id="client-1",
        lti_deployment_id="deployment-1",
        lti_openid_configuration={
            "token_endpoint": "https://canvas.example.edu/login/oauth2/token"
        },
        capability_snapshot={
            "nrps_context_memberships_url": "https://canvas.example.edu/api/lti/courses/42/memberships"
        },
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-mixed",
        organization_id=platform.organization_id,
        platform_id=platform.id,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        evidence_requirements=[
            {
                "requirement_id": "native-score",
                "source": "canvas_rest",
                "fact_type": "canvas.assignment_score",
                "scope": {"course_id": "42", "activity_id": "9"},
                "pass_rule": {"min_score_percent": 80},
                "required": True,
            },
            {
                "requirement_id": "marty-score",
                "source": "ags_result",
                "fact_type": "canvas.assignment_score",
                "scope": {
                    "course_id": "42",
                    "line_item_url": "https://canvas.example.edu/api/lti/courses/42/line_items/5",
                },
                "pass_rule": {"min_score_percent": 80},
                "required": True,
            },
        ],
    )

    async def fetch_collection(client, *, path: str, **kwargs):
        assert path.endswith("/users?enrollment_type%5B%5D=student")
        return [{"id": 7}]

    async def fake_token(**kwargs):
        return type("Token", (), {"value": "lti-token"})()

    async def fail_evidence_read(**kwargs):
        raise AssertionError("evidence must not be read until opaque and numeric identities are joined")

    monkeypatch.setattr(canvas_routes, "canvas_http_client", _unused_canvas_client)
    monkeypatch.setattr(canvas_routes, "validate_canvas_origin", lambda value: value.rstrip("/"))
    monkeypatch.setattr(canvas_routes, "_canvas_oauth_access_token", lambda **kwargs: _async_value("oauth-token"))
    monkeypatch.setattr(canvas_routes, "_fetch_canvas_api_collection", fetch_collection)
    monkeypatch.setattr(canvas_routes, "_lti_service_client_assertion", lambda *args, **kwargs: _async_value("assertion"))
    monkeypatch.setattr(canvas_routes, "request_lti_access_token", fake_token)
    target = _background_target(platform, binding)
    platform.capability_snapshot["nrps_context_memberships_url"] = (
        "https://canvas.example.edu/api/lti/courses/999/memberships"
    )

    async def memberships(**kwargs):
        assert kwargs["memberships_url"] == (
            "https://canvas.example.edu/api/lti/courses/42/memberships"
        )
        return [{"user_id": "opaque-subject", "status": "Active"}]

    monkeypatch.setattr(canvas_routes, "read_nrps_memberships", memberships)
    monkeypatch.setattr(canvas_routes, "_read_canvas_rest_evidence", fail_evidence_read)
    monkeypatch.setattr(canvas_routes, "read_ags_results", fail_evidence_read)

    result = await canvas_routes._process_background_canvas_roster(
        repo=repo,
        target=target,
        platform=platform,
        binding=binding,
    )

    candidates = await repo.list_canvas_award_candidates(
        platform.organization_id,
        binding_id=binding.id,
    )
    assert result["identity_link_required"] == 1
    assert result["pending_claim"] == 0
    assert candidates[0].state == CanvasAwardCandidateState.IDENTITY_LINK_REQUIRED
    assert candidates[0].canvas_user_id == "7"
    assert candidates[0].lti_subject is None
    assert await repo.list_current_canvas_candidate_observations(
        platform.organization_id,
        candidates[0].id,
    ) == []


@pytest.mark.asyncio
async def test_authoritative_rest_collection_rejects_truncation() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[{"id": 1}, {"id": 2}],
            headers={
                "Link": '<https://canvas.example.edu/api/v1/courses?page=2>; rel="next"'
            },
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(canvas_routes.CanvasSyncProcessingError) as exc_info:
            await canvas_routes._fetch_canvas_api_collection(
                client,
                base_url="https://canvas.example.edu",
                token="opaque-token",
                path="courses",
                limit=2,
                require_complete=True,
            )
    assert exc_info.value.code == "canvas_roster_collection_too_large"
    assert not exc_info.value.retryable


@pytest.mark.asyncio
async def test_authoritative_rest_collection_rejects_redirect_cycles_and_large_pages() -> None:
    calls = 0

    async def repeated_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json=[{"id": 1}],
            headers={
                "Link": '<https://canvas.example.edu/api/v1/courses>; rel="next"'
            },
            request=request,
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(repeated_handler)
    ) as client:
        with pytest.raises(CanvasLtiServiceError, match="repeated a page"):
            await canvas_routes._fetch_canvas_api_collection(
                client,
                base_url="https://canvas.example.edu",
                token="opaque-token",
                path="courses",
                limit=100,
                require_complete=True,
            )
    assert calls == 2

    cross_origin_requests: list[httpx.Request] = []

    async def cross_origin_handler(request: httpx.Request) -> httpx.Response:
        cross_origin_requests.append(request)
        return httpx.Response(
            200,
            json=[{"id": 1}],
            headers={
                "Link": '<https://attacker.example/collect>; rel="next"'
            },
            request=request,
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(cross_origin_handler)
    ) as client:
        with pytest.raises(CanvasLtiServiceError, match="changed origin"):
            await canvas_routes._fetch_canvas_api_collection(
                client,
                base_url="https://canvas.example.edu",
                token="opaque-token",
                path="courses",
                limit=100,
                require_complete=True,
            )
    assert len(cross_origin_requests) == 1
    assert cross_origin_requests[0].url.host == "canvas.example.edu"

    redirected_requests: list[httpx.Request] = []

    async def redirect_handler(request: httpx.Request) -> httpx.Response:
        redirected_requests.append(request)
        return httpx.Response(
            302,
            headers={"Location": "https://attacker.example/collect"},
            request=request,
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(redirect_handler)
    ) as client:
        with pytest.raises(CanvasLtiServiceError, match="redirect"):
            await canvas_routes._fetch_canvas_api_collection(
                client,
                base_url="https://canvas.example.edu",
                token="opaque-token",
                path="courses",
                limit=100,
                require_complete=True,
            )
    assert len(redirected_requests) == 1
    assert redirected_requests[0].url.host == "canvas.example.edu"

    async def oversized_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Length": str(
                    canvas_routes.CANVAS_COLLECTION_PAGE_MAX_BYTES + 1
                )
            },
            content=b"[]",
            request=request,
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(oversized_handler)
    ) as client:
        with pytest.raises(CanvasLtiServiceError, match="size limit"):
            await canvas_routes._fetch_canvas_api_collection(
                client,
                base_url="https://canvas.example.edu",
                token="opaque-token",
                path="courses",
                limit=100,
                require_complete=True,
            )


@pytest.mark.asyncio
async def test_malformed_rest_evidence_is_not_a_verified_negative() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="platform-malformed",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
    )
    requirement = canvas_routes.validate_canvas_evidence_requirements(
        [
            {
                "requirement_id": "assignment",
                "source": "canvas_rest",
                "fact_type": "canvas.assignment_score",
                "scope": {"course_id": "42", "activity_id": "9"},
                "pass_rule": {"min_score_percent": 80},
                "required": True,
            }
        ]
    )[0]

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[], request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CanvasLtiServiceError, match="unexpected response"):
            await canvas_routes._read_canvas_rest_evidence(
                client=client,
                repo=repo,
                platform=platform,
                token="opaque-token",
                requirement=requirement,
                canvas_user_id="7",
            )


@pytest.mark.asyncio
async def test_learner_sync_processes_every_requirement_and_failed_read_preserves_negative_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="canvas-platform-learner-rest",
        organization_id="org-1",
        canvas_account_id="account-1",
        canvas_base_url="https://canvas.example.edu",
        lti_deployment_id="deployment-1",
    )
    requirements = [
        {
            "requirement_id": "assignment-score",
            "source": "canvas_rest",
            "fact_type": "canvas.assignment_score",
            "scope": {"course_id": "42", "activity_id": "9"},
            "pass_rule": {"min_score_percent": 80},
            "required": True,
        },
        {
            "requirement_id": "module-complete",
            "source": "canvas_rest",
            "fact_type": "canvas.module_completion",
            "scope": {"course_id": "42", "module_id": "3"},
            "pass_rule": {"completed": True},
            "required": True,
        },
    ]
    template = ApplicationTemplate(
        id="application-template-learner-rest",
        organization_id=platform.organization_id,
        credential_template_id="credential-template-1",
        evidence_requirements=requirements,
    )
    binding = CanvasProgramBinding(
        id="canvas-binding-learner-rest",
        organization_id=platform.organization_id,
        platform_id=platform.id,
        application_template_id=template.id,
        credential_template_id="credential-template-1",
        evidence_requirements=requirements,
    )
    app = Application(
        id="application-learner-rest",
        organization_id=platform.organization_id,
        application_template_id=template.id,
        integration_context={
            "canvas": {
                "lti_subject": "opaque-subject",
                "canvas_platform_id": platform.id,
                "canvas_program_binding_id": binding.id,
            }
        },
    )
    identity = CanvasLearnerIdentity(
        organization_id=platform.organization_id,
        platform_id=platform.id,
        deployment_id=platform.lti_deployment_id or "",
        lti_subject="opaque-subject",
        canvas_user_id="7",
        status=CanvasLearnerIdentityStatus.LINKED,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_application_template(template)
    await repo.save_canvas_program_binding(binding)
    await repo.save_application(app)
    await repo.save_canvas_learner_identity(identity)

    calls: list[str] = []

    async def first_read(*, requirement, **kwargs):
        calls.append(requirement.requirement_id)
        if requirement.requirement_id == "assignment-score":
            return (
                {
                    "id": 11,
                    "assignment_id": 9,
                    "score": 90,
                    "workflow_state": "graded",
                    "assignment": {"points_possible": 100},
                },
                requirement.scope.to_dict(),
            )
        # A successful authoritative read with no result is a verified negative.
        return {}, requirement.scope.to_dict()

    monkeypatch.setattr(canvas_routes, "canvas_http_client", _unused_canvas_client)
    monkeypatch.setattr(canvas_routes, "_canvas_oauth_access_token", lambda **kwargs: _async_value("oauth-token"))
    monkeypatch.setattr(canvas_routes, "_read_canvas_rest_evidence", first_read)

    first = await canvas_routes._synchronize_authoritative_canvas_application(
        repo=repo,
        app=app,
        platform=platform,
        binding=binding,
    )
    first_heads = {
        head.logical_key: head.fact_id
        for head in await repo.list_evidence_fact_heads_for_application(app.id)
    }
    first_facts = await repo.list_current_evidence_facts_for_application(app.id)
    module_fact = next(fact for fact in first_facts if fact.requirement_id == "module-complete")

    async def second_read(*, requirement, **kwargs):
        if requirement.requirement_id == "module-complete":
            raise canvas_routes.CanvasLtiServiceError("temporary module read failure")
        return await first_read(requirement=requirement, **kwargs)

    monkeypatch.setattr(canvas_routes, "_read_canvas_rest_evidence", second_read)
    second = await canvas_routes._synchronize_authoritative_canvas_application(
        repo=repo,
        app=app,
        platform=platform,
        binding=binding,
    )
    second_heads = {
        head.logical_key: head.fact_id
        for head in await repo.list_evidence_fact_heads_for_application(app.id)
    }

    assert calls[:2] == ["assignment-score", "module-complete"]
    assert set(first["sources_checked"]) == {"assignment-score", "module-complete"}
    assert module_fact.assertion["completed"] is False
    assert module_fact.verification["status"] == "VERIFIED"
    assert module_fact.source_revision == module_fact.payload_hash
    assert second["sources_checked"] == ["assignment-score"]
    assert "module-complete" in second["warnings"][0]
    assert second_heads == first_heads
