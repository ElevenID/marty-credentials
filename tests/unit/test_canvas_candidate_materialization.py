from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from issuance.domain.entities import (
    Application,
    ApplicationTemplate,
    CanvasAwardCandidate,
    CanvasAwardCandidateState,
    CanvasCandidateObservation,
    CanvasPlatform,
    CanvasProgramBinding,
)
from issuance.infrastructure.adapters.memory_repository import (
    InMemoryIssuanceRepository,
)
from issuance.infrastructure.api import canvas_routes


@pytest.fixture(autouse=True)
def _enable_portable_canvas_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")


async def _candidate_fixture(
    *,
    candidate_observed_at: datetime,
    observation_observed_at: datetime,
) -> tuple[
    InMemoryIssuanceRepository,
    Application,
    CanvasPlatform,
    CanvasProgramBinding,
    CanvasAwardCandidate,
    CanvasCandidateObservation,
]:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        id="candidate-freshness-platform",
        organization_id="org-1",
        canvas_account_id="account-1",
        lti_deployment_id="deployment-1",
        enabled=True,
    )
    template = ApplicationTemplate(
        id="candidate-freshness-application-template",
        organization_id="org-1",
        credential_template_id="candidate-freshness-credential-template",
    )
    binding = CanvasProgramBinding(
        id="candidate-freshness-binding",
        organization_id="org-1",
        platform_id=platform.id,
        application_template_id=template.id,
        credential_template_id=template.credential_template_id,
        evidence_requirements=[
            {
                "requirement_id": "marty-score",
                "source": "ags_result",
                "fact_type": "canvas.assignment_score",
                "scope": {
                    "course_id": "course-1",
                    "resource_id": "marty:score",
                    "line_item_url": (
                        "https://canvas.example.edu/api/lti/courses/1/line_items/1"
                    ),
                },
                "pass_rule": {"min_score_percent": 80},
                "required": True,
            }
        ],
        enabled=True,
    )
    application = Application(
        id="candidate-freshness-application",
        organization_id="org-1",
        application_template_id=template.id,
    )
    candidate = CanvasAwardCandidate(
        id="candidate-freshness-candidate",
        organization_id="org-1",
        platform_id=platform.id,
        binding_id=binding.id,
        candidate_key="lti-subject:learner-1",
        lti_subject="learner-1",
        state=CanvasAwardCandidateState.PENDING_CLAIM,
        observed_at=candidate_observed_at,
    )
    observation = CanvasCandidateObservation(
        id="candidate-freshness-observation",
        organization_id="org-1",
        candidate_id=candidate.id,
        requirement_id="marty-score",
        logical_key="marty-score",
        assertion={"completed": True, "score_percent": 95},
        verification={"status": "VERIFIED", "method": "LTI_AGS_RESULT_READ"},
        payload_hash="candidate-score-95",
        observed_at=observation_observed_at,
    )
    await repo.save_canvas_platform(platform)
    await repo.save_application_template(template)
    await repo.save_canvas_program_binding(binding)
    await repo.save_application(application)
    await repo.save_canvas_award_candidate(candidate)
    await repo.save_canvas_candidate_observation(observation)
    return repo, application, platform, binding, candidate, observation


async def _materialize(
    *,
    repo: InMemoryIssuanceRepository,
    application: Application,
    platform: CanvasPlatform,
    binding: CanvasProgramBinding,
) -> None:
    await canvas_routes._materialize_canvas_award_candidate_on_launch(
        repo=repo,
        app=application,
        verified_launch={
            "subject": "learner-1",
            "deployment_id": platform.lti_deployment_id,
            "raw_claims": {"sub": "learner-1"},
        },
        session_values={
            "canvas_platform_id": platform.id,
            "canvas_program_binding_id": binding.id,
        },
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("stale_value", ["candidate", "observation"])
async def test_stale_candidate_evidence_is_not_materialized(
    monkeypatch: pytest.MonkeyPatch,
    stale_value: str,
) -> None:
    monkeypatch.setenv("CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS", "900")
    now = datetime.now(UTC)
    recent = now - timedelta(minutes=2)
    stale = now - timedelta(minutes=16)
    repo, application, platform, binding, candidate, _observation = (
        await _candidate_fixture(
            candidate_observed_at=stale if stale_value == "candidate" else recent,
            observation_observed_at=(
                stale if stale_value == "observation" else recent
            ),
        )
    )

    await _materialize(
        repo=repo,
        application=application,
        platform=platform,
        binding=binding,
    )

    stored = await repo.get_canvas_award_candidate_for_org("org-1", candidate.id)
    assert stored is not None
    assert stored.application_id is None
    assert await repo.list_evidence_facts_for_application(application.id) == []
    refreshed_application = await repo.get_application(application.id)
    assert refreshed_application is not None
    assert "canvas" not in refreshed_application.integration_context


@pytest.mark.asyncio
async def test_materialized_candidate_preserves_authoritative_observed_at(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS", "900")
    now = datetime.now(UTC)
    observation_time = now - timedelta(minutes=7)
    repo, application, platform, binding, candidate, observation = (
        await _candidate_fixture(
            candidate_observed_at=now - timedelta(minutes=1),
            observation_observed_at=observation_time,
        )
    )

    await _materialize(
        repo=repo,
        application=application,
        platform=platform,
        binding=binding,
    )

    facts = await repo.list_evidence_facts_for_application(application.id)
    assert len(facts) == 1
    assert facts[0].observed_at == observation.observed_at
    assert facts[0].effective_at == observation.observed_at
    stored = await repo.get_canvas_award_candidate_for_org("org-1", candidate.id)
    assert stored is not None
    assert stored.application_id == application.id
