from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from issuance.application import canvas_evidence_revisions
from issuance.application.canvas_identity import (
    link_verified_canvas_learner_identity,
    record_verified_canvas_lti_subject,
)
from issuance.application.canvas_oauth_persistence import (
    consume_canvas_oauth_authorization_transaction,
    create_canvas_oauth_authorization_transaction,
    queue_canvas_oauth_revocation,
)
from issuance.application.canvas_sync_jobs import (
    complete_canvas_sync_job,
    fail_canvas_sync_job,
    resolve_dead_letter_canvas_sync_job,
    retry_dead_letter_canvas_sync_job,
)
from issuance.application.evidence_policy import (
    EvidencePolicyDecision,
    evaluate_application_evidence_policy,
)
from issuance.domain.entities import (
    Application,
    CanvasAwardCandidate,
    CanvasCandidateObservation,
    CanvasEvidenceFactType,
    CanvasEvidenceRequirement,
    CanvasEvidenceSource,
    CanvasEvidenceSyncJobStatus,
    CanvasEvidenceSyncTarget,
    CanvasEvidenceSyncTargetType,
    CanvasLearnerIdentityStatus,
    CanvasOAuthConnection,
    CanvasOAuthConnectionStatus,
    CanvasProgramBinding,
    CanvasWorkerHeartbeat,
    EvidenceFact,
    EvidencePolicyReviewStatus,
    validate_canvas_evidence_requirements,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository
from issuance.infrastructure.models import (
    canvas_oauth_authorizations_table,
    canvas_oauth_connections_table,
)


class _ContextDecision:
    def __init__(self, allowed: bool):
        self.allowed = allowed
        self.reasons = []
        self.errors = []


class _ContextEngine:
    def is_authorized(self, **kwargs):
        return _ContextDecision(bool(kwargs["context"]["all_required_evidence_satisfied"]))


def _requirement() -> CanvasEvidenceRequirement:
    return CanvasEvidenceRequirement.from_mapping(
        {
            "requirement_id": "assignment-pass",
            "source": "canvas_rest",
            "fact_type": "canvas.assignment_score",
            "scope": {"course_id": "42", "activity_id": "7"},
            "pass_rule": {"min_score_percent": 80},
            "required": True,
        }
    )


def _fact(*, app: Application, score: float, observed_at: datetime) -> EvidenceFact:
    return EvidenceFact(
        organization_id=app.organization_id,
        application_id=app.id,
        subject_id="canvas-user-9",
        provider="canvas",
        fact_type="canvas.assignment_score",
        scope={"course_id": "42", "activity_id": "7"},
        assertion={"score_percent": score},
        verification={"status": "VERIFIED", "method": "canvas_api"},
        source={"source": "canvas_rest"},
        requirement_id="assignment-pass",
        observed_at=observed_at,
    )


def test_canvas_repositories_do_not_expose_cascading_hard_delete_operations() -> None:
    for repository_type in (InMemoryIssuanceRepository, PostgresIssuanceRepository):
        assert not hasattr(repository_type, "delete_canvas_platform")
        assert not hasattr(repository_type, "delete_canvas_program_binding")


def test_canvas_requirement_is_discriminated_and_rejects_unportable_shapes() -> None:
    requirement = _requirement()
    assert requirement.source == CanvasEvidenceSource.CANVAS_REST
    assert requirement.fact_type == CanvasEvidenceFactType.ASSIGNMENT_SCORE
    assert requirement.to_dict()["scope"] == {"course_id": "42", "activity_id": "7"}

    with pytest.raises(ValueError, match="requirement_id"):
        validate_canvas_evidence_requirements(
            [
                {
                    "source": "canvas_rest",
                    "fact_type": "canvas.course_completion",
                    "scope": {"course_id": "42"},
                    "pass_rule": {"completed": True},
                }
            ]
        )
    with pytest.raises(ValueError, match="ags_result or canvas_rest"):
        CanvasEvidenceRequirement.from_mapping(
            {
                "requirement_id": "legacy",
                "source": "custom_webhook",
                "fact_type": "canvas.course_completion",
                "scope": {"course_id": "42"},
                "pass_rule": {"completed": True},
            }
        )


@pytest.mark.asyncio
async def test_evidence_revisions_are_immutable_and_policy_uses_only_current_head() -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(organization_id="org-1", application_template_id="template-1")
    await repo.save_application(app)
    now = datetime.now(timezone.utc)
    passing = _fact(app=app, score=92, observed_at=now)
    failing = _fact(app=app, score=65, observed_at=now + timedelta(minutes=1))

    stored_pass, changed = await repo.record_evidence_revision(passing)
    assert changed is True
    stored_fail, changed = await repo.record_evidence_revision(failing)
    assert changed is True
    assert stored_fail.superseded_fact_id == stored_pass.id
    assert len(await repo.list_evidence_facts_for_application(app.id)) == 2
    assert [fact.id for fact in await repo.list_current_evidence_facts_for_application(app.id)] == [stored_fail.id]

    duplicate_fail = _fact(app=app, score=65, observed_at=now + timedelta(minutes=2))
    stored_duplicate, head_changed = await repo.record_evidence_revision(duplicate_fail)
    assert head_changed is False
    assert stored_duplicate.id == stored_fail.id
    assert len(await repo.list_evidence_facts_for_application(app.id)) == 2

    late_old = _fact(app=app, score=99, observed_at=now - timedelta(minutes=5))
    stored_late, head_changed = await repo.record_evidence_revision(late_old)
    assert head_changed is False
    assert stored_late.id == late_old.id
    assert len(await repo.list_evidence_facts_for_application(app.id)) == 3
    assert [fact.id for fact in await repo.list_current_evidence_facts_for_application(app.id)] == [stored_fail.id]

    decision = evaluate_application_evidence_policy(
        app=app,
        template=None,
        binding=None,
        requirements=[_requirement()],
        facts=[stored_pass, stored_fail],
        cedar_engine=_ContextEngine(),
    )
    assert decision.allowed is False
    assert decision.context["satisfied_requirement_count"] == 0


@pytest.mark.asyncio
async def test_verified_lti_subject_is_persisted_then_enriched_by_signed_numeric_id() -> None:
    repo = InMemoryIssuanceRepository()
    subject_only = await record_verified_canvas_lti_subject(
        repo=repo,
        organization_id="org-1",
        platform_id="platform-1",
        deployment_id="deployment-1",
        lti_subject="opaque-a",
    )

    assert subject_only.status == CanvasLearnerIdentityStatus.SUBJECT_VERIFIED
    assert subject_only.canvas_user_id is None

    linked = await link_verified_canvas_learner_identity(
        repo=repo,
        organization_id="org-1",
        platform_id="platform-1",
        deployment_id="deployment-1",
        lti_subject="opaque-a",
        canvas_user_id="99",
    )

    assert linked.id == subject_only.id
    assert linked.status == CanvasLearnerIdentityStatus.LINKED
    assert linked.canvas_user_id == "99"


@pytest.mark.asyncio
async def test_verified_identity_conflict_is_quarantined_without_email_matching() -> None:
    repo = InMemoryIssuanceRepository()
    first = await link_verified_canvas_learner_identity(
        repo=repo,
        organization_id="org-1",
        platform_id="platform-1",
        deployment_id="deployment-1",
        lti_subject="opaque-a",
        canvas_user_id="99",
    )
    assert first.status == CanvasLearnerIdentityStatus.LINKED

    conflict = await link_verified_canvas_learner_identity(
        repo=repo,
        organization_id="org-1",
        platform_id="platform-1",
        deployment_id="deployment-1",
        lti_subject="opaque-b",
        canvas_user_id="99",
    )
    assert conflict.status == CanvasLearnerIdentityStatus.QUARANTINED
    assert first.status == CanvasLearnerIdentityStatus.QUARANTINED
    assert "another LTI subject" in (conflict.conflict_reason or "")


@pytest.mark.asyncio
async def test_sync_job_leasing_retry_dead_letter_and_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")
    repo = InMemoryIssuanceRepository()
    target = CanvasEvidenceSyncTarget(
        organization_id="org-1",
        platform_id="platform-1",
        binding_id="binding-1",
        target_type=CanvasEvidenceSyncTargetType.LEARNER_APPLICATION,
        logical_key="application:app-1",
    )
    await repo.save_canvas_sync_target(target)
    assert (
        await repo.get_canvas_sync_target_by_logical_key("org-1", "application:app-1")
    ).id == target.id
    first = await repo.enqueue_canvas_sync_job(target)
    assert (await repo.enqueue_canvas_sync_job(target)).id == first.id

    leased = (await repo.lease_canvas_sync_jobs(worker_id="worker-1"))[0]
    leased.max_attempts = 1
    failed = await fail_canvas_sync_job(
        repo=repo,
        job=leased,
        worker_id="worker-1",
        error_code="canvas_rate_limited",
        error_summary="provider body must be bounded " * 100,
        retry_after_seconds=120,
    )
    assert failed.status == CanvasEvidenceSyncJobStatus.DEAD_LETTER
    assert len(failed.last_error_summary or "") <= 500
    stored_target = await repo.get_canvas_sync_target_for_org("org-1", target.id)
    assert stored_target is not None and stored_target.enabled is False

    retried = await retry_dead_letter_canvas_sync_job(
        repo=repo,
        organization_id="org-1",
        job_id=failed.id,
    )
    assert retried is not None and retried.status == CanvasEvidenceSyncJobStatus.QUEUED
    assert retried.max_attempts == 8
    assert stored_target.enabled is True
    leased_again = (await repo.lease_canvas_sync_jobs(worker_id="worker-2"))[0]
    completed = await complete_canvas_sync_job(
        repo=repo,
        job=leased_again,
        worker_id="worker-2",
        target_config_version=target.config_version,
        result={"facts_changed": 1},
    )
    assert completed.status == CanvasEvidenceSyncJobStatus.SUCCEEDED
    assert completed.result == {"facts_changed": 1}
    assert target.last_succeeded_at is not None

    terminal = await repo.enqueue_canvas_sync_job(target)
    terminal = (await repo.lease_canvas_sync_jobs(worker_id="worker-3"))[0]
    terminal.max_attempts = terminal.attempt_count
    dead_letter = await fail_canvas_sync_job(
        repo=repo,
        job=terminal,
        worker_id="worker-3",
        error_code="canvas_sync_poison_record",
    )
    assert dead_letter.status == CanvasEvidenceSyncJobStatus.DEAD_LETTER
    assert stored_target.enabled is False
    resolved = await resolve_dead_letter_canvas_sync_job(
        repo=repo,
        organization_id="org-1",
        job_id=dead_letter.id,
    )
    assert resolved is not None
    assert resolved.status == CanvasEvidenceSyncJobStatus.CANCELLED
    assert stored_target.enabled is False


@pytest.mark.asyncio
async def test_oauth_state_is_hashed_single_use_and_refresh_is_serialized() -> None:
    repo = InMemoryIssuanceRepository()
    raw_state, authorization = await create_canvas_oauth_authorization_transaction(
        repo=repo,
        organization_id="org-1",
        platform_id="platform-1",
        canvas_base_url="https://canvas.example.edu",
        platform_config_version=1,
        client_id="canvas-client-1",
        client_secret_ref="org_secret://org-1/canvas-client-secret",
        capabilities=["catalog"],
        scopes=["url:GET|/api/v1/courses"],
        redirect_uri="https://marty.example/canvas/oauth/callback",
    )
    assert raw_state != authorization.state_hash
    assert raw_state not in repo._canvas_oauth_authorizations
    consumed = await consume_canvas_oauth_authorization_transaction(repo=repo, raw_state=raw_state)
    assert consumed is not None and consumed.id == authorization.id
    assert consumed.client_id == "canvas-client-1"
    assert consumed.client_secret_ref == "org_secret://org-1/canvas-client-secret"
    assert await consume_canvas_oauth_authorization_transaction(repo=repo, raw_state=raw_state) is None

    connection = CanvasOAuthConnection(
        organization_id="org-1",
        platform_id="platform-1",
        canvas_base_url="https://canvas.example.edu",
        platform_config_version=1,
        client_id="canvas-client-1",
        client_secret_ref="org_secret://org-1/canvas-client-secret",
        capabilities=["catalog"],
        scopes=["url:GET|/api/v1/courses"],
        access_token_secret_ref="org_secret://org-1/access",
        refresh_token_secret_ref="org_secret://org-1/refresh",
    )
    await repo.save_canvas_oauth_connection(connection)
    leased = await repo.acquire_canvas_oauth_refresh_lease(
        organization_id="org-1",
        platform_id="platform-1",
        lease_owner="worker-1",
    )
    assert leased is not None
    assert await repo.acquire_canvas_oauth_refresh_lease(
        organization_id="org-1",
        platform_id="platform-1",
        lease_owner="worker-2",
    ) is None
    assert await repo.complete_canvas_oauth_refresh(
        organization_id="org-1",
        platform_id="platform-1",
        lease_owner="worker-2",
        access_token_secret_ref="org_secret://org-1/access-2",
        refresh_token_secret_ref=None,
        token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    ) is None
    refreshed = await repo.complete_canvas_oauth_refresh(
        organization_id="org-1",
        platform_id="platform-1",
        lease_owner="worker-1",
        access_token_secret_ref="org_secret://org-1/access-2",
        refresh_token_secret_ref=None,
        token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    assert refreshed is not None
    assert refreshed.access_token_secret_ref.endswith("access-2")
    assert refreshed.refresh_token_secret_ref.endswith("refresh")
    assert refreshed.client_id == "canvas-client-1"
    assert refreshed.client_secret_ref == "org_secret://org-1/canvas-client-secret"

    await repo.acquire_canvas_oauth_refresh_lease(
        organization_id="org-1",
        platform_id="platform-1",
        lease_owner="worker-3",
    )
    assert await repo.release_canvas_oauth_refresh_lease(
        organization_id="org-1",
        platform_id="platform-1",
        lease_owner="worker-3",
        reauthorization_required=True,
    ) is True
    stored = await repo.get_canvas_oauth_connection("org-1", "platform-1")
    assert stored.status == CanvasOAuthConnectionStatus.REAUTHORIZATION_REQUIRED
    assert stored.reauthorization_required is True
    assert stored.client_id == "canvas-client-1"
    assert stored.client_secret_ref == "org_secret://org-1/canvas-client-secret"
    assert await repo.acquire_canvas_oauth_refresh_lease(
        organization_id="org-1",
        platform_id="platform-1",
        lease_owner="worker-4",
    ) is None


@pytest.mark.asyncio
async def test_oauth_revocation_queue_is_durable_and_idempotent() -> None:
    repo = InMemoryIssuanceRepository()
    connection = CanvasOAuthConnection(
        organization_id="org-1",
        platform_id="platform-1",
        canvas_base_url="https://canvas.example.edu",
        platform_config_version=1,
        access_token_secret_ref="org_secret://org-1/access",
    )
    await repo.save_canvas_oauth_connection(connection)

    assert await queue_canvas_oauth_revocation(
        repo=repo,
        organization_id="org-1",
        platform_id="platform-1",
        reason_code="canvas_platform_archived",
    )
    queued = await repo.get_canvas_oauth_connection("org-1", "platform-1")
    assert queued is not None
    assert queued.status == CanvasOAuthConnectionStatus.REVOCATION_PENDING
    assert queued.refresh_lease_owner is None
    assert queued.revoke_retry_at is not None
    assert queued.revoke_last_error_code == "canvas_platform_archived"

    assert await queue_canvas_oauth_revocation(
        repo=repo,
        organization_id="org-1",
        platform_id="platform-1",
        reason_code="canvas_platform_archived",
    )


@pytest.mark.asyncio
async def test_worker_heartbeat_freshness_and_binding_readiness_snapshot() -> None:
    repo = InMemoryIssuanceRepository()
    now = datetime.now(timezone.utc)
    stale = CanvasWorkerHeartbeat(
        worker_id="stale-worker",
        last_heartbeat_at=now - timedelta(minutes=10),
    )
    fresh = CanvasWorkerHeartbeat(
        worker_id="fresh-worker",
        last_heartbeat_at=now,
        metadata={"leased_jobs": 2},
    )
    await repo.upsert_canvas_worker_heartbeat(stale)
    await repo.upsert_canvas_worker_heartbeat(fresh)
    selected = await repo.get_fresh_canvas_worker_heartbeat(max_age_seconds=120)
    assert selected is not None and selected.worker_id == "fresh-worker"
    assert [item.worker_id for item in await repo.list_canvas_worker_heartbeats()] == [
        "fresh-worker",
        "stale-worker",
    ]

    binding = CanvasProgramBinding(
        organization_id="org-1",
        platform_id="platform-1",
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        config_version=3,
        validated_config_version=3,
        readiness_checks=[{"code": "worker_heartbeat", "status": "ready", "blocking": True}],
        readiness_validated_at=now,
        activated_at=now,
        credential_template_snapshot={"id": "credential-template-1", "format": "open_badge_v3"},
        enabled=True,
    )
    await repo.save_canvas_program_binding(binding)
    stored = await repo.get_canvas_program_binding_for_org("org-1", binding.id)
    assert stored.config_version == stored.validated_config_version == 3
    assert stored.credential_template_snapshot["format"] == "open_badge_v3"


def test_postgres_oauth_and_heartbeat_mappers_preserve_normalized_fields() -> None:
    now = datetime.now(timezone.utc)
    authorization = PostgresIssuanceRepository._row_to_canvas_oauth_authorization(
        SimpleNamespace(
            id="authorization-1",
            organization_id="org-1",
            platform_id="platform-1",
            canvas_base_url="https://canvas.example.edu",
            platform_config_version=1,
            client_id="canvas-client-1",
            client_secret_ref="org_secret://org-1/canvas-client-secret",
            state_hash="f" * 64,
            capabilities=["catalog"],
            scopes=["url:GET|/api/v1/courses"],
            redirect_uri="https://marty.example/canvas/oauth/callback",
            expires_at=now + timedelta(minutes=10),
            consumed_at=None,
            created_at=now,
        )
    )
    assert authorization.client_id == "canvas-client-1"
    assert authorization.client_secret_ref == "org_secret://org-1/canvas-client-secret"
    connection = PostgresIssuanceRepository._row_to_canvas_oauth_connection(
        SimpleNamespace(
            id="connection-1",
            organization_id="org-1",
            platform_id="platform-1",
            canvas_base_url="https://canvas.example.edu",
            platform_config_version=1,
            client_id="canvas-client-1",
            client_secret_ref="org_secret://org-1/canvas-client-secret",
            capabilities=["catalog"],
            scopes=["url:GET|/api/v1/courses"],
            access_token_secret_ref="org_secret://org-1/access",
            refresh_token_secret_ref="org_secret://org-1/refresh",
            token_expires_at=now + timedelta(hours=1),
            status="connected",
            reauthorization_required=False,
            refresh_lease_owner="worker-1",
            refresh_lease_expires_at=now + timedelta(minutes=1),
            revoke_retry_count=0,
            revoke_retry_at=None,
            revoke_last_error_code=None,
            connected_at=now,
            last_refreshed_at=now,
            created_at=now,
            updated_at=now,
        )
    )
    assert connection.access_token_secret_ref == "org_secret://org-1/access"
    assert connection.client_id == "canvas-client-1"
    assert connection.client_secret_ref == "org_secret://org-1/canvas-client-secret"
    assert connection.capabilities == ["catalog"]
    heartbeat = PostgresIssuanceRepository._row_to_canvas_worker_heartbeat(
        SimpleNamespace(
            worker_id="worker-1",
            role="canvas_sync",
            started_at=now,
            last_heartbeat_at=now,
            metadata={"leased_jobs": 1},
        )
    )
    assert heartbeat.worker_id == "worker-1"
    assert heartbeat.metadata == {"leased_jobs": 1}


def test_canvas_oauth_tables_require_client_snapshots() -> None:
    for table in (canvas_oauth_authorizations_table, canvas_oauth_connections_table):
        assert table.c.canvas_base_url.nullable is False
        assert table.c.platform_config_version.nullable is False
        assert table.c.client_id.nullable is False
        assert table.c.client_secret_ref.nullable is False


@pytest.mark.asyncio
async def test_candidate_observations_head_and_post_issue_review_recovers(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    candidate = CanvasAwardCandidate(
        organization_id="org-1",
        platform_id="platform-1",
        binding_id="binding-1",
        candidate_key="canvas-user:99",
    )
    await repo.save_canvas_award_candidate(candidate)
    first = CanvasCandidateObservation(
        organization_id="org-1",
        candidate_id=candidate.id,
        requirement_id="assignment-pass",
        logical_key="assignment-pass",
        assertion={"score_percent": 90},
        verification={"status": "VERIFIED"},
        payload_hash="pass",
    )
    second = CanvasCandidateObservation(
        organization_id="org-1",
        candidate_id=candidate.id,
        requirement_id="assignment-pass",
        logical_key="assignment-pass",
        assertion={"score_percent": 50},
        verification={"status": "VERIFIED"},
        payload_hash="fail",
    )
    await repo.save_canvas_candidate_observation(first)
    await repo.save_canvas_candidate_observation(second)
    current = await repo.list_current_canvas_candidate_observations("org-1", candidate.id)
    assert [item.id for item in current] == [second.id]
    assert second.superseded_observation_id == first.id

    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        credential_id="credential-1",
    )
    await repo.save_application(app)
    now = datetime.now(timezone.utc)
    passing = _fact(app=app, score=90, observed_at=now)
    await repo.record_evidence_revision(passing)
    binding = CanvasProgramBinding(id="binding-1", organization_id="org-1")

    def fake_evaluate(*, facts, **_kwargs):
        score = max((fact.assertion.get("score_percent", 0) for fact in facts), default=0)
        return EvidencePolicyDecision(
            allowed=score >= 80,
            engine="test",
            policy_source="test",
        )

    monkeypatch.setattr(canvas_evidence_revisions, "evaluate_application_evidence_policy", fake_evaluate)
    failing = _fact(app=app, score=55, observed_at=now + timedelta(minutes=1))
    drift = await canvas_evidence_revisions.record_authoritative_canvas_evidence_revision(
        repo=repo,
        app=app,
        template=None,
        binding=binding,
        fact=failing,
        requirements=[_requirement()],
    )
    assert drift.correction_review is not None
    assert drift.correction_review.status == EvidencePolicyReviewStatus.OPEN

    recovered = _fact(app=app, score=95, observed_at=now + timedelta(minutes=2))
    recovery = await canvas_evidence_revisions.record_authoritative_canvas_evidence_revision(
        repo=repo,
        app=app,
        template=None,
        binding=binding,
        fact=recovered,
        requirements=[_requirement()],
    )
    assert recovery.correction_review is not None
    assert recovery.correction_review.status == EvidencePolicyReviewStatus.RESOLVED
    assert recovery.correction_review.resolution_action == "evidence_recovered"
