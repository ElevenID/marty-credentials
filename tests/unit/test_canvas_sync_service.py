from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from issuance.application.canvas_sync_service import (
    CanvasSyncConflictError,
    CanvasSyncNotFoundError,
    CanvasSyncProcessingError,
    enqueue_application_canvas_sync,
    process_canvas_sync_target,
    resolve_evidence_policy_review,
)
from issuance.domain.entities import (
    Application,
    CanvasEvidenceSyncTarget,
    CanvasEvidenceSyncTargetType,
    CanvasPlatform,
    CanvasProgramBinding,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
    IssuedCredential,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository


@pytest.fixture(autouse=True)
def _enable_portable_canvas_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")


async def _canvas_application_fixture(
    repo: InMemoryIssuanceRepository,
    *,
    organization_id: str = "org-1",
) -> tuple[Application, CanvasPlatform, CanvasProgramBinding]:
    platform = CanvasPlatform(
        id="platform-1",
        organization_id=organization_id,
        canvas_account_id="account-1",
        enabled=True,
    )
    binding = CanvasProgramBinding(
        id="binding-1",
        organization_id=organization_id,
        platform_id=platform.id,
        application_template_id="template-1",
        credential_template_id="credential-template-1",
        enabled=True,
    )
    app = Application(
        id="application-1",
        organization_id=organization_id,
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
    await repo.save_application(app)
    return app, platform, binding


@pytest.mark.asyncio
async def test_application_enqueue_is_tenant_scoped_and_idempotent() -> None:
    repo = InMemoryIssuanceRepository()
    app, _platform, _binding = await _canvas_application_fixture(repo)

    target, first = await enqueue_application_canvas_sync(
        repo=repo,
        organization_id="org-1",
        application_id=app.id,
    )
    same_target, second = await enqueue_application_canvas_sync(
        repo=repo,
        organization_id="org-1",
        application_id=app.id,
    )

    assert target.id == same_target.id
    assert first.id == second.id
    assert target.logical_key == f"application:{app.id}"
    assert target.schedule_seconds == 15 * 60

    with pytest.raises(CanvasSyncNotFoundError):
        await enqueue_application_canvas_sync(
            repo=repo,
            organization_id="org-foreign",
            application_id=app.id,
        )


@pytest.mark.asyncio
async def test_application_enqueue_fails_when_binding_is_inactive() -> None:
    repo = InMemoryIssuanceRepository()
    app, _platform, binding = await _canvas_application_fixture(repo)
    binding.enabled = False
    await repo.save_canvas_program_binding(binding)

    with pytest.raises(CanvasSyncConflictError) as exc_info:
        await enqueue_application_canvas_sync(
            repo=repo,
            organization_id="org-1",
            application_id=app.id,
        )
    assert exc_info.value.code == "canvas_binding_inactive"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("global_enabled", "pilot_organizations"),
    [("false", "org-1"), ("true", "org-other")],
)
async def test_application_enqueue_fails_closed_outside_rollout(
    monkeypatch: pytest.MonkeyPatch,
    global_enabled: str,
    pilot_organizations: str,
) -> None:
    repo = InMemoryIssuanceRepository()
    app, _platform, _binding = await _canvas_application_fixture(repo)
    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", global_enabled)
    monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", pilot_organizations)

    with pytest.raises(CanvasSyncConflictError) as exc_info:
        await enqueue_application_canvas_sync(
            repo=repo,
            organization_id=app.organization_id,
            application_id=app.id,
        )

    assert exc_info.value.code == "canvas_rollout_disabled"
    assert await repo.get_canvas_sync_target_by_logical_key(
        app.organization_id,
        f"application:{app.id}",
    ) is None


@pytest.mark.asyncio
async def test_processor_does_not_dispatch_when_rollout_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    app, platform, binding = await _canvas_application_fixture(repo)
    target = CanvasEvidenceSyncTarget(
        organization_id=app.organization_id,
        platform_id=platform.id,
        binding_id=binding.id,
        target_type=CanvasEvidenceSyncTargetType.LEARNER_APPLICATION,
        logical_key=f"application:{app.id}",
        application_id=app.id,
    )
    dispatched = False

    async def processor(_repo, _target):
        nonlocal dispatched
        dispatched = True
        return {"facts_changed": 1}

    monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "false")
    result = await process_canvas_sync_target(repo, target, processor=processor)

    assert result == {"no_change": True}
    assert dispatched is False


@pytest.mark.asyncio
async def test_processor_rejects_secret_metadata_and_signing_outcomes() -> None:
    repo = InMemoryIssuanceRepository()
    app, platform, binding = await _canvas_application_fixture(repo)
    target = CanvasEvidenceSyncTarget(
        organization_id="org-1",
        platform_id=platform.id,
        binding_id=binding.id,
        target_type=CanvasEvidenceSyncTargetType.LEARNER_APPLICATION,
        logical_key=f"application:{app.id}",
        application_id=app.id,
        metadata={"access_token": "must-not-be-persisted"},
    )

    async def harmless_processor(_repo, _target):
        return {"facts_changed": 1}

    with pytest.raises(CanvasSyncProcessingError) as exc_info:
        await process_canvas_sync_target(repo, target, processor=harmless_processor)
    assert exc_info.value.code == "canvas_sync_target_contains_secret"
    assert not exc_info.value.retryable

    target.metadata = {}

    async def signing_processor(_repo, _target):
        return {"credential_id": "credential-1"}

    with pytest.raises(CanvasSyncProcessingError) as exc_info:
        await process_canvas_sync_target(repo, target, processor=signing_processor)
    assert exc_info.value.code == "canvas_background_signing_forbidden"


@pytest.mark.asyncio
async def test_processor_disables_stale_binding_configuration_without_dispatch() -> None:
    repo = InMemoryIssuanceRepository()
    app, platform, binding = await _canvas_application_fixture(repo)
    target = CanvasEvidenceSyncTarget(
        organization_id=app.organization_id,
        platform_id=platform.id,
        binding_id=binding.id,
        target_type=CanvasEvidenceSyncTargetType.LEARNER_APPLICATION,
        logical_key=f"application:{app.id}",
        application_id=app.id,
        config_version=1,
    )
    await repo.save_canvas_sync_target(target)
    binding.config_version = 2
    await repo.save_canvas_program_binding(binding)
    dispatched = False

    async def processor(_repo, _target):
        nonlocal dispatched
        dispatched = True
        return {}

    with pytest.raises(CanvasSyncProcessingError) as exc_info:
        await process_canvas_sync_target(repo, target, processor=processor)

    assert exc_info.value.code == "canvas_sync_target_config_stale"
    assert not exc_info.value.retryable
    assert dispatched is False
    stored = await repo.get_canvas_sync_target_for_org(app.organization_id, target.id)
    assert stored is not None and stored.enabled is False


@pytest.mark.asyncio
async def test_review_resolution_applies_lifecycle_action_before_closing() -> None:
    repo = InMemoryIssuanceRepository()
    app, _platform, binding = await _canvas_application_fixture(repo)
    credential = IssuedCredential(
        id="credential-1",
        transaction_id="transaction-1",
        organization_id="org-1",
    )
    await repo.save_credential(credential)
    review = EvidencePolicyReview(
        id="review-1",
        organization_id="org-1",
        application_id=app.id,
        credential_id=credential.id,
        binding_id=binding.id,
    )
    await repo.save_evidence_policy_review(review)
    lifecycle_calls: list[tuple[str, str, str]] = []

    async def lifecycle_handler(action, credential_id, reason, _repo):
        lifecycle_calls.append((action, credential_id, reason))

    resolved = await resolve_evidence_policy_review(
        repo=repo,
        organization_id="org-1",
        review_id=review.id,
        action="suspend",
        notes="Authoritative grade was lowered",
        resolved_by="admin-1",
        credential_handler=lifecycle_handler,
    )

    assert lifecycle_calls == [
        ("suspend", credential.id, "Authoritative grade was lowered")
    ]
    assert resolved.status == EvidencePolicyReviewStatus.SUSPENDED
    assert resolved.resolved_by == "admin-1"
    assert resolved.resolved_at is not None
    assert resolved.updated_at <= datetime.now(UTC)

    with pytest.raises(CanvasSyncConflictError):
        await resolve_evidence_policy_review(
            repo=repo,
            organization_id="org-1",
            review_id=review.id,
            action="dismiss",
            notes=None,
            resolved_by="admin-1",
        )

    with pytest.raises(CanvasSyncNotFoundError):
        await resolve_evidence_policy_review(
            repo=repo,
            organization_id="org-foreign",
            review_id=review.id,
            action="dismiss",
            notes=None,
            resolved_by="admin-1",
        )


@pytest.mark.asyncio
async def test_concurrent_review_resolution_claim_allows_only_one_lifecycle_side_effect() -> None:
    repo = InMemoryIssuanceRepository()
    app, _platform, binding = await _canvas_application_fixture(repo)
    credential = IssuedCredential(
        id="credential-1",
        transaction_id="transaction-1",
        organization_id="org-1",
    )
    await repo.save_credential(credential)
    review = EvidencePolicyReview(
        id="review-1",
        organization_id="org-1",
        application_id=app.id,
        credential_id=credential.id,
        binding_id=binding.id,
    )
    await repo.save_evidence_policy_review(review)
    handler_started = asyncio.Event()
    allow_handler_to_finish = asyncio.Event()
    lifecycle_calls: list[str] = []

    async def lifecycle_handler(action, _credential_id, _reason, _repo):
        lifecycle_calls.append(action)
        handler_started.set()
        await allow_handler_to_finish.wait()

    first_resolution = asyncio.create_task(
        resolve_evidence_policy_review(
            repo=repo,
            organization_id="org-1",
            review_id=review.id,
            action="suspend",
            notes="Authoritative grade was lowered",
            resolved_by="admin-1",
            credential_handler=lifecycle_handler,
        )
    )
    await handler_started.wait()
    try:
        with pytest.raises(CanvasSyncConflictError):
            await resolve_evidence_policy_review(
                repo=repo,
                organization_id="org-1",
                review_id=review.id,
                action="revoke",
                notes="Concurrent correction",
                resolved_by="admin-2",
                credential_handler=lifecycle_handler,
            )
    finally:
        allow_handler_to_finish.set()
    resolved = await first_resolution

    assert lifecycle_calls == ["suspend"]
    assert resolved.status == EvidencePolicyReviewStatus.SUSPENDED
    assert resolved.resolution_claim_token is None
    events = await repo.list_events_for_application(app.id)
    assert len(events) == 1
    assert events[0].metadata["resolution_action"] == "suspend"


@pytest.mark.asyncio
async def test_failed_review_handler_releases_claim_back_to_open() -> None:
    repo = InMemoryIssuanceRepository()
    app, _platform, binding = await _canvas_application_fixture(repo)
    credential = IssuedCredential(
        id="credential-1",
        transaction_id="transaction-1",
        organization_id="org-1",
    )
    await repo.save_credential(credential)
    review = EvidencePolicyReview(
        id="review-1",
        organization_id="org-1",
        application_id=app.id,
        credential_id=credential.id,
        binding_id=binding.id,
    )
    await repo.save_evidence_policy_review(review)

    async def failing_handler(*_args):
        raise RuntimeError("credential service unavailable")

    with pytest.raises(RuntimeError, match="credential service unavailable"):
        await resolve_evidence_policy_review(
            repo=repo,
            organization_id="org-1",
            review_id=review.id,
            action="revoke",
            notes=None,
            resolved_by="admin-1",
            credential_handler=failing_handler,
        )

    reopened = await repo.get_evidence_policy_review_for_org("org-1", review.id)
    assert reopened is not None
    assert reopened.status == EvidencePolicyReviewStatus.OPEN
    assert reopened.resolution_claim_token is None
    assert await repo.list_events_for_application(app.id) == []

    dismissed = await resolve_evidence_policy_review(
        repo=repo,
        organization_id="org-1",
        review_id=review.id,
        action="dismiss",
        notes="No lifecycle change required",
        resolved_by="admin-2",
    )
    assert dismissed.status == EvidencePolicyReviewStatus.DISMISSED


@pytest.mark.asyncio
async def test_failed_review_handler_finalizes_recovery_observed_during_claim() -> None:
    repo = InMemoryIssuanceRepository()
    app, _platform, binding = await _canvas_application_fixture(repo)
    credential = IssuedCredential(
        id="credential-1",
        transaction_id="transaction-1",
        organization_id="org-1",
    )
    await repo.save_credential(credential)
    review = EvidencePolicyReview(
        id="review-1",
        organization_id="org-1",
        application_id=app.id,
        credential_id=credential.id,
        binding_id=binding.id,
        resolution_recovery_pending=True,
    )
    await repo.save_evidence_policy_review(review)

    async def failing_handler(*_args):
        raise RuntimeError("credential service unavailable")

    with pytest.raises(RuntimeError, match="credential service unavailable"):
        await resolve_evidence_policy_review(
            repo=repo,
            organization_id="org-1",
            review_id=review.id,
            action="suspend",
            notes=None,
            resolved_by="admin-1",
            credential_handler=failing_handler,
        )

    recovered = await repo.get_evidence_policy_review_for_org("org-1", review.id)
    assert recovered is not None
    assert recovered.status == EvidencePolicyReviewStatus.RESOLVED
    assert recovered.resolution_action == "evidence_recovered"
    assert recovered.resolution_claim_token is None
    assert recovered.resolution_recovery_pending is False
    events = await repo.list_events_for_application(app.id)
    assert len(events) == 1
    assert events[0].metadata["resolution_action"] == "evidence_recovered"
