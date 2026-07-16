from __future__ import annotations

import asyncio
import copy
from collections import Counter
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from issuance.application import canvas_evidence_revisions, canvas_sync_service
from issuance.application.evidence_policy import EvidencePolicyDecision
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    CanvasPlatform,
    CanvasProgramBinding,
    EventType,
    EvidenceFact,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
    IssuanceEvent,
)
from issuance.domain.ports import CanvasEvidenceAtomicMutation
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository


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
        requirement_id="assignment-pass",
        observed_at=observed_at,
        effective_at=observed_at,
    )


def _score_policy(*, facts: list[EvidenceFact], **_kwargs) -> EvidencePolicyDecision:
    score = max((fact.assertion.get("score_percent", 0) for fact in facts), default=0)
    return EvidencePolicyDecision(
        allowed=score >= 80,
        engine="atomicity-test",
        policy_source="test",
    )


class _YieldingMemoryRepository(InMemoryIssuanceRepository):
    """Force scheduling points inside the application-scoped atomic lock."""

    async def record_evidence_revision(self, fact: EvidenceFact) -> tuple[EvidenceFact, bool]:
        await asyncio.sleep(0)
        return await super().record_evidence_revision(fact)

    async def list_current_evidence_facts_for_application(
        self,
        application_id: str,
        *,
        organization_id: str | None = None,
    ) -> list[EvidenceFact]:
        await asyncio.sleep(0)
        return await super().list_current_evidence_facts_for_application(
            application_id,
            organization_id=organization_id,
        )

    async def get_open_evidence_policy_review(
        self,
        organization_id: str,
        application_id: str,
    ) -> EvidencePolicyReview | None:
        await asyncio.sleep(0)
        return await super().get_open_evidence_policy_review(organization_id, application_id)


class _FailSecondEventMemoryRepository(InMemoryIssuanceRepository):
    def __init__(self) -> None:
        super().__init__()
        self.event_write_count = 0

    async def save_event(self, event: IssuanceEvent) -> None:
        self.event_write_count += 1
        if self.event_write_count == 2:
            raise RuntimeError("review audit insert failed")
        await super().save_event(event)


@pytest.mark.asyncio
async def test_concurrent_authoritative_revisions_create_one_review_and_one_review_audit_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _YieldingMemoryRepository()
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        credential_id="credential-1",
    )
    await repo.save_application(app)
    started_at = datetime(2026, 7, 14, tzinfo=UTC)
    passing = _fact(app=app, score=95, observed_at=started_at)
    await repo.record_evidence_revision(passing)
    monkeypatch.setattr(
        canvas_evidence_revisions,
        "evaluate_application_evidence_policy",
        _score_policy,
    )
    binding = CanvasProgramBinding(id="binding-1", organization_id=app.organization_id)
    failing_facts = [
        _fact(app=app, score=50 + index, observed_at=started_at + timedelta(minutes=index + 1))
        for index in range(8)
    ]

    results = await asyncio.gather(
        *(
            canvas_evidence_revisions.record_authoritative_canvas_evidence_revision(
                repo=repo,
                app=app,
                template=None,
                binding=binding,
                fact=fact,
                requirements=[],
            )
            for fact in failing_facts
        )
    )

    current = await repo.list_current_evidence_facts_for_application(
        app.id,
        organization_id=app.organization_id,
    )
    reviews = await repo.list_evidence_policy_reviews(
        app.organization_id,
        status=EvidencePolicyReviewStatus.OPEN,
    )
    events = await repo.list_events_for_application(app.id)
    assert [fact.id for fact in current] == [failing_facts[-1].id]
    assert len(reviews) == 1
    assert reviews[0].triggering_fact_id == failing_facts[-1].id
    expected_fact_event_ids = Counter(
        result.evidence_fact.id for result in results if result.inserted
    )
    actual_fact_event_ids = Counter(
        event.metadata["fact_id"]
        for event in events
        if event.event_type == EventType.EVIDENCE_FACT_CREATED
    )
    assert actual_fact_event_ids == expected_fact_event_ids
    assert all(count == 1 for count in actual_fact_event_ids.values())
    assert sum(
        event.event_type == EventType.EVIDENCE_POLICY_REVIEW_CREATED for event in events
    ) == 1
    for event in events:
        if event.event_type == EventType.EVIDENCE_FACT_CREATED:
            assert event.metadata.keys() >= {
                "organization_id",
                "provider",
                "requirement_id",
                "fact_id",
                "source_revision",
            }
            assert event.metadata["organization_id"] == app.organization_id
            assert event.metadata["provider"] == "canvas"
            assert event.metadata["requirement_id"] == "assignment-pass"
            assert event.metadata["fact_id"] in {fact.id for fact in failing_facts}
            assert event.metadata["source_revision"]


@pytest.mark.asyncio
async def test_memory_atomic_transition_rolls_back_fact_head_review_and_event_on_policy_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        credential_id="credential-1",
    )
    await repo.save_application(app)
    started_at = datetime(2026, 7, 14, tzinfo=UTC)
    passing = _fact(app=app, score=95, observed_at=started_at)
    await repo.record_evidence_revision(passing)
    evaluation_count = 0

    def fail_current_policy(**kwargs) -> EvidencePolicyDecision:
        nonlocal evaluation_count
        evaluation_count += 1
        if evaluation_count == 2:
            raise RuntimeError("policy engine unavailable")
        return _score_policy(**kwargs)

    monkeypatch.setattr(
        canvas_evidence_revisions,
        "evaluate_application_evidence_policy",
        fail_current_policy,
    )
    failing = _fact(app=app, score=45, observed_at=started_at + timedelta(minutes=1))

    with pytest.raises(RuntimeError, match="policy engine unavailable"):
        await canvas_evidence_revisions.record_authoritative_canvas_evidence_revision(
            repo=repo,
            app=app,
            template=None,
            binding=CanvasProgramBinding(id="binding-1", organization_id=app.organization_id),
            fact=failing,
            requirements=[],
        )

    current = await repo.list_current_evidence_facts_for_application(
        app.id,
        organization_id=app.organization_id,
    )
    history = await repo.list_evidence_facts_for_application(
        app.id,
        organization_id=app.organization_id,
    )
    assert [fact.id for fact in current] == [passing.id]
    assert [fact.id for fact in history] == [passing.id]
    assert await repo.list_evidence_policy_reviews(app.organization_id) == []
    assert await repo.list_events_for_application(app.id) == []


@pytest.mark.asyncio
async def test_memory_atomic_transition_rolls_back_after_late_review_event_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _FailSecondEventMemoryRepository()
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        credential_id="credential-1",
    )
    await repo.save_application(app)
    started_at = datetime(2026, 7, 14, tzinfo=UTC)
    passing = _fact(app=app, score=95, observed_at=started_at)
    await repo.record_evidence_revision(passing)
    monkeypatch.setattr(
        canvas_evidence_revisions,
        "evaluate_application_evidence_policy",
        _score_policy,
    )
    failing = _fact(app=app, score=45, observed_at=started_at + timedelta(minutes=1))

    with pytest.raises(RuntimeError, match="review audit insert failed"):
        await canvas_evidence_revisions.record_authoritative_canvas_evidence_revision(
            repo=repo,
            app=app,
            template=None,
            binding=CanvasProgramBinding(id="binding-1", organization_id=app.organization_id),
            fact=failing,
            requirements=[],
        )

    current = await repo.list_current_evidence_facts_for_application(
        app.id,
        organization_id=app.organization_id,
    )
    history = await repo.list_evidence_facts_for_application(
        app.id,
        organization_id=app.organization_id,
    )
    assert [fact.id for fact in current] == [passing.id]
    assert [fact.id for fact in history] == [passing.id]
    assert await repo.list_evidence_policy_reviews(app.organization_id) == []
    assert await repo.list_events_for_application(app.id) == []


@pytest.mark.asyncio
async def test_automatic_recovery_does_not_resolve_a_manually_claimed_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        credential_id="credential-1",
    )
    await repo.save_application(app)
    started_at = datetime(2026, 7, 14, tzinfo=UTC)
    failing = _fact(app=app, score=45, observed_at=started_at)
    await repo.record_evidence_revision(failing)
    review = EvidencePolicyReview(
        organization_id=app.organization_id,
        application_id=app.id,
        credential_id=app.credential_id or "",
        prior_decision={"allowed": True},
        current_decision={"allowed": False},
        triggering_fact_id=failing.id,
    )
    await repo.save_evidence_policy_review(review)
    claimed = await repo.claim_evidence_policy_review_resolution(
        app.organization_id,
        review.id,
        claim_token="manual-claim",
        action="suspend",
    )
    assert claimed is not None
    monkeypatch.setattr(
        canvas_evidence_revisions,
        "evaluate_application_evidence_policy",
        _score_policy,
    )

    recovered = _fact(app=app, score=95, observed_at=started_at + timedelta(minutes=1))
    result = await canvas_evidence_revisions.record_authoritative_canvas_evidence_revision(
        repo=repo,
        app=app,
        template=None,
        binding=CanvasProgramBinding(id="binding-1", organization_id=app.organization_id),
        fact=recovered,
        requirements=[],
    )

    stored = await repo.get_evidence_policy_review_for_org(app.organization_id, review.id)
    assert stored is not None
    assert stored.status == EvidencePolicyReviewStatus.OPEN
    assert stored.resolution_claim_token == "manual-claim"
    assert stored.resolution_recovery_pending is True
    assert result.correction_review is not None
    assert result.correction_review.status == EvidencePolicyReviewStatus.OPEN
    assert await repo.release_evidence_policy_review_resolution(
        app.organization_id,
        review.id,
        claim_token="manual-claim",
    )
    await canvas_sync_service._finalize_pending_evidence_recovery(
        repo=repo,
        organization_id=app.organization_id,
        review_id=review.id,
    )
    stored = await repo.get_evidence_policy_review_for_org(app.organization_id, review.id)
    assert stored is not None
    assert stored.status == EvidencePolicyReviewStatus.RESOLVED
    assert stored.resolution_recovery_pending is False
    events = await repo.list_events_for_application(app.id)
    assert [event.event_type for event in events] == [
        EventType.EVIDENCE_FACT_CREATED,
        EventType.EVIDENCE_POLICY_REVIEW_RESOLVED,
    ]


@pytest.mark.asyncio
async def test_out_of_order_revision_is_audited_once_without_advancing_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
    )
    await repo.save_application(app)
    started_at = datetime(2026, 7, 14, tzinfo=UTC)
    newest = _fact(app=app, score=95, observed_at=started_at + timedelta(minutes=2))
    await repo.record_evidence_revision(newest)
    monkeypatch.setattr(
        canvas_evidence_revisions,
        "evaluate_application_evidence_policy",
        _score_policy,
    )
    older = _fact(app=app, score=45, observed_at=started_at + timedelta(minutes=1))

    first = await canvas_evidence_revisions.record_authoritative_canvas_evidence_revision(
        repo=repo,
        app=app,
        template=None,
        binding=CanvasProgramBinding(id="binding-1", organization_id=app.organization_id),
        fact=older,
        requirements=[],
    )
    replay = await canvas_evidence_revisions.record_authoritative_canvas_evidence_revision(
        repo=repo,
        app=app,
        template=None,
        binding=CanvasProgramBinding(id="binding-1", organization_id=app.organization_id),
        fact=older,
        requirements=[],
    )

    current = await repo.list_current_evidence_facts_for_application(
        app.id,
        organization_id=app.organization_id,
    )
    history = await repo.list_evidence_facts_for_application(
        app.id,
        organization_id=app.organization_id,
    )
    events = await repo.list_events_for_application(app.id)
    assert first.inserted is True
    assert first.changed is False
    assert replay.inserted is False
    assert replay.changed is False
    assert [fact.id for fact in current] == [newest.id]
    assert {fact.id for fact in history} == {newest.id, older.id}
    assert [event.metadata["fact_id"] for event in events] == [older.id]


class _Result:
    def __init__(self, *, row=None, rows=None) -> None:
        self._row = row
        self._rows = list(rows or [])

    def first(self):
        return self._row

    def all(self):
        return list(self._rows)


class _FakeTransaction:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    async def __aenter__(self):
        self._session.begin_count += 1
        self._session.transaction_active = True
        return self

    async def __aexit__(self, exc_type, _exc, _traceback):
        if exc_type is None:
            self._session.committed = True
        else:
            self._session.rolled_back = True
        self._session.transaction_active = False
        return False


class _FakeSession:
    def __init__(self, results: list[_Result | Exception]) -> None:
        self._results = list(results)
        self.statements = []
        self.begin_count = 0
        self.transaction_active = False
        self.execute_transaction_states: list[bool] = []
        self.committed = False
        self.rolled_back = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def begin(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    async def execute(self, statement):
        self.statements.append(statement)
        self.execute_transaction_states.append(self.transaction_active)
        result = self._results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class _FakeSessionFactory:
    def __init__(self, session: _FakeSession) -> None:
        self.session = session
        self.call_count = 0

    def __call__(self) -> _FakeSession:
        self.call_count += 1
        return self.session


def _application_row(app: Application) -> SimpleNamespace:
    return SimpleNamespace(
        id=app.id,
        organization_id=app.organization_id,
        application_template_id=app.application_template_id,
        applicant_identifier=app.applicant_identifier,
        form_data=app.form_data,
        submitted_evidence=app.evidence_submissions,
        integration_context=app.integration_context,
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        rejection_reason=app.rejection_reason,
        derived_claims=app.derived_claims,
        issuance_transaction_id=app.issuance_transaction_id,
        credential_id=app.credential_id,
        created_at=app.created_at,
        updated_at=app.updated_at,
        submitted_at=app.submitted_at,
        reviewed_at=app.reviewed_at,
        expires_at=app.expires_at,
    )


def _fact_row(fact: EvidenceFact) -> SimpleNamespace:
    return SimpleNamespace(**vars(fact))


def _review_row(review: EvidencePolicyReview) -> SimpleNamespace:
    return SimpleNamespace(**vars(review))


def _platform_row(platform: CanvasPlatform) -> SimpleNamespace:
    return SimpleNamespace(**vars(platform))


@pytest.mark.asyncio
async def test_postgres_authoritative_transition_uses_one_transaction_and_application_lock() -> None:
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        credential_id="credential-1",
    )
    started_at = datetime(2026, 7, 14, tzinfo=UTC)
    passing = _fact(app=app, score=95, observed_at=started_at)
    failing = _fact(app=app, score=45, observed_at=started_at + timedelta(minutes=1))
    failing.superseded_fact_id = passing.id
    review = EvidencePolicyReview(
        organization_id=app.organization_id,
        application_id=app.id,
        credential_id=app.credential_id or "",
        prior_decision={"allowed": True},
        current_decision={"allowed": False},
        triggering_fact_id=failing.id,
    )
    fact_event = IssuanceEvent(
        application_id=app.id,
        event_type=EventType.EVIDENCE_FACT_CREATED,
        metadata={"fact_id": failing.id},
    )
    review_event = IssuanceEvent(
        application_id=app.id,
        event_type=EventType.EVIDENCE_POLICY_REVIEW_CREATED,
        metadata={"review_id": review.id},
    )
    session = _FakeSession(
        [
            _Result(row=_application_row(app)),
            _Result(rows=[_fact_row(passing)]),
            _Result(row=_fact_row(passing)),
            _Result(row=_fact_row(failing)),
            _Result(),
            _Result(rows=[_fact_row(failing)]),
            _Result(row=None),
            _Result(),
            _Result(),
            _Result(),
        ]
    )
    factory = _FakeSessionFactory(session)
    repo = PostgresIssuanceRepository(factory)

    def transition(**values) -> CanvasEvidenceAtomicMutation:
        assert values["app"].credential_id == "credential-1"
        assert [fact.id for fact in values["previous_facts"]] == [passing.id]
        assert [fact.id for fact in values["current_facts"]] == [failing.id]
        return CanvasEvidenceAtomicMutation(
            policy_decision=EvidencePolicyDecision(
                allowed=False,
                engine="atomicity-test",
            ),
            correction_review=review,
            review_changed=True,
            audit_events=(fact_event, review_event),
        )

    result = await repo.commit_authoritative_canvas_evidence_revision(
        failing,
        transition=transition,
    )

    sql = [str(statement).upper() for statement in session.statements]
    assert factory.call_count == 1
    assert session.begin_count == 1
    assert session.committed is True
    assert session.rolled_back is False
    assert all(session.execute_transaction_states)
    assert "FOR UPDATE" in sql[0]
    assert "FOR UPDATE" in sql[2]
    assert "FOR UPDATE" in sql[6]
    assert "INSERT INTO ISSUANCE_SERVICE.EVIDENCE_POLICY_REVIEWS" in sql[7]
    assert "INSERT INTO ISSUANCE_SERVICE.ISSUANCE_EVENTS" in sql[8]
    assert "INSERT INTO ISSUANCE_SERVICE.ISSUANCE_EVENTS" in sql[9]
    assert result.changed is True
    assert result.inserted is True
    assert result.evidence_fact.id == failing.id
    assert result.correction_review is review


@pytest.mark.asyncio
async def test_postgres_atomic_transition_rolls_back_when_audit_insert_fails() -> None:
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        credential_id="credential-1",
    )
    started_at = datetime(2026, 7, 14, tzinfo=UTC)
    passing = _fact(app=app, score=95, observed_at=started_at)
    failing = _fact(app=app, score=45, observed_at=started_at + timedelta(minutes=1))
    failing.superseded_fact_id = passing.id
    review = EvidencePolicyReview(
        organization_id=app.organization_id,
        application_id=app.id,
        credential_id=app.credential_id or "",
    )
    fact_event = IssuanceEvent(
        application_id=app.id,
        event_type=EventType.EVIDENCE_FACT_CREATED,
    )
    review_event = IssuanceEvent(
        application_id=app.id,
        event_type=EventType.EVIDENCE_POLICY_REVIEW_CREATED,
    )
    session = _FakeSession(
        [
            _Result(row=_application_row(app)),
            _Result(rows=[_fact_row(passing)]),
            _Result(row=_fact_row(passing)),
            _Result(row=_fact_row(failing)),
            _Result(),
            _Result(rows=[_fact_row(failing)]),
            _Result(row=None),
            _Result(),
            _Result(),
            RuntimeError("audit insert failed"),
        ]
    )
    factory = _FakeSessionFactory(session)
    repo = PostgresIssuanceRepository(factory)

    with pytest.raises(RuntimeError, match="audit insert failed"):
        await repo.commit_authoritative_canvas_evidence_revision(
            failing,
            transition=lambda **_values: CanvasEvidenceAtomicMutation(
                policy_decision=EvidencePolicyDecision(False, "atomicity-test"),
                correction_review=review,
                review_changed=True,
                audit_events=(fact_event, review_event),
            ),
        )

    assert factory.call_count == 1
    assert session.begin_count == 1
    assert session.committed is False
    assert session.rolled_back is True
    assert all(session.execute_transaction_states)
    sql = [str(statement).upper() for statement in session.statements]
    assert "INSERT INTO ISSUANCE_SERVICE.EVIDENCE_POLICY_REVIEWS" in sql[-3]
    assert "INSERT INTO ISSUANCE_SERVICE.ISSUANCE_EVENTS" in sql[-2]
    assert "INSERT INTO ISSUANCE_SERVICE.ISSUANCE_EVENTS" in sql[-1]


@pytest.mark.asyncio
async def test_postgres_manual_review_claim_and_finalize_use_cas_transactions() -> None:
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        credential_id="credential-1",
    )
    review = EvidencePolicyReview(
        id="review-1",
        organization_id=app.organization_id,
        application_id=app.id,
        credential_id=app.credential_id or "",
    )
    claimed_review = EvidencePolicyReview(**vars(review))
    claimed_review.resolution_claim_token = "claim-1"
    claimed_review.resolution_claim_action = "suspend"
    claimed_review.resolution_claimed_at = datetime(2026, 7, 14, tzinfo=UTC)
    claim_session = _FakeSession(
        [
            _Result(row=SimpleNamespace(application_id=app.id)),
            _Result(row=SimpleNamespace(id=app.id)),
            _Result(row=_review_row(claimed_review)),
        ]
    )
    claim_factory = _FakeSessionFactory(claim_session)
    repo = PostgresIssuanceRepository(claim_factory)

    claimed = await repo.claim_evidence_policy_review_resolution(
        app.organization_id,
        review.id,
        claim_token="claim-1",
        action="suspend",
    )

    claim_sql = [str(statement).upper() for statement in claim_session.statements]
    assert claimed is not None
    assert claimed.resolution_claim_token == "claim-1"
    assert claim_factory.call_count == 1
    assert claim_session.begin_count == 1
    assert claim_session.committed is True
    assert all(claim_session.execute_transaction_states)
    assert "FOR UPDATE" in claim_sql[1]
    assert "RESOLUTION_CLAIM_TOKEN IS NULL" in claim_sql[2]

    resolved_at = datetime(2026, 7, 14, 1, tzinfo=UTC)
    finalized_review = EvidencePolicyReview(**vars(claimed_review))
    finalized_review.status = EvidencePolicyReviewStatus.SUSPENDED
    finalized_review.resolution_action = "suspend"
    finalized_review.resolved_by = "admin-1"
    finalized_review.resolved_at = resolved_at
    finalized_review.resolution_claim_token = None
    finalized_review.resolution_claim_action = None
    finalized_review.resolution_claimed_at = None
    audit_event = IssuanceEvent(
        application_id=app.id,
        event_type=EventType.EVIDENCE_POLICY_REVIEW_RESOLVED,
    )
    finalize_session = _FakeSession(
        [
            _Result(row=_review_row(finalized_review)),
            _Result(),
        ]
    )
    finalize_factory = _FakeSessionFactory(finalize_session)
    finalize_repo = PostgresIssuanceRepository(finalize_factory)

    finalized = await finalize_repo.finalize_evidence_policy_review_resolution(
        app.organization_id,
        review.id,
        claim_token="claim-1",
        status=EvidencePolicyReviewStatus.SUSPENDED,
        resolution_action="suspend",
        resolution_notes=None,
        resolved_by="admin-1",
        resolved_at=resolved_at,
        audit_event=audit_event,
    )

    finalize_sql = [str(statement).upper() for statement in finalize_session.statements]
    assert finalized is not None
    assert finalized.status == EvidencePolicyReviewStatus.SUSPENDED
    assert finalized.resolution_claim_token is None
    assert finalize_factory.call_count == 1
    assert finalize_session.begin_count == 1
    assert finalize_session.committed is True
    assert all(finalize_session.execute_transaction_states)
    assert "RESOLUTION_CLAIM_TOKEN" in finalize_sql[0]
    assert "RESOLUTION_CLAIM_ACTION" in finalize_sql[0]
    assert "INSERT INTO ISSUANCE_SERVICE.ISSUANCE_EVENTS" in finalize_sql[1]


@pytest.mark.asyncio
async def test_narrow_application_context_patch_preserves_concurrent_lifecycle_fields() -> None:
    repo = InMemoryIssuanceRepository()
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        integration_context={
            "canvas": {"launch_id": "launch-1", "last_evidence_sync_at": "old"},
            "other_integration": {"preserve": True},
        },
    )
    await repo.save_application(app)
    stale_updated_at = app.updated_at
    authoritative = copy.deepcopy(app)
    authoritative.status = ApplicationStatus.APPROVED
    authoritative.credential_id = "credential-1"
    authoritative.issuance_transaction_id = "transaction-1"
    authoritative.reviewer_id = "approver-1"
    authoritative.updated_at = stale_updated_at + timedelta(seconds=1)
    await repo.save_application(authoritative)

    stale_cas = await repo.patch_application_integration_context(
        app.organization_id,
        app.id,
        patch={"canvas": {"last_evidence_sync_at": "should-not-write"}},
        expected_updated_at=stale_updated_at,
    )
    patched = await repo.patch_application_integration_context(
        app.organization_id,
        app.id,
        patch={
            "canvas": {
                "last_evidence_sync_at": "2026-07-14T00:00:00Z",
                "last_evidence_policy_allowed": True,
            }
        },
    )

    assert stale_cas is None
    assert patched is not None
    assert patched.status == ApplicationStatus.APPROVED
    assert patched.credential_id == "credential-1"
    assert patched.issuance_transaction_id == "transaction-1"
    assert patched.reviewer_id == "approver-1"
    assert patched.integration_context == {
        "canvas": {
            "launch_id": "launch-1",
            "last_evidence_sync_at": "2026-07-14T00:00:00Z",
            "last_evidence_policy_allowed": True,
        },
        "other_integration": {"preserve": True},
    }


@pytest.mark.asyncio
async def test_postgres_context_patch_updates_only_context_and_timestamp() -> None:
    app = Application(
        organization_id="org-1",
        application_template_id="template-1",
        status=ApplicationStatus.APPROVED,
        credential_id="credential-1",
        issuance_transaction_id="transaction-1",
        reviewer_id="approver-1",
        integration_context={"canvas": {"launch_id": "launch-1"}},
    )
    updated_app = copy.deepcopy(app)
    updated_app.integration_context = {
        "canvas": {
            "launch_id": "launch-1",
            "last_evidence_sync_at": "2026-07-14T00:00:00Z",
        }
    }
    updated_app.updated_at = app.updated_at + timedelta(seconds=1)
    session = _FakeSession(
        [
            _Result(row=_application_row(app)),
            _Result(row=_application_row(updated_app)),
        ]
    )
    factory = _FakeSessionFactory(session)
    repo = PostgresIssuanceRepository(factory)

    patched = await repo.patch_application_integration_context(
        app.organization_id,
        app.id,
        patch={"canvas": {"last_evidence_sync_at": "2026-07-14T00:00:00Z"}},
    )

    sql = [str(statement).upper() for statement in session.statements]
    assert patched is not None
    assert patched.status == ApplicationStatus.APPROVED
    assert patched.credential_id == "credential-1"
    assert patched.issuance_transaction_id == "transaction-1"
    assert factory.call_count == 1
    assert session.begin_count == 1
    assert "FOR UPDATE" in sql[0]
    assert "SET INTEGRATION_CONTEXT=" in sql[1]
    assert "UPDATED_AT=" in sql[1]
    assert "STATUS=" not in sql[1]
    assert "CREDENTIAL_ID=" not in sql[1]
    assert "ISSUANCE_TRANSACTION_ID=" not in sql[1]


@pytest.mark.asyncio
async def test_platform_validation_patch_cas_preserves_concurrent_configuration() -> None:
    repo = InMemoryIssuanceRepository()
    platform = CanvasPlatform(
        organization_id="org-1",
        canvas_account_id="account-1",
        display_name="Original",
        canvas_base_url="https://canvas.example.edu",
        connection_config={"oauth_status": "connected"},
        capability_snapshot={"assignment_grade_services": True},
        config_version=1,
        enabled=True,
    )
    await repo.save_canvas_platform(platform)
    concurrent = copy.deepcopy(platform)
    concurrent.display_name = "Concurrent configuration"
    concurrent.connection_config = {"oauth_status": "reauthorization_required"}
    concurrent.capability_snapshot = {"assignment_grade_services": False}
    concurrent.config_version = 2
    concurrent.enabled = False
    await repo.save_canvas_platform(concurrent)
    validated_at = datetime(2026, 7, 14, tzinfo=UTC)

    stale = await repo.patch_canvas_platform_validation_state(
        platform.organization_id,
        platform.id,
        expected_config_version=1,
        last_validated_at=validated_at,
        last_connection_error=None,
    )
    patched = await repo.patch_canvas_platform_validation_state(
        platform.organization_id,
        platform.id,
        expected_config_version=2,
        last_validated_at=validated_at,
        last_connection_error="canvas_authoritative_reads_failed",
    )

    assert stale is None
    assert patched is not None
    assert patched.display_name == "Concurrent configuration"
    assert patched.connection_config == {"oauth_status": "reauthorization_required"}
    assert patched.capability_snapshot == {"assignment_grade_services": False}
    assert patched.config_version == 2
    assert patched.enabled is False
    assert patched.last_validated_at == validated_at
    assert patched.last_connection_error == "canvas_authoritative_reads_failed"


@pytest.mark.asyncio
async def test_postgres_platform_validation_patch_updates_only_operational_columns() -> None:
    platform = CanvasPlatform(
        organization_id="org-1",
        canvas_account_id="account-1",
        display_name="Concurrent configuration",
        canvas_base_url="https://canvas.example.edu",
        connection_config={"oauth_status": "reauthorization_required"},
        capability_snapshot={"assignment_grade_services": False},
        config_version=2,
        enabled=False,
    )
    validated_at = datetime(2026, 7, 14, tzinfo=UTC)
    returned = copy.deepcopy(platform)
    returned.last_validated_at = validated_at
    returned.last_connection_error = None
    session = _FakeSession([_Result(row=_platform_row(returned))])
    factory = _FakeSessionFactory(session)
    repo = PostgresIssuanceRepository(factory)

    patched = await repo.patch_canvas_platform_validation_state(
        platform.organization_id,
        platform.id,
        expected_config_version=platform.config_version,
        last_validated_at=validated_at,
        last_connection_error=None,
    )

    sql = str(session.statements[0]).upper()
    set_clause = sql.split(" SET ", 1)[1].split(" WHERE ", 1)[0]
    assert patched is not None
    assert patched.display_name == "Concurrent configuration"
    assert patched.connection_config == {"oauth_status": "reauthorization_required"}
    assert patched.config_version == 2
    assert factory.call_count == 1
    assert session.begin_count == 1
    assert "LAST_VALIDATED_AT=" in set_clause
    assert "LAST_CONNECTION_ERROR=" in set_clause
    assert "UPDATED_AT=" in set_clause
    assert "DISPLAY_NAME=" not in set_clause
    assert "CONNECTION_CONFIG=" not in set_clause
    assert "CAPABILITY_SNAPSHOT=" not in set_clause
    assert "CONFIG_VERSION=" not in set_clause
    assert "ENABLED=" not in set_clause
