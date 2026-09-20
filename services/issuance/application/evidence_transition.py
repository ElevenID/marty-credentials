"""Shared MIP evidence fact to policy and issuance transition service."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from issuance.application.application_approval import (
    ApplicationTransitionConflictError,
    IssuerContextApplier,
    commit_prepared_application_issuance,
    prepare_application_issuance,
)
from issuance.application.evidence_policy import (
    EvidencePolicyDecision,
    evaluate_application_evidence_policy,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    EventType,
    EvidenceFact,
    IssuanceEvent,
    IssuanceTransaction,
)
from issuance.domain.ports import IIssuanceRepository


@dataclass(frozen=True)
class EvidenceTransitionResult:
    """Outcome after a provider fact has been persisted and evaluated."""

    evidence_fact: EvidenceFact
    facts: list[EvidenceFact]
    policy_decision: EvidencePolicyDecision | None = None
    issuance_transaction: IssuanceTransaction | None = None


async def _save_application_revision(
    *,
    repo: IIssuanceRepository,
    app: Application,
    expected_status: ApplicationStatus,
    expected_updated_at: datetime,
    evidence_fact: EvidenceFact,
    audit_events: tuple[IssuanceEvent, ...],
) -> None:
    if not await repo.save_application_if_status(
        app,
        expected_status=expected_status,
        expected_updated_at=expected_updated_at,
        evidence_fact=evidence_fact,
        audit_events=audit_events,
    ):
        raise ApplicationTransitionConflictError(
            "Application lifecycle changed during evidence processing"
        )


def _audit_event(
    *,
    app: Application,
    event_type: EventType,
    metadata: dict[str, Any],
    transaction_id: str | None = None,
) -> IssuanceEvent:
    return IssuanceEvent(
        transaction_id=transaction_id,
        application_id=app.id,
        event_type=event_type,
        metadata={"organization_id": app.organization_id, **metadata},
    )


def _merge_context(existing: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in updates.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = {**current, **value}
        else:
            merged[key] = value
    return merged


async def _load_approval_policy_set(
    *,
    repo: IIssuanceRepository,
    app: Application,
    template: ApplicationTemplate | None,
    binding: Any | None,
):
    policy_set_id = (
        getattr(binding, "approval_policy_set_id", None)
        or (getattr(template, "approval_policy_set_id", None) if template else None)
    )
    if not policy_set_id:
        return None
    return await repo.get_approval_policy_set(app.organization_id, policy_set_id)


async def persist_evidence_fact_and_apply_policy(
    *,
    repo: IIssuanceRepository,
    app: Application,
    template: ApplicationTemplate | None,
    evidence_fact: EvidenceFact,
    evidence_submission: dict[str, Any],
    integration_context_updates: dict[str, Any] | None,
    requirements: list[Any],
    source: str,
    audit_metadata: dict[str, Any] | None = None,
    binding: Any | None = None,
    evaluate_policy: bool = True,
    issue_on_permit: bool = True,
    auto_issue_on_permit: bool = False,
    reviewer_id: str = "mip-evidence:auto-approval",
    review_notes: str = "Auto-approved by MIP policy after verified evidence satisfied requirements",
    issuer_context_applier: IssuerContextApplier | None = None,
) -> EvidenceTransitionResult:
    """Persist a normalized fact, evaluate approval policy, and optionally issue.

    Provider adapters should do provider-specific validation and normalization, then
    call this service for the canonical MIP transition behavior.
    """

    now = datetime.now(timezone.utc)
    metadata = dict(audit_metadata or {})
    expected_status = app.status
    expected_updated_at = app.updated_at

    if not isinstance(app.evidence_submissions, list):
        app.evidence_submissions = []

    submission = dict(evidence_submission)
    submission.setdefault("submitted_at", now.isoformat())
    submission.setdefault("evidence_fact_ids", [evidence_fact.id])
    app.evidence_submissions.append(submission)

    existing_context = app.integration_context if isinstance(app.integration_context, dict) else {}
    app.integration_context = _merge_context(
        existing_context,
        dict(integration_context_updates or {}),
    )
    facts = await repo.list_evidence_facts_for_application(app.id)
    existing_fact = next(
        (
            fact
            for fact in facts
            if fact.logical_key == evidence_fact.logical_key
            and fact.payload_hash == evidence_fact.payload_hash
        ),
        None,
    )
    if existing_fact is not None:
        evidence_fact.id = existing_fact.id
        evidence_fact.superseded_fact_id = existing_fact.superseded_fact_id
    else:
        facts = sorted([*facts, evidence_fact], key=lambda fact: fact.created_at)

    audit_events = [
        _audit_event(
            app=app,
            event_type=EventType.EVIDENCE_FACT_CREATED,
            metadata={
                "source": source,
                "evidence_fact_id": evidence_fact.id,
                "fact_type": evidence_fact.fact_type,
                "provider": evidence_fact.provider,
                "verification_method": (evidence_fact.verification or {}).get("method"),
                **metadata,
            },
        )
    ]
    policy_decision: EvidencePolicyDecision | None = None
    tx: IssuanceTransaction | None = None

    if evaluate_policy:
        policy_set = await _load_approval_policy_set(
            repo=repo,
            app=app,
            template=template,
            binding=binding,
        )
        policy_decision = evaluate_application_evidence_policy(
            app=app,
            template=template,
            binding=binding,
            requirements=requirements,
            facts=facts,
            policy_set=policy_set,
        )
        app.integration_context = _merge_context(
            app.integration_context if isinstance(app.integration_context, dict) else {},
            {"policy": policy_decision.to_dict()},
        )
        audit_events.append(
            _audit_event(
                app=app,
                event_type=(
                    EventType.EVIDENCE_POLICY_PERMITTED
                    if policy_decision.allowed
                    else EventType.EVIDENCE_POLICY_DENIED
                ),
                metadata={
                    "source": source,
                    "policy_decision": policy_decision.to_dict(),
                    "evidence_fact_ids": [fact.id for fact in facts],
                    **metadata,
                },
            )
        )

        if policy_decision.allowed and issue_on_permit and auto_issue_on_permit and template is not None:
            try:
                tx = await prepare_application_issuance(
                    repo=repo,
                    app=app,
                    template=template,
                    issuer_context_applier=issuer_context_applier,
                )
                success_event = _audit_event(
                    app=app,
                    event_type=EventType.APPROVAL_ISSUANCE_SUCCEEDED,
                    transaction_id=tx.id,
                    metadata={
                        "source": source,
                        "policy_decision": policy_decision.to_dict(),
                        "evidence_fact_ids": [fact.id for fact in facts],
                        **metadata,
                    },
                )
                tx = await commit_prepared_application_issuance(
                    repo=repo,
                    app=app,
                    tx=tx,
                    reviewer_id=reviewer_id,
                    review_notes=review_notes,
                    evidence_fact=evidence_fact,
                    audit_events=(*audit_events, success_event),
                )
            except ApplicationTransitionConflictError as exc:
                policy_decision = replace(
                    policy_decision,
                    allowed=False,
                    errors=[*policy_decision.errors, str(exc)],
                )
                failure_event = _audit_event(
                    app=app,
                    event_type=EventType.APPROVAL_ISSUANCE_FAILED,
                    metadata={
                        "source": source,
                        "policy_decision": policy_decision.to_dict(),
                        "evidence_fact_ids": [fact.id for fact in facts],
                        "errors": [str(exc)],
                        **metadata,
                    },
                )
                await repo.save_evidence_fact_with_events(
                    evidence_fact,
                    audit_events=(*audit_events, failure_event),
                )
                raise
            except ValueError as exc:
                policy_decision = replace(
                    policy_decision,
                    allowed=False,
                    errors=[*policy_decision.errors, str(exc)],
                )
                app.integration_context = _merge_context(
                    app.integration_context if isinstance(app.integration_context, dict) else {},
                    {"policy": policy_decision.to_dict()},
                )
                app.updated_at = now
                await _save_application_revision(
                    repo=repo,
                    app=app,
                    expected_status=expected_status,
                    expected_updated_at=expected_updated_at,
                    evidence_fact=evidence_fact,
                    audit_events=(
                        *audit_events,
                        _audit_event(
                            app=app,
                            event_type=EventType.APPROVAL_ISSUANCE_FAILED,
                            metadata={
                                "source": source,
                                "policy_decision": policy_decision.to_dict(),
                                "evidence_fact_ids": [fact.id for fact in facts],
                                "errors": [str(exc)],
                                **metadata,
                            },
                        ),
                    ),
                )
        else:
            app.updated_at = now
            await _save_application_revision(
                repo=repo,
                app=app,
                expected_status=expected_status,
                expected_updated_at=expected_updated_at,
                evidence_fact=evidence_fact,
                audit_events=tuple(audit_events),
            )
    else:
        app.updated_at = now
        await _save_application_revision(
            repo=repo,
            app=app,
            expected_status=expected_status,
            expected_updated_at=expected_updated_at,
            evidence_fact=evidence_fact,
            audit_events=tuple(audit_events),
        )

    return EvidenceTransitionResult(
        evidence_fact=evidence_fact,
        facts=facts,
        policy_decision=policy_decision,
        issuance_transaction=tx,
    )
