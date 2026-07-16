"""Transactional domain behavior for authoritative Canvas evidence revisions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from issuance.application.evidence_policy import (
    EvidencePolicyDecision,
    evaluate_application_evidence_policy,
)
from issuance.domain.entities import (
    Application,
    ApplicationTemplate,
    EventType,
    EvidenceFact,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
    IssuanceEvent,
)
from issuance.domain.ports import (
    CanvasEvidenceAtomicMutation,
    IIssuanceRepository,
)


@dataclass(frozen=True)
class CanvasEvidenceRevisionResult:
    evidence_fact: EvidenceFact
    inserted: bool
    changed: bool
    current_facts: list[EvidenceFact]
    policy_decision: EvidencePolicyDecision
    correction_review: EvidencePolicyReview | None = None


async def record_authoritative_canvas_evidence_revision(
    *,
    repo: IIssuanceRepository,
    app: Application,
    template: ApplicationTemplate | None,
    binding: Any,
    fact: EvidenceFact,
    requirements: list[Any],
    policy_set: Any | None = None,
) -> CanvasEvidenceRevisionResult:
    """Append a verified fact, evaluate heads, and manage correction review drift.

    Signing and credential status changes are intentionally outside this service.
    A permit-to-deny change after issuance creates one administrator review; a
    later recovery resolves that review without touching the credential.
    """

    if fact.organization_id != app.organization_id or fact.application_id != app.id:
        raise ValueError("Canvas evidence fact does not belong to the application organization")
    if str((fact.verification or {}).get("status") or "").upper() != "VERIFIED":
        raise ValueError("Authoritative Canvas evidence must use verification.status=VERIFIED")
    if not fact.requirement_id:
        raise ValueError("Authoritative Canvas evidence requires requirement_id")

    def plan_transition(
        *,
        app: Application,
        previous_facts: list[EvidenceFact],
        evidence_fact: EvidenceFact,
        inserted: bool,
        changed: bool,
        current_facts: list[EvidenceFact],
        open_review: EvidencePolicyReview | None,
    ) -> CanvasEvidenceAtomicMutation:
        previous_decision = evaluate_application_evidence_policy(
            app=app,
            template=template,
            binding=binding,
            requirements=requirements,
            facts=previous_facts,
            policy_set=policy_set,
        )
        current_decision = evaluate_application_evidence_policy(
            app=app,
            template=template,
            binding=binding,
            requirements=requirements,
            facts=current_facts,
            policy_set=policy_set,
        )
        review = open_review
        review_changed = False
        audit_events: list[IssuanceEvent] = []
        issued_credential_id = app.credential_id
        now = datetime.now(UTC)

        if inserted:
            audit_events.append(
                IssuanceEvent(
                    application_id=app.id,
                    event_type=EventType.EVIDENCE_FACT_CREATED,
                    metadata={
                        "organization_id": app.organization_id,
                        "provider": evidence_fact.provider,
                        "requirement_id": evidence_fact.requirement_id,
                        "fact_id": evidence_fact.id,
                        "source_revision": evidence_fact.source_revision,
                    },
                )
            )

        if review is not None and review.resolution_claim_token is not None:
            # A manual lifecycle handler owns this review. Evidence and its
            # audit event still commit. Persist a recovery marker so a failed
            # handler release can close a review that policy already permits.
            review.current_decision = current_decision.to_dict()
            review.resolution_recovery_pending = current_decision.allowed
            review.updated_at = now
            return CanvasEvidenceAtomicMutation(
                policy_decision=current_decision,
                correction_review=review,
                review_changed=True,
                audit_events=tuple(audit_events),
            )

        if changed and issued_credential_id and previous_decision.allowed and not current_decision.allowed:
            if review is None:
                review = EvidencePolicyReview(
                    organization_id=app.organization_id,
                    application_id=app.id,
                    credential_id=issued_credential_id,
                    binding_id=getattr(binding, "id", None),
                    prior_decision=previous_decision.to_dict(),
                    current_decision=current_decision.to_dict(),
                    triggering_fact_id=evidence_fact.id,
                )
                audit_events.append(
                    IssuanceEvent(
                        application_id=app.id,
                        event_type=EventType.EVIDENCE_POLICY_REVIEW_CREATED,
                        metadata={
                            "review_id": review.id,
                            "credential_id": issued_credential_id,
                            "triggering_fact_id": evidence_fact.id,
                        },
                    )
                )
            else:
                review.current_decision = current_decision.to_dict()
                review.triggering_fact_id = evidence_fact.id
                review.resolution_recovery_pending = False
                review.updated_at = now
            review_changed = True
        elif changed and review is not None and not current_decision.allowed:
            # Keep the open review synchronized with the latest authoritative
            # denied head while retaining its original permit-to-deny baseline.
            review.current_decision = current_decision.to_dict()
            review.triggering_fact_id = evidence_fact.id
            review.resolution_recovery_pending = False
            review.updated_at = now
            review_changed = True
        elif review is not None and current_decision.allowed:
            review.status = EvidencePolicyReviewStatus.RESOLVED
            review.resolution_action = "evidence_recovered"
            review.resolution_notes = (
                "Authoritative Canvas evidence recovered before administrator action"
            )
            review.resolved_by = "canvas-evidence-sync"
            review.resolved_at = now
            review.current_decision = current_decision.to_dict()
            review.resolution_recovery_pending = False
            review.updated_at = now
            review_changed = True
            audit_events.append(
                IssuanceEvent(
                    application_id=app.id,
                    event_type=EventType.EVIDENCE_POLICY_REVIEW_RESOLVED,
                    metadata={
                        "review_id": review.id,
                        "credential_id": review.credential_id,
                        "resolution_action": "evidence_recovered",
                    },
                )
            )

        return CanvasEvidenceAtomicMutation(
            policy_decision=current_decision,
            correction_review=review,
            review_changed=review_changed,
            audit_events=tuple(audit_events),
        )

    commit = await repo.commit_authoritative_canvas_evidence_revision(
        fact,
        transition=plan_transition,
    )
    return CanvasEvidenceRevisionResult(
        evidence_fact=commit.evidence_fact,
        inserted=commit.inserted,
        changed=commit.changed,
        current_facts=commit.current_facts,
        policy_decision=commit.policy_decision,
        correction_review=commit.correction_review,
    )
