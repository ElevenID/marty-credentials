"""Shared MIP evidence fact to policy and issuance transition service."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from issuance.application.application_approval import (
    IssuerContextApplier,
    approve_application_for_issuance,
)
from issuance.application.evidence_policy import (
    EvidencePolicyDecision,
    evaluate_application_evidence_policy,
)
from issuance.application.evidence_reconciliation import record_evidence_policy_audit_event
from issuance.domain.entities import (
    Application,
    ApplicationTemplate,
    EventType,
    EvidenceFact,
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

    await repo.save_evidence_fact(evidence_fact)
    await record_evidence_policy_audit_event(
        repo=repo,
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

    facts = await repo.list_evidence_facts_for_application(app.id)
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
        await record_evidence_policy_audit_event(
            repo=repo,
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

        if policy_decision.allowed and issue_on_permit and auto_issue_on_permit and template is not None:
            try:
                tx = await approve_application_for_issuance(
                    repo=repo,
                    app=app,
                    template=template,
                    reviewer_id=reviewer_id,
                    review_notes=review_notes,
                    issuer_context_applier=issuer_context_applier,
                )
                await record_evidence_policy_audit_event(
                    repo=repo,
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
                await repo.save_application(app)
                await record_evidence_policy_audit_event(
                    repo=repo,
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
        else:
            app.updated_at = now
            await repo.save_application(app)
    else:
        app.updated_at = now
        await repo.save_application(app)

    return EvidenceTransitionResult(
        evidence_fact=evidence_fact,
        facts=facts,
        policy_decision=policy_decision,
        issuance_transaction=tx,
    )
