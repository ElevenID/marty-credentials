"""Background reconciliation for MIP evidence policy and issuance transitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from issuance.application.application_approval import (
    IssuerContextApplier,
    approve_application_for_issuance,
)
from issuance.application.canvas_runtime import (
    CanvasRuntimeConfig,
    canvas_runtime_from_program_binding,
    resolve_canvas_program_binding_for_scope,
)
from issuance.application.evidence_policy import (
    EvidencePolicyDecision,
    evaluate_application_evidence_policy,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApprovalPolicySet,
    CanvasEventReceipt,
    EventType,
    EvidenceFact,
    IssuanceEvent,
    IssuanceStatus,
)
from issuance.domain.ports import IIssuanceRepository


_DEFAULT_CANVAS_REQUIREMENTS = ["canvas.course_completion"]
_RECONCILIATION_REVIEWER_ID = "canvas:evidence-reconciliation"


@dataclass(frozen=True)
class EvidenceReconciliationRecord:
    application_id: str
    status_before: str
    status_after: str
    action: str
    fact_count: int = 0
    policy_decision: dict[str, Any] | None = None
    issuance_transaction_id: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "application_id": self.application_id,
            "status_before": self.status_before,
            "status_after": self.status_after,
            "action": self.action,
            "fact_count": self.fact_count,
            "policy_decision": self.policy_decision,
            "issuance_transaction_id": self.issuance_transaction_id,
            "errors": self.errors,
        }


@dataclass(frozen=True)
class StaleCanvasEvidenceReceipt:
    receipt_id: str
    provider_event_id: str
    canvas_account_id: str | None
    application_id: str | None
    status: str
    reasons: list[str]
    last_seen_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "provider_event_id": self.provider_event_id,
            "canvas_account_id": self.canvas_account_id,
            "application_id": self.application_id,
            "status": self.status,
            "reasons": self.reasons,
            "last_seen_at": self.last_seen_at,
        }


@dataclass(frozen=True)
class EvidenceReconciliationResult:
    organization_id: str
    dry_run: bool
    metrics: dict[str, int]
    records: list[EvidenceReconciliationRecord]
    stale_receipts: list[StaleCanvasEvidenceReceipt]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "dry_run": self.dry_run,
            "metrics": self.metrics,
            "records": [record.to_dict() for record in self.records],
            "stale_receipts": [receipt.to_dict() for receipt in self.stale_receipts],
            "generated_at": self.generated_at.isoformat(),
        }


def _status_value(app: Application) -> str:
    status = getattr(app, "status", "")
    return status.value if hasattr(status, "value") else str(status)


def _app_context(app: Application) -> dict[str, Any]:
    return dict(app.integration_context) if isinstance(app.integration_context, dict) else {}


def _policy_context(app: Application) -> dict[str, Any] | None:
    policy = _app_context(app).get("policy")
    return policy if isinstance(policy, dict) else None


def _policy_allowed(policy: dict[str, Any] | None) -> bool:
    return bool(policy and policy.get("allowed") is True)


def _effective_requirements(
    *,
    binding: Any | None,
    template: Any | None,
) -> list[Any]:
    binding_requirements = list(getattr(binding, "evidence_requirements", None) or [])
    if binding_requirements:
        return binding_requirements
    template_requirements = list(getattr(template, "evidence_requirements", None) or [])
    if template_requirements:
        return template_requirements
    return list(_DEFAULT_CANVAS_REQUIREMENTS)


def _canvas_account_id_from_fact(fact: EvidenceFact) -> str | None:
    scope_account = (fact.scope or {}).get("canvas_account_id")
    if scope_account:
        return str(scope_account)
    source = fact.source or {}
    mip_receipt = source.get("mip_receipt")
    if isinstance(mip_receipt, dict):
        mip_source = mip_receipt.get("source")
        if isinstance(mip_source, dict) and mip_source.get("provider_account_id"):
            return str(mip_source["provider_account_id"])
    return None


async def _resolve_canvas_runtime_config(
    *,
    repo: IIssuanceRepository,
    app: Application,
    facts: list[EvidenceFact],
) -> CanvasRuntimeConfig | None:
    context = _app_context(app)
    canvas_context = context.get("canvas")
    if not isinstance(canvas_context, dict):
        canvas_context = {}

    binding_id = canvas_context.get("canvas_program_binding_id")
    if binding_id:
        binding = await repo.get_canvas_program_binding(str(binding_id))
        if binding is not None:
            platform = await repo.get_canvas_platform(binding.platform_id)
            if platform is not None:
                return canvas_runtime_from_program_binding(
                    platform=platform,
                    binding=binding,
                )

    canvas_account_id = canvas_context.get("canvas_account_id")
    if not canvas_account_id and facts:
        canvas_account_id = _canvas_account_id_from_fact(facts[-1])
    if canvas_account_id:
        platform, binding = await resolve_canvas_program_binding_for_scope(
            repo=repo,
            organization_id=app.organization_id,
            canvas_account_id=str(canvas_account_id),
            actual_scope=facts[-1].scope if facts else {},
            application_template_id=app.application_template_id,
        )
        if platform is not None and binding is not None:
            return canvas_runtime_from_program_binding(
                platform=platform,
                binding=binding,
            )
    return None


async def _load_approval_policy_set(
    *,
    repo: IIssuanceRepository,
    app: Application,
    template: Any | None,
    binding: Any | None = None,
) -> ApprovalPolicySet | None:
    policy_set_id = (
        getattr(binding, "approval_policy_set_id", None)
        or (getattr(template, "approval_policy_set_id", None) if template else None)
    )
    if not policy_set_id:
        return None
    return await repo.get_approval_policy_set(app.organization_id, policy_set_id)


def _with_reconciliation_metadata(
    *,
    app: Application,
    policy_decision: dict[str, Any] | None,
    action: str,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    context = _app_context(app)
    if policy_decision is not None:
        context["policy"] = policy_decision
    context["evidence_reconciliation"] = {
        "last_action": action,
        "last_errors": list(errors or []),
        "last_reconciled_at": datetime.now(timezone.utc).isoformat(),
    }
    return context


async def record_evidence_policy_audit_event(
    *,
    repo: IIssuanceRepository,
    app: Application,
    event_type: EventType,
    transaction_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Append an issuance audit event for evidence and policy transitions."""

    await repo.save_event(
        IssuanceEvent(
            transaction_id=transaction_id,
            application_id=app.id,
            event_type=event_type,
            metadata={
                "organization_id": app.organization_id,
                **(metadata or {}),
            },
        )
    )


async def _evaluate_policy(
    *,
    repo: IIssuanceRepository,
    app: Application,
    template: Any | None,
    binding: Any | None,
    facts: list[EvidenceFact],
) -> EvidencePolicyDecision:
    policy_set = await _load_approval_policy_set(repo=repo, app=app, template=template, binding=binding)
    return evaluate_application_evidence_policy(
        app=app,
        template=template,
        binding=binding,
        requirements=_effective_requirements(binding=binding, template=template),
        facts=facts,
        policy_set=policy_set,
    )


async def _reconcile_application(
    *,
    repo: IIssuanceRepository,
    app: Application,
    dry_run: bool,
    issue_on_permit: bool,
    metrics: dict[str, int],
    issuer_context_applier: IssuerContextApplier | None = None,
) -> EvidenceReconciliationRecord:
    status_before = _status_value(app)
    facts = await repo.list_evidence_facts_for_application(app.id)
    canvas_facts = [fact for fact in facts if fact.provider == "canvas"]
    if not canvas_facts:
        metrics["skipped"] += 1
        return EvidenceReconciliationRecord(
            application_id=app.id,
            status_before=status_before,
            status_after=status_before,
            action="skipped_no_canvas_evidence_facts",
        )

    if app.status not in (ApplicationStatus.PENDING, ApplicationStatus.APPROVED):
        metrics["skipped"] += 1
        return EvidenceReconciliationRecord(
            application_id=app.id,
            status_before=status_before,
            status_after=status_before,
            action="skipped_terminal_application_status",
            fact_count=len(canvas_facts),
        )

    template = await repo.get_application_template(app.application_template_id)
    if template is None:
        metrics["approval_issuance_failures"] += 1
        return EvidenceReconciliationRecord(
            application_id=app.id,
            status_before=status_before,
            status_after=status_before,
            action="failed_missing_application_template",
            fact_count=len(canvas_facts),
            errors=[f"Application template {app.application_template_id} was not found"],
        )

    binding = await _resolve_canvas_runtime_config(repo=repo, app=app, facts=canvas_facts)
    if binding is None:
        metrics["skipped"] += 1
        return EvidenceReconciliationRecord(
            application_id=app.id,
            status_before=status_before,
            status_after=status_before,
            action="skipped_missing_canvas_program_binding",
            fact_count=len(canvas_facts),
            errors=["Canvas evidence reconciliation requires a Canvas program binding"],
        )

    existing_policy = _policy_context(app)
    policy = existing_policy
    action = "policy_decision_already_recorded"

    if policy is None:
        decision = await _evaluate_policy(
            repo=repo,
            app=app,
            template=template,
            binding=binding,
            facts=canvas_facts,
        )
        policy = decision.to_dict()
        metrics["evaluated_policies"] += 1
        action = "policy_evaluated"
        if decision.allowed:
            metrics["policy_permits"] += 1
            event_type = EventType.EVIDENCE_POLICY_PERMITTED
        else:
            metrics["policy_denies"] += 1
            event_type = EventType.EVIDENCE_POLICY_DENIED
        if not dry_run:
            app.integration_context = _with_reconciliation_metadata(
                app=app,
                policy_decision=policy,
                action=action,
            )
            await repo.save_application(app)
            await record_evidence_policy_audit_event(
                repo=repo,
                app=app,
                event_type=event_type,
                metadata={
                    "source": "reconciliation",
                    "policy_decision": policy,
                    "evidence_fact_ids": [fact.id for fact in canvas_facts],
                },
            )

    if not _policy_allowed(policy):
        return EvidenceReconciliationRecord(
            application_id=app.id,
            status_before=status_before,
            status_after=_status_value(app),
            action="policy_denied",
            fact_count=len(canvas_facts),
            policy_decision=policy,
            issuance_transaction_id=app.issuance_transaction_id,
            errors=list((policy or {}).get("errors") or []),
        )

    existing_tx = None
    if app.issuance_transaction_id:
        existing_tx = await repo.get_transaction(app.issuance_transaction_id)
    if existing_tx is not None and existing_tx.status == IssuanceStatus.PENDING and not existing_tx.is_expired:
        return EvidenceReconciliationRecord(
            application_id=app.id,
            status_before=status_before,
            status_after=_status_value(app),
            action="issuance_transaction_already_pending",
            fact_count=len(canvas_facts),
            policy_decision=policy,
            issuance_transaction_id=existing_tx.id,
        )

    if not issue_on_permit:
        return EvidenceReconciliationRecord(
            application_id=app.id,
            status_before=status_before,
            status_after=_status_value(app),
            action="policy_permitted_issue_disabled",
            fact_count=len(canvas_facts),
            policy_decision=policy,
            issuance_transaction_id=app.issuance_transaction_id,
        )

    if dry_run:
        return EvidenceReconciliationRecord(
            application_id=app.id,
            status_before=status_before,
            status_after=status_before,
            action="would_create_or_refresh_issuance_transaction",
            fact_count=len(canvas_facts),
            policy_decision=policy,
            issuance_transaction_id=app.issuance_transaction_id,
        )

    try:
        tx = await approve_application_for_issuance(
            repo=repo,
            app=app,
            template=template,
            reviewer_id=_RECONCILIATION_REVIEWER_ID,
            review_notes="Recovered by MIP evidence policy reconciliation",
            issuer_context_applier=issuer_context_applier,
        )
    except ValueError as exc:
        metrics["approval_issuance_failures"] += 1
        errors = [str(exc)]
        app.integration_context = _with_reconciliation_metadata(
            app=app,
            policy_decision=policy,
            action="approval_issuance_failed",
            errors=errors,
        )
        await repo.save_application(app)
        await record_evidence_policy_audit_event(
            repo=repo,
            app=app,
            event_type=EventType.APPROVAL_ISSUANCE_FAILED,
            metadata={
                "source": "reconciliation",
                "policy_decision": policy,
                "errors": errors,
                "evidence_fact_ids": [fact.id for fact in canvas_facts],
            },
        )
        return EvidenceReconciliationRecord(
            application_id=app.id,
            status_before=status_before,
            status_after=_status_value(app),
            action="approval_issuance_failed",
            fact_count=len(canvas_facts),
            policy_decision=policy,
            issuance_transaction_id=app.issuance_transaction_id,
            errors=errors,
        )

    metrics["approval_issuance_successes"] += 1
    await record_evidence_policy_audit_event(
        repo=repo,
        app=app,
        event_type=EventType.APPROVAL_ISSUANCE_SUCCEEDED,
        transaction_id=tx.id,
        metadata={
            "source": "reconciliation",
            "policy_decision": policy,
            "evidence_fact_ids": [fact.id for fact in canvas_facts],
        },
    )
    return EvidenceReconciliationRecord(
        application_id=app.id,
        status_before=status_before,
        status_after=_status_value(app),
        action="approval_issuance_succeeded"
        if action == "policy_evaluated"
        else "approval_issuance_recovered_from_policy_permit",
        fact_count=len(canvas_facts),
        policy_decision=policy,
        issuance_transaction_id=tx.id,
    )


async def _stale_receipts_for_org(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    limit: int,
) -> list[StaleCanvasEvidenceReceipt]:
    receipts = await repo.list_canvas_event_receipts(
        organization_id=organization_id,
        status="evidence_received",
        limit=limit,
    )
    stale: list[StaleCanvasEvidenceReceipt] = []
    for receipt in receipts:
        stale_reasons = await _receipt_stale_reasons(repo=repo, receipt=receipt)
        if not stale_reasons:
            continue
        response = receipt.issuance_response if isinstance(receipt.issuance_response, dict) else {}
        app_id = response.get("application_id")
        stale.append(
            StaleCanvasEvidenceReceipt(
                receipt_id=receipt.id,
                provider_event_id=receipt.provider_event_id,
                canvas_account_id=receipt.canvas_account_id,
                application_id=str(app_id) if app_id else None,
                status=receipt.status,
                reasons=stale_reasons,
                last_seen_at=receipt.last_seen_at.isoformat(),
            )
        )
    return stale


async def _receipt_stale_reasons(
    *,
    repo: IIssuanceRepository,
    receipt: CanvasEventReceipt,
) -> list[str]:
    reasons: list[str] = []
    response = receipt.issuance_response if isinstance(receipt.issuance_response, dict) else {}
    app_id = response.get("application_id")
    if not app_id:
        reasons.append("receipt_missing_application_id")
        return reasons

    app = await repo.get_application(str(app_id))
    if app is None:
        reasons.append("receipt_application_missing")
        return reasons

    if not response.get("evidence_facts"):
        reasons.append("receipt_without_evidence_fact_metadata")
    policy = response.get("policy_decision")
    if not isinstance(policy, dict):
        policy = _policy_context(app)
    if not isinstance(policy, dict):
        reasons.append("receipt_without_policy_decision")
    elif policy.get("allowed") is True and not receipt.issuance_transaction_id and not app.issuance_transaction_id:
        reasons.append("policy_permit_without_issuance_transaction")
    return reasons


async def reconcile_canvas_evidence_transitions(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    application_id: str | None = None,
    limit: int = 100,
    dry_run: bool = False,
    issue_on_permit: bool = True,
    issuer_context_applier: IssuerContextApplier | None = None,
) -> EvidenceReconciliationResult:
    """Evaluate and recover Canvas evidence policy/issuance transitions."""

    metrics = {
        "scanned_applications": 0,
        "evaluated_policies": 0,
        "policy_permits": 0,
        "policy_denies": 0,
        "approval_issuance_successes": 0,
        "approval_issuance_failures": 0,
        "skipped": 0,
        "stale_receipts": 0,
    }
    if application_id:
        app = await repo.get_application(application_id)
        apps = [app] if app is not None and app.organization_id == organization_id else []
    else:
        apps = await repo.list_applications(org_id=organization_id)
    apps = apps[: max(0, limit)]

    records: list[EvidenceReconciliationRecord] = []
    for app in apps:
        metrics["scanned_applications"] += 1
        records.append(
            await _reconcile_application(
                repo=repo,
                app=app,
                dry_run=dry_run,
                issue_on_permit=issue_on_permit,
                metrics=metrics,
                issuer_context_applier=issuer_context_applier,
            )
        )

    stale_receipts = await _stale_receipts_for_org(
        repo=repo,
        organization_id=organization_id,
        limit=limit,
    )
    metrics["stale_receipts"] = len(stale_receipts)
    return EvidenceReconciliationResult(
        organization_id=organization_id,
        dry_run=dry_run,
        metrics=metrics,
        records=records,
        stale_receipts=stale_receipts,
    )


async def build_canvas_evidence_reconciliation_report(
    *,
    repo: IIssuanceRepository,
    organization_id: str,
    limit: int = 100,
) -> EvidenceReconciliationResult:
    """Return a dry-run reconciliation report for Canvas evidence state."""

    return await reconcile_canvas_evidence_transitions(
        repo=repo,
        organization_id=organization_id,
        limit=limit,
        dry_run=True,
        issue_on_permit=True,
        issuer_context_applier=None,
    )
