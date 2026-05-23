"""Application workflow endpoints."""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, Field

ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "https://beta.elevenidllc.com")
CREDENTIAL_TEMPLATE_SERVICE_URL = os.environ.get(
    "CREDENTIAL_TEMPLATE_SERVICE_URL", "http://credential-template-service:8003"
)

from issuance.application.application_approval import (
    CredentialContext,
    approve_application_for_issuance,
)
from issuance.application.evidence_reconciliation import (
    build_canvas_evidence_reconciliation_report,
    reconcile_canvas_evidence_transitions,
)
from issuance.application.evidence_transition import persist_evidence_fact_and_apply_policy
from issuance.application.external_evidence_api import (
    ExternalEvidenceApiError,
    execute_external_evidence_api_check,
    find_external_api_requirement,
    requirement_check_id,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    EvidenceFact,
    IssuanceEvent,
    IssuanceStatus,
    IssuanceTransaction,
    EventType,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.delivery_records import (
    delivery_mode_from_integration_context,
)
from issuance.infrastructure.api.routes import (
    ApplicationApproval,
    ApplicationCreate,
    ApplicationRejection,
    ApplicationResponse,
    ApplicationTemplateCreate,
    ApplicationTemplateResponse,
    EvidenceSubmission,
    _verify_management_api_key,
    apply_remote_issuer_context,
    application_router,
    application_template_router,
)

logger = logging.getLogger(__name__)


class IssuanceEventResponse(BaseModel):
    id: str
    transaction_id: str | None
    application_id: str | None
    event_type: str
    metadata: dict
    created_at: str


class EvidenceFactResponse(BaseModel):
    id: str
    organization_id: str
    application_id: str
    subject_id: str
    provider: str
    fact_type: str
    scope: dict[str, Any]
    assertion: dict[str, Any]
    verification: dict[str, Any]
    source: dict[str, Any]
    created_at: str


class ApplicationEvidenceSummaryResponse(BaseModel):
    application_id: str
    organization_id: str
    status: str
    evidence_facts: list[EvidenceFactResponse]
    policy_decision: dict[str, Any] | None = None
    policy_source: str | None = None
    policy_set_id: str | None = None
    issuance_transaction_id: str | None = None
    canvas: dict[str, Any] | None = None
    available_api_checks: list[dict[str, Any]] = Field(default_factory=list)


class EvidenceReconciliationRequest(BaseModel):
    organization_id: str
    application_id: str | None = None
    limit: int = 100
    dry_run: bool = False
    issue_on_permit: bool = True


class ExternalEvidenceApiCheckRequest(BaseModel):
    inputs: dict[str, Any] = {}
    issue_on_permit: bool = True


class ExternalEvidenceApiCheckResponse(BaseModel):
    application_id: str
    organization_id: str
    check_id: str
    status: str
    application_status: str
    evidence_fact: EvidenceFactResponse
    policy_decision: dict[str, Any]
    issuance_transaction_id: str | None = None
    response_metadata: dict[str, Any]


def _evidence_fact_to_response(fact: EvidenceFact) -> EvidenceFactResponse:
    return EvidenceFactResponse(
        id=fact.id,
        organization_id=fact.organization_id,
        application_id=fact.application_id,
        subject_id=fact.subject_id,
        provider=fact.provider,
        fact_type=fact.fact_type,
        scope=fact.scope,
        assertion=fact.assertion,
        verification=fact.verification,
        source=fact.source,
        created_at=fact.created_at.isoformat(),
    )


def _application_policy_context(app: Application) -> tuple[dict[str, Any] | None, str | None, str | None, dict[str, Any] | None]:
    integration_context = app.integration_context if isinstance(app.integration_context, dict) else {}
    policy = integration_context.get("policy")
    if not isinstance(policy, dict):
        policy = None
    canvas = integration_context.get("canvas")
    if not isinstance(canvas, dict):
        canvas = None
    return (
        policy,
        policy.get("policy_source") if policy else None,
        policy.get("policy_set_id") if policy else None,
        canvas,
    )


def _available_external_api_checks(template: ApplicationTemplate | None) -> list[dict[str, Any]]:
    """Return reviewer-safe descriptors for configured user-defined API checks."""

    checks: list[dict[str, Any]] = []
    if template is None:
        return checks
    for requirement in template.evidence_requirements or []:
        if not isinstance(requirement, dict):
            continue
        evidence_type = str(requirement.get("evidence_type") or "").upper()
        if evidence_type not in {"EXTERNAL_API", "EXTERNAL_FACT"}:
            continue
        if evidence_type == "EXTERNAL_API" and not isinstance(requirement.get("api"), dict):
            continue
        check_id = requirement_check_id(requirement)
        if not check_id:
            continue
        api = requirement.get("api") if isinstance(requirement.get("api"), dict) else {}
        checks.append(
            {
                "check_id": check_id,
                "evidence_type": evidence_type,
                "description": requirement.get("description") or requirement.get("label") or check_id,
                "provider": requirement.get("provider") or "external_api",
                "fact_type": requirement.get("fact_type") or "",
                "required": requirement.get("required", True) is not False,
                "verification_method": requirement.get("verification_method") or "EXTERNAL_API_RESPONSE",
                "auto_issue_on_permit": bool(
                    requirement.get("auto_issue_on_permit")
                    or requirement.get("auto_approve_on_evidence")
                ),
                "api_method": str(api.get("method") or "POST").upper(),
                "scope": requirement.get("scope") if isinstance(requirement.get("scope"), dict) else {},
            }
        )
    return checks


# ============================================================================
# Application Template Endpoints
# ============================================================================

@application_template_router.post("", response_model=ApplicationTemplateResponse, dependencies=[Depends(_verify_management_api_key)])
async def create_application_template(
    request: ApplicationTemplateCreate,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationTemplateResponse:
    """Create an Application Template defining how users apply for credentials."""
    template = ApplicationTemplate(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        credential_template_id=request.credential_template_id,
        form_fields=request.form_fields,
        evidence_requirements=request.evidence_requirements,
        claim_collection_rules=request.claim_collection_rules,
        required_checks=request.required_checks,
        approval_strategy=request.approval_strategy,
        approval_policy_set_id=request.approval_policy_set_id,
        application_validity_days=request.application_validity_days,
        auto_approval_rules=request.auto_approval_rules,
        ui_config=request.ui_config,
        notification_config=request.notification_config,
    )
    await repo.save_application_template(template)
    
    logger.info(f"Created application template {template.id} for organization {template.organization_id}")
    
    return ApplicationTemplateResponse(
        id=template.id,
        organization_id=template.organization_id,
        name=template.name,
        description=template.description,
        credential_template_id=template.credential_template_id,
        form_fields=template.form_fields,
        evidence_requirements=template.evidence_requirements,
        claim_collection_rules=template.claim_collection_rules,
        required_checks=template.required_checks,
        approval_strategy=template.approval_strategy,
        approval_policy_set_id=template.approval_policy_set_id,
        application_validity_days=template.application_validity_days,
        auto_approval_rules=template.auto_approval_rules,
        ui_config=template.ui_config,
        notification_config=template.notification_config,
        status=template.status,
        created_at=template.created_at.isoformat(),
        updated_at=template.updated_at.isoformat(),
    )


@application_template_router.get("", response_model=list[ApplicationTemplateResponse], dependencies=[Depends(_verify_management_api_key)])
async def list_application_templates(
    organization_id: str = Query(...),
    repo: IIssuanceRepository = Depends(),
) -> list[ApplicationTemplateResponse]:
    """List all application templates for an organization."""
    templates = await repo.list_application_templates(organization_id)
    
    return [
        ApplicationTemplateResponse(
            id=t.id,
            organization_id=t.organization_id,
            name=t.name,
            description=t.description,
            credential_template_id=t.credential_template_id,
            form_fields=t.form_fields,
            evidence_requirements=t.evidence_requirements,
            claim_collection_rules=t.claim_collection_rules,
            required_checks=t.required_checks,
            approval_strategy=t.approval_strategy,
            approval_policy_set_id=t.approval_policy_set_id,
            application_validity_days=t.application_validity_days,
            auto_approval_rules=t.auto_approval_rules,
            ui_config=t.ui_config,
            notification_config=t.notification_config,
            status=t.status,
            created_at=t.created_at.isoformat(),
            updated_at=t.updated_at.isoformat(),
        )
        for t in templates
    ]


@application_template_router.get("/{template_id}", response_model=ApplicationTemplateResponse, dependencies=[Depends(_verify_management_api_key)])
async def get_application_template(
    template_id: str,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationTemplateResponse:
    """Get an application template by ID."""
    template = await repo.get_application_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    
    return ApplicationTemplateResponse(
        id=template.id,
        organization_id=template.organization_id,
        name=template.name,
        description=template.description,
        credential_template_id=template.credential_template_id,
        form_fields=template.form_fields,
        evidence_requirements=template.evidence_requirements,
        claim_collection_rules=template.claim_collection_rules,
        required_checks=template.required_checks,
        approval_strategy=template.approval_strategy,
        approval_policy_set_id=template.approval_policy_set_id,
        application_validity_days=template.application_validity_days,
        auto_approval_rules=template.auto_approval_rules,
        ui_config=template.ui_config,
        notification_config=template.notification_config,
        status=template.status,
        created_at=template.created_at.isoformat(),
        updated_at=template.updated_at.isoformat(),
    )


@application_template_router.put("/{template_id}", response_model=ApplicationTemplateResponse, dependencies=[Depends(_verify_management_api_key)])
async def update_application_template(
    template_id: str,
    request: ApplicationTemplateCreate,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationTemplateResponse:
    """Update an existing application template."""
    template = await repo.get_application_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")

    template.name = request.name
    template.description = request.description
    template.credential_template_id = request.credential_template_id
    template.form_fields = request.form_fields
    template.evidence_requirements = request.evidence_requirements
    template.claim_collection_rules = request.claim_collection_rules
    template.required_checks = request.required_checks
    template.approval_strategy = request.approval_strategy
    template.approval_policy_set_id = request.approval_policy_set_id
    template.application_validity_days = request.application_validity_days
    template.auto_approval_rules = request.auto_approval_rules
    template.ui_config = request.ui_config
    template.notification_config = request.notification_config
    template.updated_at = datetime.now(timezone.utc)

    await repo.save_application_template(template)

    logger.info(f"Updated application template {template.id}")

    return ApplicationTemplateResponse(
        id=template.id,
        organization_id=template.organization_id,
        name=template.name,
        description=template.description,
        credential_template_id=template.credential_template_id,
        form_fields=template.form_fields,
        evidence_requirements=template.evidence_requirements,
        claim_collection_rules=template.claim_collection_rules,
        required_checks=template.required_checks,
        approval_strategy=template.approval_strategy,
        approval_policy_set_id=template.approval_policy_set_id,
        application_validity_days=template.application_validity_days,
        auto_approval_rules=template.auto_approval_rules,
        ui_config=template.ui_config,
        notification_config=template.notification_config,
        status=template.status,
        created_at=template.created_at.isoformat(),
        updated_at=template.updated_at.isoformat(),
    )


# ============================================================================
# Application Endpoints
# ============================================================================

@application_router.post("", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def create_application(
    request: ApplicationCreate,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Create a new application submission."""
    template = await repo.get_application_template(request.application_template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    
    applicant_data = request.applicant_data
    applicant_identifier = (
        f"{applicant_data.get('given_name', '')}_{applicant_data.get('family_name', '')}"
        or applicant_data.get('email')
        or f"applicant_{uuid.uuid4().hex[:8]}"
    )
    
    app = Application(
        organization_id=template.organization_id,
        application_template_id=request.application_template_id,
        applicant_identifier=applicant_identifier,
        form_data=applicant_data,
        integration_context=request.integration_context,
    )
    await repo.save_application(app)
    
    logger.info(f"Created application {app.id} for template {template.id}")
    
    return ApplicationResponse(
        id=app.id,
        organization_id=app.organization_id,
        application_template_id=app.application_template_id,
        applicant_identifier=app.applicant_identifier,
        form_data=app.form_data,
        evidence_submissions=app.evidence_submissions,
        integration_context=app.integration_context,
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )


@application_router.get("", response_model=list[ApplicationResponse], dependencies=[Depends(_verify_management_api_key)])
async def list_applications(
    organization_id: str = Query(...),
    status: str = Query(None),
    application_template_id: str = Query(None),
    repo: IIssuanceRepository = Depends(),
) -> list[ApplicationResponse]:
    """List applications with optional filters."""
    status_enum = ApplicationStatus(status) if status else None
    apps = await repo.list_applications(
        org_id=organization_id,
        status=status_enum,
        template_id=application_template_id,
    )
    
    return [
        ApplicationResponse(
            id=a.id,
            organization_id=a.organization_id,
            application_template_id=a.application_template_id,
            applicant_identifier=a.applicant_identifier,
            form_data=a.form_data,
            evidence_submissions=a.evidence_submissions,
            integration_context=a.integration_context,
            status=a.status.value,
            review_notes=a.review_notes,
            reviewer_id=a.reviewer_id,
            submitted_at=a.submitted_at.isoformat(),
            reviewed_at=a.reviewed_at.isoformat() if a.reviewed_at else None,
            expires_at=a.expires_at.isoformat(),
            issuance_transaction_id=a.issuance_transaction_id,
        )
        for a in apps
    ]


@application_router.get("/{application_id}", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def get_application(
    application_id: str,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Get an application by ID."""
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    return ApplicationResponse(
        id=app.id,
        organization_id=app.organization_id,
        application_template_id=app.application_template_id,
        applicant_identifier=app.applicant_identifier,
        form_data=app.form_data,
        evidence_submissions=app.evidence_submissions,
        integration_context=app.integration_context,
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )


@application_router.get("/{application_id}/evidence-facts", response_model=list[EvidenceFactResponse], dependencies=[Depends(_verify_management_api_key)])
async def list_application_evidence_facts(
    application_id: str,
    repo: IIssuanceRepository = Depends(),
) -> list[EvidenceFactResponse]:
    """List normalized MIP evidence facts for an application."""
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    facts = await repo.list_evidence_facts_for_application(application_id)
    return [_evidence_fact_to_response(fact) for fact in facts]


@application_router.get("/{application_id}/evidence-summary", response_model=ApplicationEvidenceSummaryResponse, dependencies=[Depends(_verify_management_api_key)])
async def get_application_evidence_summary(
    application_id: str,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationEvidenceSummaryResponse:
    """Return application evidence facts and latest approval policy metadata."""
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    facts = await repo.list_evidence_facts_for_application(application_id)
    template = await repo.get_application_template(app.application_template_id)
    policy, policy_source, policy_set_id, canvas = _application_policy_context(app)
    return ApplicationEvidenceSummaryResponse(
        application_id=app.id,
        organization_id=app.organization_id,
        status=app.status.value,
        evidence_facts=[_evidence_fact_to_response(fact) for fact in facts],
        policy_decision=policy,
        policy_source=policy_source,
        policy_set_id=policy_set_id,
        issuance_transaction_id=app.issuance_transaction_id,
        canvas=canvas,
        available_api_checks=_available_external_api_checks(template),
    )


@application_router.post(
    "/{application_id}/evidence/api-checks/{check_id}/run",
    response_model=ExternalEvidenceApiCheckResponse,
    dependencies=[Depends(_verify_management_api_key)],
)
async def run_external_evidence_api_check(
    application_id: str,
    check_id: str,
    request: ExternalEvidenceApiCheckRequest,
    repo: IIssuanceRepository = Depends(),
) -> ExternalEvidenceApiCheckResponse:
    """Run a user-defined external evidence API check and create a MIP fact."""
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    if app.status not in (ApplicationStatus.PENDING, ApplicationStatus.APPROVED):
        raise HTTPException(status_code=400, detail=f"Cannot run evidence check for application in {app.status} status")

    template = await repo.get_application_template(app.application_template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    requirement = find_external_api_requirement(template, check_id)
    if requirement is None:
        raise HTTPException(status_code=404, detail="External evidence API check not found on application template")

    try:
        check_result = await execute_external_evidence_api_check(
            app=app,
            requirement=requirement,
            inputs=request.inputs,
        )
    except ExternalEvidenceApiError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"External evidence API request failed: {exc}") from exc

    evidence_fact = check_result.evidence_fact
    external_context = {
        "last_check_id": check_id,
        "last_evidence_fact_id": evidence_fact.id,
        "provider": evidence_fact.provider,
        "fact_type": evidence_fact.fact_type,
        "verification_status": evidence_fact.verification.get("status"),
        "response_metadata": check_result.response_metadata,
        "checked_at": evidence_fact.created_at.isoformat(),
    }
    auto_issue_enabled = bool(
        requirement.get("auto_issue_on_permit")
        or requirement.get("auto_approve_on_evidence")
    )
    transition = await persist_evidence_fact_and_apply_policy(
        repo=repo,
        app=app,
        template=template,
        evidence_fact=evidence_fact,
        evidence_submission={
            "evidence_type": requirement.get("evidence_type") or "EXTERNAL_API",
            "evidence_data": {
                "provider": evidence_fact.provider,
                "fact_type": evidence_fact.fact_type,
                "scope": evidence_fact.scope,
                "assertion": evidence_fact.assertion,
            },
            "source": evidence_fact.source,
            "evidence_fact_ids": [evidence_fact.id],
            "verification": evidence_fact.verification,
        },
        integration_context_updates={"external_evidence_api": external_context},
        requirements=template.evidence_requirements,
        source="external_evidence_api",
        audit_metadata={"check_id": check_id},
        connector=None,
        evaluate_policy=True,
        issue_on_permit=request.issue_on_permit,
        auto_issue_on_permit=auto_issue_enabled,
        reviewer_id="external-evidence:auto-approval",
        review_notes="Auto-approved by MIP policy after user-defined external evidence API check",
        issuer_context_applier=apply_remote_issuer_context,
    )
    policy_decision = transition.policy_decision
    tx = transition.issuance_transaction

    return ExternalEvidenceApiCheckResponse(
        application_id=app.id,
        organization_id=app.organization_id,
        check_id=check_id,
        status="evidence_received",
        application_status=app.status.value,
        evidence_fact=_evidence_fact_to_response(evidence_fact),
        policy_decision=(getattr(app, "integration_context", {}) or {}).get(
            "policy",
            policy_decision.to_dict() if policy_decision else {},
        ),
        issuance_transaction_id=tx.id if tx else app.issuance_transaction_id,
        response_metadata=check_result.response_metadata,
    )


@application_router.post("/evidence/reconcile", response_model=dict[str, Any], dependencies=[Depends(_verify_management_api_key)])
async def reconcile_application_evidence(
    request: EvidenceReconciliationRequest,
    repo: IIssuanceRepository = Depends(),
) -> dict[str, Any]:
    """Recover Canvas evidence policy and approval-to-issuance transitions."""
    if request.application_id:
        app = await repo.get_application(request.application_id)
        if not app or app.organization_id != request.organization_id:
            raise HTTPException(status_code=404, detail="Application not found for organization")

    result = await reconcile_canvas_evidence_transitions(
        repo=repo,
        organization_id=request.organization_id,
        application_id=request.application_id,
        limit=max(1, min(request.limit, 1000)),
        dry_run=request.dry_run,
        issue_on_permit=request.issue_on_permit,
        issuer_context_applier=apply_remote_issuer_context,
    )
    return result.to_dict()


@application_router.get("/evidence/reconciliation-report", response_model=dict[str, Any], dependencies=[Depends(_verify_management_api_key)])
async def get_application_evidence_reconciliation_report(
    organization_id: str = Query(...),
    limit: int = Query(100),
    repo: IIssuanceRepository = Depends(),
) -> dict[str, Any]:
    """Return a dry-run Canvas evidence reconciliation report."""
    result = await build_canvas_evidence_reconciliation_report(
        repo=repo,
        organization_id=organization_id,
        limit=max(1, min(limit, 1000)),
    )
    return result.to_dict()


@application_router.post("/{application_id}/submit-evidence", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def submit_evidence(
    application_id: str,
    evidence: EvidenceSubmission,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Submit evidence for an application."""
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    if app.status != ApplicationStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Cannot submit evidence for application in {app.status} status")
    
    app.evidence_submissions.append({
        "evidence_type": evidence.evidence_type,
        "evidence_data": evidence.evidence_data,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    })
    await repo.save_application(app)
    
    logger.info(f"Added evidence to application {application_id}: {evidence.evidence_type}")
    
    return ApplicationResponse(
        id=app.id,
        organization_id=app.organization_id,
        application_template_id=app.application_template_id,
        applicant_identifier=app.applicant_identifier,
        form_data=app.form_data,
        evidence_submissions=app.evidence_submissions,
        integration_context=app.integration_context,
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )


@application_router.post("/{application_id}/approve", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def approve_application(
    application_id: str,
    approval: ApplicationApproval,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Approve an application and trigger credential issuance."""
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    if app.status != ApplicationStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Cannot approve application in {app.status} status")
    
    template = await repo.get_application_template(app.application_template_id)
    if not template or not template.credential_template_id:
        raise HTTPException(status_code=400, detail="Application template missing credential template ID")
    
    # Resolve the credential type from the template (needed for signing).
    credential_type = "org.iso.18013.5.1.mDL"  # Default fallback
    credential_vct: str | None = None
    try:
        ct_url = f"{CREDENTIAL_TEMPLATE_SERVICE_URL}/v1/credential-templates/{template.credential_template_id}"
        async with httpx.AsyncClient(timeout=10.0) as _client:
            _resp = await _client.get(ct_url)
        if _resp.status_code < 400:
            _tmpl = _resp.json()
            credential_type = _tmpl.get("credential_type") or credential_type
            raw_vct = _tmpl.get("vct") or ""
            credential_vct = (
                raw_vct if raw_vct.startswith("http")
                else f"{ISSUER_BASE_URL}/credentials/{credential_type}"
            )
    except Exception:
        pass

    logger.info(
        "[approve] app=%s template=%s cred_type=%s form_data_keys=%s",
        application_id,
        template.credential_template_id,
        credential_type,
        list(app.form_data.keys()) if app.form_data else [],
    )

    tx = await approve_application_for_issuance(
        repo=repo,
        app=app,
        template=template,
        reviewer_id=approval.reviewer_id,
        review_notes=approval.review_notes,
        credential_context=CredentialContext(
            credential_type=credential_type,
            credential_vct=credential_vct,
        ),
        issuer_context_applier=apply_remote_issuer_context,
    )
    
    logger.info(f"Approved application {application_id}, created issuance transaction {tx.id}")
    
    return ApplicationResponse(
        id=app.id,
        organization_id=app.organization_id,
        application_template_id=app.application_template_id,
        applicant_identifier=app.applicant_identifier,
        form_data=app.form_data,
        evidence_submissions=app.evidence_submissions,
        integration_context=app.integration_context,
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )


@application_router.post("/{application_id}/reject", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def reject_application(
    application_id: str,
    rejection: ApplicationRejection,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Reject an application."""
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    if app.status != ApplicationStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Cannot reject application in {app.status} status")
    
    app.status = ApplicationStatus.REJECTED
    app.review_notes = rejection.review_notes
    app.reviewer_id = rejection.reviewer_id
    app.reviewed_at = datetime.now(timezone.utc)
    await repo.save_application(app)
    
    logger.info(f"Rejected application {application_id}")
    
    return ApplicationResponse(
        id=app.id,
        organization_id=app.organization_id,
        application_template_id=app.application_template_id,
        applicant_identifier=app.applicant_identifier,
        form_data=app.form_data,
        evidence_submissions=app.evidence_submissions,
        integration_context=app.integration_context,
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )


# ============================================================================
# Issuance Offer Endpoints
# ============================================================================

class IssuanceOfferWallet(BaseModel):
    id: str
    name: str
    logo_url: str | None
    deep_link_url: str
    platforms: list[str]


class IssuanceOfferResponse(BaseModel):
    offer_url: str
    qr_payload: str             # same as offer_url — wallets use this directly
    wallets: list[IssuanceOfferWallet]
    email_payload: dict         # {subject, body, offer_url}
    expires_at: str
    transaction_id: str
    status: str                 # active | expired
    credential_offer_uris: dict[str, str] = {}  # wallet_id → deep-link URI


def _build_offer_uri(
    pre_auth_code: str,
    org_id: str,
    credential_config_id: str = "default",
) -> str:
    """Build an openid-credential-offer:// URI with a per-org credential_issuer.

    Per OID4VCI v1 \u00a712.2.2 the wallet uses credential_issuer to derive the
    well-known metadata URL, so it must be org-scoped.
    """
    from issuance.infrastructure.api.routes import org_issuer_url
    offer_data = {
        "credential_issuer": org_issuer_url(org_id),
        "credential_configuration_ids": [credential_config_id],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code,
            }
        },
    }
    return f"openid-credential-offer://?credential_offer={quote(json.dumps(offer_data))}"


def _build_wallet_offer_uris(
    pre_auth_code: str,
    org_id: str,
    credential_type: str,
    wallet_configs: list[dict],
) -> dict[str, str]:
    """Build per-wallet credential_offer_uris from a transaction's wallet_configs.

    Mirrors the logic in routes.initiate_issuance so that GET endpoints return
    the same correctly-keyed deep-link URIs as the POST that created the offer.
    SpruceKit (mso_mdoc / spruce-vc+sd-jwt) gets the /spruce issuer URL so its
    ProfilesCredentialConfiguration enum can parse the metadata without error.
    """
    from issuance.infrastructure.api.routes import org_issuer_url, org_issuer_url_spruce
    from issuance.application.rust_integration import oid4vci_create_credential_offer
    uris: dict[str, str] = {}
    for wc in wallet_configs:
        wid = wc.get("wallet_id", "")
        scheme = wc.get("deep_link_scheme", "openid-credential-offer://")
        fmt_variant = wc.get("format_variant")
        if not wid:
            continue
        # Select credential_configuration_id suffix for this format variant
        if fmt_variant == "spruce-vc+sd-jwt":
            config_id = f"{credential_type}#spruce-sd-jwt"
        elif fmt_variant == "mso_mdoc":
            config_id = f"{credential_type}#mdoc"
        else:
            config_id = credential_type
        # SpruceKit requires the /spruce issuer URL to avoid metadata parse errors
        issuer_url = (
            org_issuer_url_spruce(org_id)
            if fmt_variant in ("spruce-vc+sd-jwt", "mso_mdoc")
            else org_issuer_url(org_id)
        )
        offer_json = oid4vci_create_credential_offer(
            issuer_url=issuer_url,
            credential_types=[config_id],
            pre_authorized_code=pre_auth_code,
            user_pin_required=False,
        )
        sep = "&" if "?" in scheme else "?"
        uris[wid] = f"{scheme}{sep}credential_offer={quote(offer_json)}"
    return uris


async def _fetch_wallets_for_template(credential_template_id: str | None) -> list[IssuanceOfferWallet]:
    """Fetch wallet registry entries for a credential template.

    Uses gRPC to CredentialTemplateService (ListWallets / GetWallet) with
    HTTP fallback when the gRPC target is unreachable.
    """
    if not credential_template_id:
        return []

    # --- helper: try gRPC first -----------------------------------------------
    async def _fetch_via_grpc() -> list[IssuanceOfferWallet] | None:
        """Return wallets via gRPC, or None on failure (triggers HTTP fallback)."""
        try:
            import grpc as _grpc
            import grpc.aio as grpc_aio
            from marty_proto.v1 import credential_template_service_pb2 as ct_pb2
            from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc

            ct_grpc_target = os.environ.get("CT_GRPC_TARGET", "credential-template:9003")
            async with grpc_aio.insecure_channel(ct_grpc_target) as channel:
                ct_stub = ct_grpc.CredentialTemplateServiceStub(channel)

                # 1. Get template to check for supported_wallet_ids via wallet_configs_json
                tmpl_resp = await ct_stub.GetTemplate(
                    ct_pb2.GetTemplateRequest(template_id=credential_template_id)
                )
                if not tmpl_resp.id:
                    return []

                # Extract wallet IDs from wallet_configs_json
                wallet_ids: list[str] = []
                if tmpl_resp.wallet_configs_json:
                    import json as _json
                    wc_list = _json.loads(tmpl_resp.wallet_configs_json)
                    wallet_ids = [wc.get("wallet_id", "") for wc in wc_list if wc.get("wallet_id")]

                if not wallet_ids:
                    # Fallback: return all active wallets from registry
                    list_resp = await ct_stub.ListWallets(
                        ct_pb2.ListWalletsRequest(active_only=True)
                    )
                    return [
                        IssuanceOfferWallet(
                            id=w.id,
                            name=w.name,
                            logo_url=w.logo_url or None,
                            deep_link_url="",
                            platforms=list(w.platforms),
                        )
                        for w in list_resp.wallets
                    ]

                # 2. Fetch each wallet by ID
                wallets: list[IssuanceOfferWallet] = []
                for wid in wallet_ids:
                    try:
                        w = await ct_stub.GetWallet(ct_pb2.GetWalletRequest(wallet_id=wid))
                        if w.id:
                            wallets.append(IssuanceOfferWallet(
                                id=w.id,
                                name=w.name,
                                logo_url=w.logo_url or None,
                                deep_link_url="",
                                platforms=list(w.platforms),
                            ))
                    except _grpc.RpcError:
                        continue
                return wallets
        except Exception as e:
            logger.warning(f"gRPC wallet fetch failed, falling back to HTTP: {e}")
            return None

    # --- attempt gRPC ----------------------------------------------------------
    result = await _fetch_via_grpc()
    if result is not None:
        return result

    # --- HTTP fallback ---------------------------------------------------------
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # 1. Get template to find supported_wallet_ids
            tmpl_resp = await client.get(
                f"{CREDENTIAL_TEMPLATE_SERVICE_URL}/v1/credential-templates/{credential_template_id}"
            )
            if tmpl_resp.status_code != 200:
                return []
            wallet_ids: list[str] = tmpl_resp.json().get("supported_wallet_ids", [])
            if not wallet_ids:
                # fall back: return all wallets from registry
                registry_resp = await client.get(
                    f"{CREDENTIAL_TEMPLATE_SERVICE_URL}/v1/wallet-registry?active_only=true"
                )
                if registry_resp.status_code != 200:
                    return []
                return [
                    IssuanceOfferWallet(
                        id=w["id"],
                        name=w["name"],
                        logo_url=w.get("logo_url"),
                        deep_link_url="",
                        platforms=w.get("platforms", []),
                    )
                    for w in registry_resp.json()
                ]
            # 2. Fetch each wallet entry
            wallets: list[IssuanceOfferWallet] = []
            for wid in wallet_ids:
                wr = await client.get(f"{CREDENTIAL_TEMPLATE_SERVICE_URL}/v1/wallet-registry/{wid}")
                if wr.status_code == 200:
                    w = wr.json()
                    wallets.append(IssuanceOfferWallet(
                        id=w["id"],
                        name=w["name"],
                        logo_url=w.get("logo_url"),
                        deep_link_url="",
                        platforms=w.get("platforms", []),
                    ))
            return wallets
    except Exception as e:
        logger.warning(f"Could not fetch wallets for template {credential_template_id}: {e}")
        return []


async def _get_or_refresh_transaction(
    app: "Application",
    repo: IIssuanceRepository,
    template: "ApplicationTemplate | None",
) -> IssuanceTransaction:
    """Return a reusable transaction or create a fresh one for single-use offers."""
    tx: IssuanceTransaction | None = None
    if app.issuance_transaction_id:
        tx = await repo.get_transaction(app.issuance_transaction_id)

    if tx and tx.status == IssuanceStatus.PENDING and not tx.is_expired:
        delivery_before = tx.delivery_mode
        tx.delivery_mode = delivery_mode_from_integration_context(app.integration_context)
        before = (tx.issuer_did_override, tx.signing_service_id)
        await apply_remote_issuer_context(tx)
        if before != (tx.issuer_did_override, tx.signing_service_id) or delivery_before != tx.delivery_mode:
            await repo.save_transaction(tx)
        return tx

    # Create a fresh transaction
    credential_template_id = (template.credential_template_id if template else None)
    tx = IssuanceTransaction(
        organization_id=app.organization_id,
        credential_template_id=credential_template_id,
        applicant_id=app.applicant_identifier,
        application_id=app.id,
        subject_did=None,
        delivery_mode=delivery_mode_from_integration_context(app.integration_context),
        claims=app.form_data,
    )
    await apply_remote_issuer_context(tx)
    await repo.save_transaction(tx)
    app.issuance_transaction_id = tx.id
    await repo.save_application(app)
    logger.info(f"Created fresh issuance transaction {tx.id} for application {app.id}")
    return tx


@application_router.post(
    "/{application_id}/issuance-offer",
    response_model=IssuanceOfferResponse,
    summary="Generate Wallet Invite (Admin)",
    dependencies=[Depends(_verify_management_api_key)],
)
async def generate_issuance_offer(
    application_id: str,
    repo: IIssuanceRepository = Depends(),
) -> IssuanceOfferResponse:
    """Generate (or refresh) a wallet credential offer for an approved application.

    Returns:
    - offer_url: openid-credential-offer:// URI for QR display
    - qr_payload: same URI encoded for QR generation
    - wallets: deep-link buttons derived from credential template's supported wallets
    - email_payload: pre-built email subject/body for invite sending
    - expires_at: ISO-8601 expiry of the offer
    """
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    if app.status != ApplicationStatus.APPROVED:
        raise HTTPException(
            status_code=400,
            detail=f"Issuance offer requires APPROVED status; current status is {app.status.value}",
        )

    template = None
    if app.application_template_id:
        template = await repo.get_application_template(app.application_template_id)

    tx = await _get_or_refresh_transaction(app, repo, template)
    # Resolve credential config id from the transaction's credential type
    credential_config_id = tx.credential_type or "default"
    offer_url = _build_offer_uri(
        pre_auth_code=tx.pre_auth_code,
        org_id=app.organization_id,
        credential_config_id=credential_config_id,
    )

    # Build per-wallet deep-link URIs (with correct issuer URL per wallet type)
    credential_offer_uris = _build_wallet_offer_uris(
        pre_auth_code=tx.pre_auth_code,
        org_id=app.organization_id,
        credential_type=tx.credential_type or "default",
        wallet_configs=list(tx.wallet_configs or []),
    )

    # Enrich with wallet deep links
    from urllib.parse import quote as url_quote
    raw_wallets = await _fetch_wallets_for_template(
        template.credential_template_id if template else None
    )
    wallets = [
        IssuanceOfferWallet(
            id=w.id,
            name=w.name,
            logo_url=w.logo_url,
            deep_link_url=offer_url,  # most wallets use the same openid-credential-offer:// scheme
            platforms=w.platforms,
        )
        for w in raw_wallets
    ]

    email_payload = {
        "subject": "Your credential is ready",
        "body": (
            "Your credential has been approved and is ready to add to your wallet.\n\n"
            f"Click the link below to receive your credential:\n{offer_url}\n\n"
            "Or scan the QR code from another device."
        ),
        "offer_url": offer_url,
    }

    logger.info(f"Generated issuance offer for application {application_id}, tx {tx.id}")

    await repo.save_event(IssuanceEvent(
        transaction_id=tx.id,
        application_id=application_id,
        event_type=EventType.OFFER_GENERATED,
        metadata={"expires_at": tx.expires_at.isoformat(), "wallet_count": len(wallets)},
    ))

    return IssuanceOfferResponse(
        offer_url=offer_url,
        qr_payload=offer_url,
        wallets=wallets,
        email_payload=email_payload,
        expires_at=tx.expires_at.isoformat(),
        transaction_id=tx.id,
        status="expired" if tx.is_expired else "active",
        credential_offer_uris=credential_offer_uris,
    )


@application_router.get(
    "/{application_id}/issuance-offer",
    response_model=IssuanceOfferResponse,
    summary="Get Wallet Invite (Applicant)",
)
async def get_issuance_offer(
    application_id: str,
    repo: IIssuanceRepository = Depends(),
) -> IssuanceOfferResponse:
    """Retrieve the current issuance offer for an application (applicant-facing).

    Returns 404 if no offer has been generated yet.
    Returns the offer with status='expired' if the offer PIN has expired.
    """
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    if app.status not in (ApplicationStatus.APPROVED, ApplicationStatus.ISSUED):
        raise HTTPException(
            status_code=404,
            detail="No issuance offer available for this application",
        )

    if not app.issuance_transaction_id:
        raise HTTPException(
            status_code=404,
            detail="Wallet invite has not been generated yet. Please contact the issuer.",
        )

    tx = await repo.get_transaction(app.issuance_transaction_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Issuance transaction not found")

    template = None
    if app.application_template_id:
        template = await repo.get_application_template(app.application_template_id)

    credential_config_id = tx.credential_type or "default"
    offer_url = _build_offer_uri(
        pre_auth_code=tx.pre_auth_code,
        org_id=app.organization_id,
        credential_config_id=credential_config_id,
    )

    # Build per-wallet deep-link URIs (with correct issuer URL per wallet type)
    credential_offer_uris = _build_wallet_offer_uris(
        pre_auth_code=tx.pre_auth_code,
        org_id=app.organization_id,
        credential_type=tx.credential_type or "default",
        wallet_configs=list(tx.wallet_configs or []),
    )

    raw_wallets = await _fetch_wallets_for_template(
        template.credential_template_id if template else None
    )
    wallets = [
        IssuanceOfferWallet(
            id=w.id,
            name=w.name,
            logo_url=w.logo_url,
            deep_link_url=offer_url,
            platforms=w.platforms,
        )
        for w in raw_wallets
    ]

    email_payload = {
        "subject": "Your credential is ready",
        "body": (
            "Your credential has been approved and is ready to add to your wallet.\n\n"
            f"Click the link below to receive your credential:\n{offer_url}\n\n"
            "Or scan the QR code from another device."
        ),
        "offer_url": offer_url,
    }

    event_type = EventType.OFFER_EXPIRED if tx.is_expired else EventType.OFFER_VIEWED
    await repo.save_event(IssuanceEvent(
        transaction_id=tx.id,
        application_id=application_id,
        event_type=event_type,
        metadata={"expired": tx.is_expired},
    ))

    return IssuanceOfferResponse(
        offer_url=offer_url,
        qr_payload=offer_url,
        wallets=wallets,
        email_payload=email_payload,
        expires_at=tx.expires_at.isoformat(),
        transaction_id=tx.id,
        status="expired" if tx.is_expired else "active",
        credential_offer_uris=credential_offer_uris,
    )


@application_router.get(
    "/{application_id}/issuance-events",
    response_model=list[IssuanceEventResponse],
    summary="List Issuance Events (Admin)",
    dependencies=[Depends(_verify_management_api_key)],
)
async def list_issuance_events(
    application_id: str,
    repo: IIssuanceRepository = Depends(),
) -> list[IssuanceEventResponse]:
    """List all lifecycle events for an application (admin audit timeline).

    Returns events in chronological order: offer_generated, offer_viewed,
    offer_expired, credential_issued, etc.
    """
    app = await repo.get_application(application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    events = await repo.list_events_for_application(application_id)
    return [
        IssuanceEventResponse(
            id=e.id,
            transaction_id=e.transaction_id,
            application_id=e.application_id,
            event_type=e.event_type,
            metadata=e.metadata,
            created_at=e.created_at.isoformat(),
        )
        for e in events
    ]
