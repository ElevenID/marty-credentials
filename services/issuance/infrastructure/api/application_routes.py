"""Application workflow endpoints."""

import logging
import uuid
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Query

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    IssuanceTransaction,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.api.routes import (
    ApplicationApproval,
    ApplicationCreate,
    ApplicationRejection,
    ApplicationResponse,
    ApplicationTemplateCreate,
    ApplicationTemplateResponse,
    EvidenceSubmission,
    application_router,
    application_template_router,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Application Template Endpoints
# ============================================================================

@application_template_router.post("", response_model=ApplicationTemplateResponse)
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
        approval_strategy=request.approval_strategy,
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
        approval_strategy=template.approval_strategy,
        application_validity_days=template.application_validity_days,
        auto_approval_rules=template.auto_approval_rules,
        ui_config=template.ui_config,
        notification_config=template.notification_config,
        status=template.status,
        created_at=template.created_at.isoformat(),
        updated_at=template.updated_at.isoformat(),
    )


@application_template_router.get("", response_model=list[ApplicationTemplateResponse])
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
            approval_strategy=t.approval_strategy,
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


@application_template_router.get("/{template_id}", response_model=ApplicationTemplateResponse)
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
        approval_strategy=template.approval_strategy,
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

@application_router.post("", response_model=ApplicationResponse)
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
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )


@application_router.get("", response_model=list[ApplicationResponse])
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


@application_router.get("/{application_id}", response_model=ApplicationResponse)
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
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )


@application_router.post("/{application_id}/submit-evidence", response_model=ApplicationResponse)
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
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )


@application_router.post("/{application_id}/approve", response_model=ApplicationResponse)
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
    
    app.status = ApplicationStatus.APPROVED
    app.review_notes = approval.review_notes
    app.reviewer_id = approval.reviewer_id
    app.reviewed_at = datetime.now(timezone.utc)
    
    # Trigger credential issuance
    tx = IssuanceTransaction(
        organization_id=app.organization_id,
        credential_template_id=template.credential_template_id,
        applicant_id=app.applicant_identifier,
        application_id=application_id,
        subject_did=None,
        claims=app.form_data,
    )
    await repo.save_transaction(tx)
    
    app.issuance_transaction_id = tx.id
    await repo.save_application(app)
    
    logger.info(f"Approved application {application_id}, created issuance transaction {tx.id}")
    
    return ApplicationResponse(
        id=app.id,
        organization_id=app.organization_id,
        application_template_id=app.application_template_id,
        applicant_identifier=app.applicant_identifier,
        form_data=app.form_data,
        evidence_submissions=app.evidence_submissions,
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )


@application_router.post("/{application_id}/reject", response_model=ApplicationResponse)
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
        status=app.status.value,
        review_notes=app.review_notes,
        reviewer_id=app.reviewer_id,
        submitted_at=app.submitted_at.isoformat(),
        reviewed_at=app.reviewed_at.isoformat() if app.reviewed_at else None,
        expires_at=app.expires_at.isoformat(),
        issuance_transaction_id=app.issuance_transaction_id,
    )
