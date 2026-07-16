"""Application workflow endpoints."""

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "https://beta.elevenidllc.com")
CREDENTIAL_TEMPLATE_SERVICE_URL = os.environ.get(
    "CREDENTIAL_TEMPLATE_SERVICE_URL", "http://credential-template-service:8003"
)

from issuance.application.application_approval import (
    CredentialContext,
    approve_application_for_issuance,
)
from issuance.application.canvas_issuance_guard import (
    CanvasIssuanceGuardError,
    canvas_approval_credential_context,
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
    EventType,
    EvidenceFact,
    IssuanceEvent,
    IssuanceStatus,
    IssuanceTransaction,
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
    ApplicationTemplatePatch,
    ApplicationTemplateResponse,
    EvidenceSubmission,
    _require_active_revocation_profile_binding,
    _verify_management_api_key,
    application_template_router,
    apply_remote_issuer_context,
    apply_required_remote_issuer_context,
    internal_application_router,
)

logger = logging.getLogger(__name__)
_INTERNAL_REVIEWER_ID = "issuance-management-api"


def _trusted_application_organization_id(request: Request) -> str:
    """Require the gateway-authenticated tenant on application management routes."""

    organization_id = (request.headers.get("x-organization-id") or "").strip()
    if not organization_id:
        raise HTTPException(
            status_code=400,
            detail="X-Organization-ID is required for application management",
        )
    return organization_id


def _application_management_organization_id(
    trusted_organization_id: Any,
    claimed_organization_id: str,
) -> str:
    """Recheck a caller-supplied organization against the trusted tenant."""

    claimed = str(claimed_organization_id or "").strip()
    if isinstance(trusted_organization_id, str) and trusted_organization_id.strip():
        trusted = trusted_organization_id.strip()
        if claimed != trusted:
            raise HTTPException(status_code=404, detail="Application resource not found")
        return trusted
    # Direct unit invocation bypasses FastAPI dependency resolution.
    return claimed


async def _managed_application(
    *,
    repo: IIssuanceRepository,
    application_id: str,
    trusted_organization_id: Any,
) -> Application:
    app = await repo.get_application(application_id)
    if app is None or (
        isinstance(trusted_organization_id, str)
        and trusted_organization_id.strip()
        and app.organization_id != trusted_organization_id.strip()
    ):
        raise HTTPException(status_code=404, detail="Application not found")
    return app


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
    requirement_id: str | None = None
    logical_key: str
    source_revision: str
    payload_hash: str
    observed_at: str
    effective_at: str | None = None
    superseded_fact_id: str | None = None
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
        requirement_id=fact.requirement_id,
        logical_key=fact.logical_key,
        source_revision=fact.source_revision,
        payload_hash=fact.payload_hash,
        observed_at=fact.observed_at.isoformat(),
        effective_at=fact.effective_at.isoformat() if fact.effective_at else None,
        superseded_fact_id=fact.superseded_fact_id,
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
                "auto_issue_on_permit": bool(requirement.get("auto_issue_on_permit")),
                "api_method": str(api.get("method") or "POST").upper(),
                "scope": requirement.get("scope") if isinstance(requirement.get("scope"), dict) else {},
            }
        )
    return checks


# ============================================================================
# Application Template Endpoints
# ============================================================================

def _template_response(template: ApplicationTemplate) -> ApplicationTemplateResponse:
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
        ui_config=template.ui_config,
        notification_config=template.notification_config,
        status=template.status,
        created_at=template.created_at.isoformat(),
        updated_at=template.updated_at.isoformat(),
    )


async def _application_template_validation_errors(
    template: ApplicationTemplate,
    repo: IIssuanceRepository,
) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []

    def add(section: str, field: str, code: str, message: str) -> None:
        errors.append({"section": section, "field": field, "code": code, "message": message})

    if not template.credential_template_id:
        add("credential_template", "credential_template_id", "REQUIRED", "Select a Credential Template.")
        credential_template = None
    else:
        credential_template = None
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{CREDENTIAL_TEMPLATE_SERVICE_URL}/v1/credential-templates/{template.credential_template_id}"
                )
            if response.status_code == 200:
                credential_template = response.json()
            else:
                add("credential_template", "credential_template_id", "NOT_FOUND", "Credential Template was not found.")
        except Exception:
            add("credential_template", "credential_template_id", "UNAVAILABLE", "Credential Template validation is unavailable.")

    if credential_template:
        if str(credential_template.get("organization_id") or "") != template.organization_id:
            add("credential_template", "credential_template_id", "WRONG_ORGANIZATION", "Credential Template belongs to another organization.")
        if str(credential_template.get("status") or "").upper() != "ACTIVE":
            add("credential_template", "credential_template_id", "NOT_ACTIVE", "Credential Template must be active.")
        if not str(credential_template.get("revocation_profile_id") or "").strip():
            add(
                "credential_template",
                "credential_template_id",
                "REVOCATION_PROFILE_REQUIRED",
                "Credential Template must reference an active Revocation Profile.",
            )

    if not template.form_fields:
        add("form_fields", "form_fields", "REQUIRED", "Add at least one form field.")

    credential_claims = {
        str(claim.get("name") or claim.get("field_id") or "")
        for claim in ((credential_template or {}).get("claims") or [])
        if isinstance(claim, dict)
    }
    seen_fields: set[str] = set()
    for index, field in enumerate(template.form_fields):
        if not isinstance(field, dict):
            add("form_fields", f"form_fields.{index}", "INVALID", "Form fields must use the canonical object shape.")
            continue
        field_id = str(field.get("field_id") or "")
        if not field_id:
            add("form_fields", f"form_fields.{index}.field_id", "REQUIRED", "Field ID is required.")
        if not str(field.get("label") or "").strip():
            add("form_fields", f"form_fields.{index}.label", "REQUIRED", "Field label is required.")
        if str(field.get("field_type") or "") not in {
            "TEXT", "DATE", "DATETIME", "SELECT", "FILE_UPLOAD",
            "INTEGER", "NUMBER", "BOOLEAN", "EMAIL", "URL",
        }:
            add("form_fields", f"form_fields.{index}.field_type", "INVALID", "Select a canonical field type.")
        if field_id in seen_fields:
            add("form_fields", f"form_fields.{index}.field_id", "DUPLICATE", "Field IDs must be unique.")
        seen_fields.add(field_id)
        if field.get("field_type") == "SELECT" and not field.get("options"):
            add("form_fields", f"form_fields.{index}.options", "REQUIRED", "Select fields require options.")
        if field.get("minimum") is not None and field.get("maximum") is not None and field["minimum"] > field["maximum"]:
            add("form_fields", f"form_fields.{index}.minimum", "INVALID_RANGE", "Minimum cannot exceed maximum.")
        validation_pattern = field.get("validation_pattern")
        if validation_pattern:
            try:
                re.compile(str(validation_pattern))
            except re.error:
                add("form_fields", f"form_fields.{index}.validation_pattern", "INVALID_PATTERN", "Validation pattern is not a valid regular expression.")
        claim_mapping = str(field.get("claim_mapping") or "")
        if claim_mapping and credential_claims and claim_mapping not in credential_claims:
            add("claim_mappings", f"form_fields.{index}.claim_mapping", "UNKNOWN_CLAIM", "Claim mapping is not defined by the Credential Template.")

    seen_evidence: set[str] = set()
    evidence_types = {
        "DOCUMENT_SCAN", "BIOMETRIC", "SELFIE", "THIRD_PARTY_VERIFICATION",
        "EXTERNAL_FACT", "EXTERNAL_API",
    }
    for index, requirement in enumerate(template.evidence_requirements):
        if not isinstance(requirement, dict):
            add("evidence", f"evidence_requirements.{index}", "INVALID", "Evidence must use the canonical object shape.")
            continue
        evidence_id = str(requirement.get("evidence_id") or "").strip()
        evidence_type = str(requirement.get("evidence_type") or "")
        if not evidence_id:
            add("evidence", f"evidence_requirements.{index}.evidence_id", "REQUIRED", "Evidence ID is required.")
        elif evidence_id in seen_evidence:
            add("evidence", f"evidence_requirements.{index}.evidence_id", "DUPLICATE", "Evidence IDs must be unique.")
        seen_evidence.add(evidence_id)
        if evidence_type not in evidence_types:
            add("evidence", f"evidence_requirements.{index}.evidence_type", "INVALID", "Select a canonical evidence type.")
        if not str(requirement.get("description") or "").strip():
            add("evidence", f"evidence_requirements.{index}.description", "REQUIRED", "Evidence description is required.")
        if not isinstance(requirement.get("required"), bool):
            add("evidence", f"evidence_requirements.{index}.required", "REQUIRED", "Evidence required state must be explicit.")
        if evidence_type in {"EXTERNAL_FACT", "EXTERNAL_API"}:
            if not str(requirement.get("provider") or "").strip():
                add("evidence", f"evidence_requirements.{index}.provider", "REQUIRED", "External evidence provider is required.")
            if not str(requirement.get("fact_type") or "").strip():
                add("evidence", f"evidence_requirements.{index}.fact_type", "REQUIRED", "External evidence fact type is required.")
        if evidence_type == "EXTERNAL_API":
            api = requirement.get("api")
            if not isinstance(api, dict) or not str(api.get("url") or "").strip():
                add("evidence", f"evidence_requirements.{index}.api.url", "REQUIRED", "External API URL is required.")

    valid_sources = {"FORM_FIELD", "EVIDENCE_EXTRACTION", "EXTERNAL_API", "SYSTEM"}
    valid_system_fields = {
        "applicant.user_id", "applicant.email", "applicant.given_name", "applicant.family_name",
        "application.id", "application.reference_number", "application.organization_id",
        "current.date", "current.datetime", "validity.expiry_date",
        "template.name", "template.description", "constant",
    }
    for index, rule in enumerate(template.claim_collection_rules):
        if not isinstance(rule, dict):
            add("claim_mappings", f"claim_collection_rules.{index}", "INVALID", "Claim rules must use the canonical object shape.")
            continue
        if not str(rule.get("claim_name") or "").strip():
            add("claim_mappings", f"claim_collection_rules.{index}.claim_name", "REQUIRED", "Claim name is required.")
        source = str(rule.get("source") or "")
        if source not in valid_sources:
            add("claim_mappings", f"claim_collection_rules.{index}.source", "INVALID", "Select a canonical claim source.")
        source_config = rule.get("source_config")
        if not isinstance(source_config, dict):
            add("claim_mappings", f"claim_collection_rules.{index}.source_config", "INVALID", "Claim source configuration must be an object.")
        elif source == "FORM_FIELD" and source_config.get("field_id") not in seen_fields:
            add("claim_mappings", f"claim_collection_rules.{index}.source_config.field_id", "UNKNOWN_FIELD", "Claim source must reference a configured form field.")
        elif source == "SYSTEM":
            system_field = str(source_config.get("system_field") or "")
            if system_field not in valid_system_fields:
                add("claim_mappings", f"claim_collection_rules.{index}.source_config.system_field", "INVALID", "Select a supported system claim source.")
            elif system_field == "constant" and "value" not in source_config:
                add("claim_mappings", f"claim_collection_rules.{index}.source_config.value", "REQUIRED", "Constant system claims require a value.")

    seen_check_orders: set[int] = set()
    for index, check in enumerate(template.required_checks):
        if not isinstance(check, dict) or not str(check.get("check_type") or "").strip():
            add("required_checks", f"required_checks.{index}.check_type", "REQUIRED", "Check type is required.")
            continue
        order = check.get("order")
        if not isinstance(order, int) or order < 1:
            add("required_checks", f"required_checks.{index}.order", "INVALID", "Check order must be a positive integer.")
        elif order in seen_check_orders:
            add("required_checks", f"required_checks.{index}.order", "DUPLICATE", "Check order values must be unique.")
        else:
            seen_check_orders.add(order)

    if template.approval_strategy == "RULES_BASED":
        if not template.approval_policy_set_id:
            add("approval", "approval_policy_set_id", "REQUIRED", "Rules-based approval requires an approval Policy Set.")
        else:
            policy_set = await repo.get_approval_policy_set(
                template.organization_id,
                template.approval_policy_set_id,
            )
            if policy_set is None:
                add("approval", "approval_policy_set_id", "NOT_FOUND", "Approval Policy Set was not found.")
            elif str(policy_set.policy_type).upper() != "APPROVAL_RULES":
                add("approval", "approval_policy_set_id", "WRONG_TYPE", "Policy Set must have type APPROVAL_RULES.")
            elif str(policy_set.status).upper() != "ACTIVE":
                add("approval", "approval_policy_set_id", "NOT_ACTIVE", "Approval Policy Set must be active.")
    if not 1 <= template.application_validity_days <= 3650:
        add("validity", "application_validity_days", "OUT_OF_RANGE", "Validity must be between 1 and 3650 days.")
    if not isinstance(template.notification_config, dict):
        add("notifications", "notification_config", "INVALID", "Notification configuration must be an object.")
    if not isinstance(template.ui_config, dict):
        add("preview", "ui_config", "INVALID", "UI configuration must be an object.")
    return errors

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
        form_fields=[field.model_dump(exclude_none=True) for field in request.form_fields],
        evidence_requirements=[item.model_dump(exclude_none=True) for item in request.evidence_requirements],
        claim_collection_rules=[item.model_dump(exclude_none=True) for item in request.claim_collection_rules],
        required_checks=[check.model_dump(exclude_none=True) for check in request.required_checks],
        approval_strategy=request.approval_strategy,
        approval_policy_set_id=request.approval_policy_set_id,
        application_validity_days=request.application_validity_days,
        ui_config=request.ui_config,
        notification_config=request.notification_config,
        status="DRAFT",
    )
    await repo.save_application_template(template)
    
    logger.info(f"Created application template {template.id} for organization {template.organization_id}")
    
    return _template_response(template)


@application_template_router.get("", response_model=list[ApplicationTemplateResponse], dependencies=[Depends(_verify_management_api_key)])
async def list_application_templates(
    organization_id: str = Query(...),
    repo: IIssuanceRepository = Depends(),
) -> list[ApplicationTemplateResponse]:
    """List all application templates for an organization."""
    templates = await repo.list_application_templates(organization_id)
    
    return [_template_response(template) for template in templates]


@application_template_router.get("/{template_id}", response_model=ApplicationTemplateResponse, dependencies=[Depends(_verify_management_api_key)])
async def get_application_template(
    template_id: str,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationTemplateResponse:
    """Get an application template by ID."""
    template = await repo.get_application_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    
    return _template_response(template)


@application_template_router.patch("/{template_id}", response_model=ApplicationTemplateResponse, dependencies=[Depends(_verify_management_api_key)])
async def update_application_template(
    template_id: str,
    request: ApplicationTemplatePatch,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationTemplateResponse:
    """Patch a draft Application Template."""
    template = await repo.get_application_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    if template.status != "DRAFT":
        raise HTTPException(status_code=409, detail="Only draft Application Templates can be edited")

    changes = request.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if key == "form_fields" and value is not None:
            value = [field.model_dump(exclude_none=True) if hasattr(field, "model_dump") else field for field in request.form_fields or []]
        elif key == "evidence_requirements" and value is not None:
            value = [item.model_dump(exclude_none=True) for item in request.evidence_requirements or []]
        elif key == "claim_collection_rules" and value is not None:
            value = [item.model_dump(exclude_none=True) for item in request.claim_collection_rules or []]
        elif key == "required_checks" and value is not None:
            value = [check.model_dump(exclude_none=True) if hasattr(check, "model_dump") else check for check in request.required_checks or []]
        setattr(template, key, value)
    template.updated_at = datetime.now(timezone.utc)
    await repo.save_application_template(template)
    logger.info(f"Updated application template {template.id}")
    return _template_response(template)


@application_template_router.post("/{template_id}/validate", dependencies=[Depends(_verify_management_api_key)])
async def validate_application_template(
    template_id: str,
    repo: IIssuanceRepository = Depends(),
) -> dict[str, Any]:
    template = await repo.get_application_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    errors = await _application_template_validation_errors(template, repo)
    return {"valid": not errors, "errors": errors}


@application_template_router.post("/{template_id}/activate", response_model=ApplicationTemplateResponse, dependencies=[Depends(_verify_management_api_key)])
async def activate_application_template(
    template_id: str,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationTemplateResponse:
    template = await repo.get_application_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    if template.status != "DRAFT":
        raise HTTPException(status_code=409, detail="Only draft Application Templates can be activated")
    errors = await _application_template_validation_errors(template, repo)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"error": "APPLICATION_TEMPLATE_INVALID", "errors": errors},
        )
    template.status = "ACTIVE"
    template.updated_at = datetime.now(timezone.utc)
    await repo.save_application_template(template)
    return _template_response(template)


@application_template_router.post("/{template_id}/deprecate", response_model=ApplicationTemplateResponse, dependencies=[Depends(_verify_management_api_key)])
async def deprecate_application_template(
    template_id: str,
    repo: IIssuanceRepository = Depends(),
) -> ApplicationTemplateResponse:
    template = await repo.get_application_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    if template.status != "ACTIVE":
        raise HTTPException(status_code=409, detail="Only active Application Templates can be deprecated")
    template.status = "DEPRECATED"
    template.updated_at = datetime.now(timezone.utc)
    await repo.save_application_template(template)
    return _template_response(template)


@application_template_router.delete("/{template_id}", status_code=204, dependencies=[Depends(_verify_management_api_key)])
async def delete_application_template(
    template_id: str,
    repo: IIssuanceRepository = Depends(),
) -> Response:
    template = await repo.get_application_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    if template.status != "DRAFT":
        raise HTTPException(status_code=409, detail="Only draft Application Templates can be deleted")
    await repo.delete_application_template(template_id)
    return Response(status_code=204)


# ============================================================================
# Application Endpoints
# ============================================================================

@internal_application_router.post("", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def create_application(
    request: ApplicationCreate,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Create a new application submission."""
    template = await repo.get_application_template(request.application_template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Application template not found")
    _application_management_organization_id(
        trusted_organization_id,
        template.organization_id,
    )
    if template.status != "ACTIVE":
        raise HTTPException(status_code=422, detail="Application template must be active")
    
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


@internal_application_router.get("", response_model=list[ApplicationResponse], dependencies=[Depends(_verify_management_api_key)])
async def list_applications(
    organization_id: str = Query(...),
    status: str = Query(None),
    application_template_id: str = Query(None),
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> list[ApplicationResponse]:
    """List applications with optional filters."""
    organization_id = _application_management_organization_id(
        trusted_organization_id,
        organization_id,
    )
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


@internal_application_router.get("/{application_id}", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def get_application(
    application_id: str,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Get an application by ID."""
    app = await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )
    
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


@internal_application_router.get("/{application_id}/evidence-facts", response_model=list[EvidenceFactResponse], dependencies=[Depends(_verify_management_api_key)])
async def list_application_evidence_facts(
    application_id: str,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> list[EvidenceFactResponse]:
    """List normalized MIP evidence facts for an application."""
    await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )

    facts = await repo.list_evidence_facts_for_application(application_id)
    return [_evidence_fact_to_response(fact) for fact in facts]


@internal_application_router.get("/{application_id}/evidence-summary", response_model=ApplicationEvidenceSummaryResponse, dependencies=[Depends(_verify_management_api_key)])
async def get_application_evidence_summary(
    application_id: str,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> ApplicationEvidenceSummaryResponse:
    """Return application evidence facts and latest approval policy metadata."""
    app = await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )

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


@internal_application_router.post(
    "/{application_id}/evidence/api-checks/{check_id}/run",
    response_model=ExternalEvidenceApiCheckResponse,
    dependencies=[Depends(_verify_management_api_key)],
)
async def run_external_evidence_api_check(
    application_id: str,
    check_id: str,
    request: ExternalEvidenceApiCheckRequest,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> ExternalEvidenceApiCheckResponse:
    """Run a user-defined external evidence API check and create a MIP fact."""
    app = await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )
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
    auto_issue_enabled = bool(requirement.get("auto_issue_on_permit"))
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
        binding=None,
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


@internal_application_router.post("/evidence/reconcile", response_model=dict[str, Any], dependencies=[Depends(_verify_management_api_key)])
async def reconcile_application_evidence(
    request: EvidenceReconciliationRequest,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> dict[str, Any]:
    """Recover Canvas evidence policy and approval-to-issuance transitions."""
    organization_id = _application_management_organization_id(
        trusted_organization_id,
        request.organization_id,
    )
    if request.application_id:
        await _managed_application(
            repo=repo,
            application_id=request.application_id,
            trusted_organization_id=trusted_organization_id,
        )

    result = await reconcile_canvas_evidence_transitions(
        repo=repo,
        organization_id=organization_id,
        application_id=request.application_id,
        limit=max(1, min(request.limit, 1000)),
        dry_run=request.dry_run,
        issue_on_permit=request.issue_on_permit,
        issuer_context_applier=apply_remote_issuer_context,
    )
    return result.to_dict()


@internal_application_router.get("/evidence/reconciliation-report", response_model=dict[str, Any], dependencies=[Depends(_verify_management_api_key)])
async def get_application_evidence_reconciliation_report(
    organization_id: str = Query(...),
    limit: int = Query(100),
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> dict[str, Any]:
    """Return a dry-run Canvas evidence reconciliation report."""
    organization_id = _application_management_organization_id(
        trusted_organization_id,
        organization_id,
    )
    result = await build_canvas_evidence_reconciliation_report(
        repo=repo,
        organization_id=organization_id,
        limit=max(1, min(limit, 1000)),
    )
    return result.to_dict()


@internal_application_router.post("/{application_id}/submit-evidence", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def submit_evidence(
    application_id: str,
    evidence: EvidenceSubmission,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Submit evidence for an application."""
    app = await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )
    
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


@internal_application_router.post("/{application_id}/approve", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def approve_application(
    application_id: str,
    approval: ApplicationApproval,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Approve an application and trigger credential issuance."""
    app = await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )
    
    if app.status != ApplicationStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Cannot approve application in {app.status} status")
    
    template = await repo.get_application_template(app.application_template_id)
    if not template or not template.credential_template_id:
        raise HTTPException(status_code=400, detail="Application template missing credential template ID")
    
    try:
        canvas_credential_context = await canvas_approval_credential_context(
            repo=repo,
            app=app,
            template=template,
        )
    except CanvasIssuanceGuardError as exc:
        logger.warning(
            "[approve] Canvas readiness denied app=%s code=%s",
            application_id,
            exc.code,
        )
        raise HTTPException(
            status_code=409,
            detail="Canvas application is not ready for approval",
        ) from None

    if canvas_credential_context is not None:
        credential_context = canvas_credential_context
        issuer_context_applier = apply_required_remote_issuer_context
        credential_type = credential_context.credential_type
    else:
        # Preserve the historical non-Canvas approval contract.
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
        credential_context = CredentialContext(
            credential_type=credential_type,
            credential_vct=credential_vct,
        )
        issuer_context_applier = apply_remote_issuer_context

    logger.info(
        "[approve] app=%s template=%s cred_type=%s form_data_keys=%s",
        application_id,
        template.credential_template_id,
        credential_type,
        list(app.form_data.keys()) if app.form_data else [],
    )

    try:
        tx = await approve_application_for_issuance(
            repo=repo,
            app=app,
            template=template,
            reviewer_id=_INTERNAL_REVIEWER_ID,
            review_notes=approval.review_notes,
            credential_context=credential_context,
            issuer_context_applier=issuer_context_applier,
        )
    except (RuntimeError, ValueError) as exc:
        if canvas_credential_context is None:
            raise
        logger.warning(
            "[approve] Canvas issuer context denied app=%s error_type=%s",
            application_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=409,
            detail="Canvas application is not ready for approval",
        ) from None
    
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


@internal_application_router.post("/{application_id}/reject", response_model=ApplicationResponse, dependencies=[Depends(_verify_management_api_key)])
async def reject_application(
    application_id: str,
    rejection: ApplicationRejection,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> ApplicationResponse:
    """Reject an application."""
    app = await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )
    
    if app.status != ApplicationStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Cannot reject application in {app.status} status")
    
    app.status = ApplicationStatus.REJECTED
    app.review_notes = rejection.review_notes
    app.reviewer_id = _INTERNAL_REVIEWER_ID
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
    from issuance.application.rust_integration import oid4vci_create_credential_offer
    from issuance.infrastructure.api.routes import org_issuer_url, org_issuer_url_spruce
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
    try:
        canvas_credential_context = await canvas_approval_credential_context(
            repo=repo,
            app=app,
            template=template,
        )
    except CanvasIssuanceGuardError as exc:
        logger.warning(
            "[issuance-offer] Canvas readiness denied app=%s code=%s",
            app.id,
            exc.code,
        )
        raise HTTPException(
            status_code=409,
            detail="Canvas application is not ready for issuance",
        ) from None
    if canvas_credential_context is not None:
        try:
            return await approve_application_for_issuance(
                repo=repo,
                app=app,
                template=template,
                reviewer_id=app.reviewer_id or _INTERNAL_REVIEWER_ID,
                review_notes=app.review_notes or "Canvas issuance offer refreshed",
                credential_context=canvas_credential_context,
                issuer_context_applier=apply_required_remote_issuer_context,
            )
        except (RuntimeError, ValueError) as exc:
            logger.warning(
                "[issuance-offer] Canvas issuer context denied app=%s error_type=%s",
                app.id,
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=409,
                detail="Canvas application is not ready for issuance",
            ) from None

    credential_template_id = template.credential_template_id if template else None
    revocation_profile_id: str | None = None
    if credential_template_id:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{CREDENTIAL_TEMPLATE_SERVICE_URL}/v1/credential-templates/{credential_template_id}"
                )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail="Credential Template validation is unavailable.",
            ) from exc
        if response.status_code == 404:
            raise HTTPException(status_code=422, detail="Credential Template not found.")
        if response.status_code >= 400:
            raise HTTPException(
                status_code=503,
                detail="Credential Template validation is unavailable.",
            )
        credential_template = response.json()
        revocation_profile_id = str(
            credential_template.get("revocation_profile_id") or ""
        ).strip() or None
        await _require_active_revocation_profile_binding(
            organization_id=app.organization_id,
            revocation_profile_id=revocation_profile_id,
        )

    tx: IssuanceTransaction | None = None
    if app.issuance_transaction_id:
        tx = await repo.get_transaction(app.issuance_transaction_id)

    if tx and tx.status == IssuanceStatus.PENDING and not tx.is_expired:
        delivery_before = tx.delivery_mode
        tx.delivery_mode = delivery_mode_from_integration_context(app.integration_context)
        tx.revocation_profile_id = revocation_profile_id
        before = (tx.issuer_did_override, tx.signing_service_id)
        await apply_remote_issuer_context(tx)
        if before != (tx.issuer_did_override, tx.signing_service_id) or delivery_before != tx.delivery_mode:
            await repo.save_transaction(tx)
        return tx

    # Create a fresh transaction
    tx = IssuanceTransaction(
        organization_id=app.organization_id,
        credential_template_id=credential_template_id,
        applicant_id=app.applicant_identifier,
        application_id=app.id,
        subject_did=None,
        delivery_mode=delivery_mode_from_integration_context(app.integration_context),
        claims=app.form_data,
        revocation_profile_id=revocation_profile_id,
    )
    await apply_remote_issuer_context(tx)
    await repo.save_transaction(tx)
    app.issuance_transaction_id = tx.id
    await repo.save_application(app)
    logger.info(f"Created fresh issuance transaction {tx.id} for application {app.id}")
    return tx


@internal_application_router.post(
    "/{application_id}/issuance-offer",
    response_model=IssuanceOfferResponse,
    summary="Generate Wallet Invite (Admin)",
    dependencies=[Depends(_verify_management_api_key)],
)
async def generate_issuance_offer(
    application_id: str,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
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
    app = await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )

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


@internal_application_router.get(
    "/{application_id}/issuance-offer",
    response_model=IssuanceOfferResponse,
    summary="Get Wallet Invite (Applicant)",
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_issuance_offer(
    application_id: str,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> IssuanceOfferResponse:
    """Retrieve the current issuance offer for an application (applicant-facing).

    Returns 404 if no offer has been generated yet.
    Returns the offer with status='expired' if the offer PIN has expired.
    """
    app = await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )

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


@internal_application_router.get(
    "/{application_id}/issuance-events",
    response_model=list[IssuanceEventResponse],
    summary="List Issuance Events (Admin)",
    dependencies=[Depends(_verify_management_api_key)],
)
async def list_issuance_events(
    application_id: str,
    trusted_organization_id: str = Depends(_trusted_application_organization_id),
    repo: IIssuanceRepository = Depends(),
) -> list[IssuanceEventResponse]:
    """List all lifecycle events for an application (admin audit timeline).

    Returns events in chronological order: offer_generated, offer_viewed,
    offer_expired, credential_issued, etc.
    """
    await _managed_application(
        repo=repo,
        application_id=application_id,
        trusted_organization_id=trusted_organization_id,
    )

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
