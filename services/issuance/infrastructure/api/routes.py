"""OID4VCI HTTP API endpoints."""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Form, Header, HTTPException, Query
from pydantic import BaseModel

from issuance.application.rust_integration import (
    get_marty_rs,
    get_or_generate_issuer_key,
    create_verifiable_credential_wrapper,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    CredentialStatus,
    IssuanceStatus,
    IssuanceTransaction,
)
from issuance.domain.ports import IIssuanceRepository

logger = logging.getLogger(__name__)

# Configuration
REVOCATION_PROFILE_SERVICE_URL = os.environ.get(
    "REVOCATION_PROFILE_SERVICE_URL", "http://localhost:8013"
)
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "http://gateway:8000")

# Routers
issuance_router = APIRouter(prefix="/v1/issuance", tags=["issuance"])
application_template_router = APIRouter(prefix="/v1/application-templates", tags=["application-templates"])
application_router = APIRouter(prefix="/v1/applications", tags=["applications"])


# ============================================================================
# Request/Response Models
# ============================================================================

class InitiateIssuanceRequest(BaseModel):
    organization_id: str
    credential_template_id: str
    applicant_id: str | None = None
    subject_did: str | None = None
    claims: dict[str, Any] = {}


class IssuanceResponse(BaseModel):
    id: str
    organization_id: str
    credential_template_id: str
    status: str
    credential_offer_uri: str
    pre_auth_code: str
    expires_at: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    c_nonce: str


class CredentialRequest(BaseModel):
    format: str = "jwt_vc_json"
    proof: dict[str, Any] | None = None


class CredentialResponse(BaseModel):
    credential: str
    format: str


class ApplicationTemplateCreate(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    credential_template_id: str | None = None
    form_fields: list[dict[str, Any]] = []
    evidence_requirements: list[str] = []
    claim_collection_rules: list[dict[str, Any]] = []
    approval_strategy: str = "auto"
    application_validity_days: int = 30
    auto_approval_rules: list[dict[str, Any]] = []
    ui_config: dict[str, Any] = {}
    notification_config: dict[str, Any] = {}


class ApplicationTemplateResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    credential_template_id: str | None
    form_fields: list[dict[str, Any]]
    evidence_requirements: list[str]
    claim_collection_rules: list[dict[str, Any]]
    approval_strategy: str
    application_validity_days: int
    auto_approval_rules: list[dict[str, Any]]
    ui_config: dict[str, Any]
    notification_config: dict[str, Any]
    status: str
    created_at: str
    updated_at: str


class ApplicationCreate(BaseModel):
    application_template_id: str
    applicant_data: dict[str, Any]


class ApplicationResponse(BaseModel):
    id: str
    organization_id: str
    application_template_id: str
    applicant_identifier: str
    form_data: dict[str, Any]
    evidence_submissions: list[dict[str, Any]]
    status: str
    review_notes: str | None
    reviewer_id: str | None
    submitted_at: str
    reviewed_at: str | None
    expires_at: str
    issuance_transaction_id: str | None


class EvidenceSubmission(BaseModel):
    evidence_type: str
    evidence_data: dict[str, Any]


class ApplicationApproval(BaseModel):
    review_notes: str | None = None
    reviewer_id: str | None = None


class ApplicationRejection(BaseModel):
    review_notes: str
    reviewer_id: str | None = None


class CredentialStatusRequest(BaseModel):
    reason: str | None = None


class CredentialStatusResponse(BaseModel):
    id: str
    status: str
    status_updated_at: str
    reason: str | None = None


# ============================================================================
# OID4VCI Endpoints
# ============================================================================

@issuance_router.get("/.well-known/openid-credential-issuer")
async def get_issuer_metadata() -> dict:
    """Return OID4VCI issuer metadata."""
    return {
        "credential_issuer": ISSUER_BASE_URL,
        "credential_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/credential",
        "token_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/token",
        "credential_configurations_supported": {
            "default": {
                "format": "jwt_vc_json",
                "cryptographic_binding_methods_supported": ["did"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
                "display": [
                    {
                        "name": "Verifiable Credential",
                        "locale": "en-US"
                    }
                ]
            }
        }
    }

@issuance_router.post("/initiate", response_model=IssuanceResponse)
async def initiate_issuance(
    request: InitiateIssuanceRequest,
    repo: IIssuanceRepository = Depends(),
) -> IssuanceResponse:
    """Initiate a credential issuance transaction."""
    
    # Validate organization exists
    try:
        org_url = f"http://organization-service:8002/v1/organizations/{request.organization_id}"
        async with httpx.AsyncClient(timeout=5.0) as client:
            org_response = await client.get(org_url)
            if org_response.status_code == 404:
                raise HTTPException(status_code=404, detail=f"Organization not found: {request.organization_id}")
            org_response.raise_for_status()
    except HTTPException:
        raise  # Re-raise FastAPI HTTPException
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail=f"Organization not found: {request.organization_id}")
        logger.error(f"Error validating organization: {e}")
        raise HTTPException(status_code=500, detail="Organization validation failed")
    except Exception as e:
        logger.error(f"Error connecting to organization service: {e}")
        raise HTTPException(status_code=500, detail="Organization service unavailable")
    
    # Fetch and validate credential template
    credential_type = "org.iso.18013.5.1.mDL"  # Default fallback
    if request.credential_template_id:
        try:
            template_url = f"http://credential-template-service:8003/v1/credential-templates/{request.credential_template_id}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(template_url)
                if response.status_code == 404:
                    raise HTTPException(status_code=404, detail=f"Credential template not found: {request.credential_template_id}")
                response.raise_for_status()
                template = response.json()
                credential_type = template.get("credential_type", credential_type)
                logger.info(f"Fetched credential type from template: {credential_type}")
        except HTTPException:
            raise  # Re-raise FastAPI HTTPException
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise HTTPException(status_code=404, detail=f"Credential template not found: {request.credential_template_id}")
            logger.error(f"Error fetching template: {e}")
            raise HTTPException(status_code=500, detail="Template validation failed")
        except Exception as e:
            logger.error(f"Error connecting to template service: {e}")
            raise HTTPException(status_code=500, detail="Template service unavailable")
    
    tx = IssuanceTransaction(
        organization_id=request.organization_id,
        credential_template_id=request.credential_template_id,
        applicant_id=request.applicant_id,
        subject_did=request.subject_did,
        claims=request.claims,
        credential_type=credential_type,
    )
    await repo.save_transaction(tx)
    
    # OID4VCI: Pass credential offer inline for better wallet compatibility
    # Some wallets (like Walt.ID) have issues fetching by reference
    import json
    from urllib.parse import quote
    
    offer_data = {
        "credential_issuer": ISSUER_BASE_URL,
        "credential_configuration_ids": ["default"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": tx.pre_auth_code,
                "tx_code": None,
            }
        },
    }
    
    # Encode offer as inline JSON in openid-credential-offer URI
    offer_json = quote(json.dumps(offer_data))
    offer_uri = f"openid-credential-offer://?credential_offer={offer_json}"
    
    return IssuanceResponse(
        id=tx.id,
        organization_id=tx.organization_id,
        credential_template_id=tx.credential_template_id,
        status=tx.status.value,
        credential_offer_uri=offer_uri,
        pre_auth_code=tx.pre_auth_code,
        expires_at=tx.expires_at.isoformat(),
    )


@issuance_router.post("/token", response_model=TokenResponse)
async def exchange_token(
    grant_type: str = Form(...),
    pre_authorized_code: str = Form(None, alias="pre-authorized_code"),
    repo: IIssuanceRepository = Depends(),
) -> TokenResponse:
    """Exchange pre-authorized code for access token (OID4VCI)."""
    if not pre_authorized_code:
        raise HTTPException(status_code=400, detail="pre-authorized_code required")
    
    if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        raise HTTPException(status_code=400, detail="Unsupported grant type")
    
    tx = await repo.get_by_pre_auth_code(pre_authorized_code)
    if not tx:
        raise HTTPException(status_code=400, detail="Invalid pre-authorized code")
    
    if tx.is_expired:
        raise HTTPException(status_code=400, detail="Transaction expired")
    
    if tx.status != IssuanceStatus.PENDING:
        raise HTTPException(status_code=400, detail="Invalid transaction state")
    
    access_token = tx.authorize()
    await repo.save_transaction(tx)
    
    return TokenResponse(
        access_token=access_token,
        expires_in=1800,
        c_nonce=tx.c_nonce,
    )


@issuance_router.post("/credential", response_model=CredentialResponse)
async def issue_credential(
    request: CredentialRequest,
    authorization: str = Header(None),
    repo: IIssuanceRepository = Depends(),
) -> CredentialResponse:
    """Issue a credential (OID4VCI credential endpoint)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization")
    
    access_token = authorization.split(" ", 1)[1]
    
    tx = await repo.get_by_access_token(access_token)
    if not tx:
        raise HTTPException(status_code=401, detail="Invalid access token")
    
    if tx.status != IssuanceStatus.AUTHORIZED:
        raise HTTPException(status_code=400, detail="Invalid transaction state")
    
    # Get issuer key for organization
    try:
        issuer_key = get_or_generate_issuer_key(tx.organization_id)
    except ImportError as e:
        logger.error(f"Rust bindings not available: {e}")
        tx.fail("Rust bindings not available")
        await repo.save_transaction(tx)
        raise HTTPException(status_code=500, detail="Credential signing service unavailable")
    
    # Get credential type from transaction (stored during initiation)
    credential_type = tx.credential_type or "org.iso.18013.5.1.mDL"
    logger.info(f"Using credential type: {credential_type}")
    
    # Get Rust bindings and create signed credential
    try:
        jwt_credential, credential_id = create_verifiable_credential_wrapper(
            issuer_did=issuer_key["did"],
            issuer_jwk_json="",  # Not used - kept for API compatibility
            subject_id=tx.subject_did,
            credential_type=credential_type,
            claims_json=json.dumps(tx.claims),
            expiration_seconds=31536000,  # 1 year
        )
        
        tx.complete()
        await repo.save_transaction(tx)
        
        logger.info(f"Credential issued via Rust: {credential_id}")
        return CredentialResponse(credential=jwt_credential, format="jwt_vc_json")
        
    except Exception as e:
        logger.error(f"Rust credential creation failed: {e}")
        tx.fail(str(e))
        await repo.save_transaction(tx)
        raise HTTPException(status_code=500, detail=f"Credential creation failed: {e}")


@issuance_router.get("/offers/{tx_id}")
async def get_credential_offer(
    tx_id: str,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Get OID4VCI credential offer for a transaction."""
    tx = await repo.get_transaction(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Offer not found")
    
    if tx.is_expired:
        raise HTTPException(status_code=410, detail="Offer expired")
    
    return {
        "credential_issuer": ISSUER_BASE_URL,
        "credential_configuration_ids": ["default"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": tx.pre_auth_code,
                "tx_code": None,
            }
        },
    }


@issuance_router.get("/transactions", response_model=list[dict])
async def list_transactions(
    organization_id: str = Query(...),
    repo: IIssuanceRepository = Depends(),
) -> list[dict]:
    """List issuance transactions for an organization."""
    transactions = await repo.list_transactions(organization_id)
    return [
        {
            "id": tx.id,
            "organization_id": tx.organization_id,
            "credential_template_id": tx.credential_template_id,
            "applicant_id": tx.applicant_id,
            "application_id": tx.application_id,
            "subject_did": tx.subject_did,
            "status": tx.status.value,
            "created_at": tx.created_at.isoformat(),
        }
        for tx in transactions
    ]


@issuance_router.get("/transactions/{tx_id}")
async def get_transaction(
    tx_id: str,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Get a specific issuance transaction."""
    tx = await repo.get_transaction(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return {
        "id": tx.id,
        "organization_id": tx.organization_id,
        "credential_template_id": tx.credential_template_id,
        "applicant_id": tx.applicant_id,
        "subject_did": tx.subject_did,
        "status": tx.status.value,
        "created_at": tx.created_at.isoformat(),
        "expires_at": tx.expires_at.isoformat(),
        "issued_at": tx.issued_at.isoformat() if tx.issued_at else None,
    }


# ============================================================================
# Credential Lifecycle Management
# ============================================================================

async def _delegate_to_revocation_profile(
    credential_id: str,
    action: str,
    reason: str | None = None,
) -> dict:
    """Delegate revocation action to RevocationProfile service."""
    # Call RevocationProfile internal endpoint
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{REVOCATION_PROFILE_SERVICE_URL}/internal/revocation-profiles/default/process-revocation",
                json={
                    "credential_id": credential_id,
                    "action": action,
                    "credential_format": "sd_jwt",
                    "status_list_index": 0,
                    "reason": reason,
                },
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"RevocationProfile service error: {e}")
            raise HTTPException(
                status_code=503,
                detail=f"Revocation service unavailable: {str(e)}"
            )


@issuance_router.post("/credentials/{credential_id}/revoke", response_model=CredentialStatusResponse)
async def revoke_credential(
    credential_id: str,
    request: CredentialStatusRequest,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Revoke a credential."""
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    if cred.status == CredentialStatus.REVOKED:
        raise HTTPException(status_code=400, detail="Credential already revoked")
    
    try:
        await _delegate_to_revocation_profile(
            credential_id=credential_id,
            action="revoke",
            reason=request.reason,
        )
    except HTTPException:
        logger.warning("RevocationProfile service unavailable, using local revocation")
    
    cred.status = CredentialStatus.REVOKED
    cred.status_updated_at = datetime.now(timezone.utc)
    cred.revoked = True
    cred.revoked_at = cred.status_updated_at
    cred.revocation_reason = request.reason
    await repo.save_credential(cred)
    
    logger.info(f"Revoked credential {credential_id}: {request.reason}")
    
    return {
        "id": cred.id,
        "status": cred.status.value,
        "status_updated_at": cred.status_updated_at.isoformat(),
        "reason": request.reason,
    }


@issuance_router.post("/credentials/{credential_id}/suspend", response_model=CredentialStatusResponse)
async def suspend_credential(
    credential_id: str,
    request: CredentialStatusRequest,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Suspend a credential temporarily."""
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    if cred.status == CredentialStatus.REVOKED:
        raise HTTPException(status_code=400, detail="Cannot suspend revoked credential")
    
    try:
        await _delegate_to_revocation_profile(
            credential_id=credential_id,
            action="suspend",
            reason=request.reason,
        )
    except HTTPException:
        logger.warning("RevocationProfile service unavailable, using local suspension")
    
    cred.status = CredentialStatus.SUSPENDED
    cred.status_updated_at = datetime.now(timezone.utc)
    await repo.save_credential(cred)
    
    logger.info(f"Suspended credential {credential_id}: {request.reason}")
    
    return {
        "id": cred.id,
        "status": cred.status.value,
        "status_updated_at": cred.status_updated_at.isoformat(),
        "reason": request.reason,
    }


@issuance_router.post("/credentials/{credential_id}/reinstate", response_model=CredentialStatusResponse)
async def reinstate_credential(
    credential_id: str,
    request: CredentialStatusRequest,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Reinstate a suspended credential."""
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    if cred.status == CredentialStatus.REVOKED:
        raise HTTPException(status_code=400, detail="Cannot reinstate revoked credential")
    
    if cred.status != CredentialStatus.SUSPENDED:
        raise HTTPException(status_code=400, detail="Only suspended credentials can be reinstated")
    
    try:
        await _delegate_to_revocation_profile(
            credential_id=credential_id,
            action="reinstate",
            reason=request.reason,
        )
    except HTTPException:
        logger.warning("RevocationProfile service unavailable, using local reinstatement")
    
    cred.status = CredentialStatus.ACTIVE
    cred.status_updated_at = datetime.now(timezone.utc)
    await repo.save_credential(cred)
    
    logger.info(f"Reinstated credential {credential_id}: {request.reason}")
    
    return {
        "id": cred.id,
        "status": cred.status.value,
        "status_updated_at": cred.status_updated_at.isoformat(),
        "reason": request.reason,
    }


@issuance_router.get("/credentials/{credential_id}/status", response_model=CredentialStatusResponse)
async def get_credential_status(
    credential_id: str,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Get current status of a credential."""
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    return {
        "id": cred.id,
        "status": cred.status.value,
        "status_updated_at": cred.status_updated_at.isoformat(),
        "reason": cred.revocation_reason,
    }


@issuance_router.get("/credentials", response_model=list[dict])
async def list_credentials(
    organization_id: str = Query(...),
    status: str = Query(None),
    repo: IIssuanceRepository = Depends(),
) -> list[dict]:
    """List all credentials for an organization with optional status filter."""
    creds = await repo.list_credentials_by_org(organization_id)
    
    if status:
        creds = [c for c in creds if c.status.value == status]
    
    return [
        {
            "id": c.id,
            "credential_template_id": c.credential_template_id,
            "applicant_id": c.applicant_id,
            "subject_did": c.subject_did,
            "status": c.status.value,
            "issued_at": c.issued_at.isoformat(),
            "status_updated_at": c.status_updated_at.isoformat(),
        }
        for c in creds
    ]


# Continued in next part...
