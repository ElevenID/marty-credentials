"""API routes for verification service."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from mmf.infrastructure.database.session import get_db_session

from ..application.rust_verifier import RustCredentialVerifier
from ..application.service import VerificationService
from ..infrastructure.persistence.postgres_repository import PostgresVerificationRepository

logger = logging.getLogger(__name__)

verification_router = APIRouter(prefix="/v1/verification", tags=["Verification"])


# ============================================================================
# Request/Response Models
# ============================================================================

class PresentationDefinition(BaseModel):
    """OID4VP Presentation Definition."""
    id: str
    input_descriptors: list[dict[str, Any]]
    format: dict[str, Any] | None = None


class CreateSessionRequest(BaseModel):
    """Request to create a verification session."""
    organization_id: str
    verifier_did: str
    presentation_definition: PresentationDefinition
    required_credential_types: list[str] = []
    trusted_issuers: list[str] = []
    session_duration_seconds: int = 600


class SessionResponse(BaseModel):
    """Verification session response."""
    id: str
    organization_id: str
    verifier_did: str
    status: str
    request_uri: str
    nonce: str
    expires_at: str
    created_at: str


class SubmitPresentationRequest(BaseModel):
    """Request to submit a presentation."""
    presentation: dict[str, Any] | str  # Can be JWT or JSON


class VerificationResult(BaseModel):
    """Verification result response."""
    valid: bool
    verified_claims: dict[str, Any] | None = None
    verification_method: str | None = None
    error: str | None = None
    verified_at: str | None = None


class VerifyDirectRequest(BaseModel):
    """Request for direct (stateless) verification."""
    organization_id: str
    presentation: dict[str, Any] | str
    presentation_definition: PresentationDefinition
    verifier_did: str
    trusted_issuers: list[str] = []


# ============================================================================
# Dependency Injection
# ============================================================================

def get_verification_repository() -> PostgresVerificationRepository:
    """Get verification repository instance."""
    session = get_db_session()
    return PostgresVerificationRepository(session)


def get_credential_verifier() -> RustCredentialVerifier:
    """Get credential verifier instance."""
    return RustCredentialVerifier()


def get_verification_service(
    repo: PostgresVerificationRepository = Depends(get_verification_repository),
    verifier: RustCredentialVerifier = Depends(get_credential_verifier)
) -> VerificationService:
    """Get verification service instance."""
    return VerificationService(repo, verifier)


# ============================================================================
# Endpoints
# ============================================================================

@verification_router.post("/sessions", response_model=SessionResponse)
async def create_verification_session(
    request: CreateSessionRequest,
    service: VerificationService = Depends(get_verification_service)
) -> SessionResponse:
    """Create a new verification session for OID4VP flow."""
    try:
        session = await service.create_verification_session(
            organization_id=request.organization_id,
            verifier_did=request.verifier_did,
            presentation_definition=request.presentation_definition.dict(),
            required_credential_types=request.required_credential_types,
            trusted_issuers=request.trusted_issuers,
            session_duration_seconds=request.session_duration_seconds
        )
        
        return SessionResponse(
            id=session.id,
            organization_id=session.organization_id,
            verifier_did=session.verifier_did,
            status=session.status.value,
            request_uri=session.request_uri or "",
            nonce=session.nonce or "",
            expires_at=session.expires_at.isoformat() if session.expires_at else "",
            created_at=session.created_at.isoformat()
        )
        
    except Exception as e:
        logger.error(f"Failed to create verification session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@verification_router.post("/sessions/{session_id}/submit", response_model=VerificationResult)
async def submit_presentation(
    session_id: str,
    request: SubmitPresentationRequest,
    service: VerificationService = Depends(get_verification_service)
) -> VerificationResult:
    """Submit a presentation to an existing verification session."""
    try:
        session = await service.submit_presentation(
            session_id=session_id,
            presentation=request.presentation
        )
        
        return VerificationResult(
            valid=session.status.value == "verified",
            verified_claims=session.verified_claims,
            verification_method=session.verification_method.value if session.verification_method else None,
            error=session.error_message,
            verified_at=session.verified_at.isoformat() if session.verified_at else None
        )
        
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to submit presentation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@verification_router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    service: VerificationService = Depends(get_verification_service)
) -> SessionResponse:
    """Get a verification session."""
    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    
    return SessionResponse(
        id=session.id,
        organization_id=session.organization_id,
        verifier_did=session.verifier_did,
        status=session.status.value,
        request_uri=session.request_uri or "",
        nonce=session.nonce or "",
        expires_at=session.expires_at.isoformat() if session.expires_at else "",
        created_at=session.created_at.isoformat()
    )


@verification_router.post("/verify", response_model=VerificationResult)
async def verify_presentation_direct(
    request: VerifyDirectRequest,
    service: VerificationService = Depends(get_verification_service)
) -> VerificationResult:
    """Verify a presentation directly without creating a session (stateless)."""
    try:
        result = await service.verify_presentation_direct(
            organization_id=request.organization_id,
            presentation=request.presentation,
            presentation_definition=request.presentation_definition.dict(),
            verifier_did=request.verifier_did,
            trusted_issuers=request.trusted_issuers
        )
        
        return VerificationResult(
            valid=result["valid"],
            verified_claims=result.get("verified_claims"),
            verification_method=result.get("verification_method"),
            error=result.get("error")
        )
        
    except Exception as e:
        logger.error(f"Direct verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@verification_router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}
