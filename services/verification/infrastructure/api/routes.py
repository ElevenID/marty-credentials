"""API routes for verification service."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from mmf.infrastructure.database.session import get_db_session

from ..application.rust_verifier import RustCredentialVerifier
from ..application.service import VerificationService
from ..infrastructure.persistence.postgres_repository import PostgresVerificationRepository
from .models import (
    ClaimResult,
    CreateSessionRequest,
    PresentationDefinition,
    SessionResponse,
    SubmitPresentationRequest,
    VerificationResult,
    VerifyDirectRequest,
)

logger = logging.getLogger(__name__)

verification_router = APIRouter(prefix="/v1/verification", tags=["Verification"])

# Re-export models so existing "from …routes import X" still works
__all__ = [
    "ClaimResult",
    "CreateSessionRequest",
    "PresentationDefinition",
    "SessionResponse",
    "SubmitPresentationRequest",
    "VerificationResult",
    "VerifyDirectRequest",
    "verification_router",
]


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
        
        is_valid = session.status.value == "verified"
        return VerificationResult(
            valid=is_valid,
            overall_result="PASS" if is_valid else "FAIL",
            trust_chain_valid=is_valid,
            revocation_checked=is_valid,
            revocation_status="VALID" if is_valid else "SKIPPED",
            evaluated_at=session.verified_at.isoformat() if session.verified_at else None,
            verifier_nonce=session.nonce if hasattr(session, 'nonce') else None,
            verified_claims=session.verified_claims,
            verification_method=session.verification_method.value if session.verification_method else None,
            error=session.error_message,
            verified_at=session.verified_at.isoformat() if session.verified_at else None,
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
        
        is_valid = result["valid"]
        return VerificationResult(
            valid=is_valid,
            overall_result="PASS" if is_valid else "FAIL",
            trust_chain_valid=is_valid,
            revocation_checked=is_valid,
            revocation_status="VALID" if is_valid else "SKIPPED",
            verified_claims=result.get("verified_claims"),
            verification_method=result.get("verification_method"),
            error=result.get("error"),
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
