"""API routes for verification service."""

import json
import logging
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...application.canonical_result import (
    adapter_processing_status,
    build_canonical_result,
    canonical_result_from_evidence,
)
from ...application.did_resolver import resolve_issuer_did
from ...application.governance import (
    DIRECT_VERIFY_PURPOSE,
    SESSION_CREATE_PURPOSE,
    VDS_NC_VERIFY_PURPOSE,
    GovernanceAuthorizationError,
    GovernanceConfigurationError,
    GovernancePolicyMismatchError,
    VerificationGovernanceContext,
    load_governance,
)
from ...application.rust_verifier import RustCredentialVerifier
from ...application.service import (
    UnsupportedSessionPresentationError,
    VerificationService,
    VerificationSessionBusyError,
    VerificationSessionConflictError,
    VerificationSessionExpiredError,
    VerificationSessionNotFoundError,
)
from ..persistence.database import get_db_session
from ..persistence.postgres_repository import PostgresVerificationRepository
from .models import (
    ClaimResult,
    CreateSessionRequest,
    PresentationDefinition,
    SessionResponse,
    SubmitPresentationRequest,
    VerificationResult,
    VerifyDirectRequest,
    VerifyVdsNcRequest,
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
    "VerifyVdsNcRequest",
    "verification_router",
]


# ============================================================================
# Purpose-scoped caller authentication
# ============================================================================


async def _authorize(
    purpose: str,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> VerificationGovernanceContext:
    """Bind one caller credential to its organization and governed profiles."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header is missing")
    try:
        return load_governance().authorize(x_api_key, purpose)
    except GovernanceConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Verification governance is unavailable",
        ) from exc
    except GovernanceAuthorizationError as exc:
        raise HTTPException(status_code=401, detail="Invalid or unauthorized API key") from exc


async def _authorize_session_create(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> VerificationGovernanceContext:
    return await _authorize(SESSION_CREATE_PURPOSE, x_api_key)


async def _authorize_direct_verify(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> VerificationGovernanceContext:
    return await _authorize(DIRECT_VERIFY_PURPOSE, x_api_key)


async def _authorize_vds_nc_verify(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> VerificationGovernanceContext:
    return await _authorize(VDS_NC_VERIFY_PURPOSE, x_api_key)


def _verification_result(
    evidence: dict[str, object],
    *,
    verification_method: str | None,
    error: str | None = None,
) -> VerificationResult:
    canonical = canonical_result_from_evidence(evidence)
    if canonical is None:
        return VerificationResult(
            canonical_result=None,
            processing_status="UNAVAILABLE",
            decision="INDETERMINATE",
            decision_code="PROCESSING_NOT_COMPLETED",
            valid=False,
            overall_result="INDETERMINATE",
            verification_method=verification_method,
            error=error or "Legacy verification evidence has no canonical provenance",
        )

    checks = {
        check.get("check_id"): check
        for check in canonical.get("checks", [])
        if isinstance(check, dict)
    }
    trust_check = checks.get("issuer.trust", {})
    status_check = checks.get("credential.status", {})
    status_code = status_check.get("code")
    if status_code == "CREDENTIAL_STATUS_VALID":
        revocation_status = "VALID"
    elif status_code == "CREDENTIAL_STATUS_REVOKED":
        revocation_status = "REVOKED"
    else:
        revocation_status = "UNKNOWN"
    decision = str(canonical.get("decision", "INDETERMINATE"))
    valid = canonical.get("valid") is True and decision == "PASS"
    return VerificationResult(
        canonical_result=canonical,
        processing_status=str(canonical.get("processing_status", "UNAVAILABLE")),
        decision=decision,
        decision_code=str(canonical.get("decision_code", "PROCESSING_NOT_COMPLETED")),
        valid=valid,
        overall_result=decision,
        trust_chain_valid=trust_check.get("outcome") == "PASSED",
        revocation_checked=status_check.get("outcome") in {"PASSED", "FAILED", "ERROR"},
        revocation_status=revocation_status,
        evaluated_at=canonical.get("evaluated_at"),
        policy_id=(canonical.get("policy") or {}).get("id"),
        verified_claims=None,
        verification_method=verification_method,
        error=None if valid else error or "Canonical verification did not pass",
        verified_at=canonical.get("evaluated_at") if valid else None,
    )


# ============================================================================
# Dependency Injection
# ============================================================================


def get_verification_repository(
    session: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> PostgresVerificationRepository:
    """Get verification repository instance."""
    return PostgresVerificationRepository(session)


def get_credential_verifier() -> RustCredentialVerifier:
    """Get credential verifier instance."""
    return RustCredentialVerifier()


def get_verification_service(
    repo: PostgresVerificationRepository = Depends(get_verification_repository),
    verifier: RustCredentialVerifier = Depends(get_credential_verifier),
) -> VerificationService:
    """Get verification service instance."""
    return VerificationService(repo, verifier)


# ============================================================================
# Endpoints
# ============================================================================


@verification_router.post("/sessions", response_model=SessionResponse)
async def create_verification_session(
    request: CreateSessionRequest,
    service: VerificationService = Depends(get_verification_service),
    governance: VerificationGovernanceContext = Depends(_authorize_session_create),  # noqa: B008
) -> SessionResponse:
    """Create a new verification session for OID4VP flow."""
    try:
        session = await service.create_verification_session(
            verifier_did=request.verifier_did,
            presentation_definition=request.presentation_definition.model_dump(exclude_none=True),
            governance=governance,
            session_duration_seconds=request.session_duration_seconds,
        )

        return SessionResponse(
            id=session.id,
            organization_id=session.organization_id,
            verifier_did=session.verifier_did,
            status=session.status.value,
            request_uri=session.request_uri or "",
            nonce=session.nonce or "",
            expires_at=session.expires_at.isoformat() if session.expires_at else "",
            created_at=session.created_at.isoformat(),
        )

    except GovernancePolicyMismatchError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Verification request does not match its governed policy",
        ) from exc
    except Exception as e:
        logger.error(f"Failed to create verification session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create verification session",
        )


@verification_router.post("/sessions/{session_id}/submit", response_model=VerificationResult)
async def submit_presentation(
    session_id: str,
    request: SubmitPresentationRequest,
    service: VerificationService = Depends(get_verification_service),
) -> VerificationResult:
    """Submit a presentation to an existing verification session."""
    try:
        session = await service.submit_presentation(
            session_id=session_id, presentation=request.presentation
        )

        return _verification_result(
            session.verification_evidence,
            verification_method=(
                session.verification_method.value if session.verification_method else None
            ),
            error=session.error_message,
        )

    except VerificationSessionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Verification session not found",
        ) from exc
    except VerificationSessionExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Verification session has expired",
        ) from exc
    except (VerificationSessionBusyError, VerificationSessionConflictError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Verification session submission conflicts",
        ) from exc
    except UnsupportedSessionPresentationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Session presentation cannot be bound to the verifier nonce",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid presentation data",
        ) from exc
    except Exception as e:
        logger.error(f"Failed to submit presentation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Presentation submission failed",
        )


@verification_router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str, service: VerificationService = Depends(get_verification_service)
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
        created_at=session.created_at.isoformat(),
    )


@verification_router.post("/verify", response_model=VerificationResult)
async def verify_presentation_direct(
    request: VerifyDirectRequest,
    service: VerificationService = Depends(get_verification_service),
    governance: VerificationGovernanceContext = Depends(_authorize_direct_verify),  # noqa: B008
) -> VerificationResult:
    """Verify a presentation directly without creating a session (stateless)."""
    try:
        result = await service.verify_presentation_direct(
            presentation=request.presentation,
            presentation_definition=request.presentation_definition.model_dump(exclude_none=True),
            verifier_did=request.verifier_did,
            governance=governance,
        )
        return _verification_result(
            result["evidence"],
            verification_method=result.get("verification_method"),
        )

    except GovernancePolicyMismatchError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Verification request does not match its governed policy",
        ) from exc
    except Exception as e:
        logger.error(f"Direct verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Verification failed"
        )


@verification_router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@verification_router.post(
    "/verify/vds-nc",
    response_model=VerificationResult,
)
async def verify_vds_nc_barcode(
    request: VerifyVdsNcRequest,
    verifier: RustCredentialVerifier = Depends(get_credential_verifier),
    governance: VerificationGovernanceContext = Depends(_authorize_vds_nc_verify),  # noqa: B008
) -> VerificationResult:
    """Verify a VDS-NC barcode under caller-bound governance.

    Validates the tilde-separated ``header~payload_json~signature_b64`` envelope
    using the Rust ``vds_nc_verify`` binding and projects only the canonical,
    privacy-minimized decision result.
    """
    try:
        governance.require_purpose(VDS_NC_VERIFY_PURPOSE)
        issuer_resolution = await resolve_issuer_did(
            request.issuer_did,
            organization_id=governance.organization_id,
            verification_method_id=request.verification_method_id,
            trusted_issuers=list(governance.trust_profile.trusted_issuers),
            credential_format="vds_nc",
            key_purpose="vdsnc_signing",
            algorithm=request.algorithm,
            allow_public_fallback=governance.trust_profile.allow_public_did_fallback,
        )
        public_jwk = (
            issuer_resolution.get("public_jwk") if isinstance(issuer_resolution, dict) else None
        )
        if not isinstance(public_jwk, dict):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="issuer_did did not resolve to a usable public JWK",
            )

        result = await verifier.verify_vds_nc(
            barcode=request.barcode,
            issuer_jwk_json=json.dumps(public_jwk),
        )
        evidence = build_canonical_result(
            governance=governance,
            verification_id=f"verification:{secrets.token_urlsafe(24)}",
            transaction_id=f"transaction:{secrets.token_urlsafe(24)}",
            presentation=request.barcode,
            adapter_result={
                "credential_proofs_valid": result.get("valid") is True,
                "trust_chain_valid": True,
            },
            processing_status=adapter_processing_status(result),
        )
        return _verification_result(
            evidence,
            verification_method="vds_nc",
            error=(
                None if result.get("valid") is True else "VDS-NC credential proof did not verify"
            ),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("VDS-NC barcode verification endpoint error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="VDS-NC verification failed",
        )
