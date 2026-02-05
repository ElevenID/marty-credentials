"""Application service for verification."""

import secrets
from datetime import datetime, timedelta
from typing import Any

from mmf.core.exceptions import ValidationError

from ..domain.entities import VerificationMethod, VerificationSession, VerificationStatus
from ..domain.ports import ICredentialVerifier, IVerificationRepository


class VerificationService:
    """Application service coordinating verification operations."""
    
    def __init__(
        self,
        repository: IVerificationRepository,
        verifier: ICredentialVerifier
    ):
        self.repository = repository
        self.verifier = verifier
    
    async def create_verification_session(
        self,
        organization_id: str,
        verifier_did: str,
        presentation_definition: dict[str, Any],
        required_credential_types: list[str] | None = None,
        trusted_issuers: list[str] | None = None,
        session_duration_seconds: int = 600
    ) -> VerificationSession:
        """Create a new verification session (OID4VP flow)."""
        session_id = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        
        session = VerificationSession(
            id=session_id,
            organization_id=organization_id,
            verifier_did=verifier_did,
            presentation_definition=presentation_definition,
            required_credential_types=required_credential_types or [],
            trusted_issuers=trusted_issuers or [],
            nonce=nonce,
            expires_at=datetime.utcnow() + timedelta(seconds=session_duration_seconds),
            request_uri=f"oid4vp://request?session_id={session_id}"
        )
        
        await self.repository.save_session(session)
        return session
    
    async def verify_presentation_direct(
        self,
        organization_id: str,
        presentation: dict[str, Any] | str,
        presentation_definition: dict[str, Any],
        verifier_did: str,
        trusted_issuers: list[str] | None = None
    ) -> dict[str, Any]:
        """Verify a presentation directly without session (stateless)."""
        # Determine verification method
        if isinstance(presentation, str):
            # JWT VP
            result = await self.verifier.verify_jwt_vp(
                presentation_jwt=presentation,
                expected_audience=verifier_did,
                expected_nonce=None
            )
            method = VerificationMethod.JWT_VP
        else:
            # Structured presentation
            result = await self.verifier.verify_presentation(
                presentation=presentation,
                presentation_definition=presentation_definition,
                verifier_did=verifier_did
            )
            method = VerificationMethod.W3C_VC
        
        return {
            "valid": result.get("valid", False),
            "verified_claims": result.get("claims", result.get("verified_claims", {})),
            "verification_method": method.value,
            "error": result.get("error")
        }
    
    async def submit_presentation(
        self,
        session_id: str,
        presentation: dict[str, Any] | str
    ) -> VerificationSession:
        """Submit a presentation to an existing session."""
        session = await self.repository.get_by_id(session_id)
        if not session:
            raise ValidationError("Verification session not found")
        
        if session.is_expired():
            session.expire()
            await self.repository.save_session(session)
            raise ValidationError("Verification session has expired")
        
        if session.status != VerificationStatus.PENDING:
            raise ValidationError(f"Session is not in pending state: {session.status}")
        
        # Mark as in progress
        session.status = VerificationStatus.IN_PROGRESS
        await self.repository.save_session(session)
        
        try:
            # Verify the presentation
            if isinstance(presentation, str):
                # JWT VP
                result = await self.verifier.verify_jwt_vp(
                    presentation_jwt=presentation,
                    expected_audience=session.verifier_did,
                    expected_nonce=session.nonce
                )
                method = VerificationMethod.JWT_VP
            else:
                # Structured presentation
                result = await self.verifier.verify_presentation(
                    presentation=presentation,
                    presentation_definition=session.presentation_definition,
                    verifier_did=session.verifier_did
                )
                method = VerificationMethod.W3C_VC
            
            if result.get("valid"):
                session.verify(
                    presentation=presentation if isinstance(presentation, dict) else {},
                    verified_claims=result.get("claims", result.get("verified_claims", {})),
                    method=method
                )
            else:
                session.fail(result.get("error", "Verification failed"))
            
        except Exception as e:
            session.fail(str(e))
        
        await self.repository.save_session(session)
        return session
    
    async def get_session(self, session_id: str) -> VerificationSession | None:
        """Retrieve a verification session."""
        return await self.repository.get_by_id(session_id)
    
    async def list_sessions(
        self,
        organization_id: str,
        limit: int = 100,
        offset: int = 0
    ) -> list[VerificationSession]:
        """List verification sessions for an organization."""
        return await self.repository.list_by_organization(
            organization_id, limit, offset
        )
