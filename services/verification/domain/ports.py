"""Domain ports (interfaces) for verification service."""

from abc import ABC, abstractmethod
from typing import Any

from .entities import VerificationSession


class IVerificationRepository(ABC):
    """Repository interface for verification sessions."""
    
    @abstractmethod
    async def save_session(self, session: VerificationSession) -> None:
        """Save or update a verification session."""
        pass
    
    @abstractmethod
    async def get_by_id(self, session_id: str) -> VerificationSession | None:
        """Retrieve a verification session by ID."""
        pass
    
    @abstractmethod
    async def get_by_nonce(self, nonce: str) -> VerificationSession | None:
        """Retrieve a verification session by nonce."""
        pass
    
    @abstractmethod
    async def list_by_organization(
        self,
        organization_id: str,
        limit: int = 100,
        offset: int = 0
    ) -> list[VerificationSession]:
        """List verification sessions for an organization."""
        pass


class ICredentialVerifier(ABC):
    """Interface for credential verification logic."""
    
    @abstractmethod
    async def verify_w3c_vc(
        self,
        credential: dict[str, Any],
        verifier_did: str,
        trusted_issuers: list[str] | None = None,
        organization_id: str | None = None,
        credential_format: str | None = None,
        key_purpose: str | None = None,
        algorithm: str | None = None,
        allow_public_did_fallback: bool = False,
    ) -> dict[str, Any]:
        """Verify a W3C Verifiable Credential."""
        pass
    
    @abstractmethod
    async def verify_jwt_vp(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None
    ) -> dict[str, Any]:
        """Verify a JWT Verifiable Presentation."""
        pass
    
    @abstractmethod
    async def verify_presentation(
        self,
        presentation: dict[str, Any],
        presentation_definition: dict[str, Any],
        verifier_did: str,
        trusted_issuers: list[str] | None = None,
        organization_id: str | None = None,
        allow_public_did_fallback: bool = False,
    ) -> dict[str, Any]:
        """Verify a presentation against a presentation definition."""
        pass

    @abstractmethod
    async def verify_vds_nc(
        self,
        barcode: str,
        issuer_jwk_json: str,
    ) -> dict[str, Any]:
        """Verify a VDS-NC barcode against an issuer JWK."""
        pass
