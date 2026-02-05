"""Domain entities for verification service."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class VerificationStatus(str, Enum):
    """Verification session status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


class VerificationMethod(str, Enum):
    """Methods for credential verification."""
    W3C_VC = "w3c_vc"
    SD_JWT = "sd_jwt"
    MDOC = "mdoc"
    ZK_PROOF = "zk_proof"
    JWT_VP = "jwt_vp"


@dataclass
class VerificationSession:
    """Verification session aggregate root."""
    
    id: str
    organization_id: str
    verifier_did: str
    presentation_definition: dict[str, Any]
    status: VerificationStatus = VerificationStatus.PENDING
    
    # Optional constraints
    required_credential_types: list[str] = field(default_factory=list)
    trusted_issuers: list[str] = field(default_factory=list)
    required_claims: list[str] = field(default_factory=list)
    
    # Verification results
    presentation_data: dict[str, Any] | None = None
    verified_claims: dict[str, Any] | None = None
    verification_method: VerificationMethod | None = None
    verified_at: datetime | None = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    
    # State tracking
    error_message: str | None = None
    request_uri: str | None = None  # For OID4VP flow
    nonce: str | None = None  # For replay protection
    
    def verify(
        self,
        presentation: dict[str, Any],
        verified_claims: dict[str, Any],
        method: VerificationMethod
    ) -> None:
        """Mark session as successfully verified."""
        self.status = VerificationStatus.VERIFIED
        self.presentation_data = presentation
        self.verified_claims = verified_claims
        self.verification_method = method
        self.verified_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def fail(self, error: str) -> None:
        """Mark session as failed."""
        self.status = VerificationStatus.FAILED
        self.error_message = error
        self.updated_at = datetime.utcnow()
    
    def expire(self) -> None:
        """Mark session as expired."""
        self.status = VerificationStatus.EXPIRED
        self.updated_at = datetime.utcnow()
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
