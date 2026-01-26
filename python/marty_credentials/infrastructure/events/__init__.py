"""Domain events for credential lifecycle"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any
from uuid import uuid4


@dataclass(frozen=True)
class DomainEvent:
    """Base class for domain events"""
    event_id: str
    event_timestamp: datetime
    event_type: str
    
    def __post_init__(self):
        if not self.event_id:
            object.__setattr__(self, 'event_id', str(uuid4()))
        if not self.event_timestamp:
            object.__setattr__(self, 'event_timestamp', datetime.utcnow())


@dataclass(frozen=True)
class CredentialIssuedEvent(DomainEvent):
    """Published when a credential is successfully issued"""
    credential_id: str
    credential_type: str
    format: str  # "jwt", "mdoc", "sd-jwt", "w3c_vc"
    issuer_id: str
    holder_id: str
    organization_id: Optional[str] = None
    
    def __post_init__(self):
        super().__post_init__()
        if not self.event_type:
            object.__setattr__(self, 'event_type', 'credential.issued')


@dataclass(frozen=True)
class CredentialVerifiedEvent(DomainEvent):
    """Published when a credential is successfully verified"""
    credential_id: Optional[str]
    credential_type: str
    verifier_id: str
    verification_result: bool
    verification_method: str  # e.g., "signature", "revocation_check"
    details: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        super().__post_init__()
        if not self.event_type:
            object.__setattr__(self, 'event_type', 'credential.verified')


@dataclass(frozen=True)
class CredentialVerificationFailedEvent(DomainEvent):
    """Published when credential verification fails"""
    credential_type: str
    issuer: str
    error: str
    error_details: Optional[Dict[str, Any]] = None
    verifier_id: Optional[str] = None
    
    def __post_init__(self):
        super().__post_init__()
        if not self.event_type:
            object.__setattr__(self, 'event_type', 'credential.verification_failed')


@dataclass(frozen=True)
class CredentialRevokedEvent(DomainEvent):
    """Published when a credential is revoked"""
    credential_id: str
    credential_type: str
    reason: str
    revoked_by: str
    revocation_timestamp: datetime
    
    def __post_init__(self):
        super().__post_init__()
        if not self.event_type:
            object.__setattr__(self, 'event_type', 'credential.revoked')


@dataclass(frozen=True)
class CredentialStatusUpdatedEvent(DomainEvent):
    """Published when credential status changes"""
    credential_id: str
    credential_type: str
    old_status: str
    new_status: str
    updated_by: str
    reason: Optional[str] = None
    
    def __post_init__(self):
        super().__post_init__()
        if not self.event_type:
            object.__setattr__(self, 'event_type', 'credential.status_updated')


@dataclass(frozen=True)
class CredentialPresentationRequestedEvent(DomainEvent):
    """Published when a credential presentation is requested"""
    request_id: str
    verifier_id: str
    credential_types: list
    holder_id: Optional[str] = None
    
    def __post_init__(self):
        super().__post_init__()
        if not self.event_type:
            object.__setattr__(self, 'event_type', 'credential.presentation_requested')


@dataclass(frozen=True)
class CredentialPresentationSubmittedEvent(DomainEvent):
    """Published when a credential presentation is submitted"""
    presentation_id: str
    request_id: str
    holder_id: str
    verifier_id: str
    credential_ids: list
    
    def __post_init__(self):
        super().__post_init__()
        if not self.event_type:
            object.__setattr__(self, 'event_type', 'credential.presentation_submitted')
