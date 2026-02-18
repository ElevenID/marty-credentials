"""Domain entities for credential issuance."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class IssuanceStatus(str, Enum):
    """Issuance transaction status."""
    PENDING = "pending"
    AUTHORIZED = "authorized"
    ISSUED = "issued"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class IssuanceTransaction:
    """
    Issuance transaction aggregate.
    
    Tracks the state of a credential issuance request through the OID4VCI protocol.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    credential_template_id: str = ""
    applicant_id: str | None = None
    application_id: str | None = None
    subject_did: str | None = None
    
    # Transaction state
    status: IssuanceStatus = IssuanceStatus.PENDING
    
    # OID4VCI tokens
    pre_auth_code: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    access_token: str | None = None
    c_nonce: str | None = None
    
    # Credential data
    claims: dict[str, Any] = field(default_factory=dict)
    credential_type: str | None = None  # Store credential type from template
    
    # Timing
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=30))
    issued_at: datetime | None = None
    
    def authorize(self) -> str:
        """Generate access token for credential request."""
        self.access_token = secrets.token_urlsafe(32)
        self.c_nonce = secrets.token_urlsafe(16)
        self.status = IssuanceStatus.AUTHORIZED
        return self.access_token
    
    def complete(self) -> None:
        """Mark issuance as complete."""
        self.status = IssuanceStatus.ISSUED
        self.issued_at = datetime.now(timezone.utc)
    
    def fail(self, reason: str) -> None:
        """Mark issuance as failed."""
        self.status = IssuanceStatus.FAILED
    
    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


class EventType(str, Enum):
    """Issuance lifecycle event types."""
    OFFER_GENERATED = "offer_generated"
    OFFER_VIEWED = "offer_viewed"
    OFFER_EXPIRED = "offer_expired"
    CREDENTIAL_ISSUED = "credential_issued"
    CREDENTIAL_ACKNOWLEDGED = "credential_acknowledged"


@dataclass
class IssuanceEvent:
    """
    Immutable lifecycle event recorded for audit and analytics.

    Created at key points in the issuance flow:
      - offer_generated  : admin calls POST …/issuance-offer
      - offer_viewed     : applicant calls GET  …/issuance-offer
      - offer_expired    : offer TTL passed when applicant views it
      - credential_issued: wallet completes OID4VCI exchange
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    transaction_id: str | None = None
    application_id: str | None = None
    event_type: EventType = EventType.OFFER_GENERATED
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CredentialStatus(str, Enum):
    """Credential lifecycle status."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


@dataclass
class IssuedCredential:
    """Record of an issued credential."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    transaction_id: str = ""
    organization_id: str = ""
    credential_template_id: str = ""
    applicant_id: str | None = None
    subject_did: str | None = None
    
    # Credential data
    credential_jwt: str = ""
    credential_hash: str = ""
    
    # Lifecycle status
    status: CredentialStatus = CredentialStatus.ACTIVE
    status_updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Legacy revocation fields (deprecated, use status)
    revoked: bool = False
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    
    # Timestamps
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None


class ApplicationStatus(str, Enum):
    """Application status."""
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


@dataclass
class ApplicationTemplate:
    """Application Template defines the workflow for users to apply for credentials."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    credential_template_id: str | None = None
    
    # Application configuration
    form_fields: list[dict[str, Any]] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    claim_collection_rules: list[dict[str, Any]] = field(default_factory=list)
    # Pluggable vetting checks required for this application template.
    # Each entry: { check_type, custom_name, is_required, order, config, external_provider, webhook_url }
    required_checks: list[dict[str, Any]] = field(default_factory=list)
    
    # Workflow configuration
    approval_strategy: str = "auto"
    application_validity_days: int = 30
    auto_approval_rules: list[dict[str, Any]] = field(default_factory=list)
    
    # UI configuration
    ui_config: dict[str, Any] = field(default_factory=dict)
    notification_config: dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "active"


@dataclass
class Application:
    """Application instance - a user's submission to obtain a credential."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    application_template_id: str = ""
    
    # Applicant information
    applicant_identifier: str = ""
    
    # Application data
    form_data: dict[str, Any] = field(default_factory=dict)
    evidence_submissions: list[dict[str, Any]] = field(default_factory=list)
    
    # Status tracking
    status: ApplicationStatus = ApplicationStatus.PENDING
    review_notes: str | None = None
    reviewer_id: str | None = None
    rejection_reason: str | None = None
    
    # Derived claims for credential issuance
    derived_claims: dict[str, Any] = field(default_factory=dict)
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_at: datetime | None = None
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=30))
    
    # Link to issued credential (when approved)
    issuance_transaction_id: str | None = None
    credential_id: str | None = None
