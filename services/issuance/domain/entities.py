"""Domain entities for credential issuance."""

from __future__ import annotations

import os
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

_OFFER_TTL_MINUTES = int(os.environ.get("ISSUANCE_OFFER_TTL_MINUTES", "10080"))  # 7 days
_AUTH_SESSION_TTL_MINUTES = int(os.environ.get("ISSUANCE_AUTH_SESSION_TTL_MINUTES", "60"))  # 1 hour


class IssuanceStatus(str, Enum):
    """Issuance transaction status."""
    PENDING = "pending"
    AUTHORIZED = "authorized"
    ISSUED = "issued"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"


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
    nonce: str | None = None
    
    # Credential data
    claims: dict[str, Any] = field(default_factory=dict)
    credential_type: str | None = None  # Store credential type from template
    zk_predicate_claims: list[str] = field(default_factory=list)  # ZK-eligible claims (zk_mdoc only)
    selective_disclosure_claims: list[str] = field(default_factory=list)  # SD-JWT selectively disclosable claims
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"  # SD-JWT payload structure
    wallet_configs: list[dict] = field(default_factory=list)  # [{wallet_id, deep_link_scheme}, ...]
    
    # Timing
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=_OFFER_TTL_MINUTES))
    issued_at: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    
    def complete(self) -> None:
        """Mark issuance as complete."""
        self.status = IssuanceStatus.ISSUED
        self.issued_at = datetime.now(timezone.utc)
    
    def fail(self, reason: str) -> None:
        """Mark issuance as failed."""
        self.status = IssuanceStatus.FAILED
    
    def revoke(self, reason: str | None = None) -> None:
        """Mark issuance as revoked."""
        self.status = IssuanceStatus.REVOKED
        self.revoked_at = datetime.now(timezone.utc)
        self.revocation_reason = reason
    
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
class AuthorizationSession:
    """OAuth 2.0 authorization code session (OID4VCI §5).

    Tracks the state of an authorization code grant from the authorization
    request through to token exchange.  The authorization endpoint creates
    a session and the token endpoint consumes it.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    code: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    client_id: str = ""
    redirect_uri: str | None = None
    scope: str | None = None
    state: str | None = None

    # OID4VCI-specific
    issuer_state: str | None = None
    credential_configuration_ids: list[str] = field(default_factory=list)
    organization_id: str | None = None

    # PKCE (RFC 7636)
    code_challenge: str | None = None
    code_challenge_method: str | None = None  # "S256" or "plain"

    # Token binding
    access_token: str | None = None
    nonce: str | None = None

    # Lifecycle
    status: str = "pending"  # pending → exchanged → expired
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=_AUTH_SESSION_TTL_MINUTES))

    def mark_exchanged(self, access_token: str, nonce: str) -> None:
        """Record the token/nonce generated by the Rust engine and mark exchanged."""
        self.access_token = access_token
        self.nonce = nonce
        self.status = "exchanged"

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


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
