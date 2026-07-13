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
_CANVAS_LTI_STATE_TTL_MINUTES = int(os.environ.get("CANVAS_LTI_STATE_TTL_MINUTES", "10"))


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
    revocation_profile_id: str | None = None
    renewal_of_credential_id: str | None = None
    applicant_id: str | None = None
    application_id: str | None = None
    subject_did: str | None = None
    
    # Transaction state
    status: IssuanceStatus = IssuanceStatus.PENDING
    
    # OID4VCI tokens
    pre_auth_code: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    access_token: str | None = None
    nonce: str | None = None
    
    # Issuer identity override (injected by gateway from IssuerProfile)
    issuer_profile_id: str | None = None
    issuer_mode: str = "org_managed"
    issuer_did_override: str | None = None
    signing_service_id: str | None = None
    delivery_mode: str = "wallet_only"

    # Credential data
    claims: dict[str, Any] = field(default_factory=dict)
    credential_type: str | None = None  # Store credential type from template
    zk_predicate_claims: list[str] = field(default_factory=list)  # ZK-eligible claims (zk_mdoc only)
    selective_disclosure_claims: list[str] = field(default_factory=list)  # SD-JWT selectively disclosable claims
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"  # SD-JWT payload structure
    wallet_configs: list[dict] = field(default_factory=list)  # [{wallet_id, deep_link_scheme}, ...]
    validity_days: int = 365
    renewable: bool = False
    renewal_window_days: int = 30
    
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
    def should_mirror_to_canvas(self) -> bool:
        return self.delivery_mode == "wallet_plus_canvas_mirror"
    
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
    EVIDENCE_FACT_CREATED = "evidence_fact_created"
    EVIDENCE_POLICY_PERMITTED = "evidence_policy_permitted"
    EVIDENCE_POLICY_DENIED = "evidence_policy_denied"
    APPROVAL_ISSUANCE_SUCCEEDED = "approval_issuance_succeeded"
    APPROVAL_ISSUANCE_FAILED = "approval_issuance_failed"
    CANVAS_LTI_APPLICATION_BOOTSTRAPPED = "canvas_lti_application_bootstrapped"
    CANVAS_MIRROR_ALERT_EMITTED = "canvas_mirror_alert_emitted"


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


@dataclass
class CanvasEventReceipt:
    """Replay-safe receipt for inbound Canvas credential events."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    provider_event_id: str = ""
    organization_id: str = ""
    credential_template_id: str = ""
    canvas_account_id: str | None = None
    payload_hash: str = ""
    issuance_transaction_id: str | None = None
    issuance_response: dict[str, Any] = field(default_factory=dict)
    status: str = "processed"
    error_summary: str | None = None
    first_seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CanvasPlatform:
    """Canvas tenant/platform trust configuration.

    This separates tenant-level trust and LTI metadata from program-specific
    application, credential, evidence, issuer, and delivery behavior.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    canvas_account_id: str = ""
    display_name: str | None = None
    canvas_base_url: str | None = None
    lti_client_id: str | None = None
    lti_deployment_id: str | None = None
    lti_issuer: str | None = None
    lti_jwks_url: str | None = None
    lti_jwks_json: dict[str, Any] | None = None
    lti_jwks_fetched_at: datetime | None = None
    lti_jwks_expires_at: datetime | None = None
    lti_openid_configuration: dict[str, Any] | None = None
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CanvasProgramBinding:
    """Program-level Canvas binding for a platform/course/use case."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    platform_id: str = ""
    application_template_id: str = ""
    credential_template_id: str = ""
    display_name: str | None = None
    flow_mode: str = "elevenid_orchestrated_canvas_evidence"
    direct_issue_enabled: bool = False
    auto_approve_on_evidence: bool = False
    evidence_requirements: list[Any] = field(default_factory=list)
    canvas_scope: dict[str, Any] = field(default_factory=dict)
    delivery_mode: str = "wallet_only"
    issuer_mode: str = "org_managed"
    approval_policy_set_id: str | None = None
    deployment_profile_id: str | None = None
    feature_flags: dict[str, bool] = field(default_factory=dict)
    canvas_credentials: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class OrganizationIntegrationSecret:
    """Organization-owned encrypted integration secret metadata.

    The plaintext value is only populated on write/read-for-use paths; list/read
    responses should expose metadata and secret references, never the token.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    provider: str = ""
    purpose: str = "api_token"
    secret_value: str = ""
    secret_hint: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: datetime | None = None

    @property
    def secret_ref(self) -> str:
        return f"org_secret://{self.organization_id}/{self.id}"


@dataclass
class CanvasLtiLaunchState:
    """Server-owned nonce/state for a Canvas LTI 1.3 launch."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    platform_id: str = ""
    organization_id: str = ""
    canvas_account_id: str = ""
    state: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    nonce: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    login_hint: str | None = None
    target_link_uri: str | None = None
    lti_message_hint: str | None = None
    redirect_uri: str | None = None
    status: str = "pending"
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
        + timedelta(minutes=_CANVAS_LTI_STATE_TTL_MINUTES)
    )
    consumed_at: datetime | None = None

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def mark_consumed(self) -> None:
        self.status = "consumed"
        self.consumed_at = datetime.now(timezone.utc)


class CredentialStatus(str, Enum):
    """Credential lifecycle status."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class DeliveryTarget(str, Enum):
    """Delivery channels for issued credentials."""

    WALLET = "wallet"
    DIDCOMM_V2 = "didcomm_v2"
    CANVAS_CREDENTIALS = "canvas_credentials"


class CredentialDeliveryStatus(str, Enum):
    """Delivery record status."""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"


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
    issuer_did: str | None = None
    revocation_profile_id: str | None = None
    renewed_from_credential_id: str | None = None
    renewed_to_credential_id: str | None = None
    status_list_entries: list[dict[str, Any]] = field(default_factory=list)
    
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


@dataclass
class CredentialDeliveryRecord:
    """Outbox/audit record for post-issuance delivery targets."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    credential_id: str = ""
    transaction_id: str = ""
    organization_id: str = ""
    delivery_target: DeliveryTarget = DeliveryTarget.WALLET
    delivery_mode: str = "wallet_only"
    status: CredentialDeliveryStatus = CredentialDeliveryStatus.PENDING
    canvas_account_id: str | None = None
    external_credential_id: str | None = None
    external_issuer_id: str | None = None
    last_error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class EvidenceFact:
    """Immutable normalized evidence fact derived from a verified receipt."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    application_id: str = ""
    subject_id: str = ""
    provider: str = ""
    fact_type: str = ""
    scope: dict[str, Any] = field(default_factory=dict)
    assertion: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    source: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ApprovalPolicySet:
    """Read-only Cedar policy set referenced by an application template."""

    id: str = ""
    organization_id: str = ""
    policy_type: str = "APPROVAL_RULES"
    status: str = "active"
    cedar_policies: Any = ""
    cedar_schema_version: str | None = None
    updated_at: datetime | None = None


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
    evidence_requirements: list[Any] = field(default_factory=list)
    claim_collection_rules: list[dict[str, Any]] = field(default_factory=list)
    # Pluggable vetting checks required for this application template.
    # Each entry: { check_type, custom_name, is_required, order, config, external_provider, webhook_url }
    required_checks: list[dict[str, Any]] = field(default_factory=list)
    
    # Workflow configuration
    approval_strategy: str = "MANUAL"
    approval_policy_set_id: str | None = None
    application_validity_days: int = 30
    
    # UI configuration
    ui_config: dict[str, Any] = field(default_factory=dict)
    notification_config: dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "DRAFT"


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
    integration_context: dict[str, Any] = field(default_factory=dict)
    
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
