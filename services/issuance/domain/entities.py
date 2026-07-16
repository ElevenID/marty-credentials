"""Domain entities for credential issuance."""

from __future__ import annotations

import hashlib
import json
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
    SIGNING = "signing"
    ISSUED = "issued"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"


_ISSUANCE_SAVE_PREDECESSORS: dict[IssuanceStatus, frozenset[IssuanceStatus]] = {
    IssuanceStatus.PENDING: frozenset({IssuanceStatus.PENDING}),
    IssuanceStatus.AUTHORIZED: frozenset(
        {IssuanceStatus.PENDING, IssuanceStatus.AUTHORIZED}
    ),
    # AUTHORIZED -> SIGNING is reserved for the repository compare-and-set.
    IssuanceStatus.SIGNING: frozenset({IssuanceStatus.SIGNING}),
    # Legacy DIDComm/gRPC delivery still completes through save_transaction.
    IssuanceStatus.ISSUED: frozenset(
        {
            IssuanceStatus.PENDING,
            IssuanceStatus.AUTHORIZED,
            IssuanceStatus.ISSUED,
        }
    ),
    IssuanceStatus.FAILED: frozenset(
        {
            IssuanceStatus.PENDING,
            IssuanceStatus.AUTHORIZED,
            IssuanceStatus.SIGNING,
            IssuanceStatus.FAILED,
        }
    ),
    IssuanceStatus.EXPIRED: frozenset(
        {IssuanceStatus.PENDING, IssuanceStatus.AUTHORIZED, IssuanceStatus.EXPIRED}
    ),
    # A management action may win before signing starts, but it cannot interrupt
    # a reserved KMS call or replace its atomic finalization.
    IssuanceStatus.REVOKED: frozenset(
        {
            IssuanceStatus.PENDING,
            IssuanceStatus.AUTHORIZED,
            IssuanceStatus.ISSUED,
            IssuanceStatus.FAILED,
            IssuanceStatus.EXPIRED,
            IssuanceStatus.REVOKED,
        }
    ),
}


def issuance_save_predecessors(target: IssuanceStatus) -> frozenset[IssuanceStatus]:
    """States a generic repository save may replace with ``target``.

    This is deliberately stricter than the domain's complete lifecycle. The
    signing transition and credential finalization have dedicated atomic
    repository methods and must not be recreated by a stale whole-row save.
    """

    normalized = target if isinstance(target, IssuanceStatus) else IssuanceStatus(target)
    return _ISSUANCE_SAVE_PREDECESSORS[normalized]


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
    reserved_credential_id: str | None = None
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
    EVIDENCE_POLICY_REVIEW_CREATED = "evidence_policy_review_created"
    EVIDENCE_POLICY_REVIEW_RESOLVED = "evidence_policy_review_resolved"
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
    lti_trust_profile: str = "hosted_global"
    lti_issuer: str | None = None
    lti_jwks_url: str | None = None
    lti_jwks_json: dict[str, Any] | None = None
    lti_jwks_fetched_at: datetime | None = None
    lti_jwks_expires_at: datetime | None = None
    lti_openid_configuration: dict[str, Any] | None = None
    registration_status: str = "draft"
    connection_config: dict[str, Any] = field(default_factory=dict)
    capability_snapshot: dict[str, Any] = field(default_factory=dict)
    last_validated_at: datetime | None = None
    last_connection_error: str | None = None
    config_version: int = 1
    archived_at: datetime | None = None
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CanvasEvidenceSource(str, Enum):
    """Authoritative Canvas evidence transports supported by the portable tool."""

    AGS_RESULT = "ags_result"
    CANVAS_REST = "canvas_rest"


class CanvasEvidenceFactType(str, Enum):
    """Normalized Canvas facts that may participate in badge policy."""

    ASSIGNMENT_SCORE = "canvas.assignment_score"
    QUIZ_SCORE = "canvas.quiz_score"
    COURSE_COMPLETION = "canvas.course_completion"
    MODULE_COMPLETION = "canvas.module_completion"

    @property
    def is_score(self) -> bool:
        return self in {
            CanvasEvidenceFactType.ASSIGNMENT_SCORE,
            CanvasEvidenceFactType.QUIZ_SCORE,
        }

    @property
    def is_completion(self) -> bool:
        return not self.is_score


def _required_identifier(value: Any, field_name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field_name} is required")
    return normalized


@dataclass(frozen=True)
class CanvasEvidenceScope:
    """Typed identifiers that pin an evidence rule to Canvas resources."""

    course_id: str
    activity_id: str | None = None
    module_id: str | None = None
    line_item_url: str | None = None
    resource_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "course_id", _required_identifier(self.course_id, "scope.course_id"))
        for name in ("activity_id", "module_id", "line_item_url", "resource_id"):
            value = getattr(self, name)
            if value is not None:
                normalized = str(value).strip()
                object.__setattr__(self, name, normalized or None)
        if self.line_item_url and not self.line_item_url.startswith("https://"):
            raise ValueError("scope.line_item_url must use HTTPS")

    @classmethod
    def from_mapping(cls, value: Any) -> CanvasEvidenceScope:
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict):
            raise ValueError("scope must be an object")
        return cls(
            course_id=value.get("course_id"),
            activity_id=value.get("activity_id") or value.get("assignment_id") or value.get("quiz_id"),
            module_id=value.get("module_id"),
            line_item_url=value.get("line_item_url") or value.get("lineitem_url"),
            resource_id=value.get("resource_id") or value.get("resourceId"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            key: value
            for key, value in {
                "course_id": self.course_id,
                "activity_id": self.activity_id,
                "module_id": self.module_id,
                "line_item_url": self.line_item_url,
                "resource_id": self.resource_id,
            }.items()
            if value is not None
        }


@dataclass(frozen=True)
class CanvasEvidencePassRule:
    """Typed threshold for a score or completion observation."""

    min_score_percent: float | None = None
    completed: bool | None = None

    def __post_init__(self) -> None:
        if self.min_score_percent is not None:
            if isinstance(self.min_score_percent, bool):
                raise ValueError("pass_rule.min_score_percent must be numeric")
            normalized = float(self.min_score_percent)
            if normalized < 0 or normalized > 100:
                raise ValueError("pass_rule.min_score_percent must be between 0 and 100")
            object.__setattr__(self, "min_score_percent", normalized)
        if self.completed is not None and self.completed is not True:
            raise ValueError("pass_rule.completed must be true when supplied")

    @classmethod
    def from_mapping(cls, value: Any) -> CanvasEvidencePassRule:
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict):
            raise ValueError("pass_rule must be an object")
        unsupported = set(value) - {"min_score_percent", "completed"}
        if unsupported:
            raise ValueError(f"Unsupported Canvas pass rule fields: {', '.join(sorted(unsupported))}")
        return cls(
            min_score_percent=value.get("min_score_percent"),
            completed=value.get("completed"),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.min_score_percent is not None:
            result["min_score_percent"] = self.min_score_percent
        if self.completed is not None:
            result["completed"] = self.completed
        return result


@dataclass(frozen=True)
class CanvasEvidenceRequirement:
    """A discriminated, independently evaluated Canvas evidence requirement."""

    requirement_id: str
    source: CanvasEvidenceSource
    fact_type: CanvasEvidenceFactType
    scope: CanvasEvidenceScope
    pass_rule: CanvasEvidencePassRule
    required: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "requirement_id",
            _required_identifier(self.requirement_id, "requirement_id"),
        )
        if not isinstance(self.source, CanvasEvidenceSource):
            object.__setattr__(self, "source", CanvasEvidenceSource(str(self.source)))
        if not isinstance(self.fact_type, CanvasEvidenceFactType):
            object.__setattr__(self, "fact_type", CanvasEvidenceFactType(str(self.fact_type)))
        if not isinstance(self.scope, CanvasEvidenceScope):
            object.__setattr__(self, "scope", CanvasEvidenceScope.from_mapping(self.scope))
        if not isinstance(self.pass_rule, CanvasEvidencePassRule):
            object.__setattr__(self, "pass_rule", CanvasEvidencePassRule.from_mapping(self.pass_rule))
        if not isinstance(self.required, bool):
            raise ValueError("required must be a boolean")

        if self.fact_type.is_score:
            if self.pass_rule.min_score_percent is None or self.pass_rule.completed is not None:
                raise ValueError("score requirements need only pass_rule.min_score_percent")
            if self.source == CanvasEvidenceSource.CANVAS_REST and not self.scope.activity_id:
                raise ValueError("Canvas REST score requirements need scope.activity_id")
            if self.source == CanvasEvidenceSource.AGS_RESULT and not (
                self.scope.line_item_url or self.scope.resource_id
            ):
                raise ValueError("AGS requirements need scope.line_item_url or scope.resource_id")
        else:
            if self.source != CanvasEvidenceSource.CANVAS_REST:
                raise ValueError("completion requirements must use canvas_rest")
            if self.pass_rule.completed is not True or self.pass_rule.min_score_percent is not None:
                raise ValueError("completion requirements need only pass_rule.completed=true")
            if self.fact_type == CanvasEvidenceFactType.MODULE_COMPLETION and not self.scope.module_id:
                raise ValueError("module completion requirements need scope.module_id")

    @classmethod
    def from_mapping(cls, value: Any) -> CanvasEvidenceRequirement:
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict):
            raise ValueError("Canvas evidence requirement must be an object")
        unsupported = set(value) - {
            "requirement_id",
            "source",
            "fact_type",
            "scope",
            "pass_rule",
            "required",
        }
        if unsupported:
            raise ValueError(f"Unsupported Canvas requirement fields: {', '.join(sorted(unsupported))}")
        try:
            source = CanvasEvidenceSource(str(value.get("source") or ""))
        except ValueError as exc:
            raise ValueError("source must be ags_result or canvas_rest") from exc
        try:
            fact_type = CanvasEvidenceFactType(str(value.get("fact_type") or ""))
        except ValueError as exc:
            raise ValueError(
                "fact_type must be assignment score, quiz score, course completion, or module completion"
            ) from exc
        return cls(
            requirement_id=value.get("requirement_id"),
            source=source,
            fact_type=fact_type,
            scope=CanvasEvidenceScope.from_mapping(value.get("scope")),
            pass_rule=CanvasEvidencePassRule.from_mapping(value.get("pass_rule")),
            required=value.get("required", True),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "source": self.source.value,
            "fact_type": self.fact_type.value,
            "scope": self.scope.to_dict(),
            "pass_rule": self.pass_rule.to_dict(),
            "required": self.required,
        }


def validate_canvas_evidence_requirements(values: Any) -> list[CanvasEvidenceRequirement]:
    """Strictly validate a non-empty set of uniquely identified requirements."""

    if not isinstance(values, list) or not values:
        raise ValueError("At least one Canvas evidence requirement is required")
    parsed = [CanvasEvidenceRequirement.from_mapping(value) for value in values]
    identifiers = [requirement.requirement_id for requirement in parsed]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Canvas evidence requirement_id values must be unique")
    return parsed


def canvas_evidence_requirements_to_json(values: Any) -> list[Any]:
    """Serialize typed requirements while preserving disabled legacy review rows."""

    if not isinstance(values, list):
        raise ValueError("Canvas evidence requirements must be a list")
    return [value.to_dict() if isinstance(value, CanvasEvidenceRequirement) else value for value in values]


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
    evidence_requirements: list[CanvasEvidenceRequirement] = field(default_factory=list)
    canvas_scope: dict[str, Any] = field(default_factory=dict)
    delivery_mode: str = "wallet_only"
    issuer_mode: str = "org_managed"
    approval_policy_set_id: str | None = None
    deployment_profile_id: str | None = None
    feature_flags: dict[str, bool] = field(default_factory=dict)
    canvas_credentials: dict[str, Any] = field(default_factory=dict)
    config_version: int = 1
    validated_config_version: int | None = None
    readiness_checks: list[dict[str, Any]] = field(default_factory=list)
    readiness_validated_at: datetime | None = None
    activated_at: datetime | None = None
    archived_at: datetime | None = None
    credential_template_snapshot: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def typed_evidence_requirements(self) -> list[CanvasEvidenceRequirement]:
        """Return enabled, production-safe requirements or raise on invalid input.

        Runtime compatibility is intentionally retained for legacy rows while the
        portable-Canvas migration marks those rows disabled for administrator
        review. New API writes must call this property (or the validation helper)
        before persistence.
        """

        return validate_canvas_evidence_requirements(self.evidence_requirements)


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

    def mark_exchanged(self, access_token: str) -> None:
        """Record the access token and mark the authorization code exchanged."""
        self.access_token = access_token
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
    requirement_id: str | None = None
    logical_key: str = ""
    source_revision: str = ""
    payload_hash: str = ""
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    effective_at: datetime | None = None
    superseded_fact_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Fill deterministic revision metadata for legacy provider adapters.

        New Canvas readers should supply the authoritative payload hash and
        requirement ID explicitly. These fallbacks ensure old adapters still
        produce revision-safe facts during the migration window.
        """

        canonical_scope = json.dumps(self.scope or {}, sort_keys=True, separators=(",", ":"))
        if not self.logical_key:
            key_material = "|".join(
                [
                    self.requirement_id or "",
                    self.provider,
                    self.fact_type,
                    canonical_scope,
                    self.subject_id,
                ]
            )
            self.logical_key = hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        if not self.payload_hash:
            payload = {
                "provider": self.provider,
                "fact_type": self.fact_type,
                "scope": self.scope or {},
                "assertion": self.assertion or {},
                "verification": self.verification or {},
            }
            canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
            self.payload_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        if not self.source_revision:
            self.source_revision = self.payload_hash
        if self.effective_at is None:
            self.effective_at = self.observed_at


@dataclass
class EvidenceFactHead:
    """Current immutable evidence revision for an application/logical key."""

    organization_id: str
    application_id: str
    logical_key: str
    fact_id: str
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CanvasLearnerIdentityStatus(str, Enum):
    SUBJECT_VERIFIED = "subject_verified"
    LINKED = "linked"
    QUARANTINED = "quarantined"


@dataclass
class CanvasLearnerIdentity:
    """Verified join between an opaque LTI subject and numeric Canvas user."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    platform_id: str = ""
    deployment_id: str = ""
    lti_subject: str = ""
    canvas_user_id: str | None = None
    sis_user_id: str | None = None
    status: CanvasLearnerIdentityStatus = CanvasLearnerIdentityStatus.LINKED
    conflict_reason: str | None = None
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CanvasOAuthAuthorization:
    """Hashed, single-use OAuth transaction with immutable client snapshots."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    platform_id: str = ""
    canvas_base_url: str = ""
    platform_config_version: int = 1
    client_id: str = ""
    client_secret_ref: str = ""
    state_hash: str = ""
    capabilities: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    redirect_uri: str = ""
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    consumed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at


class CanvasOAuthConnectionStatus(str, Enum):
    CONNECTED = "connected"
    REAUTHORIZATION_REQUIRED = "reauthorization_required"
    REVOCATION_PENDING = "revocation_pending"
    DISCONNECTED = "disconnected"


@dataclass
class CanvasOAuthConnection:
    """Organization-owned Canvas API grant with reversible secret references."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    platform_id: str = ""
    canvas_base_url: str = ""
    platform_config_version: int = 1
    client_id: str = ""
    client_secret_ref: str = ""
    capabilities: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    access_token_secret_ref: str | None = None
    refresh_token_secret_ref: str | None = None
    token_expires_at: datetime | None = None
    status: CanvasOAuthConnectionStatus = CanvasOAuthConnectionStatus.CONNECTED
    reauthorization_required: bool = False
    refresh_lease_owner: str | None = None
    refresh_lease_expires_at: datetime | None = None
    revoke_retry_count: int = 0
    revoke_retry_at: datetime | None = None
    revoke_last_error_code: str | None = None
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_refreshed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CanvasEvidenceSyncTargetType(str, Enum):
    LEARNER_APPLICATION = "learner_application"
    BACKGROUND_ROSTER = "background_roster"
    AWARD_CANDIDATE = "award_candidate"
    ISSUED_DRIFT = "issued_drift"


@dataclass
class CanvasEvidenceSyncTarget:
    """Durable scheduled unit of Canvas evidence synchronization."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    platform_id: str = ""
    binding_id: str = ""
    target_type: CanvasEvidenceSyncTargetType = CanvasEvidenceSyncTargetType.LEARNER_APPLICATION
    logical_key: str = ""
    application_id: str | None = None
    candidate_id: str | None = None
    enabled: bool = True
    schedule_seconds: int = 900
    next_run_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_enqueued_at: datetime | None = None
    last_succeeded_at: datetime | None = None
    config_version: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CanvasEvidenceSyncJobStatus(str, Enum):
    QUEUED = "queued"
    LEASED = "leased"
    RETRY = "retry"
    SUCCEEDED = "succeeded"
    DEAD_LETTER = "dead_letter"
    CANCELLED = "cancelled"


@dataclass
class CanvasEvidenceSyncJob:
    """PostgreSQL-leased Canvas synchronization job."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    target_id: str = ""
    status: CanvasEvidenceSyncJobStatus = CanvasEvidenceSyncJobStatus.QUEUED
    attempt_count: int = 0
    max_attempts: int = 8
    available_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    last_error_code: str | None = None
    last_error_summary: str | None = None
    result: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None


@dataclass(frozen=True)
class CanvasSyncReadinessState:
    """Sanitized operational blockers for one tenant-owned Canvas binding."""

    dead_lettered: bool = False
    stale_backlog: bool = False


@dataclass
class CanvasWorkerHeartbeat:
    """Liveness record for a separate Canvas scheduler/worker process."""

    worker_id: str = ""
    role: str = "canvas_sync"
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.worker_id = _required_identifier(self.worker_id, "worker_id")
        self.role = _required_identifier(self.role, "role")


class CanvasAwardCandidateState(str, Enum):
    OBSERVED = "observed"
    IDENTITY_LINK_REQUIRED = "identity_link_required"
    ELIGIBLE = "eligible"
    PENDING_CLAIM = "pending_claim"
    CLAIMED = "claimed"
    DISMISSED = "dismissed"


@dataclass
class CanvasAwardCandidate:
    """Unsigned background award candidate awaiting an eligible learner claim."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    platform_id: str = ""
    binding_id: str = ""
    candidate_key: str = ""
    learner_identity_id: str | None = None
    canvas_user_id: str | None = None
    lti_subject: str | None = None
    state: CanvasAwardCandidateState = CanvasAwardCandidateState.OBSERVED
    application_id: str | None = None
    claimed_credential_id: str | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CanvasCandidateObservation:
    """Immutable evidence revision associated with an award candidate."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    candidate_id: str = ""
    requirement_id: str = ""
    logical_key: str = ""
    assertion: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    payload_hash: str = ""
    superseded_observation_id: str | None = None
    is_current: bool = True
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.logical_key:
            self.logical_key = _required_identifier(self.requirement_id, "requirement_id")
        if not self.payload_hash:
            payload = json.dumps(
                {
                    "assertion": self.assertion or {},
                    "verification": self.verification or {},
                },
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            self.payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()


class EvidencePolicyReviewStatus(str, Enum):
    OPEN = "open"
    DISMISSED = "dismissed"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    RESOLVED = "resolved"


@dataclass
class EvidencePolicyReview:
    """Manual correction review created by post-issuance evidence drift."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    application_id: str = ""
    credential_id: str = ""
    binding_id: str | None = None
    status: EvidencePolicyReviewStatus = EvidencePolicyReviewStatus.OPEN
    prior_decision: dict[str, Any] = field(default_factory=dict)
    current_decision: dict[str, Any] = field(default_factory=dict)
    triggering_fact_id: str | None = None
    resolution_action: str | None = None
    resolution_notes: str | None = None
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    resolution_claim_token: str | None = None
    resolution_claim_action: str | None = None
    resolution_claimed_at: datetime | None = None
    resolution_recovery_pending: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


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
