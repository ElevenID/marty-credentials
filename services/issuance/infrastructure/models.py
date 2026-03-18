"""SQLAlchemy models for Issuance Service."""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Boolean, JSON, Integer, Table, Index
from sqlalchemy.orm import registry

mapper_registry = registry()


def utcnow():
    """Helper function for timezone-aware timestamps."""
    return datetime.now(timezone.utc)


# Issuance Transactions table
issuance_transactions_table = Table(
    "issuance_transactions",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("organization_id", String, nullable=False),
    Column("credential_template_id", String, nullable=False),
    Column("applicant_id", String, nullable=True),
    Column("application_id", String, nullable=True),
    Column("subject_did", String, nullable=True),
    Column("status", String, nullable=False, default="pending"),
    Column("pre_auth_code", String, nullable=False, unique=True),
    Column("access_token", String, nullable=True),
    Column("c_nonce", String, nullable=True),
    Column("claims", JSON, nullable=False, default=dict),
    Column("credential_type", String, nullable=True),
    Column("zk_predicate_claims", JSON, nullable=True, default=list),
    Column("credential_payload_format", String(30), nullable=False, server_default="w3c_vcdm_v2_sd_jwt"),
    Column("wallet_configs", JSON, nullable=True, server_default="[]"),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("issued_at", DateTime(timezone=True), nullable=True),
    Column("revoked_at", DateTime(timezone=True), nullable=True),
    Column("revocation_reason", String, nullable=True),
    Index("ix_issuance_transactions_organization_id", "organization_id"),
    Index("ix_issuance_transactions_status", "status"),
    Index("ix_issuance_transactions_pre_auth_code", "pre_auth_code"),
    Index("ix_issuance_transactions_applicant_id", "applicant_id"),
    Index("ix_issuance_transactions_application_id", "application_id"),
    schema="issuance_service"
)

# Issued Credentials table
issued_credentials_table = Table(
    "issued_credentials",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("transaction_id", String, nullable=False),
    Column("organization_id", String, nullable=False),
    Column("credential_template_id", String, nullable=False),
    Column("applicant_id", String, nullable=True),
    Column("subject_did", String, nullable=True),
    Column("credential_jwt", String, nullable=False),
    Column("credential_hash", String, nullable=False),
    Column("status", String, nullable=False, default="active"),
    Column("status_updated_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("revoked", Boolean, nullable=False, default=False),
    Column("revoked_at", DateTime(timezone=True), nullable=True),
    Column("revocation_reason", String, nullable=True),
    Column("issued_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Index("ix_issued_credentials_organization_id", "organization_id"),
    Index("ix_issued_credentials_status", "status"),
    Index("ix_issued_credentials_applicant_id", "applicant_id"),
    schema="issuance_service"
)

# Application Templates table
application_templates_table = Table(
    "application_templates",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("organization_id", String, nullable=False),
    Column("name", String, nullable=False),
    Column("description", String, nullable=True),
    Column("credential_template_id", String, nullable=True),
    Column("form_fields", JSON, nullable=False, default=list),
    Column("evidence_requirements", JSON, nullable=False, default=list),
    Column("claim_collection_rules", JSON, nullable=False, default=list),
    Column("required_checks", JSON, nullable=False, default=list),
    Column("approval_strategy", String, nullable=False, default="auto"),
    Column("application_validity_days", Integer, nullable=False, default=30),
    Column("auto_approval_rules", JSON, nullable=False, default=list),
    Column("ui_config", JSON, nullable=False, default=dict),
    Column("notification_config", JSON, nullable=False, default=dict),
    Column("status", String, nullable=False, default="active"),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Index("ix_application_templates_organization_id", "organization_id"),
    Index("ix_application_templates_status", "status"),
    schema="issuance_service"
)

# Applications table
applications_table = Table(
    "applications",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("organization_id", String, nullable=False),
    Column("application_template_id", String, nullable=False),
    Column("applicant_identifier", String, nullable=False),
    Column("form_data", JSON, nullable=False, default=dict),
    Column("submitted_evidence", JSON, nullable=False, default=list),
    Column("status", String, nullable=False, default="pending"),
    Column("review_notes", String, nullable=True),
    Column("reviewer_id", String, nullable=True),
    Column("rejection_reason", String, nullable=True),
    Column("derived_claims", JSON, nullable=False, default=dict),
    Column("issuance_transaction_id", String, nullable=True),
    Column("credential_id", String, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("submitted_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("reviewed_at", DateTime(timezone=True), nullable=True),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Index("ix_applications_organization_id", "organization_id"),
    Index("ix_applications_status", "status"),
    Index("ix_applications_template_id", "application_template_id"),
    Index("ix_applications_applicant_identifier", "applicant_identifier"),
    schema="issuance_service"
)

# Issuance Events table — append-only audit/lifecycle log
issuance_events_table = Table(
    "issuance_events",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("transaction_id", String, nullable=True),
    Column("application_id", String, nullable=True),
    Column("event_type", String, nullable=False),
    Column("metadata", JSON, nullable=False, default=dict),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Index("ix_issuance_events_application_id", "application_id"),
    Index("ix_issuance_events_transaction_id", "transaction_id"),
    Index("ix_issuance_events_event_type", "event_type"),
    schema="issuance_service"
)

# Authorization Sessions table — OID4VCI authorization code flow (§5)
authorization_sessions_table = Table(
    "authorization_sessions",
    mapper_registry.metadata,
    Column("id", String, primary_key=True),
    Column("code", String, nullable=False, unique=True),
    Column("client_id", String, nullable=False),
    Column("redirect_uri", String, nullable=True),
    Column("scope", String, nullable=True),
    Column("state", String, nullable=True),
    Column("issuer_state", String, nullable=True),
    Column("credential_configuration_ids", JSON, nullable=False, default=list),
    Column("organization_id", String, nullable=True),
    Column("code_challenge", String, nullable=True),
    Column("code_challenge_method", String, nullable=True),
    Column("access_token", String, nullable=True),
    Column("c_nonce", String, nullable=True),
    Column("status", String, nullable=False, default="pending"),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Index("ix_authorization_sessions_code", "code"),
    Index("ix_authorization_sessions_status", "status"),
    Index("ix_authorization_sessions_issuer_state", "issuer_state"),
    schema="issuance_service"
)
