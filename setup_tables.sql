-- Credential Templates
CREATE TABLE IF NOT EXISTS credential_template_service.credential_templates (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    credential_type VARCHAR(255) NOT NULL,
    vct TEXT NOT NULL,
    doctype TEXT,
    claims JSON NOT NULL DEFAULT '[]',
    privacy_posture VARCHAR(30) NOT NULL DEFAULT 'selective_disclosure',
    selective_disclosure_fields JSON NOT NULL DEFAULT '[]',
    derived_attributes JSON NOT NULL DEFAULT '[]',
    display_style JSON NOT NULL DEFAULT '{}',
    validity_rules JSON NOT NULL DEFAULT '{}',
    issuer_requirements JSON NOT NULL DEFAULT '{}',
    supported_formats JSON NOT NULL DEFAULT '[]',
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Trust Profiles
CREATE TABLE IF NOT EXISTS trust_profile_service.trust_profiles (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    trusted_issuers JSON NOT NULL DEFAULT '[]',
    allowed_credential_types JSON NOT NULL DEFAULT '[]',
    validation_rules JSON NOT NULL DEFAULT '{}',
    trust_parameters JSON NOT NULL DEFAULT '{}',
    revocation_check_enabled BOOLEAN NOT NULL DEFAULT true,
    max_credential_age_days INTEGER,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Wallet Registry (global, shared across all orgs)
CREATE TABLE IF NOT EXISTS credential_template_service.wallet_registry (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    logo_url TEXT,
    deep_link_template TEXT NOT NULL,  -- e.g. "openid-credential-offer://?credential_offer={OFFER}"
    supported_formats JSON NOT NULL DEFAULT '[]',   -- ["sd_jwt_vc","jwt_vc","mdoc"]
    supported_protocols JSON NOT NULL DEFAULT '[]', -- ["oid4vci"]
    platforms JSON NOT NULL DEFAULT '[]',           -- ["ios","android","desktop","web"]
    supports_qr BOOLEAN NOT NULL DEFAULT true,
    supports_deeplink BOOLEAN NOT NULL DEFAULT true,
    docs_url TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Extend credential_templates with wallet compatibility + issuance metadata
ALTER TABLE credential_template_service.credential_templates
    ADD COLUMN IF NOT EXISTS supported_wallet_ids JSON NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS issuance_protocol VARCHAR(30) NOT NULL DEFAULT 'oid4vci',
    ADD COLUMN IF NOT EXISTS credential_format VARCHAR(30);

-- Issuance lifecycle event log
CREATE TABLE IF NOT EXISTS issuance_service.issuance_events (
    id VARCHAR(36) PRIMARY KEY,
    transaction_id VARCHAR(36),
    application_id VARCHAR(36),
    event_type VARCHAR(50) NOT NULL,  -- offer_created|offer_opened|offer_expired|credential_issued|credential_acknowledged
    metadata JSON NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Replay-safe inbound Canvas event receipts
CREATE TABLE IF NOT EXISTS issuance_service.canvas_event_receipts (
    id VARCHAR(36) PRIMARY KEY,
    provider_event_id VARCHAR(255) NOT NULL,
    organization_id VARCHAR(36) NOT NULL,
    credential_template_id VARCHAR(36) NOT NULL,
    canvas_account_id VARCHAR(255),
    payload_hash VARCHAR(64) NOT NULL,
    issuance_transaction_id VARCHAR(36),
    issuance_response JSON NOT NULL DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'processed',
    error_summary TEXT,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_canvas_event_receipts_provider_event_id
    ON issuance_service.canvas_event_receipts(provider_event_id);
CREATE INDEX IF NOT EXISTS ix_canvas_event_receipts_organization_id
    ON issuance_service.canvas_event_receipts(organization_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_event_receipts_account_event
    ON issuance_service.canvas_event_receipts(canvas_account_id, provider_event_id);
ALTER TABLE IF EXISTS issuance_service.canvas_event_receipts OWNER TO marty;
GRANT ALL PRIVILEGES ON TABLE issuance_service.canvas_event_receipts TO marty;

-- Canvas platform trust and program binding configuration
CREATE TABLE IF NOT EXISTS issuance_service.canvas_platforms (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    canvas_account_id VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    canvas_base_url TEXT,
    lti_client_id TEXT,
    lti_deployment_id TEXT,
    lti_issuer TEXT,
    lti_jwks_url TEXT,
    lti_jwks_json JSON,
    lti_jwks_fetched_at TIMESTAMP WITH TIME ZONE,
    lti_jwks_expires_at TIMESTAMP WITH TIME ZONE,
    lti_openid_configuration JSON,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT ux_canvas_platforms_org_account UNIQUE (organization_id, canvas_account_id)
);

CREATE INDEX IF NOT EXISTS ix_canvas_platforms_organization_id
    ON issuance_service.canvas_platforms(organization_id);
CREATE INDEX IF NOT EXISTS ix_canvas_platforms_canvas_account_id
    ON issuance_service.canvas_platforms(canvas_account_id);
ALTER TABLE IF EXISTS issuance_service.canvas_platforms OWNER TO marty;
GRANT ALL PRIVILEGES ON TABLE issuance_service.canvas_platforms TO marty;

CREATE TABLE IF NOT EXISTS issuance_service.canvas_program_bindings (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    platform_id VARCHAR(36) NOT NULL REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
    application_template_id VARCHAR(36) NOT NULL,
    credential_template_id VARCHAR(36) NOT NULL,
    display_name VARCHAR(255),
    flow_mode VARCHAR(80) NOT NULL DEFAULT 'elevenid_orchestrated_canvas_evidence',
    direct_issue_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    auto_approve_on_evidence BOOLEAN NOT NULL DEFAULT FALSE,
    evidence_requirements JSON NOT NULL DEFAULT '[]',
    canvas_scope JSON NOT NULL DEFAULT '{}',
    delivery_mode VARCHAR(40) NOT NULL DEFAULT 'wallet_only',
    issuer_mode VARCHAR(40) NOT NULL DEFAULT 'org_managed',
    approval_policy_set_id VARCHAR(36),
    deployment_profile_id TEXT,
    feature_flags JSON NOT NULL DEFAULT '{}',
    canvas_credentials JSON NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_organization_id
    ON issuance_service.canvas_program_bindings(organization_id);
CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_platform_id
    ON issuance_service.canvas_program_bindings(platform_id);
CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_application_template_id
    ON issuance_service.canvas_program_bindings(application_template_id);
CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_credential_template_id
    ON issuance_service.canvas_program_bindings(credential_template_id);
CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_deployment_profile_id
    ON issuance_service.canvas_program_bindings(deployment_profile_id);
ALTER TABLE IF EXISTS issuance_service.canvas_program_bindings OWNER TO marty;
GRANT ALL PRIVILEGES ON TABLE issuance_service.canvas_program_bindings TO marty;

-- Server-owned Canvas LTI launch state for nonce/replay protection
CREATE TABLE IF NOT EXISTS issuance_service.canvas_lti_launch_states (
    id VARCHAR(36) PRIMARY KEY,
    platform_id VARCHAR(36) NOT NULL REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
    organization_id VARCHAR(36) NOT NULL,
    canvas_account_id VARCHAR(255) NOT NULL,
    state VARCHAR(255) NOT NULL UNIQUE,
    nonce VARCHAR(255) NOT NULL,
    login_hint TEXT,
    target_link_uri TEXT,
    lti_message_hint TEXT,
    redirect_uri TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    metadata JSON NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS ix_canvas_lti_launch_states_state
    ON issuance_service.canvas_lti_launch_states(state);
CREATE INDEX IF NOT EXISTS ix_canvas_lti_launch_states_platform_id
    ON issuance_service.canvas_lti_launch_states(platform_id);
CREATE INDEX IF NOT EXISTS ix_canvas_lti_launch_states_organization_status
    ON issuance_service.canvas_lti_launch_states(organization_id, status);
ALTER TABLE IF EXISTS issuance_service.canvas_lti_launch_states OWNER TO marty;
GRANT ALL PRIVILEGES ON TABLE issuance_service.canvas_lti_launch_states TO marty;

-- Seed default wallet registry entries
INSERT INTO credential_template_service.wallet_registry (id, name, logo_url, deep_link_template, supported_formats, supported_protocols, platforms, supports_qr, supports_deeplink, docs_url)
VALUES
  ('wr-lissi-001', 'LISSI Wallet', 'https://lissi.id/favicon.ico', 'openid-credential-offer://?credential_offer={OFFER}', '["sd_jwt_vc","jwt_vc_json"]', '["oid4vci"]', '["ios","android"]', true, true, 'https://lissi.id'),
  ('wr-waltid-001', 'walt.id Wallet', 'https://walt.id/favicon.ico', 'openid-credential-offer://?credential_offer={OFFER}', '["sd_jwt_vc","jwt_vc_json","mdoc"]', '["oid4vci"]', '["ios","android","web"]', true, true, 'https://docs.walt.id'),
  ('wr-sphereon-001', 'Sphereon Wallet', 'https://sphereon.com/favicon.ico', 'openid-credential-offer://?credential_offer={OFFER}', '["sd_jwt_vc","jwt_vc_json"]', '["oid4vci"]', '["ios","android"]', true, true, 'https://sphereon.com'),
  ('wr-dc4eu-001', 'DC4EU Wallet', NULL, 'openid-credential-offer://?credential_offer={OFFER}', '["sd_jwt_vc","mdoc"]', '["oid4vci"]', '["ios","android"]', true, true, NULL)
ON CONFLICT (id) DO NOTHING;

-- Presentation Policy tables
CREATE TABLE IF NOT EXISTS presentation_policy_service.presentation_policies (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    credential_requirements JSON NOT NULL DEFAULT '[]',
    purpose TEXT,
    valid_from TIMESTAMP WITH TIME ZONE,
    valid_until TIMESTAMP WITH TIME ZONE,
    trust_profile_id VARCHAR(36),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
