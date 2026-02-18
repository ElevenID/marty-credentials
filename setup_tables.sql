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
