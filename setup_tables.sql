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
