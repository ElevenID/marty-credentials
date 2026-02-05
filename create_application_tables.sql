-- Create application_templates and applications tables for issuance service
-- Schema: issuance_service

CREATE TABLE IF NOT EXISTS issuance_service.application_templates (
    id VARCHAR PRIMARY KEY,
    organization_id VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    description VARCHAR,
    credential_template_id VARCHAR,
    
    -- Configuration stored as JSON
    form_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
    claim_collection_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    
    -- Workflow configuration
    approval_strategy VARCHAR NOT NULL DEFAULT 'auto',
    application_validity_days INTEGER NOT NULL DEFAULT 30,
    auto_approval_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    
    -- UI and notifications
    ui_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    notification_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Metadata
    status VARCHAR NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_application_templates_organization_id ON issuance_service.application_templates(organization_id);
CREATE INDEX IF NOT EXISTS ix_application_templates_status ON issuance_service.application_templates(status);

CREATE TABLE IF NOT EXISTS issuance_service.applications (
    id VARCHAR PRIMARY KEY,
    organization_id VARCHAR NOT NULL,
    application_template_id VARCHAR NOT NULL,
    applicant_identifier VARCHAR NOT NULL,
    
    -- Application data stored as JSON
    form_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    submitted_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    
    -- Status and review
    status VARCHAR NOT NULL,
    reviewed_by VARCHAR,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_notes VARCHAR,
    rejection_reason VARCHAR,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_applications_organization_id ON issuance_service.applications(organization_id);
CREATE INDEX IF NOT EXISTS ix_applications_status ON issuance_service.applications(status);
CREATE INDEX IF NOT EXISTS ix_applications_template_id ON issuance_service.applications(application_template_id);
CREATE INDEX IF NOT EXISTS ix_applications_applicant_identifier ON issuance_service.applications(applicant_identifier);
