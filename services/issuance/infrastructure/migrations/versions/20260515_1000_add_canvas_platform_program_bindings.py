"""add Canvas platform and program binding tables

Revision ID: add_canvas_platform_program_bindings
Revises: add_evidence_facts
Create Date: 2026-05-15 10:00:00.000000

"""

from alembic import op


revision = "add_canvas_platform_program_bindings"
down_revision = "add_evidence_facts"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
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
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_platforms_organization_id
            ON issuance_service.canvas_platforms(organization_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_platforms_canvas_account_id
            ON issuance_service.canvas_platforms(canvas_account_id)
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_program_bindings (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            platform_id VARCHAR(36) NOT NULL
                REFERENCES issuance_service.canvas_platforms(id)
                ON DELETE CASCADE,
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
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_organization_id
            ON issuance_service.canvas_program_bindings(organization_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_platform_id
            ON issuance_service.canvas_program_bindings(platform_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_application_template_id
            ON issuance_service.canvas_program_bindings(application_template_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_credential_template_id
            ON issuance_service.canvas_program_bindings(credential_template_id)
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_program_bindings_credential_template_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_program_bindings_application_template_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_program_bindings_platform_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_program_bindings_organization_id")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_program_bindings")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_platforms_canvas_account_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_platforms_organization_id")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_platforms")
