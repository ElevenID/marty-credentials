"""add Canvas integration tables

Revision ID: add_canvas_tables
Revises: add_issuer_did_to_issued_credentials
Create Date: 2026-05-07 12:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "add_canvas_tables"
down_revision = "add_issuer_did_to_issued_credentials"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_event_receipts (
            id VARCHAR(36) PRIMARY KEY,
            provider_event_id VARCHAR(255) NOT NULL UNIQUE,
            organization_id VARCHAR(36) NOT NULL,
            credential_template_id VARCHAR(36) NOT NULL,
            canvas_account_id VARCHAR(255),
            payload_hash VARCHAR(64) NOT NULL,
            issuance_transaction_id VARCHAR(36)
                REFERENCES issuance_service.issuance_transactions(id)
                ON DELETE SET NULL,
            issuance_response JSON NOT NULL DEFAULT '{}',
            status VARCHAR(50) NOT NULL DEFAULT 'processed',
            error_summary TEXT,
            first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_event_receipts_provider_event_id
            ON issuance_service.canvas_event_receipts(provider_event_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_event_receipts_organization_id
            ON issuance_service.canvas_event_receipts(organization_id)
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_connectors (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL,
            canvas_account_id VARCHAR(255) NOT NULL UNIQUE,
            credential_template_id VARCHAR(36) NOT NULL,
            display_name VARCHAR(255),
            canvas_base_url TEXT,
            lti_client_id TEXT,
            lti_deployment_id TEXT,
            lti_issuer TEXT,
            lti_jwks_url TEXT,
            lti_jwks_json JSON,
            lti_openid_configuration JSON,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_connectors
            ADD COLUMN IF NOT EXISTS lti_client_id TEXT,
            ADD COLUMN IF NOT EXISTS lti_deployment_id TEXT,
            ADD COLUMN IF NOT EXISTS lti_issuer TEXT,
            ADD COLUMN IF NOT EXISTS lti_jwks_url TEXT,
            ADD COLUMN IF NOT EXISTS lti_jwks_json JSON,
            ADD COLUMN IF NOT EXISTS lti_openid_configuration JSON
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_connectors_organization_id
            ON issuance_service.canvas_connectors(organization_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_connectors_canvas_account_id
            ON issuance_service.canvas_connectors(canvas_account_id)
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_connectors_canvas_account_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_connectors_organization_id")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_connectors")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_event_receipts_organization_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_event_receipts_provider_event_id")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_event_receipts")
