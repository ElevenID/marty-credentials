"""add organization integration secrets

Revision ID: add_org_integration_secrets
Revises: add_canvas_credentials_binding_config
Create Date: 2026-05-24 10:00:00.000000
"""

from alembic import op


revision = "add_org_integration_secrets"
down_revision = "add_canvas_credentials_binding_config"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.organization_integration_secrets (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            name VARCHAR(255) NOT NULL,
            provider VARCHAR(80) NOT NULL,
            purpose VARCHAR(80) NOT NULL DEFAULT 'api_token',
            encrypted_secret_value TEXT NOT NULL,
            secret_hint VARCHAR(80),
            metadata JSON NOT NULL DEFAULT '{}',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            last_used_at TIMESTAMP WITH TIME ZONE
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_org_integration_secrets_organization_id
            ON issuance_service.organization_integration_secrets(organization_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_org_integration_secrets_provider
            ON issuance_service.organization_integration_secrets(provider)
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_org_integration_secrets_org_provider_name
            ON issuance_service.organization_integration_secrets(organization_id, provider, name)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS issuance_service.ux_org_integration_secrets_org_provider_name")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_org_integration_secrets_provider")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_org_integration_secrets_organization_id")
    op.execute("DROP TABLE IF EXISTS issuance_service.organization_integration_secrets")
