"""Add durable Application Template management concurrency and idempotency.

Revision ID: application_template_management
Revises: canvas_review_recovery_claim
"""

from alembic import op

revision = "application_template_management"
down_revision = "canvas_review_recovery_claim"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE issuance_service.application_templates
            ADD COLUMN IF NOT EXISTS management_version BIGINT NOT NULL DEFAULT 1,
            ADD COLUMN IF NOT EXISTS idempotency_key_hash VARCHAR(64),
            ADD COLUMN IF NOT EXISTS idempotency_request_hash VARCHAR(64);

        ALTER TABLE issuance_service.application_templates
            DROP CONSTRAINT IF EXISTS ck_application_templates_management_version,
            ADD CONSTRAINT ck_application_templates_management_version
                CHECK (management_version > 0),
            DROP CONSTRAINT IF EXISTS ck_application_templates_idempotency_pair,
            ADD CONSTRAINT ck_application_templates_idempotency_pair CHECK (
                (idempotency_key_hash IS NULL AND idempotency_request_hash IS NULL)
                OR
                (idempotency_key_hash IS NOT NULL AND idempotency_request_hash IS NOT NULL)
            ),
            DROP CONSTRAINT IF EXISTS ck_application_templates_idempotency_key_hash,
            ADD CONSTRAINT ck_application_templates_idempotency_key_hash CHECK (
                idempotency_key_hash IS NULL
                OR idempotency_key_hash ~ '^[0-9a-f]{64}$'
            ),
            DROP CONSTRAINT IF EXISTS ck_application_templates_idempotency_request_hash,
            ADD CONSTRAINT ck_application_templates_idempotency_request_hash CHECK (
                idempotency_request_hash IS NULL
                OR idempotency_request_hash ~ '^[0-9a-f]{64}$'
            );

        CREATE UNIQUE INDEX IF NOT EXISTS ux_application_templates_org_idempotency_key_hash
            ON issuance_service.application_templates (
                organization_id,
                idempotency_key_hash
            )
            WHERE idempotency_key_hash IS NOT NULL;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS
            issuance_service.ux_application_templates_org_idempotency_key_hash;

        ALTER TABLE issuance_service.application_templates
            DROP CONSTRAINT IF EXISTS ck_application_templates_idempotency_request_hash,
            DROP CONSTRAINT IF EXISTS ck_application_templates_idempotency_key_hash,
            DROP CONSTRAINT IF EXISTS ck_application_templates_idempotency_pair,
            DROP CONSTRAINT IF EXISTS ck_application_templates_management_version,
            DROP COLUMN IF EXISTS idempotency_request_hash,
            DROP COLUMN IF EXISTS idempotency_key_hash,
            DROP COLUMN IF EXISTS management_version;
        """
    )
