"""Apply the MIP 0.3 Application Template clean break.

Revision ID: application_template_mip03
Revises: add_physical_document_jobs
"""

from alembic import op


revision = "application_template_mip03"
down_revision = "add_physical_document_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE issuance_service.application_templates
        SET status = UPPER(status)
        WHERE status IS NOT NULL;

        ALTER TABLE issuance_service.application_templates
        ALTER COLUMN status SET DEFAULT 'DRAFT';

        ALTER TABLE issuance_service.application_templates
        DROP COLUMN IF EXISTS auto_approval_rules;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE issuance_service.application_templates
        ADD COLUMN IF NOT EXISTS auto_approval_rules JSON NOT NULL DEFAULT '[]'::json;
        """
    )
