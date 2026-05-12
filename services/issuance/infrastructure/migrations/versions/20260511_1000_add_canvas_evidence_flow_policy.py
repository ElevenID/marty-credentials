"""add Canvas evidence flow policy

Revision ID: add_canvas_evidence_flow_policy
Revises: scope_canvas_receipts_by_account
Create Date: 2026-05-11 10:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "add_canvas_evidence_flow_policy"
down_revision = "scope_canvas_receipts_by_account"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_connectors
            ADD COLUMN IF NOT EXISTS application_template_id VARCHAR(36),
            ADD COLUMN IF NOT EXISTS flow_mode VARCHAR(80) NOT NULL DEFAULT 'elevenid_orchestrated_canvas_evidence',
            ADD COLUMN IF NOT EXISTS direct_issue_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS auto_approve_on_evidence BOOLEAN NOT NULL DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS evidence_requirements JSON NOT NULL DEFAULT '[]'
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.applications
            ADD COLUMN IF NOT EXISTS integration_context JSON NOT NULL DEFAULT '{}'
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_connectors_application_template_id
            ON issuance_service.canvas_connectors(application_template_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_connectors_flow_mode
            ON issuance_service.canvas_connectors(flow_mode)
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_connectors_flow_mode")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_connectors_application_template_id")
    op.execute(
        """
        ALTER TABLE issuance_service.applications
            DROP COLUMN IF EXISTS integration_context
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_connectors
            DROP COLUMN IF EXISTS evidence_requirements,
            DROP COLUMN IF EXISTS auto_approve_on_evidence,
            DROP COLUMN IF EXISTS direct_issue_enabled,
            DROP COLUMN IF EXISTS flow_mode,
            DROP COLUMN IF EXISTS application_template_id
        """
    )
