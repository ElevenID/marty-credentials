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
        ALTER TABLE issuance_service.applications
            ADD COLUMN IF NOT EXISTS integration_context JSON NOT NULL DEFAULT '{}'
        """
    )


def downgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.applications
            DROP COLUMN IF EXISTS integration_context
        """
    )
