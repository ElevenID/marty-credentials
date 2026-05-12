"""add explicit issuer selection

Revision ID: add_explicit_issuer_selection
Revises: add_canvas_evidence_flow_policy
Create Date: 2026-05-12 10:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "add_explicit_issuer_selection"
down_revision = "add_canvas_evidence_flow_policy"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.issuance_transactions
            ADD COLUMN IF NOT EXISTS issuer_profile_id VARCHAR(80),
            ADD COLUMN IF NOT EXISTS issuer_mode VARCHAR(40) NOT NULL DEFAULT 'org_managed'
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_issuance_transactions_issuer_profile_id
            ON issuance_service.issuance_transactions(issuer_profile_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_issuance_transactions_issuer_mode
            ON issuance_service.issuance_transactions(issuer_mode)
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_issuance_transactions_issuer_mode")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_issuance_transactions_issuer_profile_id")
    op.execute(
        """
        ALTER TABLE issuance_service.issuance_transactions
            DROP COLUMN IF EXISTS issuer_mode,
            DROP COLUMN IF EXISTS issuer_profile_id
        """
    )
