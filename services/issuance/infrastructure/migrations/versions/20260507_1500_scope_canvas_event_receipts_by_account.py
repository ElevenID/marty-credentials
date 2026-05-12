"""scope Canvas event receipts by account

Revision ID: scope_canvas_receipts_by_account
Revises: add_canvas_jwks_cache_metadata
Create Date: 2026-05-07 15:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "scope_canvas_receipts_by_account"
down_revision = "add_canvas_jwks_cache_metadata"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_event_receipts
            DROP CONSTRAINT IF EXISTS canvas_event_receipts_provider_event_id_key
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_event_receipts_account_event
            ON issuance_service.canvas_event_receipts(canvas_account_id, provider_event_id)
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS issuance_service.ux_canvas_event_receipts_account_event")
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_event_receipts
            ADD CONSTRAINT canvas_event_receipts_provider_event_id_key UNIQUE (provider_event_id)
        """
    )
