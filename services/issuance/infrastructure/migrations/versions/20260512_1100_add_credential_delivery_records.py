"""add credential delivery records

Revision ID: add_credential_delivery_records
Revises: add_explicit_issuer_selection
Create Date: 2026-05-12 11:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "add_credential_delivery_records"
down_revision = "add_explicit_issuer_selection"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.issuance_transactions
            ADD COLUMN IF NOT EXISTS delivery_mode VARCHAR(40) NOT NULL DEFAULT 'wallet_only'
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_issuance_transactions_delivery_mode
            ON issuance_service.issuance_transactions(delivery_mode)
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.credential_delivery_records (
            id VARCHAR PRIMARY KEY,
            credential_id VARCHAR NOT NULL REFERENCES issuance_service.issued_credentials(id) ON DELETE CASCADE,
            transaction_id VARCHAR NOT NULL REFERENCES issuance_service.issuance_transactions(id) ON DELETE CASCADE,
            organization_id VARCHAR NOT NULL,
            delivery_target VARCHAR(40) NOT NULL,
            delivery_mode VARCHAR(40) NOT NULL DEFAULT 'wallet_only',
            status VARCHAR(40) NOT NULL DEFAULT 'pending',
            canvas_account_id VARCHAR(255),
            external_credential_id VARCHAR(255),
            external_issuer_id VARCHAR(255),
            last_error TEXT,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_credential_delivery_records_credential_id
            ON issuance_service.credential_delivery_records(credential_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_credential_delivery_records_transaction_id
            ON issuance_service.credential_delivery_records(transaction_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_credential_delivery_records_organization_id
            ON issuance_service.credential_delivery_records(organization_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_credential_delivery_records_status
            ON issuance_service.credential_delivery_records(status)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_credential_delivery_records_delivery_target
            ON issuance_service.credential_delivery_records(delivery_target)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_credential_delivery_records_external_credential_id
            ON issuance_service.credential_delivery_records(external_credential_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_credential_delivery_records_canvas_account_id
            ON issuance_service.credential_delivery_records(canvas_account_id)
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_credential_delivery_records_canvas_account_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_credential_delivery_records_external_credential_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_credential_delivery_records_delivery_target")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_credential_delivery_records_status")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_credential_delivery_records_organization_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_credential_delivery_records_transaction_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_credential_delivery_records_credential_id")
    op.execute("DROP TABLE IF EXISTS issuance_service.credential_delivery_records")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_issuance_transactions_delivery_mode")
    op.execute(
        """
        ALTER TABLE issuance_service.issuance_transactions
            DROP COLUMN IF EXISTS delivery_mode
        """
    )
