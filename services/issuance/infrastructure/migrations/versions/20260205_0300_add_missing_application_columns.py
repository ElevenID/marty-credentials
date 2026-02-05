"""Add missing columns to applications table

Revision ID: add_missing_application_columns
Revises: add_credential_type_to_issuance_transactions
Create Date: 2026-02-05 03:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timezone


# revision identifiers, used by Alembic.
revision = 'add_missing_application_columns'
down_revision = 'add_credential_type'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add missing columns to applications table
    op.add_column('applications',
        sa.Column('reviewer_id', sa.String(), nullable=True),
        schema='issuance_service'
    )
    op.add_column('applications',
        sa.Column('issuance_transaction_id', sa.String(), nullable=True),
        schema='issuance_service'
    )
    op.add_column('applications',
        sa.Column('submitted_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        schema='issuance_service'
    )
    op.add_column('applications',
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        schema='issuance_service'
    )
    op.add_column('applications',
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP + INTERVAL '30 days'")),
        schema='issuance_service'
    )


def downgrade() -> None:
    # Remove added columns
    op.drop_column('applications', 'expires_at', schema='issuance_service')
    op.drop_column('applications', 'reviewed_at', schema='issuance_service')
    op.drop_column('applications', 'submitted_at', schema='issuance_service')
    op.drop_column('applications', 'issuance_transaction_id', schema='issuance_service')
    op.drop_column('applications', 'reviewer_id', schema='issuance_service')
