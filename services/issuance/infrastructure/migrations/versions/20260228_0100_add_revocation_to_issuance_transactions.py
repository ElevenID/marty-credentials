"""add_revocation_fields_to_issuance_transactions

Revision ID: add_revocation_to_tx
Revises: add_credential_payload_format
Create Date: 2026-02-28 01:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_revocation_to_tx'
down_revision = 'add_credential_payload_format'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'issuance_transactions',
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        schema='issuance_service',
    )
    op.add_column(
        'issuance_transactions',
        sa.Column('revocation_reason', sa.String, nullable=True),
        schema='issuance_service',
    )


def downgrade():
    op.drop_column('issuance_transactions', 'revocation_reason', schema='issuance_service')
    op.drop_column('issuance_transactions', 'revoked_at', schema='issuance_service')
