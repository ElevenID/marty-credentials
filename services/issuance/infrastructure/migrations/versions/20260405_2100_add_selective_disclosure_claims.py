"""add selective_disclosure_claims column to issuance_transactions

Revision ID: add_sd_claims_col
Revises: add_revocation_to_tx
Create Date: 2026-04-05 21:00:00.000000

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'add_sd_claims_col'
down_revision = 'add_revocation_to_tx'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'issuance_transactions',
        sa.Column('selective_disclosure_claims', sa.JSON(), nullable=True, server_default='[]'),
        schema='issuance_service',
    )


def downgrade():
    op.drop_column(
        'issuance_transactions',
        'selective_disclosure_claims',
        schema='issuance_service',
    )
