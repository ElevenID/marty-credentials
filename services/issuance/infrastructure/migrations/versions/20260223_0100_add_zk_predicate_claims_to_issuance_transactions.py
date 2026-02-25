"""add_zk_predicate_claims_to_issuance_transactions

Revision ID: add_zk_predicate_claims
Revises: add_authorization_sessions_table
Create Date: 2026-02-23 01:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_zk_predicate_claims'
down_revision = 'add_authorization_sessions_table'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'issuance_transactions',
        sa.Column('zk_predicate_claims', sa.JSON(), nullable=True),
        schema='issuance_service'
    )


def downgrade():
    op.drop_column('issuance_transactions', 'zk_predicate_claims', schema='issuance_service')
