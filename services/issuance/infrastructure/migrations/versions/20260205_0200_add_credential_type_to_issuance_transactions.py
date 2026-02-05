"""Add credential_type to issuance_transactions

Revision ID: add_credential_type
Revises: add_application_id
Create Date: 2026-02-05 02:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_credential_type'
down_revision = 'add_application_id'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add credential_type column to issuance_transactions
    op.add_column('issuance_transactions',
        sa.Column('credential_type', sa.String(), nullable=True),
        schema='issuance_service'
    )


def downgrade() -> None:
    # Remove column
    op.drop_column('issuance_transactions', 
        'credential_type', 
        schema='issuance_service'
    )
