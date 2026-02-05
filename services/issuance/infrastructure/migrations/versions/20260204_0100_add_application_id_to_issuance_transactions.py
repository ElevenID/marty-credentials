"""Add application_id to issuance_transactions

Revision ID: add_application_id
Revises: add_application_tables
Create Date: 2026-02-04 01:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_application_id'
down_revision = 'add_application_tables'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add application_id column to issuance_transactions
    op.add_column('issuance_transactions',
        sa.Column('application_id', sa.String(), nullable=True),
        schema='issuance_service'
    )
    
    # Add index for efficient querying by application_id
    op.create_index('ix_issuance_transactions_application_id', 
        'issuance_transactions', 
        ['application_id'], 
        unique=False, 
        schema='issuance_service'
    )


def downgrade() -> None:
    # Remove index
    op.drop_index('ix_issuance_transactions_application_id', 
        table_name='issuance_transactions', 
        schema='issuance_service'
    )
    
    # Remove column
    op.drop_column('issuance_transactions', 
        'application_id', 
        schema='issuance_service'
    )
