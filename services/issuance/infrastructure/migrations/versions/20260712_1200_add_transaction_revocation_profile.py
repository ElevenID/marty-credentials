"""Persist the server-derived revocation profile on issuance transactions.

Revision ID: issuance_tx_revocation_profile
Revises: application_template_mip03
"""

from alembic import op
import sqlalchemy as sa


revision = "issuance_tx_revocation_profile"
down_revision = "application_template_mip03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "issuance_transactions",
        sa.Column("revocation_profile_id", sa.String(), nullable=True),
        schema="issuance_service",
    )


def downgrade() -> None:
    op.drop_column(
        "issuance_transactions",
        "revocation_profile_id",
        schema="issuance_service",
    )
