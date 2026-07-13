"""Add first-class credential renewal linkage and validity policy.

Revision ID: credential_renewal_mip031
Revises: issuance_tx_revocation_profile
"""

from alembic import op
import sqlalchemy as sa


revision = "credential_renewal_mip031"
down_revision = "issuance_tx_revocation_profile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("issuance_transactions", sa.Column("renewal_of_credential_id", sa.String(), nullable=True), schema="issuance_service")
    op.add_column("issuance_transactions", sa.Column("validity_days", sa.Integer(), nullable=False, server_default="365"), schema="issuance_service")
    op.add_column("issuance_transactions", sa.Column("renewable", sa.Boolean(), nullable=False, server_default=sa.false()), schema="issuance_service")
    op.add_column("issuance_transactions", sa.Column("renewal_window_days", sa.Integer(), nullable=False, server_default="30"), schema="issuance_service")
    op.add_column("issued_credentials", sa.Column("renewed_from_credential_id", sa.String(), nullable=True), schema="issuance_service")
    op.add_column("issued_credentials", sa.Column("renewed_to_credential_id", sa.String(), nullable=True), schema="issuance_service")


def downgrade() -> None:
    raise RuntimeError("The MIP 0.3 credential renewal migration is one-way.")
