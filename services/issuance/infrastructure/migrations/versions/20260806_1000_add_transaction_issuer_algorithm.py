"""add the server-owned issuer algorithm to issuance transactions.

Revision ID: issuance_tx_issuer_algorithm
Revises: oid4vci_registered_clients
Create Date: 2026-08-06 10:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "issuance_tx_issuer_algorithm"
down_revision = "oid4vci_registered_clients"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "issuance_transactions",
        sa.Column("issuer_algorithm", sa.String(length=20), nullable=True),
        schema="issuance_service",
    )
    op.create_check_constraint(
        "ck_issuance_transactions_issuer_algorithm",
        "issuance_transactions",
        "issuer_algorithm IS NULL OR issuer_algorithm IN ('ES256', 'ES384', 'RS256', 'EdDSA')",
        schema="issuance_service",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_issuance_transactions_issuer_algorithm",
        "issuance_transactions",
        schema="issuance_service",
        type_="check",
    )
    op.drop_column(
        "issuance_transactions",
        "issuer_algorithm",
        schema="issuance_service",
    )
