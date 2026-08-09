"""add durable issuance-initiation idempotency.

Revision ID: issuance_offer_idempotency
Revises: drop_legacy_issuer_keys
Create Date: 2026-08-09 10:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "issuance_offer_idempotency"
down_revision = "drop_legacy_issuer_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "issuance_transactions",
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=True),
        schema="issuance_service",
    )
    op.add_column(
        "issuance_transactions",
        sa.Column("idempotency_request_hash", sa.String(length=64), nullable=True),
        schema="issuance_service",
    )
    op.create_check_constraint(
        "ck_issuance_transactions_idempotency_pair",
        "issuance_transactions",
        "(idempotency_key_hash IS NULL AND idempotency_request_hash IS NULL) OR "
        "(idempotency_key_hash IS NOT NULL AND idempotency_request_hash IS NOT NULL)",
        schema="issuance_service",
    )
    op.create_check_constraint(
        "ck_issuance_transactions_idempotency_key_hash",
        "issuance_transactions",
        "idempotency_key_hash IS NULL OR "
        "idempotency_key_hash ~ '^[0-9a-f]{64}$'",
        schema="issuance_service",
    )
    op.create_check_constraint(
        "ck_issuance_transactions_idempotency_request_hash",
        "issuance_transactions",
        "idempotency_request_hash IS NULL OR "
        "idempotency_request_hash ~ '^[0-9a-f]{64}$'",
        schema="issuance_service",
    )
    op.create_index(
        "ux_issuance_transactions_org_idempotency_key_hash",
        "issuance_transactions",
        ["organization_id", "idempotency_key_hash"],
        unique=True,
        schema="issuance_service",
    )


def downgrade() -> None:
    op.drop_index(
        "ux_issuance_transactions_org_idempotency_key_hash",
        table_name="issuance_transactions",
        schema="issuance_service",
    )
    op.drop_constraint(
        "ck_issuance_transactions_idempotency_request_hash",
        "issuance_transactions",
        schema="issuance_service",
        type_="check",
    )
    op.drop_constraint(
        "ck_issuance_transactions_idempotency_key_hash",
        "issuance_transactions",
        schema="issuance_service",
        type_="check",
    )
    op.drop_constraint(
        "ck_issuance_transactions_idempotency_pair",
        "issuance_transactions",
        schema="issuance_service",
        type_="check",
    )
    op.drop_column(
        "issuance_transactions",
        "idempotency_request_hash",
        schema="issuance_service",
    )
    op.drop_column(
        "issuance_transactions",
        "idempotency_key_hash",
        schema="issuance_service",
    )
