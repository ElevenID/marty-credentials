"""add shared OID4VCI ephemeral capabilities.

Revision ID: oid4vci_ephemeral_caps
Revises: drop_legacy_issuer_keys
Create Date: 2026-08-09 12:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "oid4vci_ephemeral_caps"
down_revision = "drop_legacy_issuer_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oid4vci_ephemeral_capabilities",
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("key_digest", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('par', 'proof_nonce')",
            name="ck_oid4vci_ephemeral_capabilities_purpose",
        ),
        sa.CheckConstraint(
            "(purpose = 'par' AND payload IS NOT NULL) OR "
            "(purpose = 'proof_nonce' AND payload IS NULL)",
            name="ck_oid4vci_ephemeral_capabilities_payload",
        ),
        sa.PrimaryKeyConstraint("purpose", "key_digest"),
        schema="issuance_service",
    )
    op.create_index(
        "ix_oid4vci_ephemeral_capabilities_expires_at",
        "oid4vci_ephemeral_capabilities",
        ["expires_at"],
        unique=False,
        schema="issuance_service",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_oid4vci_ephemeral_capabilities_expires_at",
        table_name="oid4vci_ephemeral_capabilities",
        schema="issuance_service",
    )
    op.drop_table("oid4vci_ephemeral_capabilities", schema="issuance_service")
