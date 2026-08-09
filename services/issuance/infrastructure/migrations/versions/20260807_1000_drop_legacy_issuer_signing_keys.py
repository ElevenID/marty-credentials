"""remove the legacy database-backed issuer key store.

Revision ID: drop_legacy_issuer_keys
Revises: issuance_tx_issuer_algorithm
Create Date: 2026-08-07 10:00:00.000000

Issuer signing is DID-mediated through an authorized issuer profile and its
managed custody service. Refuse to discard a legacy row: an operator must
first provision and verify the corresponding managed profile, then explicitly
remove the obsolete database record.
"""

import sqlalchemy as sa
from alembic import op

revision = "drop_legacy_issuer_keys"
down_revision = "issuance_tx_issuer_algorithm"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('issuance_service.issuer_signing_keys') IS NOT NULL
               AND EXISTS (
                   SELECT 1 FROM issuance_service.issuer_signing_keys LIMIT 1
               ) THEN
                RAISE EXCEPTION USING
                    MESSAGE = 'legacy issuer signing keys remain in PostgreSQL',
                    HINT = 'Provision and verify each DID in managed custody, then remove the legacy rows before retrying.';
            END IF;
        END
        $$;
        """
    )
    op.execute("DROP TABLE IF EXISTS issuance_service.issuer_signing_keys")


def downgrade() -> None:
    op.create_table(
        "issuer_signing_keys",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("issuer_did", sa.String(), nullable=False),
        sa.Column(
            "key_algorithm",
            sa.String(),
            nullable=False,
            server_default="Ed25519",
        ),
        sa.Column("encrypted_jwk_json", sa.Text(), nullable=False),
        sa.Column("public_key_b64", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id"),
        schema="issuance_service",
    )
    op.create_index(
        "ix_issuer_signing_keys_organization_id",
        "issuer_signing_keys",
        ["organization_id"],
        unique=False,
        schema="issuance_service",
    )
