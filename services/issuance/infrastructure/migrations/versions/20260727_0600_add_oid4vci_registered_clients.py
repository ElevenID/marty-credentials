"""add tenant-bound OID4VCI registered clients.

Revision ID: oid4vci_registered_clients
Revises: add_dpop_token_binding
Create Date: 2026-07-27 06:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "oid4vci_registered_clients"
down_revision = "add_dpop_token_binding"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "issuance_transactions",
        sa.Column("oid4vci_client_id", sa.String(length=512), nullable=True),
        schema="issuance_service",
    )
    op.create_table(
        "oid4vci_registered_clients",
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("client_id", sa.String(length=512), nullable=False),
        sa.Column("jwks", sa.JSON(), nullable=False),
        sa.Column("redirect_uris", sa.JSON(), nullable=False),
        sa.Column(
            "token_endpoint_auth_method",
            sa.String(length=40),
            nullable=False,
            server_default="private_key_jwt",
        ),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("organization_id", "client_id"),
        schema="issuance_service",
    )
    op.create_index(
        "ix_oid4vci_registered_clients_org_active",
        "oid4vci_registered_clients",
        ["organization_id", "active"],
        unique=False,
        schema="issuance_service",
    )
    op.create_table(
        "oid4vci_client_assertions",
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("client_id", sa.String(length=512), nullable=False),
        sa.Column("jti", sa.String(length=256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("organization_id", "client_id", "jti"),
        schema="issuance_service",
    )
    op.create_index(
        "ix_oid4vci_client_assertions_expires_at",
        "oid4vci_client_assertions",
        ["expires_at"],
        unique=False,
        schema="issuance_service",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_oid4vci_client_assertions_expires_at",
        table_name="oid4vci_client_assertions",
        schema="issuance_service",
    )
    op.drop_table("oid4vci_client_assertions", schema="issuance_service")
    op.drop_index(
        "ix_oid4vci_registered_clients_org_active",
        table_name="oid4vci_registered_clients",
        schema="issuance_service",
    )
    op.drop_table("oid4vci_registered_clients", schema="issuance_service")
    op.drop_column(
        "issuance_transactions",
        "oid4vci_client_id",
        schema="issuance_service",
    )
