"""add issuer_did to issued_credentials

Revision ID: add_issuer_did_to_issued_credentials
Revises: add_issuer_did_override
Create Date: 2026-04-18 10:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "add_issuer_did_to_issued_credentials"
down_revision = "add_issuer_did_override"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "alembic_version",
        "version_num",
        schema="issuance_service",
        existing_type=sa.String(length=32),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
    op.add_column(
        "issued_credentials",
        sa.Column("issuer_did", sa.String(), nullable=True),
        schema="issuance_service",
    )


def downgrade():
    op.drop_column(
        "issued_credentials",
        "issuer_did",
        schema="issuance_service",
    )
    op.alter_column(
        "alembic_version",
        "version_num",
        schema="issuance_service",
        existing_type=sa.String(length=64),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
