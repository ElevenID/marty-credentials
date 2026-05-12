"""add issuer_did_override and signing_service_id to issuance_transactions

Revision ID: add_issuer_did_override
Revises: seed_marty_application_templates
Create Date: 2026-04-17 14:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "add_issuer_did_override"
down_revision = "seed_marty_application_templates"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "issuance_transactions",
        sa.Column("issuer_did_override", sa.String(), nullable=True),
        schema="issuance_service",
    )
    op.add_column(
        "issuance_transactions",
        sa.Column("signing_service_id", sa.String(), nullable=True),
        schema="issuance_service",
    )


def downgrade():
    op.drop_column(
        "issuance_transactions",
        "signing_service_id",
        schema="issuance_service",
    )
    op.drop_column(
        "issuance_transactions",
        "issuer_did_override",
        schema="issuance_service",
    )
