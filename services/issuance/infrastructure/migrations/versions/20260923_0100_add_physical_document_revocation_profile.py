"""Align physical document jobs with the revocation profile model.

Revision ID: physical_document_revocation_profile
Revises: application_template_management
"""

import sqlalchemy as sa
from alembic import op

revision = "physical_document_revocation_profile"
down_revision = "application_template_management"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "physical_document_jobs",
        sa.Column("revocation_profile_id", sa.String(), nullable=True),
        schema="issuance_service",
    )


def downgrade() -> None:
    op.drop_column(
        "physical_document_jobs",
        "revocation_profile_id",
        schema="issuance_service",
    )
