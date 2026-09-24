"""Keep audit-event tenant ownership after linked records expire.

Revision ID: issuance_event_owner
Revises: physical_document_revocation_profile
"""

import sqlalchemy as sa
from alembic import op

revision = "issuance_event_owner"
down_revision = "physical_document_revocation_profile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "issuance_events",
        sa.Column("organization_id", sa.String(), nullable=True),
        schema="issuance_service",
    )
    op.execute(
        """UPDATE issuance_service.issuance_events AS event
        SET organization_id = transaction.organization_id
        FROM issuance_service.issuance_transactions AS transaction
        WHERE event.transaction_id = transaction.id"""
    )
    op.execute(
        """UPDATE issuance_service.issuance_events AS event
        SET organization_id = application.organization_id
        FROM issuance_service.applications AS application
        WHERE event.organization_id IS NULL AND event.application_id = application.id"""
    )
    op.create_index(
        "ix_issuance_events_organization_id",
        "issuance_events",
        ["organization_id"],
        schema="issuance_service",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_issuance_events_organization_id",
        table_name="issuance_events",
        schema="issuance_service",
    )
    op.drop_column("issuance_events", "organization_id", schema="issuance_service")
