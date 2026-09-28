"""Carry explicit issuer DID through the temporary physical document owner.

Revision ID: physical_document_issuer_did
Revises: issuance_event_owner
"""

from alembic import op

revision = "physical_document_issuer_did"
down_revision = "issuance_event_owner"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Rust migration 0002 may already own the table during rollback rehearsal.
    op.execute(
        "ALTER TABLE issuance_service.physical_document_jobs "
        "ADD COLUMN IF NOT EXISTS issuer_did text"
    )


def downgrade() -> None:
    # The shared Rust owner also uses this durable column. Dropping the Python
    # Alembic revision must not erase issuer identity for Rust-owned jobs.
    pass
