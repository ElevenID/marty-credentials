"""add issued credential status list metadata

Revision ID: add_issued_credential_status_list_metadata
Revises: add_canvas_program_binding_feature_gates
Create Date: 2026-05-19 10:00:00.000000

"""

from alembic import op


revision = "add_issued_credential_status_list_metadata"
down_revision = "add_canvas_program_binding_feature_gates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE issuance_service.issued_credentials
            ADD COLUMN IF NOT EXISTS revocation_profile_id VARCHAR(36),
            ADD COLUMN IF NOT EXISTS status_list_entries JSON NOT NULL DEFAULT '[]'::json
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_issued_credentials_revocation_profile_id
            ON issuance_service.issued_credentials(revocation_profile_id)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_issued_credentials_revocation_profile_id")
    op.execute(
        """
        ALTER TABLE issuance_service.issued_credentials
            DROP COLUMN IF EXISTS status_list_entries,
            DROP COLUMN IF EXISTS revocation_profile_id
        """
    )
