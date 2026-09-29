"""Share the bureau callback binding with native issuance during rollback.

Revision ID: physical_document_bureau_binding
Revises: physical_document_issuer_did
"""

from alembic import op

revision = "physical_document_bureau_binding"
down_revision = "physical_document_issuer_did"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Native migration 0003 may already have created this shared column.
    op.execute(
        "ALTER TABLE issuance_service.physical_document_jobs "
        "ADD COLUMN IF NOT EXISTS bureau_provider_profile_id varchar(128)"
    )
    op.execute(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint "
        "WHERE conrelid = 'issuance_service.physical_document_jobs'::regclass "
        "AND conname = 'ck_physical_document_jobs_bureau_provider_binding') THEN "
        "ALTER TABLE issuance_service.physical_document_jobs "
        "ADD CONSTRAINT ck_physical_document_jobs_bureau_provider_binding "
        "CHECK (bureau_provider_profile_id IS NULL OR "
        "(bureau_job_id IS NOT NULL AND LENGTH(BTRIM(bureau_job_id)) BETWEEN 1 AND 255 "
        "AND LENGTH(BTRIM(bureau_provider_profile_id)) BETWEEN 1 AND 128)); "
        "END IF; END $$"
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "ux_physical_document_jobs_bureau_provider_job "
        "ON issuance_service.physical_document_jobs "
        "(bureau_provider_profile_id, bureau_job_id) "
        "WHERE bureau_provider_profile_id IS NOT NULL AND bureau_job_id IS NOT NULL"
    )


def downgrade() -> None:
    # Rust owns the shared callback identity and must retain it.
    pass
