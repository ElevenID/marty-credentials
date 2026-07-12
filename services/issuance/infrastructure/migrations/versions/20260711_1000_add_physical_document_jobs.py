"""Add MIP physical document production jobs.

Revision ID: add_physical_document_jobs
Revises: add_org_integration_secrets
"""

import sqlalchemy as sa
from alembic import op


revision = "add_physical_document_jobs"
down_revision = "add_org_integration_secrets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "physical_document_jobs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("flow_execution_id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("application_template_id", sa.String(), nullable=False),
        sa.Column("credential_template_id", sa.String(), nullable=False),
        sa.Column("delivery_destination_profile_id", sa.String(128), nullable=False),
        sa.Column("document_type", sa.String(3), nullable=False),
        sa.Column("country_code", sa.String(3), nullable=False),
        sa.Column("secure_artifact_ciphertext", sa.Text(), nullable=False),
        sa.Column("secure_artifact_reference", sa.String(512), nullable=False),
        sa.Column("sod_sha256", sa.String(64), nullable=True),
        sa.Column("bureau_job_id", sa.String(255), nullable=True),
        sa.Column("tracking_number", sa.String(255), nullable=True),
        sa.Column("status", sa.String(40), nullable=False, server_default="DRAFT"),
        sa.Column("quality_result", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(128), nullable=True),
        sa.Column("error_message", sa.String(1024), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_id"),
        schema="issuance_service",
    )
    op.create_index("ix_physical_document_jobs_organization_id", "physical_document_jobs", ["organization_id"], schema="issuance_service")
    op.create_index("ix_physical_document_jobs_flow_execution_id", "physical_document_jobs", ["flow_execution_id"], schema="issuance_service")
    op.create_index("ix_physical_document_jobs_status", "physical_document_jobs", ["status"], schema="issuance_service")
    op.create_index("ix_physical_document_jobs_bureau_job_id", "physical_document_jobs", ["bureau_job_id"], schema="issuance_service")


def downgrade() -> None:
    op.drop_table("physical_document_jobs", schema="issuance_service")
