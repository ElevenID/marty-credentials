"""add evidence facts

Revision ID: add_evidence_facts
Revises: add_credential_delivery_records
Create Date: 2026-05-14 10:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "add_evidence_facts"
down_revision = "add_credential_delivery_records"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.application_templates
            ADD COLUMN IF NOT EXISTS approval_policy_set_id VARCHAR(36)
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.evidence_facts (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            application_id VARCHAR NOT NULL REFERENCES issuance_service.applications(id) ON DELETE CASCADE,
            subject_id VARCHAR NOT NULL,
            provider VARCHAR(80) NOT NULL,
            fact_type VARCHAR(160) NOT NULL,
            scope JSONB NOT NULL DEFAULT '{}'::jsonb,
            assertion JSONB NOT NULL DEFAULT '{}'::jsonb,
            verification JSONB NOT NULL DEFAULT '{}'::jsonb,
            source JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_evidence_facts_organization_id
            ON issuance_service.evidence_facts(organization_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_evidence_facts_application_id
            ON issuance_service.evidence_facts(application_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_evidence_facts_provider
            ON issuance_service.evidence_facts(provider)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_evidence_facts_fact_type
            ON issuance_service.evidence_facts(fact_type)
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_evidence_facts_fact_type")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_evidence_facts_provider")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_evidence_facts_application_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_evidence_facts_organization_id")
    op.execute("DROP TABLE IF EXISTS issuance_service.evidence_facts")
    op.execute(
        """
        ALTER TABLE issuance_service.application_templates
            DROP COLUMN IF EXISTS approval_policy_set_id
        """
    )
