"""Create verification session persistence and retain minimized decision evidence.

Revision ID: 202608081900
Revises:
Create Date: 2026-08-08 19:00:00+00:00
"""

from alembic import op

revision = "202608081900"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS public.verification_sessions (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            verifier_did VARCHAR NOT NULL,
            presentation_definition JSONB NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
            required_credential_types JSONB,
            trusted_issuers JSONB,
            required_claims JSONB,
            presentation_data JSONB,
            verified_claims JSONB,
            verification_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
            verification_method VARCHAR(32),
            verified_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            expires_at TIMESTAMP WITHOUT TIME ZONE,
            error_message TEXT,
            request_uri VARCHAR,
            nonce VARCHAR
        )
        """
    )
    op.execute(
        """
        ALTER TABLE public.verification_sessions
        ADD COLUMN IF NOT EXISTS verification_evidence JSONB NOT NULL DEFAULT '{}'::jsonb
        """
    )
    op.execute(
        "UPDATE public.verification_sessions SET verification_evidence = '{}'::jsonb "
        "WHERE verification_evidence IS NULL"
    )
    op.execute(
        "ALTER TABLE public.verification_sessions "
        "ALTER COLUMN verification_evidence SET DEFAULT '{}'::jsonb"
    )
    op.execute(
        "ALTER TABLE public.verification_sessions "
        "ALTER COLUMN verification_evidence SET NOT NULL"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_verification_sessions_organization_id "
        "ON public.verification_sessions (organization_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_verification_sessions_nonce "
        "ON public.verification_sessions (nonce)"
    )
    # Existing raw presentations are not needed to reconstruct a decision and
    # should not survive the data-minimization migration.
    op.execute(
        "UPDATE public.verification_sessions SET presentation_data = NULL "
        "WHERE presentation_data IS NOT NULL"
    )


def downgrade() -> None:
    # Raw presentation data is intentionally irrecoverable. Preserve the table
    # and session records while removing only the field introduced here.
    op.execute(
        "ALTER TABLE public.verification_sessions DROP COLUMN IF EXISTS verification_evidence"
    )
