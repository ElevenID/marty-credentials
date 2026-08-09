"""Make verification-session claims and terminal decisions atomic.

Revision ID: 202608091200
Revises: 202608081900
Create Date: 2026-08-09 12:00:00+00:00
"""

from alembic import op

revision = "202608091200"
down_revision = "202608081900"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE public.verification_sessions "
        "ADD COLUMN IF NOT EXISTS submission_sha256 VARCHAR(64)"
    )
    op.execute(
        "ALTER TABLE public.verification_sessions "
        "ADD COLUMN IF NOT EXISTS processing_token_sha256 VARCHAR(64)"
    )
    op.execute(
        "ALTER TABLE public.verification_sessions "
        "ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMP WITHOUT TIME ZONE"
    )
    op.execute(
        "ALTER TABLE public.verification_sessions "
        "ADD COLUMN IF NOT EXISTS processing_expires_at TIMESTAMP WITHOUT TIME ZONE"
    )

    # Preserve only a validated digest from the minimized evidence introduced
    # by the parent migration. Missing legacy digests remain unknown rather
    # than being fabricated from data that was intentionally redacted.
    op.execute(
        """
        UPDATE public.verification_sessions
        SET submission_sha256 = lower(verification_evidence->>'presentation_sha256')
        WHERE upper(status) IN ('VERIFIED', 'FAILED')
          AND verification_evidence->>'presentation_sha256' ~ '^[0-9A-Fa-f]{64}$'
        """
    )

    # A pre-migration IN_PROGRESS row has no authenticated digest or worker
    # fence. Reopening it would allow nonce reuse, so migrate it fail closed.
    op.execute(
        """
        UPDATE public.verification_sessions
        SET nonce = NULL,
            processing_token_sha256 = NULL,
            processing_started_at = NULL,
            processing_expires_at = NULL
        WHERE upper(status) IN ('VERIFIED', 'FAILED', 'EXPIRED')
        """
    )

    # Historical terminal decisions are immutable. Once their retained nonces
    # are cleared above, only live rows participate in fail-closed validation.
    op.execute(
        """
        UPDATE public.verification_sessions
        SET status = 'EXPIRED',
            nonce = NULL,
            updated_at = clock_timestamp() AT TIME ZONE 'UTC',
            error_message = 'Verification session had no valid nonce during atomic migration'
        WHERE upper(status) IN ('PENDING', 'IN_PROGRESS')
          AND (nonce IS NULL OR length(nonce) <> 43)
        """
    )
    op.execute(
        """
        WITH duplicate_nonces AS (
            SELECT nonce
            FROM public.verification_sessions
            WHERE nonce IS NOT NULL
              AND upper(status) IN ('PENDING', 'IN_PROGRESS')
            GROUP BY nonce
            HAVING count(*) > 1
        )
        UPDATE public.verification_sessions AS sessions
        SET status = 'EXPIRED',
            nonce = NULL,
            updated_at = clock_timestamp() AT TIME ZONE 'UTC',
            error_message = 'Verification session nonce was not unique during atomic migration'
        FROM duplicate_nonces
        WHERE sessions.nonce = duplicate_nonces.nonce
          AND upper(sessions.status) IN ('PENDING', 'IN_PROGRESS')
        """
    )
    op.execute(
        """
        UPDATE public.verification_sessions
        SET status = 'EXPIRED',
            nonce = NULL,
            processing_token_sha256 = NULL,
            processing_started_at = NULL,
            processing_expires_at = NULL,
            updated_at = clock_timestamp() AT TIME ZONE 'UTC',
            error_message = 'Verification session expired before atomic migration'
        WHERE upper(status) IN ('PENDING', 'IN_PROGRESS')
          AND expires_at IS NOT NULL
          AND expires_at <= clock_timestamp() AT TIME ZONE 'UTC'
        """
    )
    op.execute(
        """
        UPDATE public.verification_sessions
        SET status = 'EXPIRED',
            nonce = NULL,
            processing_token_sha256 = NULL,
            processing_started_at = NULL,
            processing_expires_at = NULL,
            updated_at = clock_timestamp() AT TIME ZONE 'UTC',
            error_message = 'Verification interrupted before atomic session migration'
        WHERE upper(status) = 'IN_PROGRESS'
        """
    )
    op.execute(
        """
        ALTER TABLE public.verification_sessions
        ADD CONSTRAINT ck_verification_nonce_length
        CHECK (nonce IS NULL OR length(nonce) = 43)
        """
    )
    op.execute(
        """
        ALTER TABLE public.verification_sessions
        ADD CONSTRAINT ck_verification_submission_digest
        CHECK (
            submission_sha256 IS NULL
            OR submission_sha256 ~ '^[0-9a-f]{64}$'
        )
        """
    )
    op.execute(
        """
        ALTER TABLE public.verification_sessions
        ADD CONSTRAINT ck_verification_processing_token_digest
        CHECK (
            processing_token_sha256 IS NULL
            OR processing_token_sha256 ~ '^[0-9a-f]{64}$'
        )
        """
    )
    op.execute(
        """
        ALTER TABLE public.verification_sessions
        ADD CONSTRAINT ck_verification_processing_lease
        CHECK (
            processing_started_at IS NULL
            OR processing_expires_at > processing_started_at
        )
        """
    )
    op.execute(
        """
        ALTER TABLE public.verification_sessions
        ADD CONSTRAINT ck_verification_atomic_state
        CHECK (
            (upper(status) = 'PENDING'
             AND nonce IS NOT NULL
             AND submission_sha256 IS NULL
             AND processing_token_sha256 IS NULL
             AND processing_started_at IS NULL
             AND processing_expires_at IS NULL)
            OR
            (upper(status) = 'IN_PROGRESS'
             AND submission_sha256 IS NOT NULL
             AND processing_token_sha256 IS NOT NULL
             AND processing_started_at IS NOT NULL
             AND processing_expires_at IS NOT NULL
             AND nonce IS NOT NULL)
            OR
            (upper(status) IN ('VERIFIED', 'FAILED')
             AND processing_token_sha256 IS NULL
             AND processing_started_at IS NULL
             AND processing_expires_at IS NULL
             AND nonce IS NULL)
            OR
            (upper(status) = 'EXPIRED'
             AND processing_token_sha256 IS NULL
             AND processing_started_at IS NULL
             AND processing_expires_at IS NULL
             AND nonce IS NULL)
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX ux_verification_sessions_live_nonce
        ON public.verification_sessions (nonce)
        WHERE nonce IS NOT NULL
        """
    )


def downgrade() -> None:
    raise RuntimeError(
        "Atomic nonce binding and terminal-decision fencing cannot be safely removed"
    )
