"""canonicalize Canvas LTI launch states on platform runtime

Revision ID: canonicalize_canvas_lti_launch_states
Revises: add_issued_credential_status_list_metadata
Create Date: 2026-05-21 10:00:00.000000

"""

from alembic import op


revision = "canonicalize_canvas_lti_launch_states"
down_revision = "add_issued_credential_status_list_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_lti_launch_states
            ADD COLUMN IF NOT EXISTS platform_id VARCHAR(36)
        """
    )
    op.execute(
        """
        UPDATE issuance_service.canvas_lti_launch_states launch
        SET platform_id = platform.id
        FROM issuance_service.canvas_platforms platform
        WHERE launch.platform_id IS NULL
          AND platform.organization_id = launch.organization_id
          AND platform.canvas_account_id = launch.canvas_account_id
        """
    )
    op.execute(
        """
        DELETE FROM issuance_service.canvas_lti_launch_states
        WHERE platform_id IS NULL
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'issuance_service'
                  AND table_name = 'canvas_lti_launch_states'
                  AND column_name = 'connector_id'
            ) THEN
                ALTER TABLE issuance_service.canvas_lti_launch_states
                    DROP CONSTRAINT IF EXISTS canvas_lti_launch_states_connector_id_fkey;
                DROP INDEX IF EXISTS issuance_service.ix_canvas_lti_launch_states_connector_id;
                ALTER TABLE issuance_service.canvas_lti_launch_states
                    DROP COLUMN IF EXISTS connector_id;
            END IF;
        END $$;
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_lti_launch_states
            ALTER COLUMN platform_id SET NOT NULL
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'canvas_lti_launch_states_platform_id_fkey'
                  AND conrelid = 'issuance_service.canvas_lti_launch_states'::regclass
            ) THEN
                ALTER TABLE issuance_service.canvas_lti_launch_states
                    ADD CONSTRAINT canvas_lti_launch_states_platform_id_fkey
                    FOREIGN KEY (platform_id)
                    REFERENCES issuance_service.canvas_platforms(id)
                    ON DELETE CASCADE;
            END IF;
        END $$;
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_lti_launch_states_platform_id
            ON issuance_service.canvas_lti_launch_states(platform_id)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_lti_launch_states_platform_id")
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_lti_launch_states
            DROP CONSTRAINT IF EXISTS canvas_lti_launch_states_platform_id_fkey
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_lti_launch_states
            DROP COLUMN IF EXISTS platform_id
        """
    )
