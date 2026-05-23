"""add Canvas LTI launch state table

Revision ID: add_canvas_lti_launch_states
Revises: add_canvas_tables
Create Date: 2026-05-07 13:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "add_canvas_lti_launch_states"
down_revision = "add_canvas_tables"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_lti_launch_states (
            id VARCHAR(36) PRIMARY KEY,
            platform_id VARCHAR(36) NOT NULL,
            organization_id VARCHAR(36) NOT NULL,
            canvas_account_id VARCHAR(255) NOT NULL,
            state VARCHAR(255) NOT NULL UNIQUE,
            nonce VARCHAR(255) NOT NULL,
            login_hint TEXT,
            target_link_uri TEXT,
            lti_message_hint TEXT,
            redirect_uri TEXT,
            status VARCHAR(50) NOT NULL DEFAULT 'pending',
            metadata JSON NOT NULL DEFAULT '{}',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            consumed_at TIMESTAMP WITH TIME ZONE
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_lti_launch_states_state
            ON issuance_service.canvas_lti_launch_states(state)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_lti_launch_states_platform_id
            ON issuance_service.canvas_lti_launch_states(platform_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_lti_launch_states_organization_status
            ON issuance_service.canvas_lti_launch_states(organization_id, status)
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_lti_launch_states_organization_status")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_lti_launch_states_platform_id")
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_lti_launch_states_state")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_lti_launch_states")
