"""add Canvas JWKS cache metadata

Revision ID: add_canvas_jwks_cache_metadata
Revises: add_canvas_lti_launch_states
Create Date: 2026-05-07 14:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "add_canvas_jwks_cache_metadata"
down_revision = "add_canvas_lti_launch_states"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_connectors
            ADD COLUMN IF NOT EXISTS lti_jwks_fetched_at TIMESTAMP WITH TIME ZONE,
            ADD COLUMN IF NOT EXISTS lti_jwks_expires_at TIMESTAMP WITH TIME ZONE
        """
    )


def downgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_connectors
            DROP COLUMN IF EXISTS lti_jwks_expires_at,
            DROP COLUMN IF EXISTS lti_jwks_fetched_at
        """
    )
