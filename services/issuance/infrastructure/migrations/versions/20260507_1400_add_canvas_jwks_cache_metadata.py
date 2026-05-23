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
    # Canvas JWKS metadata now lives on canvas_platforms, created by
    # add_canvas_platform_program_bindings. The old connector table is gone.
    pass


def downgrade():
    pass
