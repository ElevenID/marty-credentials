"""add Canvas Credentials config to Canvas program bindings

Revision ID: add_canvas_credentials_binding_config
Revises: canonicalize_canvas_lti_launch_states
Create Date: 2026-05-21 11:00:00.000000

"""

from alembic import op


revision = "add_canvas_credentials_binding_config"
down_revision = "canonicalize_canvas_lti_launch_states"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_program_bindings
            ADD COLUMN IF NOT EXISTS canvas_credentials JSON NOT NULL DEFAULT '{}'
        """
    )


def downgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_program_bindings
            DROP COLUMN IF EXISTS canvas_credentials
        """
    )
