"""Add Canvas program binding deployment profile feature gates.

Revision ID: add_canvas_program_binding_feature_gates
Revises: add_canvas_platform_program_bindings
"""

from alembic import op


revision = "add_canvas_program_binding_feature_gates"
down_revision = "add_canvas_platform_program_bindings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_program_bindings
            ADD COLUMN IF NOT EXISTS deployment_profile_id TEXT,
            ADD COLUMN IF NOT EXISTS feature_flags JSON NOT NULL DEFAULT '{}'::json
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_canvas_program_bindings_deployment_profile_id
            ON issuance_service.canvas_program_bindings(deployment_profile_id)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS issuance_service.ix_canvas_program_bindings_deployment_profile_id")
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_program_bindings
            DROP COLUMN IF EXISTS feature_flags,
            DROP COLUMN IF EXISTS deployment_profile_id
        """
    )
