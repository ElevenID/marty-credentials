"""persist DPoP sender-constrained token thumbprints.

Revision ID: add_dpop_token_binding
Revises: portable_canvas_connections
Create Date: 2026-07-19 10:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "add_dpop_token_binding"
down_revision = "portable_canvas_connections"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("authorization_sessions", sa.Column("dpop_jkt", sa.String(), nullable=True), schema="issuance_service")


def downgrade() -> None:
    op.drop_column("authorization_sessions", "dpop_jkt", schema="issuance_service")
