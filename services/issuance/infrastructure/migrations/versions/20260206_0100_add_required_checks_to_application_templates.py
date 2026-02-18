"""Add required_checks column to application_templates table

Revision ID: add_required_checks_to_templates
Revises: add_missing_application_columns
Create Date: 2026-02-06 01:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_required_checks_to_templates'
down_revision = 'add_missing_application_columns'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add required_checks column to application_templates table.
    # Stores a JSON array of pluggable vetting check configurations:
    # [{ check_type, custom_name, is_required, order, config, external_provider, webhook_url }]
    op.add_column(
        'application_templates',
        sa.Column(
            'required_checks',
            sa.JSON(),
            nullable=False,
            server_default='[]',
        ),
        schema='issuance_service',
    )


def downgrade() -> None:
    op.drop_column('application_templates', 'required_checks', schema='issuance_service')
