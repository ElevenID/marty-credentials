"""add_credential_payload_format_and_wallet_configs_to_issuance_transactions

Revision ID: add_credential_payload_format
Revises: add_zk_predicate_claims
Create Date: 2026-02-24 01:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_credential_payload_format'
down_revision = 'add_zk_predicate_claims'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'issuance_transactions',
        sa.Column(
            'credential_payload_format',
            sa.String(30),
            nullable=False,
            server_default='w3c_vcdm_v2_sd_jwt',
        ),
        schema='issuance_service',
    )
    op.add_column(
        'issuance_transactions',
        sa.Column(
            'wallet_configs',
            sa.JSON(),
            nullable=True,
            server_default='[]',
        ),
        schema='issuance_service',
    )


def downgrade():
    op.drop_column('issuance_transactions', 'wallet_configs', schema='issuance_service')
    op.drop_column('issuance_transactions', 'credential_payload_format', schema='issuance_service')
