"""add issuer_signing_keys table for encrypted persistent key storage

Revision ID: add_issuer_signing_keys
Revises: add_revocation_to_tx
Create Date: 2026-03-30 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_issuer_signing_keys'
down_revision = 'add_revocation_to_tx'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'issuer_signing_keys',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(), nullable=False),
        sa.Column('issuer_did', sa.String(), nullable=False),
        sa.Column('key_algorithm', sa.String(), nullable=False, server_default='Ed25519'),
        sa.Column('encrypted_jwk_json', sa.Text(), nullable=False),
        sa.Column('public_key_b64', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id'),
        schema='issuance_service',
    )
    op.create_index(
        'ix_issuer_signing_keys_organization_id',
        'issuer_signing_keys',
        ['organization_id'],
        unique=False,
        schema='issuance_service',
    )


def downgrade():
    op.drop_index(
        'ix_issuer_signing_keys_organization_id',
        table_name='issuer_signing_keys',
        schema='issuance_service',
    )
    op.drop_table('issuer_signing_keys', schema='issuance_service')