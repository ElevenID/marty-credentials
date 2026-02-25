"""Add authorization_sessions table for OID4VCI authorization code flow

Revision ID: add_authorization_sessions_table
Revises: add_issuance_events_table
Create Date: 2026-02-21 01:00:00.000000+00:00

Stores OAuth 2.0 authorization code sessions used during the OID4VCI
authorization code flow (§5).  The authorization endpoint creates a
session and the token endpoint consumes it.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_authorization_sessions_table'
down_revision = 'add_issuance_events_table'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'authorization_sessions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('code', sa.String(), nullable=False, unique=True),
        sa.Column('client_id', sa.String(), nullable=False),
        sa.Column('redirect_uri', sa.String(), nullable=True),
        sa.Column('scope', sa.String(), nullable=True),
        sa.Column('state', sa.String(), nullable=True),
        sa.Column('issuer_state', sa.String(), nullable=True),
        sa.Column('credential_configuration_ids', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('organization_id', sa.String(), nullable=True),
        sa.Column('code_challenge', sa.String(), nullable=True),
        sa.Column('code_challenge_method', sa.String(), nullable=True),
        sa.Column('access_token', sa.String(), nullable=True),
        sa.Column('c_nonce', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='pending'),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text('NOW()'),
        ),
        sa.Column(
            'expires_at',
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW() + INTERVAL '10 minutes'"),
        ),
        sa.PrimaryKeyConstraint('id'),
        schema='issuance_service',
    )
    op.create_index(
        'ix_authorization_sessions_code',
        'authorization_sessions',
        ['code'],
        schema='issuance_service',
    )
    op.create_index(
        'ix_authorization_sessions_status',
        'authorization_sessions',
        ['status'],
        schema='issuance_service',
    )
    op.create_index(
        'ix_authorization_sessions_issuer_state',
        'authorization_sessions',
        ['issuer_state'],
        schema='issuance_service',
    )


def downgrade() -> None:
    op.drop_index('ix_authorization_sessions_issuer_state', table_name='authorization_sessions', schema='issuance_service')
    op.drop_index('ix_authorization_sessions_status', table_name='authorization_sessions', schema='issuance_service')
    op.drop_index('ix_authorization_sessions_code', table_name='authorization_sessions', schema='issuance_service')
    op.drop_table('authorization_sessions', schema='issuance_service')
