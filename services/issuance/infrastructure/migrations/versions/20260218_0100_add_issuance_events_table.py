"""Add issuance_events table for lifecycle audit logging

Revision ID: add_issuance_events_table
Revises: add_required_checks_to_templates
Create Date: 2026-02-18 01:00:00.000000+00:00

Records immutable lifecycle events emitted during the issuance flow:
  offer_generated    – admin generated a wallet invite
  offer_viewed       – applicant retrieved the offer
  offer_expired      – offer TTL had passed when applicant viewed it
  credential_issued  – wallet completed the OID4VCI exchange
  credential_acknowledged – (reserved for future wallet confirmation)
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_issuance_events_table'
down_revision = 'add_required_checks_to_templates'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'issuance_events',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('transaction_id', sa.String(), nullable=True),
        sa.Column('application_id', sa.String(), nullable=True),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text('NOW()'),
        ),
        sa.PrimaryKeyConstraint('id'),
        schema='issuance_service',
    )
    op.create_index(
        'ix_issuance_events_application_id',
        'issuance_events',
        ['application_id'],
        schema='issuance_service',
    )
    op.create_index(
        'ix_issuance_events_transaction_id',
        'issuance_events',
        ['transaction_id'],
        schema='issuance_service',
    )
    op.create_index(
        'ix_issuance_events_event_type',
        'issuance_events',
        ['event_type'],
        schema='issuance_service',
    )


def downgrade() -> None:
    op.drop_index('ix_issuance_events_event_type', table_name='issuance_events', schema='issuance_service')
    op.drop_index('ix_issuance_events_transaction_id', table_name='issuance_events', schema='issuance_service')
    op.drop_index('ix_issuance_events_application_id', table_name='issuance_events', schema='issuance_service')
    op.drop_table('issuance_events', schema='issuance_service')
