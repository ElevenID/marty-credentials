"""Add application_templates and applications tables

Revision ID: add_application_tables
Revises: 735160618517
Create Date: 2026-02-04 00:30:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_application_tables'
down_revision = '735160618517'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create application_templates table
    op.create_table('application_templates',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('credential_template_id', sa.String(), nullable=False),
        sa.Column('form_fields', sa.JSON(), nullable=False),
        sa.Column('evidence_requirements', sa.JSON(), nullable=False),
        sa.Column('claim_collection_rules', sa.JSON(), nullable=False),
        sa.Column('approval_strategy', sa.String(), nullable=False),
        sa.Column('application_validity_days', sa.Integer(), nullable=False),
        sa.Column('auto_approval_rules', sa.JSON(), nullable=False),
        sa.Column('ui_config', sa.JSON(), nullable=False),
        sa.Column('notification_config', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='issuance_service'
    )
    op.create_index('ix_application_templates_organization_id', 'application_templates', ['organization_id'], unique=False, schema='issuance_service')
    op.create_index('ix_application_templates_status', 'application_templates', ['status'], unique=False, schema='issuance_service')
    
    # Create applications table
    op.create_table('applications',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(), nullable=False),
        sa.Column('application_template_id', sa.String(), nullable=False),
        sa.Column('applicant_identifier', sa.String(), nullable=False),
        sa.Column('form_data', sa.JSON(), nullable=False),
        sa.Column('submitted_evidence', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('review_notes', sa.String(), nullable=True),
        sa.Column('rejection_reason', sa.String(), nullable=True),
        sa.Column('derived_claims', sa.JSON(), nullable=False),
        sa.Column('credential_id', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='issuance_service'
    )
    op.create_index('ix_applications_organization_id', 'applications', ['organization_id'], unique=False, schema='issuance_service')
    op.create_index('ix_applications_status', 'applications', ['status'], unique=False, schema='issuance_service')
    op.create_index('ix_applications_template_id', 'applications', ['application_template_id'], unique=False, schema='issuance_service')
    op.create_index('ix_applications_applicant_identifier', 'applications', ['applicant_identifier'], unique=False, schema='issuance_service')


def downgrade() -> None:
    # Drop applications table
    op.drop_index('ix_applications_applicant_identifier', table_name='applications', schema='issuance_service')
    op.drop_index('ix_applications_template_id', table_name='applications', schema='issuance_service')
    op.drop_index('ix_applications_status', table_name='applications', schema='issuance_service')
    op.drop_index('ix_applications_organization_id', table_name='applications', schema='issuance_service')
    op.drop_table('applications', schema='issuance_service')
    
    # Drop application_templates table
    op.drop_index('ix_application_templates_status', table_name='application_templates', schema='issuance_service')
    op.drop_index('ix_application_templates_organization_id', table_name='application_templates', schema='issuance_service')
    op.drop_table('application_templates', schema='issuance_service')
