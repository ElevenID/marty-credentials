"""Allow the existing internal evidence-recovery resolution claim.

Revision ID: canvas_review_recovery_claim
Revises: merge_issuance_heads

No row is rewritten. Downgrade refuses active recovery claims via PostgreSQL
constraint validation, rather than clearing a live claim or losing its work.
"""

from alembic import op

revision = "canvas_review_recovery_claim"
down_revision = "merge_issuance_heads"
branch_labels = None
depends_on = None


def _replace_claim_constraint(actions: str) -> None:
    op.drop_constraint(
        "ck_evidence_policy_reviews_resolution_claim",
        "evidence_policy_reviews",
        schema="issuance_service",
        type_="check",
    )
    op.create_check_constraint(
        "ck_evidence_policy_reviews_resolution_claim",
        "evidence_policy_reviews",
        "(resolution_claim_token IS NULL AND resolution_claim_action IS NULL "
        "AND resolution_claimed_at IS NULL) OR "
        "(status = 'open' AND resolution_claim_token IS NOT NULL "
        f"AND resolution_claim_action IN ({actions}) "
        "AND resolution_claimed_at IS NOT NULL)",
        schema="issuance_service",
    )


def upgrade() -> None:
    _replace_claim_constraint("'dismiss', 'suspend', 'revoke', 'evidence_recovered'")


def downgrade() -> None:
    _replace_claim_constraint("'dismiss', 'suspend', 'revoke'")
