"""Merge the issuance idempotency and ephemeral capability branches.

Revision ID: merge_issuance_heads
Revises: issuance_offer_idempotency, oid4vci_ephemeral_caps
Create Date: 2026-08-10 01:00:00
"""

from collections.abc import Sequence


revision: str = "merge_issuance_heads"
down_revision: tuple[str, str] = (
    "issuance_offer_idempotency",
    "oid4vci_ephemeral_caps",
)
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Join the two schema-complete migration branches."""


def downgrade() -> None:
    """Restore both branch heads without changing either schema."""
