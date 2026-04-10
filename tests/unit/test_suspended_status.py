"""Unit tests exposing 'suspended' status gap in credential template filter.

Issue 6.1: The test data and production SQL only handle 'active', 'draft',
and 'deprecated'.  Templates with status='suspended' are silently excluded
from OID4VCI metadata, which could break wallet flows that previously
fetched configuration for that template ID.

This file extends the existing test_status_filter.py fixtures with the
'suspended' status to demonstrate the gap.
"""

import pytest
from sqlalchemy import text


def _query_with_production_filter(engine, org_id: str) -> list[str]:
    """Run the current production WHERE clause."""
    sql = """
        SELECT DISTINCT credential_type
        FROM "credential_template_service.credential_templates"
        WHERE organization_id = :org_id
          AND status IN ('active', 'draft')
          AND credential_type IS NOT NULL
        ORDER BY credential_type
    """
    with engine.connect() as conn:
        result = conn.execute(text(sql), {"org_id": org_id})
        return [row[0] for row in result.all()]


def _query_all_templates(engine, org_id: str) -> dict[str, str]:
    """Return all templates as {id: status} for inspection."""
    sql = """
        SELECT id, credential_type, status
        FROM "credential_template_service.credential_templates"
        WHERE organization_id = :org_id
        ORDER BY id
    """
    with engine.connect() as conn:
        result = conn.execute(text(sql), {"org_id": org_id})
        return {row[0]: {"type": row[1], "status": row[2]} for row in result.all()}


class TestSuspendedStatusGap:
    """Issue 6.1: suspended templates are excluded from OID4VCI metadata."""

    def test_suspended_template_exists_in_database(self, db_engine_with_suspended) -> None:
        """Verify the 'suspended' template exists."""
        all_templates = _query_all_templates(db_engine_with_suspended, "org-1")
        assert "t4" in all_templates
        assert all_templates["t4"]["status"] == "suspended"
        assert all_templates["t4"]["type"] == "EmployeeBadge"

    def test_suspended_excluded_from_metadata(self, db_engine_with_suspended) -> None:
        """BUG: suspended templates are silently dropped from issuer metadata.

        A wallet that obtained a credential_configuration_id for 'EmployeeBadge'
        before suspension will fail to find it in the metadata, causing confusing
        errors (OID4VCI §10.2.3 says the config SHOULD remain discoverable with
        a status indicator).
        """
        types = _query_with_production_filter(db_engine_with_suspended, "org-1")

        # Active and draft are returned
        assert "DriverLicense" in types
        assert "NationalID" in types

        # BUG: suspended is excluded — no explicit handling
        assert "EmployeeBadge" not in types

    def test_revoked_status_also_excluded(self, db_engine_with_suspended) -> None:
        """'revoked' is another status not in the allow-list."""
        types = _query_with_production_filter(db_engine_with_suspended, "org-1")
        assert "AccessPass" not in types

    def test_only_known_statuses_are_included(self, db_engine_with_suspended) -> None:
        """Only 'active' and 'draft' pass the filter — any new status is excluded.

        This is a maintenance risk: adding a new status like 'pending_review'
        requires updating the SQL WHERE clause, or those templates become invisible.
        """
        types = _query_with_production_filter(db_engine_with_suspended, "org-1")
        # Exactly 2 results (active DriverLicense + draft NationalID)
        assert len(types) == 2
