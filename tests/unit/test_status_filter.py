"""Unit tests for the SQL status filter in credential template discovery (Bug #2).

The OID4VCI issuer metadata endpoint must list credential_configuration_ids
for all templates that wallets might request.  Draft templates are valid —
they have a credential_type and their configuration must appear in the
metadata so that wallets with pre-generated QR codes can still complete
issuance.  Only 'deprecated' templates should be excluded.

The original bug filtered ``status = 'active'`` which silently dropped
draft templates.  The fix changed the query to ``status IN ('active', 'draft')``.

These tests verify the WHERE-clause logic against an in-memory SQLite
database so no Postgres instance is required.
"""

import pytest
from sqlalchemy import text


class TestStatusFilterIncludesDraft:
    """Bug #2: Draft templates must be discoverable in issuer metadata."""

    def _query_credential_types(
        self, engine, org_id: str, *, include_draft: bool = True
    ) -> list[str]:
        """Run the query with the fixed or unfixed WHERE clause."""
        if include_draft:
            # FIXED query — must match production code
            sql = """
                SELECT DISTINCT credential_type
                FROM "credential_template_service.credential_templates"
                WHERE organization_id = :org_id
                  AND status IN ('active', 'draft')
                  AND credential_type IS NOT NULL
                ORDER BY credential_type
            """
        else:
            # BUGGY original query
            sql = """
                SELECT DISTINCT credential_type
                FROM "credential_template_service.credential_templates"
                WHERE organization_id = :org_id
                  AND status = 'active'
                  AND credential_type IS NOT NULL
                ORDER BY credential_type
            """
        with engine.connect() as conn:
            result = conn.execute(text(sql), {"org_id": org_id})
            return [row[0] for row in result.all()]

    def test_fixed_query_returns_active_and_draft(self, db_engine) -> None:
        """The fixed query must return both 'active' and 'draft' templates."""
        types = self._query_credential_types(db_engine, "org-1", include_draft=True)
        assert "DriverLicense" in types
        assert "NationalID" in types  # draft — this was the missing one

    def test_fixed_query_excludes_deprecated(self, db_engine) -> None:
        """Deprecated templates must NOT appear in the results."""
        types = self._query_credential_types(db_engine, "org-1", include_draft=True)
        assert "Passport" not in types

    def test_fixed_query_excludes_null_type(self, db_engine) -> None:
        """Templates without credential_type must be excluded."""
        types = self._query_credential_types(db_engine, "org-1", include_draft=True)
        assert None not in types
        # id=t4 has NULL type — should not produce a row
        assert len(types) == 2

    def test_buggy_query_misses_draft(self, db_engine) -> None:
        """Demonstrate the original bug: draft templates are lost."""
        types = self._query_credential_types(db_engine, "org-1", include_draft=False)
        assert "NationalID" not in types  # draft is missing!
        assert "DriverLicense" in types

    def test_org_isolation(self, db_engine) -> None:
        """Each organisation only sees its own templates."""
        types = self._query_credential_types(db_engine, "org-2", include_draft=True)
        assert types == ["DriverLicense"]
        assert "NationalID" not in types  # belongs to org-1
