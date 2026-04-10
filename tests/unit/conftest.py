"""Shared fixtures for marty-credentials unit tests."""

import pytest
from sqlalchemy import create_engine, text


# ---------------------------------------------------------------------------
# SQLite credential-template fixtures (used by test_status_filter.py and
# test_suspended_status.py)
# ---------------------------------------------------------------------------

_CREATE_TABLE = """
CREATE TABLE "credential_template_service.credential_templates" (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    credential_type TEXT,
    status TEXT NOT NULL DEFAULT 'active'
)
"""


def _make_db_engine(rows: list[tuple[str, str, str | None, str]]):
    """Return a SQLite engine pre-loaded with the given template rows.

    Each row is (id, organization_id, credential_type, status).
    """
    engine = create_engine("sqlite:///:memory:")
    with engine.connect() as conn:
        conn.execute(text(_CREATE_TABLE))
        for row_id, org_id, cred_type, status in rows:
            conn.execute(
                text(
                    'INSERT INTO "credential_template_service.credential_templates"'
                    " (id, organization_id, credential_type, status)"
                    " VALUES (:id, :org, :ctype, :status)"
                ),
                {"id": row_id, "org": org_id, "ctype": cred_type, "status": status},
            )
        conn.commit()
    return engine


_BASE_ROWS = [
    ("t1", "org-1", "DriverLicense", "active"),
    ("t2", "org-1", "NationalID", "draft"),
    ("t3", "org-1", "Passport", "deprecated"),
    ("t4", "org-1", None, "active"),
    ("t5", "org-2", "DriverLicense", "active"),
]

_SUSPENDED_ROWS = [
    ("t1", "org-1", "DriverLicense", "active"),
    ("t2", "org-1", "NationalID", "draft"),
    ("t3", "org-1", "Passport", "deprecated"),
    ("t4", "org-1", "EmployeeBadge", "suspended"),
    ("t5", "org-1", "AccessPass", "revoked"),
    ("t6", "org-1", None, "active"),
]


@pytest.fixture()
def db_engine():
    """In-memory SQLite engine with base test rows (active, draft, deprecated)."""
    return _make_db_engine(_BASE_ROWS)


@pytest.fixture()
def db_engine_with_suspended():
    """In-memory SQLite engine with suspended/revoked rows added."""
    return _make_db_engine(_SUSPENDED_ROWS)
