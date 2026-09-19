"""Keep Application Template management storage and migration guarantees aligned."""

from importlib import import_module

from issuance.infrastructure.models import application_templates_table


def test_model_enforces_versioned_tenant_idempotency() -> None:
    columns = application_templates_table.c
    assert columns.management_version.nullable is False
    assert columns.management_version.default.arg == 1
    assert columns.idempotency_key_hash.type.length == 64
    assert columns.idempotency_request_hash.type.length == 64

    constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in application_templates_table.constraints
        if constraint.name is not None and hasattr(constraint, "sqltext")
    }
    assert constraints["ck_application_templates_management_version"] == ("management_version > 0")
    assert (
        "idempotency_key_hash IS NULL" in constraints["ck_application_templates_idempotency_pair"]
    )
    assert (
        "idempotency_request_hash IS NOT NULL"
        in constraints["ck_application_templates_idempotency_pair"]
    )
    assert "^[0-9a-f]{64}$" in constraints["ck_application_templates_idempotency_key_hash"]
    assert "^[0-9a-f]{64}$" in constraints["ck_application_templates_idempotency_request_hash"]

    index = next(
        item
        for item in application_templates_table.indexes
        if item.name == "ux_application_templates_org_idempotency_key_hash"
    )
    assert index.unique is True
    assert [column.name for column in index.columns] == [
        "organization_id",
        "idempotency_key_hash",
    ]
    assert str(index.dialect_options["postgresql"]["where"]) == ("idempotency_key_hash IS NOT NULL")


def test_migration_adds_and_exactly_removes_management_storage(monkeypatch) -> None:
    migration = import_module(
        "issuance.infrastructure.migrations.versions.20260919_2200_application_template_management"
    )
    statements: list[str] = []
    monkeypatch.setattr(
        migration.op,
        "execute",
        lambda statement: statements.append(str(statement)),
    )

    migration.upgrade()

    assert migration.down_revision == "canvas_review_recovery_claim"
    assert len(statements) == 1
    upgrade = statements.pop()
    for fragment in (
        "ADD COLUMN IF NOT EXISTS management_version BIGINT NOT NULL DEFAULT 1",
        "ADD COLUMN IF NOT EXISTS idempotency_key_hash VARCHAR(64)",
        "ADD COLUMN IF NOT EXISTS idempotency_request_hash VARCHAR(64)",
        "CHECK (management_version > 0)",
        "ux_application_templates_org_idempotency_key_hash",
        "organization_id",
        "WHERE idempotency_key_hash IS NOT NULL",
    ):
        assert fragment in upgrade

    migration.downgrade()

    assert len(statements) == 1
    downgrade = statements.pop()
    for fragment in (
        "DROP INDEX IF EXISTS",
        "ux_application_templates_org_idempotency_key_hash",
        "DROP CONSTRAINT IF EXISTS ck_application_templates_idempotency_pair",
        "DROP COLUMN IF EXISTS idempotency_request_hash",
        "DROP COLUMN IF EXISTS idempotency_key_hash",
        "DROP COLUMN IF EXISTS management_version",
    ):
        assert fragment in downgrade
