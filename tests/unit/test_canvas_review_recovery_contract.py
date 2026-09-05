"""Keep the schema model, forward migration and mandatory database gate aligned."""

from importlib import import_module
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from unittest.mock import patch

import pytest
from issuance.infrastructure.models import evidence_policy_reviews_table


def test_forward_migration_matches_model_and_retains_manual_actions() -> None:
    migration = import_module(
        "issuance.infrastructure.migrations.versions.20260905_1900_allow_canvas_review_recovery_claim"
    )
    assert migration.down_revision == "merge_issuance_heads"
    model = next(
        constraint
        for constraint in evidence_policy_reviews_table.constraints
        if constraint.name == "ck_evidence_policy_reviews_resolution_claim"
    )
    with patch.object(migration, "op") as operations:
        migration.upgrade()
        args = operations.create_check_constraint.call_args.args
        assert args[0] == model.name
        assert args[2] == str(model.sqltext)
        for action in ("dismiss", "suspend", "revoke", "evidence_recovered"):
            assert f"'{action}'" in args[2]
        operations.reset_mock()
        migration.downgrade()
        assert "evidence_recovered" not in operations.create_check_constraint.call_args.args[2]


def test_real_postgres_recovery_is_mandatory_in_existing_required_job() -> None:
    workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text()
    job = workflow.split("  oid4vci-capability-postgres:", 1)[1].split("\n  test-wasm:", 1)[0]
    step = job.split("      - name: Exercise Canvas review recovery", 1)[1]
    assert "CANVAS_REVIEW_RECOVERY_TEST_DATABASE_URL:" in step
    assert "pytest tests/test_canvas_review_recovery_postgres.py -v" in step
    assert "if:" not in step and "continue-on-error" not in step


def test_consumer_oracle_distinguishes_published_and_current_schema_heads() -> None:
    path = Path(__file__).resolve().parents[2] / "scripts/verify_canvas_worker_consumer_ranges.py"
    spec = spec_from_file_location("review_recovery_consumer_probe", path)
    assert spec is not None and spec.loader is not None
    probe = module_from_spec(spec)
    spec.loader.exec_module(probe)
    assert probe.expected_migration_revisions("published") == ["merge_issuance_heads"]
    assert probe.expected_migration_revisions("checkout") == ["canvas_review_recovery_claim"]
    with pytest.raises(probe.OracleMismatch, match="Unknown source mode"):
        probe.expected_migration_revisions("unqualified")
