from __future__ import annotations

from datetime import UTC, datetime, timedelta
from importlib import import_module
from inspect import getsource

import pytest
from issuance.domain.entities import (
    CanvasEvidenceSyncJobStatus,
    CanvasEvidenceSyncTarget,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.models import (
    application_templates_table,
    applications_table,
    canvas_award_candidates_table,
    canvas_candidate_observations_table,
    canvas_evidence_sync_jobs_table,
    canvas_evidence_sync_targets_table,
    canvas_learner_identities_table,
    canvas_oauth_authorizations_table,
    canvas_oauth_connections_table,
    canvas_platforms_table,
    canvas_program_bindings_table,
    evidence_fact_heads_table,
    evidence_facts_table,
    evidence_policy_reviews_table,
    issuance_transactions_table,
    issued_credentials_table,
)
from sqlalchemy import ForeignKeyConstraint

migration = import_module(
    "issuance.infrastructure.migrations.versions.20260714_1000_portable_canvas_connections"
)


def _assignment_requirement(requirement_id: str = "assignment-pass") -> dict:
    return {
        "requirement_id": requirement_id,
        "source": "canvas_rest",
        "fact_type": "canvas.assignment_score",
        "scope": {"course_id": "42", "assignment_id": "7"},
        "pass_rule": {"min_score_percent": 80},
        "required": True,
    }


def test_migration_normalizes_only_unambiguous_portable_requirements() -> None:
    normalized = migration.normalize_portable_requirement(_assignment_requirement())

    assert normalized == {
        "requirement_id": "assignment-pass",
        "source": "canvas_rest",
        "fact_type": "canvas.assignment_score",
        "scope": {"course_id": "42", "activity_id": "7"},
        "pass_rule": {"min_score_percent": 80.0},
        "required": True,
    }

    conflicting_aliases = _assignment_requirement()
    conflicting_aliases["scope"]["activity_id"] = "8"
    assert migration.normalize_portable_requirement(conflicting_aliases) is None

    bad_ags = {
        "requirement_id": "ags-pass",
        "source": "ags_result",
        "fact_type": "canvas.assignment_score",
        "scope": {"course_id": "42", "line_item_url": "http://canvas/line-items/7"},
        "pass_rule": {"min_score_percent": 80},
        "required": True,
    }
    assert migration.normalize_portable_requirement(bad_ags) is None


def test_migration_quarantines_non_arrays_empty_sets_and_duplicate_ids() -> None:
    for raw, reason in (
        ({"webhook": "legacy"}, "requirements_not_array"),
        ([], "requirements_empty"),
    ):
        converted, ambiguous = migration.migrate_canvas_requirements("binding-1", raw)
        assert ambiguous is True
        assert converted[0]["enabled"] is False
        assert converted[0]["migration_review_required"] is True
        assert converted[0]["migration_review_reason"] == reason
        assert converted[0]["legacy_requirement"] == raw

    duplicate = [_assignment_requirement("same"), _assignment_requirement("same")]
    converted, ambiguous = migration.migrate_canvas_requirements("binding-1", duplicate)
    assert ambiguous is True
    assert [item["migration_review_reason"] for item in converted] == [
        "duplicate_requirement_id",
        "duplicate_requirement_id",
    ]
    assert [item["legacy_requirement"] for item in converted] == duplicate


def test_migration_preserves_valid_rules_while_quarantining_legacy_values() -> None:
    valid = _assignment_requirement()
    legacy = "canvas.course_completion"

    converted, ambiguous = migration.migrate_canvas_requirements(
        "binding-1",
        [valid, legacy],
    )

    assert ambiguous is True
    assert converted[0]["source"] == "canvas_rest"
    assert converted[1]["source"] == "legacy_unportable"
    assert converted[1]["legacy_requirement"] == legacy


def test_persistence_metadata_matches_database_concurrency_contracts() -> None:
    assert issuance_transactions_table.c.reserved_credential_id.nullable is True
    credential_indexes = {index.name: index for index in issued_credentials_table.indexes}
    assert credential_indexes["ux_issued_credentials_transaction_id"].unique is True

    trust_profile = canvas_platforms_table.c.lti_trust_profile
    assert trust_profile.nullable is False
    assert str(trust_profile.server_default.arg) == "hosted_global"
    assert str(canvas_platforms_table.c.enabled.server_default.arg) == "false"
    assert str(canvas_program_bindings_table.c.enabled.server_default.arg) == "false"

    target_foreign_keys = {
        foreign_key.target_fullname
        for foreign_key in canvas_evidence_sync_targets_table.c.candidate_id.foreign_keys
    }
    assert target_foreign_keys == {"issuance_service.canvas_award_candidates.id"}

    target_indexes = {index.name: index for index in canvas_evidence_sync_targets_table.indexes}
    assert target_indexes["ux_canvas_sync_targets_org_logical"].unique is True
    assert "ix_canvas_sync_targets_candidate_id" in target_indexes

    job_indexes = {index.name: index for index in canvas_evidence_sync_jobs_table.indexes}
    active = job_indexes["ux_canvas_sync_jobs_one_active_target"]
    assert active.unique is True
    assert "queued" in str(active.dialect_options["postgresql"]["where"])
    assert "leased" in str(active.dialect_options["postgresql"]["where"])
    assert "retry" in str(active.dialect_options["postgresql"]["where"])

    review_indexes = {index.name: index for index in evidence_policy_reviews_table.indexes}
    one_open = review_indexes["ux_evidence_policy_reviews_one_open_application"]
    assert one_open.unique is True
    assert "status = 'open'" in str(one_open.dialect_options["postgresql"]["where"])


def _tenant_constraint(table, name: str) -> ForeignKeyConstraint:
    matches = [
        constraint
        for constraint in table.foreign_key_constraints
        if constraint.name == name
    ]
    assert len(matches) == 1
    return matches[0]


def test_portable_canvas_models_enforce_tenant_owned_relationships() -> None:
    expected = {
        canvas_program_bindings_table: {
            "fk_canvas_program_bindings_tenant_platform",
            "fk_canvas_program_bindings_tenant_application_template",
        },
        evidence_facts_table: {
            "fk_evidence_facts_tenant_application",
            "fk_evidence_facts_tenant_superseded",
        },
        evidence_fact_heads_table: {
            "fk_evidence_fact_heads_tenant_application",
            "fk_evidence_fact_heads_tenant_fact",
        },
        canvas_learner_identities_table: {
            "fk_canvas_learner_identities_tenant_platform",
        },
        canvas_oauth_authorizations_table: {
            "fk_canvas_oauth_authorizations_tenant_platform",
        },
        canvas_oauth_connections_table: {
            "fk_canvas_oauth_connections_tenant_platform",
        },
        canvas_evidence_sync_targets_table: {
            "fk_canvas_sync_targets_tenant_platform",
            "fk_canvas_sync_targets_tenant_binding",
            "fk_canvas_sync_targets_tenant_application",
            "fk_canvas_sync_targets_tenant_candidate",
        },
        canvas_evidence_sync_jobs_table: {"fk_canvas_sync_jobs_tenant_target"},
        canvas_award_candidates_table: {
            "fk_canvas_award_candidates_tenant_platform",
            "fk_canvas_award_candidates_tenant_binding",
            "fk_canvas_award_candidates_tenant_identity",
            "fk_canvas_award_candidates_tenant_application",
            "fk_canvas_award_candidates_tenant_credential",
        },
        canvas_candidate_observations_table: {
            "fk_canvas_candidate_observations_tenant_candidate",
            "fk_canvas_candidate_observations_tenant_superseded",
        },
        evidence_policy_reviews_table: {
            "fk_evidence_policy_reviews_tenant_application",
            "fk_evidence_policy_reviews_tenant_credential",
            "fk_evidence_policy_reviews_tenant_binding",
            "fk_evidence_policy_reviews_tenant_fact",
        },
    }
    for table, names in expected.items():
        for name in names:
            constraint = _tenant_constraint(table, name)
            assert constraint.column_keys[0] == "organization_id"
            assert constraint.elements[0].target_fullname.endswith(".organization_id")
            assert name in getsource(migration.upgrade)

    assert _tenant_constraint(
        evidence_fact_heads_table,
        "fk_evidence_fact_heads_tenant_fact",
    ).column_keys == ["organization_id", "application_id", "logical_key", "fact_id"]
    assert _tenant_constraint(
        canvas_candidate_observations_table,
        "fk_canvas_candidate_observations_tenant_superseded",
    ).column_keys == [
        "organization_id",
        "candidate_id",
        "logical_key",
        "superseded_observation_id",
    ]

    for parent in (
        application_templates_table,
        applications_table,
        canvas_platforms_table,
        canvas_program_bindings_table,
        canvas_learner_identities_table,
        canvas_evidence_sync_targets_table,
        canvas_award_candidates_table,
        canvas_candidate_observations_table,
        evidence_facts_table,
        issued_credentials_table,
    ):
        assert any(
            index.unique
            and [column.name for column in index.columns][:2] == ["organization_id", "id"]
            for index in parent.indexes
        ), parent.name


def test_migration_backs_up_tenant_context_and_uses_sha256_revision_metadata() -> None:
    upgrade_source = getsource(migration.upgrade)
    downgrade_source = getsource(migration.downgrade)

    assert "canvas_program_binding_requirement_backups" in upgrade_source
    assert "canvas_platform_state_backups" in upgrade_source
    assert "binding_id,\n                organization_id," in upgrade_source
    assert "binding.organization_id = backup.organization_id" in downgrade_source
    assert "platform.organization_id = backup.organization_id" in downgrade_source
    assert "ALTER COLUMN enabled SET DEFAULT false" in upgrade_source
    assert "ALTER COLUMN enabled SET DEFAULT true" in downgrade_source
    assert "encode(sha256(convert_to(" in upgrade_source
    assert "md5(" not in upgrade_source


def test_oauth_secret_references_are_pinned_to_the_row_tenant() -> None:
    expected = {
        canvas_oauth_authorizations_table: {
            "ck_canvas_oauth_authorizations_tenant_secret_ref",
        },
        canvas_oauth_connections_table: {
            "ck_canvas_oauth_connections_tenant_secret_refs",
        },
    }
    upgrade_source = getsource(migration.upgrade)
    for table, names in expected.items():
        check_names = {constraint.name for constraint in table.constraints}
        for name in names:
            assert name in check_names
            assert name in upgrade_source


def test_platform_and_binding_persistence_fail_closed() -> None:
    expected = {
        canvas_platforms_table: {
            "ck_canvas_platforms_config_version",
            "ck_canvas_platforms_registration_status",
            "ck_canvas_platforms_archival_state",
        },
        canvas_program_bindings_table: {
            "ck_canvas_program_bindings_config_versions",
            "ck_canvas_program_bindings_archival_state",
            "ck_canvas_program_bindings_activation_state",
        },
    }
    upgrade_source = getsource(migration.upgrade)
    downgrade_source = getsource(migration.downgrade)
    for table, names in expected.items():
        check_names = {constraint.name for constraint in table.constraints}
        for name in names:
            assert name in check_names
            assert name in upgrade_source
            assert name in downgrade_source


@pytest.mark.asyncio
async def test_expired_final_attempt_is_dead_lettered_without_a_ninth_lease() -> None:
    repo = InMemoryIssuanceRepository()
    target = CanvasEvidenceSyncTarget(
        organization_id="org-1",
        platform_id="platform-1",
        binding_id="binding-1",
        logical_key="application:app-1",
    )
    await repo.save_canvas_sync_target(target)
    job = await repo.enqueue_canvas_sync_job(target)
    job.max_attempts = 1

    leased = await repo.lease_canvas_sync_jobs(worker_id="worker-1")
    assert [item.id for item in leased] == [job.id]
    job.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)

    assert await repo.lease_canvas_sync_jobs(worker_id="worker-2") == []
    assert job.status == CanvasEvidenceSyncJobStatus.DEAD_LETTER
    assert job.attempt_count == 1
    assert job.last_error_code == "canvas_worker_lease_expired"
    assert target.enabled is False


@pytest.mark.asyncio
async def test_expired_nonfinal_lease_uses_retry_backoff_before_reclaim() -> None:
    repo = InMemoryIssuanceRepository()
    target = CanvasEvidenceSyncTarget(
        organization_id="org-1",
        platform_id="platform-1",
        binding_id="binding-1",
        logical_key="application:app-retry",
    )
    await repo.save_canvas_sync_target(target)
    job = await repo.enqueue_canvas_sync_job(target)
    job.max_attempts = 2
    leased = (await repo.lease_canvas_sync_jobs(worker_id="worker-1"))[0]
    leased.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    before_recovery = datetime.now(UTC)

    assert await repo.lease_canvas_sync_jobs(worker_id="worker-2") == []
    assert job.status == CanvasEvidenceSyncJobStatus.RETRY
    assert job.available_at >= before_recovery + timedelta(seconds=14)
    assert job.last_error_code == "canvas_worker_lease_expired"
    assert target.enabled is True
