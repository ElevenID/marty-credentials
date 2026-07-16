#!/usr/bin/env python3
"""Exercise the portable Canvas revision against disposable PostgreSQL."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from alembic import command
from alembic.config import Config
from psycopg.errors import ForeignKeyViolation

BASELINE_REVISION = "derive_server_owned_claims"
PORTABLE_REVISION = "portable_canvas_connections"
DATABASE_URL = os.environ["DATABASE_URL"]
RESULT_PATH = Path(os.environ.get("CONTRACT_RESULT_PATH", "/artifacts/contract-result.json"))
SOURCE_REVISION = os.environ.get("CONTRACT_SOURCE_REVISION", "local-worktree")
MIGRATIONS = Path("/contract/migrations")

ORG_A = "00000000-0000-0000-0000-00000000a001"
ORG_B = "00000000-0000-0000-0000-00000000b001"
PLATFORM_A = "10000000-0000-0000-0000-000000000001"
BINDING_LIST = "20000000-0000-0000-0000-000000000001"
BINDING_OBJECT = "20000000-0000-0000-0000-000000000002"
TEMPLATE_A = "30000000-0000-0000-0000-000000000001"
TEMPLATE_B = "30000000-0000-0000-0000-000000000002"
APPLICATION_A = "40000000-0000-0000-0000-000000000001"
FACT_OLD = "50000000-0000-0000-0000-000000000001"
FACT_NEW = "50000000-0000-0000-0000-000000000002"

LEGACY_REQUIREMENTS_LIST: list[dict[str, Any]] = [
    {
        "requirement_id": "assignment-pass",
        "source": "canvas_rest",
        "fact_type": "canvas.assignment_score",
        "scope": {"course_id": "42", "assignment_id": "7"},
        "pass_rule": {"min_score_percent": 80},
        "required": True,
    },
    {
        "fact_type": "canvas.course_completion",
        "webhook_event": "course.completed",
    },
]
LEGACY_REQUIREMENTS_OBJECT = {
    "fact_type": "canvas.module_completion",
    "webhook_event": "module.completed",
}

assertions: list[str] = []


def require(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    assertions.append(label)


def alembic_config() -> Config:
    config = Config(str(MIGRATIONS / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS))
    config.set_main_option(
        "sqlalchemy.url", DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
    )
    return config


def current_revisions(connection: psycopg.Connection[Any]) -> list[str]:
    rows = connection.execute(
        "SELECT version_num FROM issuance_service.alembic_version ORDER BY version_num"
    ).fetchall()
    return [str(row[0]) for row in rows]


def table_exists(connection: psycopg.Connection[Any], table: str) -> bool:
    return bool(connection.execute("SELECT to_regclass(%s) IS NOT NULL", (table,)).fetchone()[0])


def column_exists(connection: psycopg.Connection[Any], table: str, column: str) -> bool:
    return bool(
        connection.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'issuance_service'
                  AND table_name = %s
                  AND column_name = %s
            )
            """,
            (table, column),
        ).fetchone()[0]
    )


def constraint_exists(connection: psycopg.Connection[Any], name: str) -> bool:
    return bool(
        connection.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = %s
                  AND connamespace = 'issuance_service'::regnamespace
            )
            """,
            (name,),
        ).fetchone()[0]
    )


def index_definition(connection: psycopg.Connection[Any], name: str) -> str | None:
    row = connection.execute(
        """
        SELECT indexdef
        FROM pg_indexes
        WHERE schemaname = 'issuance_service' AND indexname = %s
        """,
        (name,),
    ).fetchone()
    return str(row[0]) if row else None


def bootstrap_dependencies() -> None:
    with psycopg.connect(DATABASE_URL) as connection:
        connection.execute("CREATE SCHEMA issuance_service")
        connection.execute("CREATE SCHEMA organization_service")
        connection.execute(
            """
            CREATE TABLE organization_service.organizations (
                id VARCHAR PRIMARY KEY,
                name VARCHAR,
                slug VARCHAR
            )
            """
        )
        with connection.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO organization_service.organizations (id, name, slug) VALUES (%s, %s, %s)",
                (
                    (ORG_A, "Canvas Contract A", "canvas-a"),
                    (ORG_B, "Canvas Contract B", "canvas-b"),
                ),
            )


def insert_template(
    connection: psycopg.Connection[Any], template_id: str, organization_id: str
) -> None:
    connection.execute(
        """
        INSERT INTO issuance_service.application_templates (
            id, organization_id, name, description, credential_template_id,
            form_fields, evidence_requirements, claim_collection_rules, required_checks,
            approval_strategy, application_validity_days, ui_config, notification_config,
            status, created_at, updated_at
        ) VALUES (
            %s, %s, %s, %s, %s,
            '[]'::json, '[]'::json, '[]'::json, '[]'::json,
            'manual', 30, '{}'::json, '{}'::json,
            'ACTIVE', '2026-07-01T00:00:00Z', '2026-07-01T00:00:00Z'
        )
        """,
        (
            template_id,
            organization_id,
            f"Template {template_id[-1]}",
            "Migration fixture",
            f"credential-{template_id[-1]}",
        ),
    )


def seed_legacy_rows() -> None:
    with psycopg.connect(DATABASE_URL) as connection:
        insert_template(connection, TEMPLATE_A, ORG_A)
        insert_template(connection, TEMPLATE_B, ORG_B)
        connection.execute(
            """
            INSERT INTO issuance_service.applications (
                id, organization_id, application_template_id, applicant_identifier,
                form_data, submitted_evidence, status, derived_claims, created_at, updated_at
            ) VALUES (
                %s, %s, %s, 'canvas-learner-7',
                '{}'::json, '[]'::json, 'APPROVED', '{}'::json,
                '2026-07-01T00:00:00Z', '2026-07-01T00:00:00Z'
            )
            """,
            (APPLICATION_A, ORG_A, TEMPLATE_A),
        )
        connection.execute(
            """
            INSERT INTO issuance_service.canvas_platforms (
                id, organization_id, canvas_account_id, display_name, canvas_base_url,
                lti_client_id, lti_deployment_id, enabled, created_at, updated_at
            ) VALUES (
                %s, %s, 'account-42', 'Legacy hosted Canvas', 'https://canvas.example.edu',
                'client-1', 'deployment-1', true,
                '2026-07-01T00:00:00Z', '2026-07-01T00:00:00Z'
            )
            """,
            (PLATFORM_A, ORG_A),
        )
        for binding_id, raw_requirements, enabled, direct_issue, auto_approve in (
            (BINDING_LIST, LEGACY_REQUIREMENTS_LIST, True, True, True),
            (BINDING_OBJECT, LEGACY_REQUIREMENTS_OBJECT, False, False, True),
        ):
            connection.execute(
                """
                INSERT INTO issuance_service.canvas_program_bindings (
                    id, organization_id, platform_id, application_template_id,
                    credential_template_id, display_name, direct_issue_enabled,
                    auto_approve_on_evidence, evidence_requirements, canvas_scope,
                    enabled, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s,
                    'credential-1', %s, %s,
                    %s, %s::json, '{}'::json,
                    %s, '2026-07-01T00:00:00Z', '2026-07-01T00:00:00Z'
                )
                """,
                (
                    binding_id,
                    ORG_A,
                    PLATFORM_A,
                    TEMPLATE_A,
                    f"Legacy binding {binding_id[-1]}",
                    direct_issue,
                    auto_approve,
                    json.dumps(raw_requirements, separators=(",", ":")),
                    enabled,
                ),
            )
        for fact_id, score, created_at in (
            (FACT_OLD, 92, "2026-07-01T00:00:00Z"),
            (FACT_NEW, 72, "2026-07-02T00:00:00Z"),
        ):
            connection.execute(
                """
                INSERT INTO issuance_service.evidence_facts (
                    id, organization_id, application_id, subject_id, provider, fact_type,
                    scope, assertion, verification, source, created_at
                ) VALUES (
                    %s, %s, %s, 'canvas-user-7', 'canvas', 'canvas.assignment_score',
                    '{"course_id":"42","activity_id":"7"}'::jsonb,
                    %s::jsonb,
                    '{"status":"VERIFIED"}'::jsonb,
                    '{"endpoint":"assignment_submission"}'::jsonb,
                    %s
                )
                """,
                (fact_id, ORG_A, APPLICATION_A, json.dumps({"score_percent": score}), created_at),
            )


def assert_upgraded() -> str:
    portable_tables = (
        "canvas_oauth_connections",
        "canvas_oauth_authorizations",
        "canvas_learner_identities",
        "evidence_fact_heads",
        "canvas_evidence_sync_targets",
        "canvas_evidence_sync_jobs",
        "canvas_award_candidates",
        "canvas_candidate_observations",
        "evidence_policy_reviews",
    )
    with psycopg.connect(DATABASE_URL) as connection:
        require(
            current_revisions(connection) == [PORTABLE_REVISION],
            "upgrade reached portable Canvas revision",
        )
        for table in portable_tables:
            require(
                table_exists(connection, f"issuance_service.{table}"), f"upgrade created {table}"
            )

        platform = connection.execute(
            """
            SELECT enabled, registration_status, capability_snapshot, config_version
            FROM issuance_service.canvas_platforms WHERE id = %s
            """,
            (PLATFORM_A,),
        ).fetchone()
        require(platform == (False, "draft", {}, 1), "legacy platform is fail-closed after upgrade")

        migrated_list = connection.execute(
            """
            SELECT evidence_requirements, enabled, direct_issue_enabled, auto_approve_on_evidence
            FROM issuance_service.canvas_program_bindings WHERE id = %s
            """,
            (BINDING_LIST,),
        ).fetchone()
        requirements = migrated_list[0]
        require(
            migrated_list[1:] == (False, False, False),
            "legacy binding issuance switches are disabled",
        )
        require(
            requirements[0]["scope"] == {"course_id": "42", "activity_id": "7"},
            "portable assignment requirement is canonicalized",
        )
        require(
            requirements[1]["source"] == "legacy_unportable",
            "ambiguous event requirement is quarantined",
        )
        require(
            requirements[1]["legacy_requirement"] == LEGACY_REQUIREMENTS_LIST[1],
            "quarantine preserves ambiguous requirement",
        )

        migrated_object = connection.execute(
            "SELECT evidence_requirements FROM issuance_service.canvas_program_bindings WHERE id = %s",
            (BINDING_OBJECT,),
        ).fetchone()[0]
        require(
            migrated_object[0]["migration_review_reason"] == "requirements_not_array",
            "non-array requirement is quarantined",
        )
        require(
            migrated_object[0]["legacy_requirement"] == LEGACY_REQUIREMENTS_OBJECT,
            "non-array requirement is preserved",
        )

        backup_list = connection.execute(
            """
            SELECT evidence_requirements, enabled, direct_issue_enabled, auto_approve_on_evidence
            FROM issuance_service.canvas_program_binding_requirement_backups
            WHERE binding_id = %s AND organization_id = %s
            """,
            (BINDING_LIST, ORG_A),
        ).fetchone()
        require(
            backup_list == (LEGACY_REQUIREMENTS_LIST, True, True, True),
            "binding backup preserves JSON and switches",
        )
        require(
            connection.execute(
                "SELECT enabled FROM issuance_service.canvas_platform_state_backups WHERE platform_id = %s AND organization_id = %s",
                (PLATFORM_A, ORG_A),
            ).fetchone()
            == (True,),
            "platform backup preserves enabled state",
        )

        facts = connection.execute(
            """
            SELECT id, logical_key, source_revision, payload_hash, observed_at, effective_at, created_at
            FROM issuance_service.evidence_facts
            WHERE application_id = %s ORDER BY created_at
            """,
            (APPLICATION_A,),
        ).fetchall()
        require(len(facts) == 2, "legacy evidence revisions survive upgrade")
        require(
            len({row[1] for row in facts}) == 1 and len(facts[0][1]) == 64,
            "logical evidence key uses SHA-256",
        )
        require(
            all(len(row[2]) == 64 and row[2] == row[3] for row in facts),
            "revision and payload hashes use SHA-256",
        )
        require(
            all(row[4] == row[6] and row[5] == row[6] for row in facts),
            "legacy evidence timestamps are backfilled",
        )
        require(
            connection.execute(
                "SELECT fact_id FROM issuance_service.evidence_fact_heads WHERE application_id = %s",
                (APPLICATION_A,),
            ).fetchone()
            == (FACT_NEW,),
            "evidence head selects the newest legacy fact",
        )

        for constraint in (
            "fk_canvas_program_bindings_tenant_platform",
            "fk_evidence_fact_heads_tenant_fact",
            "fk_canvas_sync_jobs_tenant_target",
        ):
            require(constraint_exists(connection, constraint), f"upgrade installs {constraint}")
        unique_credential_index = index_definition(
            connection, "ux_issued_credentials_transaction_id"
        )
        require(
            bool(unique_credential_index and "UNIQUE INDEX" in unique_credential_index),
            "upgrade installs transaction uniqueness",
        )
        postgres_version = str(connection.execute("SHOW server_version").fetchone()[0])

    try:
        with psycopg.connect(DATABASE_URL) as connection:
            connection.execute(
                """
                INSERT INTO issuance_service.canvas_program_bindings (
                    id, organization_id, platform_id, application_template_id,
                    credential_template_id, evidence_requirements, enabled
                ) VALUES (
                    '20000000-0000-0000-0000-000000000099', %s, %s, %s,
                    'credential-2', '[]'::json, false
                )
                """,
                (ORG_B, PLATFORM_A, TEMPLATE_B),
            )
    except ForeignKeyViolation as exc:
        require(
            exc.diag.constraint_name == "fk_canvas_program_bindings_tenant_platform",
            "cross-tenant binding is rejected by database",
        )
    else:
        raise AssertionError("cross-tenant binding unexpectedly succeeded")
    return postgres_version


def assert_downgraded() -> None:
    removed_tables = (
        "canvas_oauth_connections",
        "canvas_oauth_authorizations",
        "canvas_learner_identities",
        "evidence_fact_heads",
        "canvas_evidence_sync_targets",
        "canvas_evidence_sync_jobs",
        "canvas_award_candidates",
        "canvas_candidate_observations",
        "evidence_policy_reviews",
        "canvas_program_binding_requirement_backups",
        "canvas_platform_state_backups",
    )
    with psycopg.connect(DATABASE_URL) as connection:
        require(
            current_revisions(connection) == [BASELINE_REVISION],
            "downgrade returned to exact baseline",
        )
        for table in removed_tables:
            require(
                not table_exists(connection, f"issuance_service.{table}"),
                f"downgrade removed {table}",
            )

        require(
            connection.execute(
                "SELECT enabled FROM issuance_service.canvas_platforms WHERE id = %s", (PLATFORM_A,)
            ).fetchone()
            == (True,),
            "downgrade restores platform enabled state",
        )
        restored_list = connection.execute(
            """
            SELECT evidence_requirements, enabled, direct_issue_enabled, auto_approve_on_evidence
            FROM issuance_service.canvas_program_bindings WHERE id = %s
            """,
            (BINDING_LIST,),
        ).fetchone()
        require(
            restored_list == (LEGACY_REQUIREMENTS_LIST, True, True, True),
            "downgrade restores list requirements and switches",
        )
        restored_object = connection.execute(
            """
            SELECT evidence_requirements, enabled, direct_issue_enabled, auto_approve_on_evidence
            FROM issuance_service.canvas_program_bindings WHERE id = %s
            """,
            (BINDING_OBJECT,),
        ).fetchone()
        require(
            restored_object == (LEGACY_REQUIREMENTS_OBJECT, False, False, True),
            "downgrade restores non-array requirements and switches",
        )

        for table, column in (
            ("canvas_platforms", "registration_status"),
            ("canvas_program_bindings", "config_version"),
            ("evidence_facts", "logical_key"),
            ("issuance_transactions", "reserved_credential_id"),
        ):
            require(
                not column_exists(connection, table, column), f"downgrade removes {table}.{column}"
            )
        require(
            not constraint_exists(connection, "fk_canvas_program_bindings_tenant_platform"),
            "downgrade removes portable tenant constraint",
        )
        require(
            index_definition(connection, "ux_issued_credentials_transaction_id") is None,
            "downgrade removes unique transaction index",
        )
        normal_index = index_definition(connection, "ix_issued_credentials_transaction_id")
        require(
            bool(normal_index and "UNIQUE INDEX" not in normal_index),
            "downgrade restores non-unique transaction index",
        )

        evidence = connection.execute(
            """
            SELECT id, assertion, verification, source, created_at
            FROM issuance_service.evidence_facts
            WHERE application_id = %s ORDER BY created_at
            """,
            (APPLICATION_A,),
        ).fetchall()
        require(
            [row[0] for row in evidence] == [FACT_OLD, FACT_NEW],
            "downgrade preserves legacy evidence rows",
        )
        require(
            [row[1]["score_percent"] for row in evidence] == [92, 72],
            "downgrade preserves legacy evidence payloads",
        )

        defaults = dict(
            connection.execute(
                """
                SELECT table_name, column_default
                FROM information_schema.columns
                WHERE table_schema = 'issuance_service'
                  AND column_name = 'enabled'
                  AND table_name IN ('canvas_platforms', 'canvas_program_bindings')
                """
            ).fetchall()
        )
        require(
            all("true" in str(value).lower() for value in defaults.values()) and len(defaults) == 2,
            "downgrade restores legacy enabled defaults",
        )


def write_result(
    status: str, *, postgres_version: str | None = None, error_type: str | None = None
) -> None:
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "schema_version": 1,
        "suite": "canvas_portable_postgresql_migration",
        "status": status,
        "baseline_revision": BASELINE_REVISION,
        "portable_revision": PORTABLE_REVISION,
        "source_revision": SOURCE_REVISION,
        "postgres_version": postgres_version,
        "execution_boundary": "docker_compose_one_shot",
        "legacy_fixture": {
            "platforms": 1,
            "bindings": 2,
            "evidence_facts": 2,
            "contains_ambiguous_requirement": True,
            "contains_non_array_requirement": True,
        },
        "assertions": assertions,
        "finished_at": datetime.now(UTC).isoformat(),
    }
    if error_type:
        result["error"] = {"type": error_type}
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    postgres_version: str | None = None
    try:
        bootstrap_dependencies()
        config = alembic_config()
        command.upgrade(config, BASELINE_REVISION)
        with psycopg.connect(DATABASE_URL) as connection:
            require(
                current_revisions(connection) == [BASELINE_REVISION],
                "fixture starts at exact legacy baseline",
            )
        seed_legacy_rows()
        command.upgrade(config, PORTABLE_REVISION)
        postgres_version = assert_upgraded()
        command.downgrade(config, BASELINE_REVISION)
        assert_downgraded()
    except Exception as exc:
        write_result("failed", postgres_version=postgres_version, error_type=type(exc).__name__)
        raise
    write_result("passed", postgres_version=postgres_version)
    print(f"Canvas portable migration contract passed ({len(assertions)} assertions).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
