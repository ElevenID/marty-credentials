"""add production-portable Canvas evidence and worker persistence

Revision ID: portable_canvas_connections
Revises: derive_server_owned_claims
Create Date: 2026-07-14 10:00:00.000000

This migration is intentionally additive. The prior portable-Canvas revision was
unreleased, so it is replaced here before any shared deployment. Legacy binding
JSON and unsafe issuance switches are retained verbatim and restored by downgrade.
"""

import hashlib
import json
from collections import Counter
from typing import Any

from alembic import op
from sqlalchemy import text

revision = "portable_canvas_connections"
down_revision = "derive_server_owned_claims"
branch_labels = None
depends_on = None


_PORTABLE_SOURCES = {"ags_result", "canvas_rest"}
_SCORE_FACT_TYPES = {"canvas.assignment_score", "canvas.quiz_score"}
_COMPLETION_FACT_TYPES = {"canvas.course_completion", "canvas.module_completion"}
_PORTABLE_FACT_TYPES = _SCORE_FACT_TYPES | _COMPLETION_FACT_TYPES
_REQUIREMENT_FIELDS = {
    "requirement_id",
    "source",
    "fact_type",
    "scope",
    "pass_rule",
    "required",
}
_SCOPE_FIELDS = {
    "course_id",
    "activity_id",
    "assignment_id",
    "quiz_id",
    "module_id",
    "line_item_url",
    "lineitem_url",
    "resource_id",
    "resourceId",
}


def _nonempty_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _scope_alias(scope: dict[str, Any], *keys: str) -> tuple[str | None, bool]:
    """Return one normalized alias value, rejecting conflicting aliases."""

    values = {
        normalized
        for key in keys
        if (normalized := _nonempty_string(scope.get(key))) is not None
    }
    if len(values) > 1:
        return None, False
    return (next(iter(values)) if values else None), True


def normalize_portable_requirement(value: Any) -> dict[str, Any] | None:
    """Normalize only requirements that are unambiguously portable.

    This deliberately mirrors the production domain validator without importing
    application code into Alembic. Anything that would require guessing is left
    as a disabled review row by :func:`migrate_canvas_requirements`.
    """

    if not isinstance(value, dict) or set(value) - _REQUIREMENT_FIELDS:
        return None
    requirement_id = _nonempty_string(value.get("requirement_id"))
    source = value.get("source")
    fact_type = value.get("fact_type")
    scope = value.get("scope")
    pass_rule = value.get("pass_rule")
    required = value.get("required", True)
    if (
        requirement_id is None
        or source not in _PORTABLE_SOURCES
        or fact_type not in _PORTABLE_FACT_TYPES
        or not isinstance(scope, dict)
        or set(scope) - _SCOPE_FIELDS
        or not isinstance(pass_rule, dict)
        or not isinstance(required, bool)
    ):
        return None

    course_id = _nonempty_string(scope.get("course_id"))
    activity_id, activity_unambiguous = _scope_alias(
        scope,
        "activity_id",
        "assignment_id",
        "quiz_id",
    )
    line_item_url, line_item_unambiguous = _scope_alias(
        scope,
        "line_item_url",
        "lineitem_url",
    )
    resource_id, resource_unambiguous = _scope_alias(
        scope,
        "resource_id",
        "resourceId",
    )
    module_id = _nonempty_string(scope.get("module_id"))
    if not all((course_id, activity_unambiguous, line_item_unambiguous, resource_unambiguous)):
        return None
    if line_item_url is not None and not line_item_url.startswith("https://"):
        return None

    canonical_scope: dict[str, str] = {"course_id": course_id}
    if fact_type in _SCORE_FACT_TYPES:
        if set(pass_rule) != {"min_score_percent"}:
            return None
        threshold = pass_rule.get("min_score_percent")
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            return None
        threshold = float(threshold)
        if threshold < 0 or threshold > 100:
            return None
        if source == "canvas_rest":
            if activity_id is None or any((module_id, line_item_url, resource_id)):
                return None
            canonical_scope["activity_id"] = activity_id
        else:
            if activity_id is not None or module_id is not None or not (line_item_url or resource_id):
                return None
            if line_item_url:
                canonical_scope["line_item_url"] = line_item_url
            if resource_id:
                canonical_scope["resource_id"] = resource_id
        canonical_pass_rule: dict[str, Any] = {"min_score_percent": threshold}
    else:
        if source != "canvas_rest" or pass_rule != {"completed": True}:
            return None
        if any((activity_id, line_item_url, resource_id)):
            return None
        if fact_type == "canvas.module_completion":
            if module_id is None:
                return None
            canonical_scope["module_id"] = module_id
        elif module_id is not None:
            return None
        canonical_pass_rule = {"completed": True}

    return {
        "requirement_id": requirement_id,
        "source": source,
        "fact_type": fact_type,
        "scope": canonical_scope,
        "pass_rule": canonical_pass_rule,
        "required": required,
    }


def _legacy_fact_type(value: Any) -> str:
    if isinstance(value, dict):
        return _nonempty_string(value.get("fact_type")) or "unknown"
    return _nonempty_string(value) or "unknown"


def _legacy_review_requirement(
    *,
    binding_id: str,
    ordinal: int,
    value: Any,
    reason: str,
) -> dict[str, Any]:
    digest = hashlib.sha256(f"{binding_id}:{ordinal}".encode()).hexdigest()[:32]
    return {
        "requirement_id": f"legacy-{digest}",
        "source": "legacy_unportable",
        "fact_type": _legacy_fact_type(value),
        "required": True,
        "enabled": False,
        "migration_review_required": True,
        "migration_review_reason": reason,
        "legacy_requirement": value,
    }


def migrate_canvas_requirements(
    binding_id: str,
    value: Any,
) -> tuple[list[dict[str, Any]], bool]:
    """Convert an entire binding atomically, preserving every ambiguous value."""

    if not isinstance(value, list):
        return [
            _legacy_review_requirement(
                binding_id=binding_id,
                ordinal=1,
                value=value,
                reason="requirements_not_array",
            )
        ], True
    if not value:
        return [
            _legacy_review_requirement(
                binding_id=binding_id,
                ordinal=1,
                value=value,
                reason="requirements_empty",
            )
        ], True

    normalized = [normalize_portable_requirement(item) for item in value]
    counts = Counter(
        item["requirement_id"]
        for item in normalized
        if item is not None
    )
    migrated: list[dict[str, Any]] = []
    has_ambiguous = False
    for ordinal, (original, portable) in enumerate(zip(value, normalized, strict=True), start=1):
        reason: str | None = None
        if portable is None:
            reason = "unsupported_or_ambiguous_requirement"
        elif counts[portable["requirement_id"]] > 1:
            reason = "duplicate_requirement_id"
        if reason is not None:
            has_ambiguous = True
            migrated.append(
                _legacy_review_requirement(
                    binding_id=binding_id,
                    ordinal=ordinal,
                    value=original,
                    reason=reason,
                )
            )
        else:
            migrated.append(portable)
    return migrated, has_ambiguous


def upgrade():
    # Wallet claims are at-most-once: reserve a stable credential identifier on
    # the transaction and let PostgreSQL reject any second credential row even
    # if a future code path accidentally bypasses the signing-state CAS.
    op.execute(
        """
        ALTER TABLE issuance_service.issuance_transactions
            ADD COLUMN IF NOT EXISTS reserved_credential_id VARCHAR NULL;

        DROP INDEX IF EXISTS issuance_service.ix_issued_credentials_transaction_id;
        CREATE UNIQUE INDEX IF NOT EXISTS ux_issued_credentials_transaction_id
            ON issuance_service.issued_credentials(transaction_id)
        """
    )

    op.execute(
        """
        ALTER TABLE issuance_service.canvas_platforms
            ADD COLUMN IF NOT EXISTS lti_trust_profile VARCHAR(40) NOT NULL DEFAULT 'hosted_global',
            ADD COLUMN IF NOT EXISTS registration_status VARCHAR(40) NOT NULL DEFAULT 'draft',
            ADD COLUMN IF NOT EXISTS connection_config JSON NOT NULL DEFAULT '{}',
            ADD COLUMN IF NOT EXISTS capability_snapshot JSON NOT NULL DEFAULT '{}',
            ADD COLUMN IF NOT EXISTS last_validated_at TIMESTAMPTZ NULL,
            ADD COLUMN IF NOT EXISTS last_connection_error TEXT NULL,
            ADD COLUMN IF NOT EXISTS config_version INTEGER NOT NULL DEFAULT 1,
            ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ NULL
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_platform_state_backups (
            platform_id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            enabled BOOLEAN NOT NULL,
            backed_up_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS ix_canvas_platform_state_backups_organization
            ON issuance_service.canvas_platform_state_backups(organization_id);

        INSERT INTO issuance_service.canvas_platform_state_backups
            (platform_id, organization_id, enabled)
        SELECT id, organization_id, enabled
        FROM issuance_service.canvas_platforms
        ON CONFLICT (platform_id) DO NOTHING;

        UPDATE issuance_service.canvas_platforms
        SET
            enabled = false,
            registration_status = 'draft',
            capability_snapshot = '{}'::json,
            last_validated_at = NULL,
            last_connection_error = NULL,
            updated_at = now();

        ALTER TABLE issuance_service.canvas_platforms
            ALTER COLUMN enabled SET DEFAULT false
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'ck_canvas_platforms_lti_trust_profile'
                  AND conrelid = 'issuance_service.canvas_platforms'::regclass
            ) THEN
                ALTER TABLE issuance_service.canvas_platforms
                    ADD CONSTRAINT ck_canvas_platforms_lti_trust_profile
                    CHECK (
                        lti_trust_profile IN (
                            'hosted_global',
                            'self_managed_same_origin'
                        )
                    );
            END IF;
        END $$
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_program_bindings
            ADD COLUMN IF NOT EXISTS config_version INTEGER NOT NULL DEFAULT 1,
            ADD COLUMN IF NOT EXISTS validated_config_version INTEGER NULL,
            ADD COLUMN IF NOT EXISTS readiness_checks JSON NOT NULL DEFAULT '[]',
            ADD COLUMN IF NOT EXISTS readiness_validated_at TIMESTAMPTZ NULL,
            ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ NULL,
            ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ NULL,
            ADD COLUMN IF NOT EXISTS credential_template_snapshot JSON NOT NULL DEFAULT '{}'
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_program_bindings
            ALTER COLUMN enabled SET DEFAULT false
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_program_binding_requirement_backups (
            binding_id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            evidence_requirements JSON NOT NULL,
            enabled BOOLEAN NOT NULL,
            direct_issue_enabled BOOLEAN NOT NULL,
            auto_approve_on_evidence BOOLEAN NOT NULL,
            backed_up_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS ix_canvas_binding_requirement_backups_organization
            ON issuance_service.canvas_program_binding_requirement_backups(organization_id)
        """
    )
    op.execute(
        """
        INSERT INTO issuance_service.canvas_program_binding_requirement_backups
            (
                binding_id,
                organization_id,
                evidence_requirements,
                enabled,
                direct_issue_enabled,
                auto_approve_on_evidence
            )
        SELECT
            id,
            organization_id,
            evidence_requirements,
            enabled,
            direct_issue_enabled,
            auto_approve_on_evidence
        FROM issuance_service.canvas_program_bindings
        ON CONFLICT (binding_id) DO NOTHING
        """
    )
    connection = op.get_bind()
    bindings = connection.execute(
        text(
            """
            SELECT id, evidence_requirements
            FROM issuance_service.canvas_program_bindings
            ORDER BY id
            """
        )
    ).mappings().all()
    for binding in bindings:
        requirements, _has_ambiguous = migrate_canvas_requirements(
            str(binding["id"]),
            binding["evidence_requirements"],
        )
        connection.execute(
            text(
                """
                UPDATE issuance_service.canvas_program_bindings
                SET
                    evidence_requirements = CAST(:requirements AS JSON),
                    enabled = false,
                    direct_issue_enabled = false,
                    auto_approve_on_evidence = false,
                    activated_at = NULL,
                    validated_config_version = NULL,
                    readiness_checks = '[]'::json,
                    readiness_validated_at = NULL,
                    updated_at = now()
                WHERE id = :binding_id
                """
            ),
            {
                "binding_id": binding["id"],
                "requirements": json.dumps(requirements, separators=(",", ":")),
            },
        )

    op.execute(
        """
        ALTER TABLE issuance_service.evidence_facts
            ADD COLUMN IF NOT EXISTS requirement_id VARCHAR NULL,
            ADD COLUMN IF NOT EXISTS logical_key VARCHAR(64) NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS source_revision VARCHAR NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS payload_hash VARCHAR(64) NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS observed_at TIMESTAMPTZ NULL,
            ADD COLUMN IF NOT EXISTS effective_at TIMESTAMPTZ NULL,
            ADD COLUMN IF NOT EXISTS superseded_fact_id VARCHAR NULL
        """
    )
    op.execute(
        """
        UPDATE issuance_service.evidence_facts
        SET
            logical_key = encode(sha256(convert_to(
                COALESCE(requirement_id, '') || '|' || provider || '|' || fact_type || '|'
                || COALESCE(scope::text, '{}') || '|' || subject_id,
                'UTF8'
            )), 'hex'),
            payload_hash = encode(sha256(convert_to(
                provider || '|' || fact_type || '|' || COALESCE(scope::text, '{}') || '|'
                || COALESCE(assertion::text, '{}') || '|' || COALESCE(verification::text, '{}'),
                'UTF8'
            )), 'hex'),
            source_revision = CASE
                WHEN source_revision = '' THEN encode(sha256(convert_to(
                    provider || '|' || fact_type || '|' || COALESCE(scope::text, '{}') || '|'
                    || COALESCE(assertion::text, '{}') || '|' || COALESCE(verification::text, '{}'),
                    'UTF8'
                )), 'hex')
                ELSE source_revision
            END,
            observed_at = COALESCE(observed_at, created_at),
            effective_at = COALESCE(effective_at, observed_at, created_at)
        WHERE logical_key = '' OR payload_hash = '' OR observed_at IS NULL OR effective_at IS NULL
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.evidence_facts
            ALTER COLUMN observed_at SET NOT NULL,
            ALTER COLUMN effective_at SET NOT NULL;

        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'fk_evidence_facts_superseded_fact_id'
                  AND conrelid = 'issuance_service.evidence_facts'::regclass
            ) THEN
                ALTER TABLE issuance_service.evidence_facts
                    ADD CONSTRAINT fk_evidence_facts_superseded_fact_id
                    FOREIGN KEY (superseded_fact_id)
                    REFERENCES issuance_service.evidence_facts(id)
                    ON DELETE SET NULL;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'ck_evidence_facts_revision_metadata'
                  AND conrelid = 'issuance_service.evidence_facts'::regclass
            ) THEN
                ALTER TABLE issuance_service.evidence_facts
                    ADD CONSTRAINT ck_evidence_facts_revision_metadata
                    CHECK (
                        logical_key <> ''
                        AND source_revision <> ''
                        AND payload_hash <> ''
                    );
            END IF;
        END $$;

        CREATE INDEX IF NOT EXISTS ix_evidence_facts_application_logical_key
            ON issuance_service.evidence_facts(application_id, logical_key);
        CREATE INDEX IF NOT EXISTS ix_evidence_facts_application_logical_payload
            ON issuance_service.evidence_facts(application_id, logical_key, payload_hash)
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.evidence_fact_heads (
            organization_id VARCHAR NOT NULL,
            application_id VARCHAR NOT NULL
                REFERENCES issuance_service.applications(id) ON DELETE CASCADE,
            logical_key VARCHAR(64) NOT NULL,
            fact_id VARCHAR NOT NULL UNIQUE
                REFERENCES issuance_service.evidence_facts(id) ON DELETE CASCADE,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_evidence_fact_heads_logical_key
                CHECK (btrim(logical_key) <> ''),
            PRIMARY KEY (application_id, logical_key)
        );
        CREATE INDEX IF NOT EXISTS ix_evidence_fact_heads_organization_id
            ON issuance_service.evidence_fact_heads(organization_id);

        INSERT INTO issuance_service.evidence_fact_heads
            (organization_id, application_id, logical_key, fact_id, updated_at)
        SELECT DISTINCT ON (application_id, logical_key)
            organization_id, application_id, logical_key, id, now()
        FROM issuance_service.evidence_facts
        ORDER BY application_id, logical_key, effective_at DESC, observed_at DESC, created_at DESC, id DESC
        ON CONFLICT (application_id, logical_key) DO UPDATE
        SET fact_id = EXCLUDED.fact_id, updated_at = EXCLUDED.updated_at
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_learner_identities (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            platform_id VARCHAR NOT NULL
                REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
            deployment_id VARCHAR NOT NULL,
            lti_subject VARCHAR NOT NULL,
            canvas_user_id VARCHAR NULL,
            sis_user_id VARCHAR NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'linked',
            conflict_reason TEXT NULL,
            verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_canvas_learner_identities_status
                CHECK (status IN ('subject_verified', 'linked', 'quarantined')),
            CONSTRAINT ck_canvas_learner_identities_subject
                CHECK (btrim(deployment_id) <> '' AND btrim(lti_subject) <> ''),
            CONSTRAINT ux_canvas_learner_identity_subject
                UNIQUE (platform_id, deployment_id, lti_subject)
        );
        CREATE INDEX IF NOT EXISTS ix_canvas_learner_identities_organization_id
            ON issuance_service.canvas_learner_identities(organization_id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_learner_identity_numeric_link
            ON issuance_service.canvas_learner_identities(platform_id, deployment_id, canvas_user_id)
            WHERE status = 'linked' AND canvas_user_id IS NOT NULL
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_oauth_authorizations (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            platform_id VARCHAR NOT NULL
                REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
            canvas_base_url TEXT NOT NULL,
            platform_config_version INTEGER NOT NULL,
            client_id TEXT NOT NULL,
            client_secret_ref TEXT NOT NULL,
            state_hash VARCHAR(64) NOT NULL UNIQUE,
            capabilities JSON NOT NULL DEFAULT '[]',
            scopes JSON NOT NULL DEFAULT '[]',
            redirect_uri TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            consumed_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_canvas_oauth_authorizations_state_hash
                CHECK (length(state_hash) = 64),
            CONSTRAINT ck_canvas_oauth_authorizations_platform_snapshot
                CHECK (
                    platform_config_version >= 1
                    AND left(lower(canvas_base_url), 8) = 'https://'
                ),
            CONSTRAINT ck_canvas_oauth_authorizations_tenant_secret_ref
                CHECK (
                    left(
                        client_secret_ref,
                        length('org_secret://' || organization_id || '/')
                    ) = 'org_secret://' || organization_id || '/'
                )
        );
        CREATE INDEX IF NOT EXISTS ix_canvas_oauth_authorizations_organization_id
            ON issuance_service.canvas_oauth_authorizations(organization_id);
        CREATE INDEX IF NOT EXISTS ix_canvas_oauth_authorizations_platform_id
            ON issuance_service.canvas_oauth_authorizations(platform_id);
        CREATE INDEX IF NOT EXISTS ix_canvas_oauth_authorizations_expiry
            ON issuance_service.canvas_oauth_authorizations(expires_at, consumed_at);

        CREATE TABLE IF NOT EXISTS issuance_service.canvas_oauth_connections (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            platform_id VARCHAR NOT NULL
                REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
            canvas_base_url TEXT NOT NULL,
            platform_config_version INTEGER NOT NULL,
            client_id TEXT NOT NULL,
            client_secret_ref TEXT NOT NULL,
            capabilities JSON NOT NULL DEFAULT '[]',
            scopes JSON NOT NULL DEFAULT '[]',
            access_token_secret_ref TEXT NULL,
            refresh_token_secret_ref TEXT NULL,
            token_expires_at TIMESTAMPTZ NULL,
            status VARCHAR(40) NOT NULL DEFAULT 'connected',
            reauthorization_required BOOLEAN NOT NULL DEFAULT false,
            refresh_lease_owner VARCHAR NULL,
            refresh_lease_expires_at TIMESTAMPTZ NULL,
            revoke_retry_count INTEGER NOT NULL DEFAULT 0,
            revoke_retry_at TIMESTAMPTZ NULL,
            revoke_last_error_code VARCHAR(120) NULL,
            connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_refreshed_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_canvas_oauth_connections_status
                CHECK (
                    status IN (
                        'connected',
                        'reauthorization_required',
                        'revocation_pending',
                        'disconnected'
                    )
                ),
            CONSTRAINT ck_canvas_oauth_connections_revoke_retry_count
                CHECK (revoke_retry_count >= 0),
            CONSTRAINT ck_canvas_oauth_connections_refresh_lease
                CHECK (
                    (refresh_lease_owner IS NULL AND refresh_lease_expires_at IS NULL)
                    OR
                    (refresh_lease_owner IS NOT NULL AND refresh_lease_expires_at IS NOT NULL)
                ),
            CONSTRAINT ck_canvas_oauth_connections_platform_snapshot
                CHECK (
                    platform_config_version >= 1
                    AND left(lower(canvas_base_url), 8) = 'https://'
                ),
            CONSTRAINT ck_canvas_oauth_connections_tenant_secret_refs
                CHECK (
                    left(
                        client_secret_ref,
                        length('org_secret://' || organization_id || '/')
                    ) = 'org_secret://' || organization_id || '/'
                    AND (
                        access_token_secret_ref IS NULL
                        OR left(
                            access_token_secret_ref,
                            length('org_secret://' || organization_id || '/')
                        ) = 'org_secret://' || organization_id || '/'
                    )
                    AND (
                        refresh_token_secret_ref IS NULL
                        OR left(
                            refresh_token_secret_ref,
                            length('org_secret://' || organization_id || '/')
                        ) = 'org_secret://' || organization_id || '/'
                    )
                ),
            CONSTRAINT ux_canvas_oauth_connections_platform
                UNIQUE (organization_id, platform_id)
        );
        CREATE INDEX IF NOT EXISTS ix_canvas_oauth_connections_status
            ON issuance_service.canvas_oauth_connections(status, reauthorization_required);
        CREATE INDEX IF NOT EXISTS ix_canvas_oauth_connections_revoke_retry
            ON issuance_service.canvas_oauth_connections(status, revoke_retry_at)
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_evidence_sync_targets (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            platform_id VARCHAR NOT NULL
                REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
            binding_id VARCHAR NOT NULL
                REFERENCES issuance_service.canvas_program_bindings(id) ON DELETE CASCADE,
            target_type VARCHAR(40) NOT NULL,
            logical_key VARCHAR NOT NULL,
            application_id VARCHAR NULL
                REFERENCES issuance_service.applications(id) ON DELETE CASCADE,
            candidate_id VARCHAR NULL,
            enabled BOOLEAN NOT NULL DEFAULT true,
            schedule_seconds INTEGER NOT NULL DEFAULT 900,
            next_run_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_enqueued_at TIMESTAMPTZ NULL,
            last_succeeded_at TIMESTAMPTZ NULL,
            config_version INTEGER NOT NULL DEFAULT 1,
            metadata JSON NOT NULL DEFAULT '{}',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_canvas_sync_targets_type
                CHECK (
                    target_type IN (
                        'learner_application',
                        'background_roster',
                        'award_candidate',
                        'issued_drift'
                    )
                ),
            CONSTRAINT ck_canvas_sync_targets_schedule
                CHECK (schedule_seconds >= 60),
            CONSTRAINT ck_canvas_sync_targets_config_version
                CHECK (config_version >= 1),
            CONSTRAINT ck_canvas_sync_targets_logical_key
                CHECK (btrim(logical_key) <> ''),
            CONSTRAINT ux_canvas_sync_targets_org_logical UNIQUE (organization_id, logical_key)
        );
        CREATE INDEX IF NOT EXISTS ix_canvas_sync_targets_due
            ON issuance_service.canvas_evidence_sync_targets(enabled, next_run_at);

        CREATE TABLE IF NOT EXISTS issuance_service.canvas_evidence_sync_jobs (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            target_id VARCHAR NOT NULL
                REFERENCES issuance_service.canvas_evidence_sync_targets(id) ON DELETE CASCADE,
            status VARCHAR(32) NOT NULL DEFAULT 'queued',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 8,
            available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            lease_owner VARCHAR NULL,
            lease_expires_at TIMESTAMPTZ NULL,
            last_error_code VARCHAR(120) NULL,
            last_error_summary TEXT NULL,
            result JSON NOT NULL DEFAULT '{}',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            started_at TIMESTAMPTZ NULL,
            completed_at TIMESTAMPTZ NULL,
            CONSTRAINT ck_canvas_sync_jobs_status
                CHECK (
                    status IN (
                        'queued', 'leased', 'retry', 'succeeded', 'dead_letter', 'cancelled'
                    )
                ),
            CONSTRAINT ck_canvas_sync_jobs_attempts
                CHECK (max_attempts >= 1 AND attempt_count >= 0 AND attempt_count <= max_attempts),
            CONSTRAINT ck_canvas_sync_jobs_lease
                CHECK (
                    (
                        status = 'leased'
                        AND lease_owner IS NOT NULL
                        AND lease_expires_at IS NOT NULL
                    )
                    OR
                    (
                        status <> 'leased'
                        AND lease_owner IS NULL
                        AND lease_expires_at IS NULL
                    )
                )
        );
        CREATE INDEX IF NOT EXISTS ix_canvas_sync_jobs_organization_id
            ON issuance_service.canvas_evidence_sync_jobs(organization_id);
        CREATE INDEX IF NOT EXISTS ix_canvas_sync_jobs_claim
            ON issuance_service.canvas_evidence_sync_jobs(status, available_at, lease_expires_at);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_sync_jobs_one_active_target
            ON issuance_service.canvas_evidence_sync_jobs(target_id)
            WHERE status IN ('queued', 'leased', 'retry')
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_worker_heartbeats (
            worker_id VARCHAR PRIMARY KEY,
            role VARCHAR(80) NOT NULL DEFAULT 'canvas_sync',
            started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            metadata JSON NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS ix_canvas_worker_heartbeats_role_fresh
            ON issuance_service.canvas_worker_heartbeats(role, last_heartbeat_at)
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.canvas_award_candidates (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            platform_id VARCHAR NOT NULL
                REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
            binding_id VARCHAR NOT NULL
                REFERENCES issuance_service.canvas_program_bindings(id) ON DELETE CASCADE,
            learner_identity_id VARCHAR NULL
                REFERENCES issuance_service.canvas_learner_identities(id) ON DELETE SET NULL,
            candidate_key VARCHAR NOT NULL,
            canvas_user_id VARCHAR NULL,
            lti_subject VARCHAR NULL,
            state VARCHAR(40) NOT NULL DEFAULT 'observed',
            application_id VARCHAR NULL
                REFERENCES issuance_service.applications(id) ON DELETE SET NULL,
            claimed_credential_id VARCHAR NULL
                REFERENCES issuance_service.issued_credentials(id) ON DELETE SET NULL,
            observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_canvas_award_candidates_state
                CHECK (
                    state IN (
                        'observed',
                        'identity_link_required',
                        'eligible',
                        'pending_claim',
                        'claimed',
                        'dismissed'
                    )
                ),
            CONSTRAINT ck_canvas_award_candidates_key
                CHECK (btrim(candidate_key) <> ''),
            CONSTRAINT ux_canvas_award_candidates_binding_key UNIQUE (binding_id, candidate_key)
        );
        CREATE INDEX IF NOT EXISTS ix_canvas_award_candidates_organization_state
            ON issuance_service.canvas_award_candidates(organization_id, state);

        CREATE TABLE IF NOT EXISTS issuance_service.canvas_candidate_observations (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            candidate_id VARCHAR NOT NULL
                REFERENCES issuance_service.canvas_award_candidates(id) ON DELETE CASCADE,
            requirement_id VARCHAR NOT NULL,
            logical_key VARCHAR(64) NOT NULL,
            assertion JSON NOT NULL DEFAULT '{}',
            verification JSON NOT NULL DEFAULT '{}',
            payload_hash VARCHAR(64) NOT NULL,
            superseded_observation_id VARCHAR NULL
                REFERENCES issuance_service.canvas_candidate_observations(id) ON DELETE SET NULL,
            is_current BOOLEAN NOT NULL DEFAULT true,
            observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_canvas_candidate_observations_revision
                CHECK (
                    btrim(requirement_id) <> ''
                    AND btrim(logical_key) <> ''
                    AND btrim(payload_hash) <> ''
                )
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_candidate_observations_current
            ON issuance_service.canvas_candidate_observations(candidate_id, logical_key)
            WHERE is_current;
        CREATE INDEX IF NOT EXISTS ix_canvas_candidate_observations_payload
            ON issuance_service.canvas_candidate_observations(candidate_id, logical_key, payload_hash)
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'fk_canvas_sync_targets_candidate_id'
                  AND conrelid = 'issuance_service.canvas_evidence_sync_targets'::regclass
            ) THEN
                ALTER TABLE issuance_service.canvas_evidence_sync_targets
                    ADD CONSTRAINT fk_canvas_sync_targets_candidate_id
                    FOREIGN KEY (candidate_id)
                    REFERENCES issuance_service.canvas_award_candidates(id)
                    ON DELETE SET NULL;
            END IF;
        END $$;
        CREATE INDEX IF NOT EXISTS ix_canvas_sync_targets_candidate_id
            ON issuance_service.canvas_evidence_sync_targets(candidate_id)
            WHERE candidate_id IS NOT NULL
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS issuance_service.evidence_policy_reviews (
            id VARCHAR PRIMARY KEY,
            organization_id VARCHAR NOT NULL,
            application_id VARCHAR NOT NULL
                REFERENCES issuance_service.applications(id) ON DELETE CASCADE,
            credential_id VARCHAR NOT NULL
                REFERENCES issuance_service.issued_credentials(id) ON DELETE CASCADE,
            binding_id VARCHAR NULL
                REFERENCES issuance_service.canvas_program_bindings(id) ON DELETE SET NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'open',
            prior_decision JSON NOT NULL DEFAULT '{}',
            current_decision JSON NOT NULL DEFAULT '{}',
            triggering_fact_id VARCHAR NULL
                REFERENCES issuance_service.evidence_facts(id) ON DELETE SET NULL,
            resolution_action VARCHAR(32) NULL,
            resolution_notes TEXT NULL,
            resolved_by VARCHAR NULL,
            resolved_at TIMESTAMPTZ NULL,
            resolution_claim_token VARCHAR(128) NULL,
            resolution_claim_action VARCHAR(32) NULL,
            resolution_claimed_at TIMESTAMPTZ NULL,
            resolution_recovery_pending BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_evidence_policy_reviews_status
                CHECK (status IN ('open', 'dismissed', 'suspended', 'revoked', 'resolved')),
            CONSTRAINT ck_evidence_policy_reviews_resolution_claim
                CHECK (
                    (
                        resolution_claim_token IS NULL
                        AND resolution_claim_action IS NULL
                        AND resolution_claimed_at IS NULL
                    )
                    OR
                    (
                        status = 'open'
                        AND resolution_claim_token IS NOT NULL
                        AND resolution_claim_action IN ('dismiss', 'suspend', 'revoke')
                        AND resolution_claimed_at IS NOT NULL
                    )
                )
        );
        CREATE INDEX IF NOT EXISTS ix_evidence_policy_reviews_organization_status
            ON issuance_service.evidence_policy_reviews(organization_id, status);
        CREATE INDEX IF NOT EXISTS ix_evidence_policy_reviews_application_id
            ON issuance_service.evidence_policy_reviews(application_id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_policy_reviews_one_open_application
            ON issuance_service.evidence_policy_reviews(application_id)
            WHERE status = 'open'
        """
    )

    # Every portable-Canvas child row carries organization_id for scoped reads.
    # Composite foreign keys make that denormalized tenant key authoritative:
    # an application bug cannot attach an org-A row to an org-B parent by ID.
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_platforms_tenant_id
            ON issuance_service.canvas_platforms(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_program_bindings_tenant_id
            ON issuance_service.canvas_program_bindings(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_application_templates_tenant_id
            ON issuance_service.application_templates(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_applications_tenant_id
            ON issuance_service.applications(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_issued_credentials_tenant_id
            ON issuance_service.issued_credentials(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_facts_tenant_id
            ON issuance_service.evidence_facts(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_facts_tenant_application_id
            ON issuance_service.evidence_facts(organization_id, application_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_facts_tenant_application_logical_id
            ON issuance_service.evidence_facts(organization_id, application_id, logical_key, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_learner_identities_tenant_id
            ON issuance_service.canvas_learner_identities(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_sync_targets_tenant_id
            ON issuance_service.canvas_evidence_sync_targets(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_award_candidates_tenant_id
            ON issuance_service.canvas_award_candidates(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_candidate_observations_tenant_id
            ON issuance_service.canvas_candidate_observations(organization_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_candidate_observations_tenant_candidate_id
            ON issuance_service.canvas_candidate_observations(organization_id, candidate_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_canvas_candidate_observations_tenant_candidate_logical_id
            ON issuance_service.canvas_candidate_observations(
                organization_id, candidate_id, logical_key, id
            );

        ALTER TABLE issuance_service.canvas_platforms
            ADD CONSTRAINT ck_canvas_platforms_config_version
            CHECK (config_version >= 1),
            ADD CONSTRAINT ck_canvas_platforms_registration_status
            CHECK (registration_status IN ('draft', 'verified', 'installed', 'active', 'archived')),
            ADD CONSTRAINT ck_canvas_platforms_archival_state
            CHECK (archived_at IS NULL OR enabled = false);
        ALTER TABLE issuance_service.canvas_program_bindings
            ADD CONSTRAINT ck_canvas_program_bindings_config_versions
            CHECK (
                config_version >= 1
                AND (
                    validated_config_version IS NULL
                    OR (
                        validated_config_version >= 1
                        AND validated_config_version <= config_version
                    )
                )
            ),
            ADD CONSTRAINT ck_canvas_program_bindings_archival_state
            CHECK (archived_at IS NULL OR enabled = false),
            ADD CONSTRAINT ck_canvas_program_bindings_activation_state
            CHECK (
                enabled = false
                OR (
                    activated_at IS NOT NULL
                    AND validated_config_version = config_version
                )
            ),
            ADD CONSTRAINT fk_canvas_program_bindings_tenant_platform
            FOREIGN KEY (organization_id, platform_id)
            REFERENCES issuance_service.canvas_platforms(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_canvas_program_bindings_tenant_application_template
            FOREIGN KEY (organization_id, application_template_id)
            REFERENCES issuance_service.application_templates(organization_id, id)
            ON DELETE CASCADE;
        ALTER TABLE issuance_service.evidence_facts
            ADD CONSTRAINT fk_evidence_facts_tenant_application
            FOREIGN KEY (organization_id, application_id)
            REFERENCES issuance_service.applications(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_evidence_facts_tenant_superseded
            FOREIGN KEY (organization_id, application_id, logical_key, superseded_fact_id)
            REFERENCES issuance_service.evidence_facts(
                organization_id, application_id, logical_key, id
            );
        ALTER TABLE issuance_service.evidence_fact_heads
            ADD CONSTRAINT fk_evidence_fact_heads_tenant_application
            FOREIGN KEY (organization_id, application_id)
            REFERENCES issuance_service.applications(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_evidence_fact_heads_tenant_fact
            FOREIGN KEY (organization_id, application_id, logical_key, fact_id)
            REFERENCES issuance_service.evidence_facts(
                organization_id, application_id, logical_key, id
            )
            ON DELETE CASCADE;
        ALTER TABLE issuance_service.canvas_learner_identities
            ADD CONSTRAINT fk_canvas_learner_identities_tenant_platform
            FOREIGN KEY (organization_id, platform_id)
            REFERENCES issuance_service.canvas_platforms(organization_id, id)
            ON DELETE CASCADE;
        ALTER TABLE issuance_service.canvas_oauth_authorizations
            ADD CONSTRAINT fk_canvas_oauth_authorizations_tenant_platform
            FOREIGN KEY (organization_id, platform_id)
            REFERENCES issuance_service.canvas_platforms(organization_id, id)
            ON DELETE CASCADE;
        ALTER TABLE issuance_service.canvas_oauth_connections
            ADD CONSTRAINT fk_canvas_oauth_connections_tenant_platform
            FOREIGN KEY (organization_id, platform_id)
            REFERENCES issuance_service.canvas_platforms(organization_id, id)
            ON DELETE CASCADE;
        ALTER TABLE issuance_service.canvas_evidence_sync_targets
            ADD CONSTRAINT fk_canvas_sync_targets_tenant_platform
            FOREIGN KEY (organization_id, platform_id)
            REFERENCES issuance_service.canvas_platforms(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_canvas_sync_targets_tenant_binding
            FOREIGN KEY (organization_id, binding_id)
            REFERENCES issuance_service.canvas_program_bindings(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_canvas_sync_targets_tenant_application
            FOREIGN KEY (organization_id, application_id)
            REFERENCES issuance_service.applications(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_canvas_sync_targets_tenant_candidate
            FOREIGN KEY (organization_id, candidate_id)
            REFERENCES issuance_service.canvas_award_candidates(organization_id, id);
        ALTER TABLE issuance_service.canvas_evidence_sync_jobs
            ADD CONSTRAINT fk_canvas_sync_jobs_tenant_target
            FOREIGN KEY (organization_id, target_id)
            REFERENCES issuance_service.canvas_evidence_sync_targets(organization_id, id)
            ON DELETE CASCADE;
        ALTER TABLE issuance_service.canvas_award_candidates
            ADD CONSTRAINT fk_canvas_award_candidates_tenant_platform
            FOREIGN KEY (organization_id, platform_id)
            REFERENCES issuance_service.canvas_platforms(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_canvas_award_candidates_tenant_binding
            FOREIGN KEY (organization_id, binding_id)
            REFERENCES issuance_service.canvas_program_bindings(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_canvas_award_candidates_tenant_identity
            FOREIGN KEY (organization_id, learner_identity_id)
            REFERENCES issuance_service.canvas_learner_identities(organization_id, id),
            ADD CONSTRAINT fk_canvas_award_candidates_tenant_application
            FOREIGN KEY (organization_id, application_id)
            REFERENCES issuance_service.applications(organization_id, id),
            ADD CONSTRAINT fk_canvas_award_candidates_tenant_credential
            FOREIGN KEY (organization_id, claimed_credential_id)
            REFERENCES issuance_service.issued_credentials(organization_id, id);
        ALTER TABLE issuance_service.canvas_candidate_observations
            ADD CONSTRAINT fk_canvas_candidate_observations_tenant_candidate
            FOREIGN KEY (organization_id, candidate_id)
            REFERENCES issuance_service.canvas_award_candidates(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_canvas_candidate_observations_tenant_superseded
            FOREIGN KEY (
                organization_id, candidate_id, logical_key, superseded_observation_id
            )
            REFERENCES issuance_service.canvas_candidate_observations(
                organization_id, candidate_id, logical_key, id
            );
        ALTER TABLE issuance_service.evidence_policy_reviews
            ADD CONSTRAINT fk_evidence_policy_reviews_tenant_application
            FOREIGN KEY (organization_id, application_id)
            REFERENCES issuance_service.applications(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_evidence_policy_reviews_tenant_credential
            FOREIGN KEY (organization_id, credential_id)
            REFERENCES issuance_service.issued_credentials(organization_id, id)
            ON DELETE CASCADE,
            ADD CONSTRAINT fk_evidence_policy_reviews_tenant_binding
            FOREIGN KEY (organization_id, binding_id)
            REFERENCES issuance_service.canvas_program_bindings(organization_id, id),
            ADD CONSTRAINT fk_evidence_policy_reviews_tenant_fact
            FOREIGN KEY (organization_id, application_id, triggering_fact_id)
            REFERENCES issuance_service.evidence_facts(organization_id, application_id, id)
        """
    )


def downgrade():
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_platforms
            DROP CONSTRAINT IF EXISTS ck_canvas_platforms_config_version,
            DROP CONSTRAINT IF EXISTS ck_canvas_platforms_registration_status,
            DROP CONSTRAINT IF EXISTS ck_canvas_platforms_archival_state;
        ALTER TABLE issuance_service.canvas_program_bindings
            DROP CONSTRAINT IF EXISTS ck_canvas_program_bindings_config_versions,
            DROP CONSTRAINT IF EXISTS ck_canvas_program_bindings_archival_state,
            DROP CONSTRAINT IF EXISTS ck_canvas_program_bindings_activation_state,
            DROP CONSTRAINT IF EXISTS fk_canvas_program_bindings_tenant_platform,
            DROP CONSTRAINT IF EXISTS fk_canvas_program_bindings_tenant_application_template;
        ALTER TABLE issuance_service.evidence_facts
            DROP CONSTRAINT IF EXISTS fk_evidence_facts_tenant_application,
            DROP CONSTRAINT IF EXISTS fk_evidence_facts_tenant_superseded
        """
    )
    op.execute("DROP TABLE IF EXISTS issuance_service.evidence_policy_reviews")
    # Sync targets reference candidates for award-candidate work. Drop the
    # dependent scheduler tables before candidate persistence.
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_evidence_sync_jobs")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_evidence_sync_targets")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_candidate_observations")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_award_candidates")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_worker_heartbeats")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_oauth_connections")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_oauth_authorizations")
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_learner_identities")
    op.execute("DROP TABLE IF EXISTS issuance_service.evidence_fact_heads")
    op.execute(
        """
        DROP INDEX IF EXISTS issuance_service.ux_canvas_candidate_observations_tenant_candidate_id;
        DROP INDEX IF EXISTS issuance_service.ux_canvas_candidate_observations_tenant_candidate_logical_id;
        DROP INDEX IF EXISTS issuance_service.ux_canvas_candidate_observations_tenant_id;
        DROP INDEX IF EXISTS issuance_service.ux_canvas_award_candidates_tenant_id;
        DROP INDEX IF EXISTS issuance_service.ux_canvas_sync_targets_tenant_id;
        DROP INDEX IF EXISTS issuance_service.ux_canvas_learner_identities_tenant_id;
        DROP INDEX IF EXISTS issuance_service.ux_evidence_facts_tenant_application_id;
        DROP INDEX IF EXISTS issuance_service.ux_evidence_facts_tenant_application_logical_id;
        DROP INDEX IF EXISTS issuance_service.ux_evidence_facts_tenant_id;
        DROP INDEX IF EXISTS issuance_service.ux_issued_credentials_tenant_id;
        DROP INDEX IF EXISTS issuance_service.ux_applications_tenant_id;
        DROP INDEX IF EXISTS issuance_service.ux_application_templates_tenant_id;
        DROP INDEX IF EXISTS issuance_service.ux_canvas_program_bindings_tenant_id;
        DROP INDEX IF EXISTS issuance_service.ux_canvas_platforms_tenant_id
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.evidence_facts
            DROP CONSTRAINT IF EXISTS fk_evidence_facts_superseded_fact_id,
            DROP COLUMN IF EXISTS superseded_fact_id,
            DROP COLUMN IF EXISTS effective_at,
            DROP COLUMN IF EXISTS observed_at,
            DROP COLUMN IF EXISTS payload_hash,
            DROP COLUMN IF EXISTS source_revision,
            DROP COLUMN IF EXISTS logical_key,
            DROP COLUMN IF EXISTS requirement_id
        """
    )
    op.execute(
        """
        DROP INDEX IF EXISTS issuance_service.ux_issued_credentials_transaction_id;
        CREATE INDEX IF NOT EXISTS ix_issued_credentials_transaction_id
            ON issuance_service.issued_credentials(transaction_id);
        ALTER TABLE issuance_service.issuance_transactions
            DROP COLUMN IF EXISTS reserved_credential_id
        """
    )
    op.execute(
        """
        UPDATE issuance_service.canvas_program_bindings binding
        SET
            evidence_requirements = backup.evidence_requirements,
            enabled = backup.enabled,
            direct_issue_enabled = backup.direct_issue_enabled,
            auto_approve_on_evidence = backup.auto_approve_on_evidence,
            updated_at = now()
        FROM issuance_service.canvas_program_binding_requirement_backups backup
        WHERE binding.id = backup.binding_id
          AND binding.organization_id = backup.organization_id
        """
    )
    op.execute("DROP TABLE IF EXISTS issuance_service.canvas_program_binding_requirement_backups")
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_program_bindings
            ALTER COLUMN enabled SET DEFAULT true,
            DROP COLUMN IF EXISTS credential_template_snapshot,
            DROP COLUMN IF EXISTS archived_at,
            DROP COLUMN IF EXISTS activated_at,
            DROP COLUMN IF EXISTS readiness_validated_at,
            DROP COLUMN IF EXISTS readiness_checks,
            DROP COLUMN IF EXISTS validated_config_version,
            DROP COLUMN IF EXISTS config_version
        """
    )
    op.execute(
        """
        UPDATE issuance_service.canvas_platforms platform
        SET
            enabled = backup.enabled,
            updated_at = now()
        FROM issuance_service.canvas_platform_state_backups backup
        WHERE platform.id = backup.platform_id
          AND platform.organization_id = backup.organization_id;

        DROP TABLE IF EXISTS issuance_service.canvas_platform_state_backups;

        ALTER TABLE issuance_service.canvas_platforms
            ALTER COLUMN enabled SET DEFAULT true
        """
    )
    op.execute(
        """
        ALTER TABLE issuance_service.canvas_platforms
            DROP CONSTRAINT IF EXISTS ck_canvas_platforms_lti_trust_profile,
            DROP COLUMN IF EXISTS last_connection_error,
            DROP COLUMN IF EXISTS last_validated_at,
            DROP COLUMN IF EXISTS capability_snapshot,
            DROP COLUMN IF EXISTS connection_config,
            DROP COLUMN IF EXISTS registration_status,
            DROP COLUMN IF EXISTS lti_trust_profile,
            DROP COLUMN IF EXISTS archived_at,
            DROP COLUMN IF EXISTS config_version
        """
    )
