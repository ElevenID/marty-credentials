"""seed Marty application templates from active credential templates

Revision ID: seed_marty_application_templates
Revises: add_sd_claims_col
Create Date: 2026-04-16 22:00:00.000000

"""

from __future__ import annotations

import json
from datetime import datetime, timezone
import uuid

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "seed_marty_application_templates"
down_revision = "add_sd_claims_col"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
APP_TEMPLATE_NAMESPACE = uuid.UUID("c7ad7bbb-3cc8-46bc-a648-f0f66be0473a")


def _to_field_type(claim_type: str | None) -> str:
    normalized = str(claim_type or "string").strip().lower()
    if normalized in {"bool", "boolean"}:
        return "boolean"
    if normalized in {"int", "integer", "number", "float", "double", "decimal"}:
        return "number"
    if normalized in {"date", "datetime", "timestamp"}:
        return "date"
    return "text"


def _default_form_fields(claims: list[dict]) -> list[dict]:
    fields: list[dict] = []
    for claim in claims:
        name = (claim or {}).get("name")
        if not name:
            continue

        options = (claim or {}).get("enum_values") or []
        if not isinstance(options, list):
            options = []

        fields.append(
            {
                "field_id": name,
                "field_type": _to_field_type((claim or {}).get("claim_type")),
                "label": (claim or {}).get("display_name") or name,
                "required": bool((claim or {}).get("required", False)),
                "options": options,
                "validation_pattern": None,
            }
        )
    return fields


def _default_claim_rules(claims: list[dict]) -> list[dict]:
    rules: list[dict] = []
    for claim in claims:
        name = (claim or {}).get("name")
        if not name:
            continue

        rules.append(
            {
                "claim_name": name,
                "source": "form",
                "source_field": name,
                "required": bool((claim or {}).get("required", False)),
            }
        )
    return rules


def _approval_strategy(issuer_requirements: dict | None) -> str:
    requirements = issuer_requirements or {}
    return "manual" if bool(requirements.get("approval_required")) else "auto"


def _has_table(conn, schema_name: str, table_name: str) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass(:fq_name) IS NOT NULL"),
            {"fq_name": f"{schema_name}.{table_name}"},
        ).scalar()
    )


def _active_marty_credential_templates(conn):
    return conn.execute(
        sa.text(
            """
            SELECT id, name, description, claims, issuer_requirements
            FROM credential_template_service.credential_templates
            WHERE organization_id = :organization_id
              AND LOWER(COALESCE(status, 'active')) = 'active'
            ORDER BY created_at ASC, id ASC
            """
        ),
        {"organization_id": MARTY_ORG_ID},
    ).fetchall()


def upgrade() -> None:
    conn = op.get_bind()

    if not _has_table(conn, "issuance_service", "application_templates"):
        return
    if not _has_table(conn, "credential_template_service", "credential_templates"):
        return

    now = datetime.now(timezone.utc)

    for row in _active_marty_credential_templates(conn):
        existing = conn.execute(
            sa.text(
                """
                SELECT 1
                FROM issuance_service.application_templates
                WHERE organization_id = :organization_id
                  AND credential_template_id = :credential_template_id
                """
            ),
            {
                "organization_id": MARTY_ORG_ID,
                "credential_template_id": row.id,
            },
        ).fetchone()
        if existing:
            continue

        claims = row.claims if isinstance(row.claims, list) else []
        issuer_requirements = row.issuer_requirements if isinstance(row.issuer_requirements, dict) else {}
        display_name = row.name or "Credential"
        app_template_id = str(uuid.uuid5(APP_TEMPLATE_NAMESPACE, f"{MARTY_ORG_ID}:{row.id}"))

        conn.execute(
            sa.text(
                """
                INSERT INTO issuance_service.application_templates (
                    id,
                    organization_id,
                    name,
                    description,
                    credential_template_id,
                    form_fields,
                    evidence_requirements,
                    claim_collection_rules,
                    required_checks,
                    approval_strategy,
                    application_validity_days,
                    auto_approval_rules,
                    ui_config,
                    notification_config,
                    status,
                    created_at,
                    updated_at
                ) VALUES (
                    :id,
                    :organization_id,
                    :name,
                    :description,
                    :credential_template_id,
                    CAST(:form_fields AS json),
                    CAST(:evidence_requirements AS json),
                    CAST(:claim_collection_rules AS json),
                    CAST(:required_checks AS json),
                    :approval_strategy,
                    :application_validity_days,
                    CAST(:auto_approval_rules AS json),
                    CAST(:ui_config AS json),
                    CAST(:notification_config AS json),
                    :status,
                    :created_at,
                    :updated_at
                )
                """
            ),
            {
                "id": app_template_id,
                "organization_id": MARTY_ORG_ID,
                "name": f"{display_name} Application",
                "description": row.description or f"Application flow for {display_name}",
                "credential_template_id": row.id,
                "form_fields": json.dumps(_default_form_fields(claims)),
                "evidence_requirements": "[]",
                "claim_collection_rules": json.dumps(_default_claim_rules(claims)),
                "required_checks": "[]",
                "approval_strategy": _approval_strategy(issuer_requirements),
                "application_validity_days": 30,
                "auto_approval_rules": "[]",
                "ui_config": json.dumps(
                    {
                        "theme": "default",
                        "instructions": f"Complete this application to request {display_name}.",
                    }
                ),
                "notification_config": json.dumps(
                    {
                        "send_confirmation": True,
                        "send_status_updates": True,
                    }
                ),
                "status": "active",
                "created_at": now,
                "updated_at": now,
            },
        )


def downgrade() -> None:
    conn = op.get_bind()

    if not _has_table(conn, "issuance_service", "application_templates"):
        return
    if not _has_table(conn, "credential_template_service", "credential_templates"):
        return

    for row in _active_marty_credential_templates(conn):
        app_template_id = str(uuid.uuid5(APP_TEMPLATE_NAMESPACE, f"{MARTY_ORG_ID}:{row.id}"))
        conn.execute(
            sa.text(
                """
                DELETE FROM issuance_service.application_templates
                WHERE id = :id
                  AND organization_id = :organization_id
                """
            ),
            {
                "id": app_template_id,
                "organization_id": MARTY_ORG_ID,
            },
        )
