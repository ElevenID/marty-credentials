"""Move server-owned claims out of applicant form fields.

Revision ID: derive_server_owned_claims
Revises: canonical_application_template_fields
"""

from __future__ import annotations

from copy import deepcopy
import json
from typing import Any

import sqlalchemy as sa
from alembic import op


revision = "derive_server_owned_claims"
down_revision = "canonical_application_template_fields"
branch_labels = None
depends_on = None

MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"


def system_source_for(
    field_id: str,
    *,
    organization_id: str,
    organization_name: str,
    template_name: str,
    template_description: str | None,
) -> dict[str, Any] | None:
    system_field = {
        "member_id": "applicant.user_id",
        "user_id": "applicant.user_id",
        "organization_id": "application.organization_id",
        "issued_at": "current.datetime",
        "issue_date": "current.date",
        "date_of_issue": "current.date",
        "expiry_date": "validity.expiry_date",
        "date_of_expiry": "validity.expiry_date",
        "document_number": "application.reference_number",
        "employee_id": "application.reference_number",
        "achievement_name": "template.name",
        "achievement_description": "template.description",
    }.get(field_id)
    if system_field:
        return {"system_field": system_field}
    if field_id in {"organization_name", "issuing_authority"} and organization_name:
        return {"system_field": "constant", "value": organization_name}
    if field_id == "role" and organization_id == MARTY_ORG_ID:
        return {"system_field": "constant", "value": "applicant"}
    return None


def upgrade() -> None:
    connection = op.get_bind()
    organization_names = {
        str(row["id"]): str(row["name"] or row["slug"] or "")
        for row in connection.execute(sa.text(
            "SELECT id, name, slug FROM organization_service.organizations"
        )).mappings()
    }
    rows = list(connection.execute(sa.text("""
        SELECT id, organization_id, name, description, form_fields,
               claim_collection_rules, ui_config
        FROM issuance_service.application_templates
    """)).mappings())

    for row in rows:
        organization_id = str(row["organization_id"])
        original_fields = list(row["form_fields"] or [])
        original_rules = list(row["claim_collection_rules"] or [])
        fields: list[dict[str, Any]] = []
        system_rules: dict[str, dict[str, Any]] = {}

        existing_claim_by_field = {
            str((rule.get("source_config") or {}).get("field_id")): str(rule.get("claim_name") or "")
            for rule in original_rules
            if isinstance(rule, dict)
            and rule.get("source") == "FORM_FIELD"
            and isinstance(rule.get("source_config"), dict)
        }
        for field in original_fields:
            if not isinstance(field, dict):
                fields.append(field)
                continue
            field_id = str(field.get("field_id") or "")
            source_config = system_source_for(
                field_id,
                organization_id=organization_id,
                organization_name=organization_names.get(organization_id, ""),
                template_name=str(row["name"] or ""),
                template_description=row["description"],
            )
            if source_config is None:
                fields.append(field)
                continue
            claim_name = str(field.get("claim_mapping") or existing_claim_by_field.get(field_id) or field_id)
            system_rules[claim_name] = {
                "claim_name": claim_name,
                "source": "SYSTEM",
                "source_config": source_config,
            }

        if not system_rules:
            continue

        rules = [
            rule for rule in original_rules
            if not (
                isinstance(rule, dict)
                and str(rule.get("claim_name") or "") in system_rules
            )
        ]
        rules.extend(system_rules.values())
        ui_config = deepcopy(row["ui_config"] or {})
        audit = dict(ui_config.get("mip_0_3_system_claim_migration") or {})
        audit.update({
            "original_form_fields": original_fields,
            "original_claim_collection_rules": original_rules,
        })
        ui_config["mip_0_3_system_claim_migration"] = audit
        connection.execute(
            sa.text("""
                UPDATE issuance_service.application_templates
                SET form_fields = CAST(:form_fields AS json),
                    claim_collection_rules = CAST(:claim_collection_rules AS json),
                    ui_config = CAST(:ui_config AS json),
                    updated_at = NOW()
                WHERE id = :id
            """),
            {
                "id": row["id"],
                "form_fields": json.dumps(fields),
                "claim_collection_rules": json.dumps(rules),
                "ui_config": json.dumps(ui_config),
            },
        )


def downgrade() -> None:
    raise RuntimeError("The MIP 0.3.1 server-owned claim migration is one-way.")
