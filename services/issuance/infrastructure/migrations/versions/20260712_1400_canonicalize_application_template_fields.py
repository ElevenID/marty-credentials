"""Canonicalize stored Application Template fields for the MIP 0.3.1 clean break.

Revision ID: canonical_application_template_fields
Revises: credential_renewal_mip031
"""

from __future__ import annotations

from copy import deepcopy
import json
from typing import Any

import sqlalchemy as sa
from alembic import op


revision = "canonical_application_template_fields"
down_revision = "credential_renewal_mip031"
branch_labels = None
depends_on = None


FIELD_TYPES = {
    "TEXT", "DATE", "DATETIME", "SELECT", "FILE_UPLOAD",
    "INTEGER", "NUMBER", "BOOLEAN", "EMAIL", "URL",
}


def _field_type(value: Any) -> str:
    normalized = str(value or "TEXT").strip().upper().replace("-", "_")
    return {
        "STRING": "TEXT",
        "STR": "TEXT",
        "TIMESTAMP": "DATETIME",
        "DATETIME_LOCAL": "DATETIME",
        "ENUM": "SELECT",
        "CHOICE": "SELECT",
        "FILE": "FILE_UPLOAD",
        "INT": "INTEGER",
        "FLOAT": "NUMBER",
        "DOUBLE": "NUMBER",
        "DECIMAL": "NUMBER",
        "BOOL": "BOOLEAN",
    }.get(normalized, normalized)


def canonical_field(value: Any) -> tuple[dict[str, Any] | None, bool]:
    if not isinstance(value, dict):
        return None, False
    field_id = str(value.get("field_id") or value.get("name") or "").strip()
    field_type = _field_type(value.get("field_type") or value.get("type"))
    if not field_id or field_type not in FIELD_TYPES:
        return None, False
    result: dict[str, Any] = {
        "field_id": field_id,
        "label": str(value.get("label") or value.get("display_name") or field_id),
        "field_type": field_type,
        "required": bool(value.get("required", False)),
    }
    optional = {
        "claim_mapping": value.get("claim_mapping"),
        "validation_pattern": value.get("validation_pattern") or value.get("pattern"),
        "options": value.get("options") if value.get("options") is not None else value.get("enum"),
        "minimum": value.get("minimum") if value.get("minimum") is not None else value.get("min"),
        "maximum": value.get("maximum") if value.get("maximum") is not None else value.get("max"),
        "placeholder": value.get("placeholder"),
        "hint": value.get("hint"),
    }
    result.update({key: item for key, item in optional.items() if item is not None})
    return result, True


def canonical_claim_rule(value: Any) -> tuple[dict[str, Any] | None, bool]:
    if not isinstance(value, dict):
        return None, False
    claim_name = str(value.get("claim_name") or "").strip()
    source = str(value.get("source") or "").strip().upper()
    source = {"FORM": "FORM_FIELD", "EVIDENCE": "EVIDENCE_EXTRACTION"}.get(source, source)
    if not claim_name or source not in {"FORM_FIELD", "EVIDENCE_EXTRACTION", "EXTERNAL_API", "SYSTEM"}:
        return None, False
    source_config = value.get("source_config") if isinstance(value.get("source_config"), dict) else {}
    if source == "FORM_FIELD" and not source_config.get("field_id") and value.get("source_field"):
        source_config = {**source_config, "field_id": value["source_field"]}
    return {
        "claim_name": claim_name,
        "source": source,
        "source_config": source_config,
    }, True


def upgrade() -> None:
    connection = op.get_bind()
    rows = connection.execute(sa.text("""
        SELECT id, status, form_fields, claim_collection_rules, ui_config
        FROM issuance_service.application_templates
    """)).mappings()

    for row in rows:
        original_fields = list(row["form_fields"] or [])
        original_rules = list(row["claim_collection_rules"] or [])
        fields: list[dict[str, Any]] = []
        rules: list[dict[str, Any]] = []
        valid = True
        for value in original_fields:
            canonical, item_valid = canonical_field(value)
            valid = valid and item_valid
            if canonical is not None:
                fields.append(canonical)
        for value in original_rules:
            canonical, item_valid = canonical_claim_rule(value)
            valid = valid and item_valid
            if canonical is not None:
                rules.append(canonical)

        changed = fields != original_fields or rules != original_rules
        if not changed and valid:
            continue

        ui_config = deepcopy(row["ui_config"] or {})
        migration_audit = dict(ui_config.get("mip_0_3_migration") or {})
        migration_audit.update({
            "original_form_fields": original_fields,
            "original_claim_collection_rules": original_rules,
            "requires_correction": not valid,
        })
        ui_config["mip_0_3_migration"] = migration_audit
        status = "DRAFT" if not valid and str(row["status"] or "").upper() == "ACTIVE" else row["status"]
        connection.execute(
            sa.text("""
                UPDATE issuance_service.application_templates
                SET form_fields = CAST(:form_fields AS json),
                    claim_collection_rules = CAST(:claim_collection_rules AS json),
                    ui_config = CAST(:ui_config AS json),
                    status = :status,
                    updated_at = NOW()
                WHERE id = :id
            """),
            {
                "id": row["id"],
                "form_fields": json.dumps(fields),
                "claim_collection_rules": json.dumps(rules),
                "ui_config": json.dumps(ui_config),
                "status": status,
            },
        )


def downgrade() -> None:
    raise RuntimeError("The MIP 0.3.1 Application Template migration is one-way.")
