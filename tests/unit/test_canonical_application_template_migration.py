from __future__ import annotations

from importlib import import_module


migration = import_module(
    "issuance.infrastructure.migrations.versions.20260712_1400_canonicalize_application_template_fields"
)


def test_canonicalizes_legacy_form_field_aliases() -> None:
    field, valid = migration.canonical_field({
        "name": "birth_date",
        "display_name": "Birth date",
        "type": "date",
        "required": True,
        "pattern": r"\d{4}-\d{2}-\d{2}",
        "enum": ["one"],
        "min": 1,
        "max": 5,
    })

    assert valid is True
    assert field == {
        "field_id": "birth_date",
        "label": "Birth date",
        "field_type": "DATE",
        "required": True,
        "validation_pattern": r"\d{4}-\d{2}-\d{2}",
        "options": ["one"],
        "minimum": 1,
        "maximum": 5,
    }


def test_canonicalizes_source_field_claim_rule() -> None:
    rule, valid = migration.canonical_claim_rule({
        "claim_name": "email",
        "source": "form",
        "source_field": "member_email",
        "required": True,
    })

    assert valid is True
    assert rule == {
        "claim_name": "email",
        "source": "FORM_FIELD",
        "source_config": {"field_id": "member_email"},
    }


def test_marks_irreducible_values_invalid() -> None:
    assert migration.canonical_field("email") == (None, False)
    assert migration.canonical_field({"field_id": "email", "field_type": "mystery"}) == (None, False)
    assert migration.canonical_claim_rule({"claim_name": "email", "source": "mystery"}) == (None, False)
