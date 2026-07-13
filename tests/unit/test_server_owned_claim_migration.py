from __future__ import annotations

from importlib import import_module


migration = import_module(
    "issuance.infrastructure.migrations.versions.20260712_1500_derive_server_owned_template_claims"
)


def source(field_id: str, organization_id: str = "org-1"):
    return migration.system_source_for(
        field_id,
        organization_id=organization_id,
        organization_name="Acme Issuer",
        template_name="Member Badge",
        template_description="Membership proof",
    )


def test_maps_identity_and_lifecycle_claims_to_server_sources() -> None:
    assert source("member_id") == {"system_field": "applicant.user_id"}
    assert source("organization_id") == {"system_field": "application.organization_id"}
    assert source("issued_at") == {"system_field": "current.datetime"}
    assert source("expiry_date") == {"system_field": "validity.expiry_date"}
    assert source("document_number") == {"system_field": "application.reference_number"}
    assert source("organization_name") == {"system_field": "constant", "value": "Acme Issuer"}


def test_only_demo_role_is_a_constant() -> None:
    assert source("role") is None
    assert source("role", migration.MARTY_ORG_ID) == {"system_field": "constant", "value": "applicant"}


def test_preserves_applicant_supplied_claims() -> None:
    assert source("email") is None
    assert source("given_name") is None
    assert source("nationality") is None
