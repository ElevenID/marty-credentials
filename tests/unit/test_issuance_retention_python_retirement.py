"""Keep Rust-owned retention and passport endpoints retired."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from scripts import issuance_surface_contract

ROOT = Path(__file__).resolve().parents[2]
RETIRED = {
    ("GET", "/v1/issuance/organizations/{organization_id}/retention"),
    ("POST", "/v1/issuance/organizations/{organization_id}/retention/purge"),
}
RETIRED_PASSPORT = {
    ("GET", "/v1/passport/applications/{application_id}/production-status"),
    ("GET", "/v1/passport/capabilities"),
    ("POST", "/v1/passport/applications"),
    ("POST", "/v1/passport/applications/{application_id}/activate"),
    ("POST", "/v1/passport/applications/{application_id}/generate-data-groups"),
    ("POST", "/v1/passport/applications/{application_id}/generate-sod"),
    ("POST", "/v1/passport/applications/{application_id}/quality-verify"),
    ("POST", "/v1/passport/applications/{application_id}/submit-personalization"),
    ("POST", "/v1/passport/webhooks/personalization"),
}


def _class_methods(relative: str, class_name: str) -> set[str]:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    owner = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    return {
        node.name
        for node in owner.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_retention_and_passport_routes_are_retired() -> None:
    surface = issuance_surface_contract.build_contract()
    routes = {(row["method"], row["path"]) for row in surface["http"]["routes"]}
    assert (RETIRED | RETIRED_PASSPORT).isdisjoint(routes)
    assert surface["http"]["route_count"] == 86
    assert surface["migrations"]["heads"] == ["issuance_event_owner"]


def test_retention_only_repository_methods_are_removed_but_shared_helpers_survive() -> None:
    retired_methods = {"get_retention_summary", "purge_retention_records"}
    for relative, class_name in (
        ("services/issuance/domain/ports.py", "IIssuanceRepository"),
        (
            "services/issuance/infrastructure/adapters/memory_repository.py",
            "InMemoryIssuanceRepository",
        ),
        (
            "services/issuance/infrastructure/adapters/postgres_repository.py",
            "PostgresIssuanceRepository",
        ),
    ):
        assert retired_methods.isdisjoint(_class_methods(relative, class_name))
    postgres = _class_methods(
        "services/issuance/infrastructure/adapters/postgres_repository.py",
        "PostgresIssuanceRepository",
    )
    assert "_result_rowcount" in postgres
    assert "get_authorization_session_by_access_token" in postgres


def test_frozen_retention_contract_remains_available_to_rust() -> None:
    contract = json.loads(
        (ROOT / "contracts/issuance-retention-management.json").read_text(encoding="utf-8")
    )
    assert contract["schema"] == "marty.issuance-retention-management/v1"
    assert {(row["method"], row["path"]) for row in contract["routes"]} == RETIRED


def test_passport_retirement_keeps_the_frozen_oracle_and_acceptance_gate() -> None:
    oracle = json.loads(
        (ROOT / "contracts/physical-passport-python-route-reference.json").read_text(
            encoding="utf-8"
        )
    )
    candidate = json.loads(
        (ROOT / "contracts/physical-passport-python-retirement-qualification.json").read_text(
            encoding="utf-8"
        )
    )
    assert {(row["method"], row["path"]) for row in oracle["operations"]} == RETIRED_PASSPORT
    assert {
        (row["method"], row["path"])
        for row in candidate["authorized_python_route_deletions"]
    } == RETIRED_PASSPORT
    assert candidate["state"] == "blocked_pending_beta_acceptance"
    assert candidate["source"]["protected_main_commit"] is None
    assert candidate["beta_acceptance_receipt"] is None
    assert candidate["full_python_service_deletion_authorized"] is False
