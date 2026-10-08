"""Keep Rust-owned retention and passport endpoints retired."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from scripts import check_physical_passport_python_retirement as passport_gate
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
PASSPORT_SOURCE_ARTIFACTS = {
    "contracts/issuance-physical-passport-native.json",
    "contracts/issuance-native-coverage.json",
    "contracts/issuance-universal-ownership.json",
    "contracts/passport-beta-bureau-behavior.json",
    "contracts/passport-webhook-progress-behavior.json",
    "contracts/passport-supported-consumer-routing.json",
    "rust/services/issuance/src/passport_http.rs",
    "rust/services/issuance/src/passport_signer.rs",
    "rust/services/issuance/src/passport_bureau.rs",
    "rust/services/gateway/src/contract.rs",
    "rust/services/flow/src/connections.rs",
    "rust/services/flow/src/http_providers.rs",
    "docker-compose.passport-supported-disposable.yml",
}


def _is_sha(value: object, length: int) -> bool:
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None


def _assert_passport_qualification_shape(candidate: dict) -> None:
    assert candidate["schema"] == "marty.physical-passport-python-retirement-qualification/v4"
    assert candidate["state"] == "source_deletion_authorized_beta_not_qualified"
    assert candidate["beta_deployment_authorized"] is False
    assert {
        (row["method"], row["path"])
        for row in candidate["authorized_python_route_deletions"]
    } == RETIRED_PASSPORT
    assert len(candidate["authorized_python_route_deletions"]) == len(RETIRED_PASSPORT)
    assert candidate["full_python_service_deletion_authorized"] is False
    assert candidate["retirement_pull_request_number"] == 305
    source = candidate["source"]
    assert source["repository"] == "ElevenID/marty-ui"
    assert set(source["required_artifacts"]) == PASSPORT_SOURCE_ARTIFACTS
    assert len(source["required_artifacts"]) == len(PASSPORT_SOURCE_ARTIFACTS)

    assert _is_sha(source["protected_main_commit"], 40)
    assert isinstance(source["ci_run_id"], int) and source["ci_run_id"] > 0
    hashes = source["artifact_sha256"]
    assert isinstance(hashes, dict) and set(hashes) == PASSPORT_SOURCE_ARTIFACTS
    assert all(_is_sha(digest, 64) for digest in hashes.values())
    assert candidate["predeletion_acceptance_receipt"] is None
    assert candidate["supported_consumer_cutover_receipt"] is None


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


def test_passport_retirement_keeps_the_frozen_oracle_and_source_gate() -> None:
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
    _assert_passport_qualification_shape(candidate)
    assert passport_gate._checkout_commit(
        ROOT / "contracts/physical-passport-python-retirement-qualification.json"
    ) == candidate["source"]["protected_main_commit"]


def test_passport_retirement_rejects_fabricated_deployment_authority(tmp_path: Path) -> None:
    candidate = json.loads(
        (ROOT / "contracts/physical-passport-python-retirement-qualification.json").read_text(
            encoding="utf-8"
        )
    )
    qualified = dict(candidate)
    qualified["beta_deployment_authorized"] = True
    with pytest.raises(AssertionError):
        _assert_passport_qualification_shape(qualified)
    candidate_path = tmp_path / "qualification.json"
    candidate_path.write_text(json.dumps(qualified), encoding="utf-8")
    with pytest.raises(passport_gate.prior_gate.QualificationError,
                       match="cannot imply beta deployment"):
        passport_gate.verify(candidate_path, tmp_path, deletion_head="a" * 40)
