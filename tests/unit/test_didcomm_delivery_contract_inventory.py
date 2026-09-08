"""Inventory/source guards, plus real current-policy parsing; not a wire oracle."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from issuance.application import rust_integration
from issuance.infrastructure.api import routes

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-didcomm-delivery-boundary.json").read_text(encoding="utf-8")
)


def test_inventory_preserves_both_modes_without_claiming_runtime_acceptance() -> None:
    assert CONTRACT["schema"] == "marty.issuance-didcomm-delivery-boundary/v1"
    assert CONTRACT["classification"] == (
        "source-and-controlled-adapter-contract-inventory-not-runtime-oracle"
    )
    execution = CONTRACT["execution_order"]
    assert execution["first"] == "feature-preserving-Rust-consumer-migration"
    assert execution["deferred"] == "DIDComm-KMS-layer-corrections"
    assert execution["custody_claim"] == "Rust-port-alone-is-not-KMS-only"
    assert (ROOT / execution["outstanding_work"]).is_file()
    encryption = CONTRACT["encryption"]
    assert encryption["required_modes"] == ["anoncrypt", "authcrypt"]
    assert encryption["failure_fallback"] == "none-neither-anoncrypt-nor-plaintext"
    assert encryption["legacy_secret_custody"] == "transition-required-not-preserved-raw-key-API"
    assert encryption["target_KMS_API"] == "design-pending-do-not-invent-or-disable-authcrypt"
    assert len(CONTRACT["missing_runtime_oracles"]) == 7
    assert CONTRACT["policy"]["max_bytes"] == rust_integration._DIDCOMM_POLICY_MAX_BYTES
    assert CONTRACT["policy"]["max_issuers"] == rust_integration._DIDCOMM_POLICY_MAX_ISSUERS


def test_inventory_names_every_existing_boundary_test() -> None:
    source = (ROOT / CONTRACT["source"]["boundary_tests"]).read_text(encoding="utf-8")
    existing = {
        node.name
        for node in ast.parse(source).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }
    inventory = CONTRACT["boundary_test_inventory"]
    assert len(inventory) == len(set(inventory)) == 25
    assert set(inventory) == existing


def test_inventory_reuses_public_surface_and_initiation_authorities() -> None:
    public = json.loads((ROOT / CONTRACT["authorities"][0]).read_text(encoding="utf-8"))
    initiation = json.loads((ROOT / CONTRACT["authorities"][1]).read_text(encoding="utf-8"))
    surface = CONTRACT["surface"]
    assert any(
        all(operation[key] == surface[key] for key in ("method", "path", "operation"))
        for operation in public["http"]["routes"]
    )
    assert set(routes.DidcommDeliverRequest.model_fields) == set(surface["request_fields"])
    assert routes.DidcommDeliverRequest.model_config["extra"] == surface["extra_request_fields"]
    assert set(routes.DidcommDeliveryResponse.model_fields) == set(surface["response_fields"])
    operation = next(
        route
        for route in routes.issuance_router.routes
        if route.endpoint.__name__ == surface["operation"]
    )
    assert routes._verify_management_api_key in {
        dependency.call for dependency in operation.dependant.dependencies
    }
    assert initiation["idempotency"]["didcomm_push_with_idempotency"] == {
        "http_status": 422,
        "grpc_status": "INVALID_ARGUMENT",
    }
    assert initiation["response"]["didcomm"]["http_without_holder"] == "pending-uri"
    assert initiation["response"]["didcomm"]["http_delivery_failure"] == (
        "sanitized-log-and-pending-uri"
    )


def test_inventory_records_current_attempt_order_not_all_validation_before_mutation() -> None:
    source = (ROOT / CONTRACT["source"]["routes"]).read_text(encoding="utf-8")
    function = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_didcomm_sign_and_deliver"
    )
    calls: dict[str, list[int]] = {}
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
            )
            calls.setdefault(name, []).append(node.lineno)
    order = CONTRACT["attempt_order"]
    assert len(order) == len(set(order)) == 11
    positions = [min(calls[name]) for name in order]
    assert positions == sorted(positions)
    assert CONTRACT["ordering_limits"]["issuer_context_can_save_before_encryption_preflight"]
    assert calls["save_transaction"][0] < calls["prepare_didcomm_delivery_encryption"][0]
    assert calls["_allocate_credential_status_list_entries"][0] < calls["_didcomm_tls_verifier"][0]


@pytest.mark.parametrize(
    "vector", CONTRACT["policy_rejection_vectors"], ids=lambda vector: vector["name"]
)
def test_captured_existing_policy_rejection_vectors(vector, tmp_path, monkeypatch) -> None:
    # Same four synthetic inputs as the retained boundary test; run the actual
    # existing parser rather than interpreting the policy in this inventory.
    policy = tmp_path / "synthetic-policy.json"
    policy.write_text(vector["JSON"], encoding="utf-8")
    monkeypatch.setenv("DIDCOMM_ENCRYPTION_POLICY_FILE", str(policy))
    with pytest.raises(rust_integration.DidcommEncryptionPolicyError) as rejected:
        rust_integration._load_didcomm_issuer_encryption_policy("did:web:issuer.example")
    assert str(rejected.value) == vector["error"]
