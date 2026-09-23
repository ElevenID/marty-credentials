"""Anti-reintroduction guards for Rust-owned issuance HTTP behavior."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from issuance import canvas_worker
from issuance.application import rust_integration
from issuance.infrastructure.adapters import canvas_credentials_adapter
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import routes
from issuance.infrastructure.api.physical_document_routes import physical_document_router

ROOT = Path(__file__).resolve().parents[2]
ISSUANCE = ROOT / "services" / "issuance"

RETIRED_ROUTE_IDENTITIES = frozenset(
    {
        ("PUT", "/v1/issuance/oid4vci-clients"),
        ("GET", "/v1/issuance/authorize"),
        ("POST", "/v1/issuance/par"),
        ("POST", "/v1/issuance/deferred-credential"),
        ("POST", "/v1/issuance/notification"),
        ("POST", "/v1/issuance/transactions/{tx_id}/revoke"),
        ("GET", "/v1/issuance/credentials"),
        (
            "POST",
            "/v1/issued-credentials/{credential_id}/deliveries/canvas-credentials/publish",
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-pending",
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle",
        ),
        ("GET", "/v1/issuance/organizations/{organization_id}/canvas-mirror-health"),
        (
            "GET",
            "/v1/issuance/delivery-records/canvas-credentials/provenance",
        ),
    }
)

RETIRED_ROUTE_SYMBOLS = frozenset(
    {
        "put_oid4vci_registered_client",
        "authorize",
        "pushed_authorization_request",
        "deferred_credential",
        "notification_endpoint",
        "revoke_transaction",
        "list_credentials",
        "publish_issued_credential_canvas_mirror",
        "process_pending_canvas_mirror_deliveries",
        "process_failed_canvas_mirror_status_syncs",
        "run_canvas_mirror_automation_cycle_endpoint",
        "get_canvas_mirror_health",
        "get_canvas_mirror_provenance",
        "run_canvas_mirror_automation_loop",
    }
)

RETAINED_LEGACY_ROUTE_IDENTITIES = frozenset(
    {
        ("GET", "/v1/issuance/organizations/{organization_id}/retention"),
        ("POST", "/v1/issuance/organizations/{organization_id}/retention/purge"),
        ("GET", "/v1/passport/capabilities"),
        ("POST", "/v1/passport/applications"),
        ("POST", "/v1/passport/applications/{application_id}/generate-sod"),
        ("POST", "/v1/passport/applications/{application_id}/generate-data-groups"),
        ("POST", "/v1/passport/applications/{application_id}/submit-personalization"),
        ("GET", "/v1/passport/applications/{application_id}/production-status"),
        ("POST", "/v1/passport/applications/{application_id}/quality-verify"),
        ("POST", "/v1/passport/applications/{application_id}/activate"),
        ("POST", "/v1/passport/webhooks/personalization"),
    }
)


def _router_identities() -> set[tuple[str, str]]:
    identities: set[tuple[str, str]] = set()
    for router in (routes.issuance_router, routes.issued_credential_router):
        for route in router.routes:
            identities.update((method, route.path) for method in route.methods or ())
    return identities


def _method_names(path: Path, class_name: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    owner = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    return {
        node.name
        for node in owner.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_rust_owned_python_routes_stay_retired() -> None:
    assert RETIRED_ROUTE_IDENTITIES.isdisjoint(_router_identities())
    assert all(not hasattr(routes, name) for name in RETIRED_ROUTE_SYMBOLS)
    assert not hasattr(canvas_credentials_adapter, "publish_canvas_credential_mirror")
    assert not hasattr(canvas_credentials_adapter, "CanvasCredentialsPublishResult")


def test_retired_python_repository_writers_stay_absent() -> None:
    port_methods = _method_names(ISSUANCE / "domain" / "ports.py", "IIssuanceRepository")
    memory_methods = _method_names(
        ISSUANCE / "infrastructure" / "adapters" / "memory_repository.py",
        "InMemoryIssuanceRepository",
    )
    postgres_methods = _method_names(
        ISSUANCE / "infrastructure" / "adapters" / "postgres_repository.py",
        "PostgresIssuanceRepository",
    )
    retired = {
        "save_oid4vci_client",
        "save_pushed_authorization_request",
        "consume_pushed_authorization_request",
    }
    assert retired.isdisjoint(port_methods)
    assert retired.isdisjoint(memory_methods)
    assert retired.isdisjoint(postgres_methods)

    assert "get_oid4vci_client" in port_methods
    assert "get_oid4vci_client" in memory_methods
    assert "get_oid4vci_client" in postgres_methods


def test_remaining_python_feature_surface_is_preserved() -> None:
    identities = _router_identities()
    assert ("POST", "/v1/issuance/didcomm/deliver") in identities
    physical_identities = {
        (method, route.path)
        for route in physical_document_router.routes
        for method in route.methods or ()
    }
    assert identities | physical_identities >= RETAINED_LEGACY_ROUTE_IDENTITIES

    assert callable(routes._sync_canvas_lifecycle_delivery_record)
    assert callable(routes._sync_canvas_lifecycle_delivery_records)
    assert callable(canvas_credentials_adapter.sync_canvas_credential_status)
    assert callable(canvas_credentials_adapter.validate_canvas_credentials_config)
    assert callable(canvas_credentials_adapter.process_canvas_evidence_event)
    assert callable(canvas_worker.run_canvas_sync_worker_cycle)
    assert callable(canvas_worker.run_canvas_sync_worker_loop)
    assert hasattr(InMemoryIssuanceRepository, "get_oid4vci_client")

    assert callable(rust_integration.didcomm_encrypt_prepared_delivery)
    assert {
        "didcomm_encrypt",
        "didcomm_encrypt_authcrypt",
        "didcomm_pack_credential",
    } <= rust_integration.REQUIRED_MARTY_RS_CAPABILITIES


def test_storage_history_and_didcomm_kms_follow_up_remain() -> None:
    models = (ISSUANCE / "infrastructure" / "models.py").read_text(encoding="utf-8")
    assert "oid4vci_registered_clients_table" in models
    assert "authorization_sessions_table" in models
    assert "credential_delivery_records_table" in models

    migrations = ISSUANCE / "infrastructure" / "migrations" / "versions"
    assert (migrations / "20260727_0600_add_oid4vci_registered_clients.py").exists()
    assert (migrations / "20260512_1100_add_credential_delivery_records.py").exists()

    surface = json.loads((ROOT / "contracts" / "issuance-runtime-surface.json").read_text())
    route_paths = {route["path"] for route in surface["http"]["routes"]}
    assert "/.well-known/openid-credential-issuer" in route_paths
    assert "/.well-known/openid-credential-issuer/org/{org_id}" in route_paths
    assert "/.well-known/oauth-authorization-server" in route_paths

    outstanding = (ROOT / "docs" / "rust-migrations" / "didcomm-kms-outstanding.md").read_text(
        encoding="utf-8"
    )
    assert "DIDCOMM-KMS-001" in outstanding


def test_retained_issuance_regression_tests_are_not_deleted_with_route_tests() -> None:
    issuance_retained = {
        "test_dpop_proof_is_bound_to_its_key_token_and_endpoint",
        "test_dpop_accepts_ps256_rsa_proofs_used_by_oidf_conformance",
        "test_root_issuer_metadata_advertises_selectable_oid4vci_formats",
        "test_postgres_transaction_mapper_preserves_lifecycle_dependencies",
        "test_issuer_profile_mdoc_signing_uses_only_trusted_certificate_chain",
        "test_post_issuance_records_wallet_and_pending_canvas_mirror",
        "test_revoke_syncs_delivered_canvas_mirror",
        "test_transaction_id_substitution_fails_closed",
        "test_renewal_offer_links_new_transaction_to_source_credential",
        "test_completed_renewal_supersedes_source_credential",
    }
    canvas_retained = {
        "test_map_canvas_event_to_mip_evidence_receipt_uses_application_primitive",
        "test_verify_canvas_signature_rejects_stale_timestamp",
        "test_validate_real_api_reports_missing_token",
        "test_tenant_metadata_cannot_select_environment_or_file_secrets",
        "test_process_canvas_evidence_event_attaches_application_evidence_and_replays",
        "test_process_canvas_evidence_event_policy_denies_wrong_scope",
    }
    for path, retained in (
        (ROOT / "tests" / "test_issuance_changes.py", issuance_retained),
        (ROOT / "tests" / "unit" / "test_canvas_credentials_adapter.py", canvas_retained),
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        tests = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert retained <= tests.keys()
        for name in retained:
            assert all("skip" not in ast.unparse(mark) for mark in tests[name].decorator_list)
        for owner in tree.body:
            if isinstance(owner, ast.ClassDef) and any(
                isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name in retained
                for child in owner.body
            ):
                assert all("skip" not in ast.unparse(mark) for mark in owner.decorator_list)
