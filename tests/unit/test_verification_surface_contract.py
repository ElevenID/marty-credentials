"""Feature-loss gates for verification-image consolidation."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "verification_surface_contract.py"
SPEC = importlib.util.spec_from_file_location("verification_surface_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
surface = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = surface
SPEC.loader.exec_module(surface)


def test_frozen_verification_surface_matches_python_oracle() -> None:
    surface.check_contract()


def test_contract_covers_every_current_runtime_boundary() -> None:
    contract = surface.build_contract()

    assert contract["schema"] == "marty.verification-runtime-surface/v1"
    assert contract["http"]["route_count"] == 7
    assert contract["migrations"]["revision_count"] == 2
    assert contract["migrations"]["heads"] == ["202608091200"]
    assert contract["runtime"]["modes"][0]["name"] == "api"
    assert contract["packaging"]["expose"] == "8006"
    assert "http://localhost:8006/health" in contract["packaging"]["health_command"]


def test_contract_retains_public_routes_and_governed_purposes() -> None:
    contract = surface.build_contract()
    routes = {(route["method"], route["path"]) for route in contract["http"]["routes"]}

    assert routes == {
        ("GET", "/health"),
        ("GET", "/v1/verification/health"),
        ("GET", "/v1/verification/sessions/{session_id}"),
        ("POST", "/v1/verification/sessions"),
        ("POST", "/v1/verification/sessions/{session_id}/submit"),
        ("POST", "/v1/verification/verify"),
        ("POST", "/v1/verification/verify/vds-nc"),
    }
    assert contract["governance"]["purposes"] == [
        "verification.direct",
        "verification.session.create",
        "verification.vds-nc",
    ]
    assert contract["governance"]["processing_states"] == [
        "COMPLETED",
        "ERROR",
        "UNAVAILABLE",
        "UNSUPPORTED",
    ]


def test_contract_retains_request_and_result_shapes() -> None:
    models = {model["name"]: model for model in surface.build_contract()["dto"]["models"]}
    create_fields = {field["name"] for field in models["CreateSessionRequest"]["fields"]}
    result_fields = {field["name"] for field in models["VerificationResult"]["fields"]}

    assert create_fields == {
        "presentation_definition",
        "session_duration_seconds",
        "verifier_did",
    }
    assert {
        "canonical_result",
        "processing_status",
        "decision",
        "decision_code",
        "valid",
        "verified_claims",
        "verification_method",
        "error",
    } <= result_fields
    assert models["CreateSessionRequest"]["model_config"] == "ConfigDict(extra='forbid')"
    assert models["VerifyDirectRequest"]["model_config"] == "ConfigDict(extra='forbid')"
    assert [validator["name"] for validator in models["VerificationResult"]["validators"]] == [
        "derive_compatibility_projection"
    ]


def test_contract_retains_authorization_and_error_mapping() -> None:
    routes = {
        (route["method"], route["path"]): route
        for route in surface.build_contract()["http"]["routes"]
    }

    create = routes[("POST", "/v1/verification/sessions")]
    direct = routes[("POST", "/v1/verification/verify")]
    submit = routes[("POST", "/v1/verification/sessions/{session_id}/submit")]
    vds = routes[("POST", "/v1/verification/verify/vds-nc")]
    assert create["request_model"] == "CreateSessionRequest"
    assert create["dependencies"] == ["_authorize_session_create", "get_verification_service"]
    assert direct["dependencies"] == ["_authorize_direct_verify", "get_verification_service"]
    assert vds["dependencies"] == ["_authorize_vds_nc_verify", "get_credential_verifier"]
    assert submit["dependencies"] == ["get_verification_service"]
    submit_statuses = {error["status"] for error in submit["declared_errors"]}
    assert {
        "status.HTTP_400_BAD_REQUEST",
        "status.HTTP_404_NOT_FOUND",
        "status.HTTP_409_CONFLICT",
        "status.HTTP_410_GONE",
        "status.HTTP_422_UNPROCESSABLE_ENTITY",
        "status.HTTP_500_INTERNAL_SERVER_ERROR",
    } <= submit_statuses


def test_contract_retains_fail_closed_configuration() -> None:
    variables = set(surface.build_contract()["configuration"]["environment_variables"])
    assert {
        "DATABASE_URL",
        "SIGNING_KEYS_INTERNAL_API_KEY",
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
        "SIGNING_KEYS_INTERNAL_URL",
        "VERIFICATION_GOVERNANCE_JSON",
        "VERIFICATION_PROCESSING_LEASE_SECONDS",
    } <= variables
    governance = surface.build_contract()["governance"]
    assert len(governance["required_native_capabilities"]) == 13
    assert surface.build_contract()["runtime"]["startup_validation_hooks"] == [
        "load_governance",
        "validate_internal_resolver_configuration",
        "validate_marty_rs_capabilities",
    ]


def _sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    service = tmp_path / "services" / "verification"
    service.parent.mkdir(parents=True)
    shutil.copytree(ROOT / "services" / "verification", service)
    manifest = tmp_path / "contracts" / "verification-runtime-surface.json"
    manifest.parent.mkdir()
    shutil.copy2(ROOT / "contracts" / "verification-runtime-surface.json", manifest)
    monkeypatch.setattr(surface, "ROOT", tmp_path)
    monkeypatch.setattr(surface, "SERVICE_ROOT", service)
    monkeypatch.setattr(surface, "MANIFEST", manifest)
    return service


def _assert_mutation_detected() -> None:
    with pytest.raises(surface.ContractError, match="verification surface drifted"):
        surface.check_contract()


def test_route_authorization_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    routes = service / "infrastructure" / "api" / "routes.py"
    routes.write_text(
        routes.read_text(encoding="utf-8").replace(
            "Depends(_authorize_direct_verify)", "Depends(_authorize_session_create)", 1
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_governance_purpose_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    governance = service / "application" / "governance.py"
    governance.write_text(
        governance.read_text(encoding="utf-8").replace(
            'DIRECT_VERIFY_PURPOSE = "verification.direct"',
            'DIRECT_VERIFY_PURPOSE = "verification.direct.changed"',
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_startup_validation_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    main = service / "main.py"
    main.write_text(
        main.read_text(encoding="utf-8").replace("    load_governance()\n", "", 1),
        encoding="utf-8",
    )
    _assert_mutation_detected()


def test_migration_semantic_mutation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sandbox(tmp_path, monkeypatch)
    migration = (
        service
        / "infrastructure"
        / "migrations"
        / "versions"
        / "20260809_1200_atomic_verification_sessions.py"
    )
    migration.write_text(
        migration.read_text(encoding="utf-8").replace(
            "ux_verification_sessions_live_nonce", "ux_verification_sessions_live_nonce_changed"
        ),
        encoding="utf-8",
    )
    _assert_mutation_detected()
