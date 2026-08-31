"""Feature-loss gates for verification-image consolidation."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

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
    assert contract["packaging"]["port"] == 8006


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
