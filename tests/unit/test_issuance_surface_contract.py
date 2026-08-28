"""Feature-loss gates for the native Rust issuance migration."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "issuance_surface_contract.py"
SPEC = importlib.util.spec_from_file_location("issuance_surface_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
surface = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = surface
SPEC.loader.exec_module(surface)


def test_frozen_issuance_surface_matches_python_parity_oracle() -> None:
    surface.check_contract()


def test_contract_covers_every_current_runtime_boundary() -> None:
    contract = surface.build_contract()

    assert contract["schema"] == "marty.issuance-runtime-surface/v1"
    assert contract["http"]["route_count"] == 131
    assert contract["grpc"]["method_count"] == 12
    assert {mode["name"] for mode in contract["runtime"]["modes"]} == {
        "api",
        "canvas-sync-worker",
    }
    assert contract["migrations"]["revision_count"] == 44
    assert contract["migrations"]["heads"] == ["merge_issuance_heads"]


def test_contract_retains_critical_protocol_and_lifecycle_operations() -> None:
    contract = surface.build_contract()
    routes = {(route["method"], route["path"]) for route in contract["http"]["routes"]}
    grpc = {method["method"]: method["transport"] for method in contract["grpc"]["methods"]}

    assert ("GET", "/.well-known/openid-credential-issuer") in routes
    assert ("POST", "/v1/issuance/token") in routes
    assert ("POST", "/v1/issuance/credential") in routes
    assert ("POST", "/v1/issued-credentials/{credential_id}/revoke") in routes
    assert (
        "POST",
        "/v1/passport/applications/{application_id}/submit-personalization",
    ) in routes
    assert (
        "POST",
        "/v1/integrations/canvas/lti/platforms/{platform_id}/login",
    ) in routes
    assert grpc["IssueCredential"] == "unary_unary"
    assert grpc["StreamCredentialEvents"] == "unary_stream"
