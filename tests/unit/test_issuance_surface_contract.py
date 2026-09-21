"""Feature-loss gates for the native Rust issuance migration."""

from __future__ import annotations

import hashlib
import importlib.util
import json
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


def test_rust_owned_application_surfaces_preserve_the_remaining_semantic_surface() -> None:
    # Baseline: reviewed Application Template and internal-Application Rust
    # cutovers. Only dynamic-lookup
    # source-line metadata is excluded; source paths, ordering and every retained
    # HTTP, RPC, configuration, runtime and migration field remain in the digest.
    # check_contract above still requires exact current source-line metadata.
    contract = surface.build_contract()
    for lookup in contract["configuration"]["dynamic_lookups"]:
        del lookup["line"]
    encoded = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == (
        "f47699f0dae769b60784414df61c46ad68d03a79bb5ccff62d11b1d3cbe3783b"
    )


def test_contract_covers_every_current_runtime_boundary() -> None:
    contract = surface.build_contract()

    assert contract["schema"] == "marty.issuance-runtime-surface/v1"
    assert contract["http"]["route_count"] == 109
    assert contract["grpc"]["method_count"] == 12
    assert {mode["name"] for mode in contract["runtime"]["modes"]} == {
        "api",
        "canvas-sync-worker",
    }
    assert contract["migrations"]["revision_count"] == 46
    assert contract["migrations"]["heads"] == ["application_template_management"]


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
