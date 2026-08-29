from __future__ import annotations

import json
from pathlib import Path

from issuance.application.canvas_oauth import (
    _CANVAS_OAUTH_CAPABILITY_ALIASES,
    CANVAS_OAUTH_CAPABILITY_SCOPES,
    canvas_oauth_scopes_for_capabilities,
    normalize_canvas_oauth_capabilities,
)
from issuance.infrastructure.api import canvas_routes

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-canvas-oauth-lifecycle.json").read_text(encoding="utf-8")
)


def test_contract_freezes_the_public_route_and_authentication_boundary() -> None:
    assert CONTRACT["schema"] == "marty.issuance-canvas-oauth-lifecycle/v1"
    expected = {
        ("POST", "/v1/integrations/canvas/platforms/{platform_id}/oauth/authorizations"),
        ("GET", "/v1/integrations/canvas/oauth/callback"),
        ("DELETE", "/v1/integrations/canvas/platforms/{platform_id}/oauth"),
    }
    assert {(route["method"], route["path"]) for route in CONTRACT["scope"]["routes"]} == expected
    actual = {
        (method, route.path)
        for route in canvas_routes.canvas_integration_router.routes
        for method in route.methods
        if (method, route.path) in expected
    }
    assert actual == expected
    routes = {route["operation"]: route for route in CONTRACT["scope"]["routes"]}
    assert routes["complete_canvas_oauth_connection"]["authentication"] == "public-one-time-state"
    assert routes["start_canvas_oauth_connection"]["authentication"] == (
        "management-api-key-and-trusted-organization"
    )
    assert routes["disconnect_canvas_oauth_connection"]["authentication"] == (
        "management-api-key-and-trusted-organization"
    )


def test_contract_freezes_capability_derived_least_privilege_scopes() -> None:
    assert CONTRACT["capabilities"] == {
        capability: list(scopes) for capability, scopes in CANVAS_OAUTH_CAPABILITY_SCOPES.items()
    }
    assert CONTRACT["capability_aliases"] == _CANVAS_OAUTH_CAPABILITY_ALIASES
    requested = list(CONTRACT["capabilities"])
    assert normalize_canvas_oauth_capabilities(requested) == requested
    assert canvas_oauth_scopes_for_capabilities(requested) == list(
        dict.fromkeys(
            scope for capability in requested for scope in CONTRACT["capabilities"][capability]
        )
    )


def test_contract_freezes_replay_origin_secret_and_revocation_safety() -> None:
    assert CONTRACT["start"]["authorization"] == {
        "endpoint_path": "/login/oauth2/auth",
        "response_type": "code",
        "state_entropy_bytes_minimum": 32,
        "persisted_state": "sha256-only",
        "ttl_seconds": 600,
        "scope_policy": "server-owned-capability-derived",
    }
    assert CONTRACT["callback"]["response_headers"] == {
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
    }
    assert CONTRACT["callback"]["token_endpoint"]["follow_redirects"] is False
    assert CONTRACT["callback"]["token_endpoint"]["exact_registered_origin"] is True
    assert CONTRACT["callback"]["publication"]["platform_snapshot_cas"] is True
    assert CONTRACT["callback"]["publication"]["browser_token_disclosure"] is False
    assert CONTRACT["disconnect"]["remote_revocation"]["exact_connection_origin"] is True
    assert CONTRACT["disconnect"]["retry"] == {
        "base_seconds": 30,
        "maximum_seconds": 3600,
        "honor_retry_after": True,
        "durable": True,
    }
    assert (
        "callback-state-is-single-use-even-on-denial-or-failure" in CONTRACT["security_invariants"]
    )
