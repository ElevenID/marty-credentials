"""Unit tests for Canvas sandbox hardening and LTI launch routes."""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import parse_qs, urlparse
from unittest.mock import MagicMock

import pytest
from starlette.requests import Request

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_SERVICES = os.path.join(_REPO_ROOT, "services")

if _SERVICES not in sys.path:
    sys.path.insert(0, _SERVICES)

for _module_name in (
    "status_list",
    "status_list.infrastructure",
    "status_list.infrastructure.security",
    "status_list.infrastructure.security.encryption",
):
    sys.modules.setdefault(_module_name, MagicMock())

from issuance.domain.entities import CanvasConnectorConfig
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import canvas_routes


def _json_request(payload: dict[str, object], path: str = "/v1/integrations/canvas/lti/launch/test") -> Request:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [(b"content-type", b"application/json")],
        },
        receive,
    )


@pytest.mark.asyncio
async def test_probe_canvas_connector_sandbox_persists_rust_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    connector = CanvasConnectorConfig(
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        credential_template_id="tmpl-123",
        canvas_base_url="https://canvas.example.edu",
    )
    await repo.save_canvas_connector(connector)

    monkeypatch.setattr(
        canvas_routes,
        "canvas_probe_lti_platform",
        lambda base_url: {
            "canvas_base_url": base_url,
            "issuer": "https://canvas.example.edu",
            "jwks_uri": "https://canvas.example.edu/jwks",
            "jwks_json": {"keys": [{"kid": "canvas-kid"}]},
            "raw_openid_configuration": {
                "issuer": "https://canvas.example.edu",
                "jwks_uri": "https://canvas.example.edu/jwks",
            },
        },
    )

    response = await canvas_routes.probe_canvas_connector_sandbox(connector.id, repo=repo)
    stored = await repo.get_canvas_connector(connector.id)

    assert response.connector.id == connector.id
    assert response.probe["issuer"] == "https://canvas.example.edu"
    assert response.connector.mip_primitives["provider"] == "canvas"
    assert "webhook_endpoint" in response.connector.mip_primitives["primitives"]
    assert "oid4vci_pre_authorized_issuance" in response.connector.mip_primitives["primitives"]
    assert "oidc_id_token_verification" in response.connector.mip_primitives["primitives"]
    assert "integrations:write" in response.connector.mip_primitives["actions"]
    assert response.connector.mip_primitives["resources"]["integration_connector"]["type"] == "IntegrationConnector"
    assert response.connector.mip_primitives["resources"]["credential_template"]["id"] == "tmpl-123"
    assert stored is not None
    assert stored.lti_issuer == "https://canvas.example.edu"
    assert stored.lti_jwks_url == "https://canvas.example.edu/jwks"
    assert stored.lti_jwks_json == {"keys": [{"kid": "canvas-kid"}]}
    assert stored.lti_jwks_fetched_at is not None
    assert stored.lti_jwks_expires_at is not None
    assert stored.lti_jwks_expires_at > stored.lti_jwks_fetched_at


@pytest.mark.asyncio
async def test_plan_canvas_evidence_flow_returns_mip_orchestration_plan() -> None:
    repo = InMemoryIssuanceRepository()
    connector = CanvasConnectorConfig(
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        credential_template_id="tmpl-123",
        canvas_base_url="https://canvas.example.edu",
    )
    await repo.save_canvas_connector(connector)

    response = await canvas_routes.plan_canvas_evidence_flow(
        connector.id,
        request=canvas_routes.CanvasEvidenceFlowRequest(
            application_id="app-123",
            application_template_id="application-template-123",
            canvas_course_id="course-101",
            auto_issue_on_completion=True,
        ),
        repo=repo,
    )

    assert response.connector.id == connector.id
    assert response.flow["mode"] == "elevenid_orchestrated_canvas_evidence"
    assert "application_evidence_request" in response.flow["primitives"]
    assert "signed_evidence_receipt" in response.flow["primitives"]
    assert "oid4vci_pre_authorized_issuance_gate" not in response.flow["primitives"]
    assert response.flow["resources"]["application"]["id"] == "app-123"
    assert response.flow["resources"]["webhook_endpoint"]["path"] == "/v1/integrations/canvas/evidence-events"
    assert response.flow["metadata"]["canvas_course_id"] == "course-101"
    assert response.flow["metadata"]["direct_issue_enabled"] is False
    assert response.flow["metadata"]["auto_issue_on_completion"] is False


@pytest.mark.asyncio
async def test_verify_canvas_lti_launch_route_returns_identity_context(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    connector = CanvasConnectorConfig(
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        credential_template_id="tmpl-123",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )
    await repo.save_canvas_connector(connector)

    login_response = await canvas_routes.initiate_canvas_lti_login_route(
        connector.id,
        request=_json_request(
            {
                "iss": "https://canvas.example.edu",
                "login_hint": "login-hint-123",
                "target_link_uri": "https://tool.example.edu/launch",
                "lti_message_hint": "message-hint-123",
                "client_id": "client-123",
            },
            path="/v1/integrations/canvas/lti/login/test",
        ),
        repo=repo,
    )
    location = login_response.headers["location"]
    params = parse_qs(urlparse(location).query)
    state = params["state"][0]
    nonce = params["nonce"][0]

    monkeypatch.setattr(
        canvas_routes,
        "verify_canvas_lti_launch",
        lambda **kwargs: {
            "issuer": kwargs["expected_issuer"],
            "subject": "student-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "issued_at": 1700000000,
            "expires_at": 1700000300,
            "message_type": "LtiResourceLinkRequest",
            "lti_version": "1.3.0",
            "target_link_uri": "https://tool.example.edu/launch",
            "context": {"id": "course-101", "label": "PORTABLE101"},
            "roles": ["Learner"],
            "learner_identity": {"subject": "student-123", "issuer": kwargs["expected_issuer"]},
            "raw_claims": {"sub": "student-123"},
        },
    )

    response = await canvas_routes.verify_canvas_lti_launch_route(
        connector.id,
        request=_json_request(
            {
                "id_token": "header.payload.signature",
                "state": state,
            }
        ),
        repo=repo,
    )

    assert response.verified is True
    assert response.connector_id == connector.id
    assert response.organization_id == "org-123"
    assert response.canvas_account_id == "canvas-acct-1"
    assert response.subject == "student-123"
    assert response.nonce == nonce
    assert response.state == state
    assert response.context == {"id": "course-101", "label": "PORTABLE101"}
    assert response.roles == ["Learner"]
    assert response.learner_identity["subject"] == "student-123"


@pytest.mark.asyncio
async def test_canvas_lti_experience_launch_redirects_and_persists_session(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    connector = CanvasConnectorConfig(
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        credential_template_id="tmpl-123",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )
    await repo.save_canvas_connector(connector)
    monkeypatch.setattr(canvas_routes, "CANVAS_LTI_EXPERIENCE_BASE_URL", "https://app.example.edu")

    login_response = await canvas_routes.initiate_canvas_lti_experience_login_route(
        connector.id,
        request=_json_request(
            {
                "iss": "https://canvas.example.edu",
                "login_hint": "login-hint-123",
                "target_link_uri": "https://tool.example.edu/launch",
                "client_id": "client-123",
            },
            path="/v1/integrations/canvas/lti/experience-login/test",
        ),
        repo=repo,
    )
    login_params = parse_qs(urlparse(login_response.headers["location"]).query)
    state = login_params["state"][0]
    nonce = login_params["nonce"][0]
    assert login_params["redirect_uri"][0].endswith(f"/v1/integrations/canvas/lti/experience/{connector.id}")

    monkeypatch.setattr(
        canvas_routes,
        "verify_canvas_lti_launch",
        lambda **kwargs: {
            "issuer": kwargs["expected_issuer"],
            "subject": "student-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "message_type": "LtiResourceLinkRequest",
            "lti_version": "1.3.0",
            "context": {"id": "course-101", "title": "Portable Trust 101"},
            "roles": ["Learner"],
            "learner_identity": {"subject": "student-123", "issuer": kwargs["expected_issuer"]},
            "raw_claims": {"sub": "student-123"},
        },
    )

    launch_response = await canvas_routes.launch_canvas_lti_experience_route(
        connector.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )
    session = await canvas_routes.get_canvas_lti_experience_session_route(state, repo=repo)

    assert launch_response.status_code == 303
    assert launch_response.headers["location"] == f"https://app.example.edu/canvas/lti/experience?state={state}"
    assert session.state == state
    assert session.status == "consumed"
    assert session.verified_launch["nonce"] == nonce
    assert session.verified_launch["subject"] == "student-123"
    assert session.mip_primitives["protocol"] == "ELEVENID_EXPERIENCE"
    assert session.mip_primitives["source"]["event_type"] == "canvas.lti_launch"


@pytest.mark.asyncio
async def test_verify_canvas_lti_launch_rejects_reused_state(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    connector = CanvasConnectorConfig(
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        credential_template_id="tmpl-123",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "canvas-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )
    await repo.save_canvas_connector(connector)

    login_response = await canvas_routes.initiate_canvas_lti_login_route(
        connector.id,
        request=_json_request(
            {"login_hint": "login-hint-123"},
            path="/v1/integrations/canvas/lti/login/test",
        ),
        repo=repo,
    )
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    monkeypatch.setattr(
        canvas_routes,
        "verify_canvas_lti_launch",
        lambda **kwargs: {
            "issuer": kwargs["expected_issuer"],
            "subject": "student-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "roles": ["Learner"],
            "learner_identity": {"subject": "student-123"},
            "raw_claims": {"sub": "student-123"},
        },
    )

    first = await canvas_routes.verify_canvas_lti_launch_route(
        connector.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )

    assert first.verified is True

    with pytest.raises(Exception) as exc_info:
        await canvas_routes.verify_canvas_lti_launch_route(
            connector.id,
            request=_json_request({"id_token": "header.payload.signature", "state": state}),
            repo=repo,
        )

    assert getattr(exc_info.value, "status_code", None) == 400


@pytest.mark.asyncio
async def test_verify_canvas_lti_launch_refreshes_jwks_on_kid_miss(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = InMemoryIssuanceRepository()
    connector = CanvasConnectorConfig(
        organization_id="org-123",
        canvas_account_id="canvas-acct-1",
        credential_template_id="tmpl-123",
        canvas_base_url="https://canvas.example.edu",
        lti_client_id="client-123",
        lti_deployment_id="deployment-xyz",
        lti_issuer="https://canvas.example.edu",
        lti_jwks_json={"keys": [{"kid": "old-kid"}]},
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )
    await repo.save_canvas_connector(connector)

    login_response = await canvas_routes.initiate_canvas_lti_login_route(
        connector.id,
        request=_json_request(
            {"login_hint": "login-hint-123"},
            path="/v1/integrations/canvas/lti/login/test",
        ),
        repo=repo,
    )
    state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

    monkeypatch.setattr(
        canvas_routes,
        "canvas_probe_lti_platform",
        lambda base_url: {
            "canvas_base_url": base_url,
            "issuer": "https://canvas.example.edu",
            "jwks_uri": "https://canvas.example.edu/jwks",
            "jwks_json": {"keys": [{"kid": "new-kid"}]},
            "raw_openid_configuration": {
                "issuer": "https://canvas.example.edu",
                "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
                "jwks_uri": "https://canvas.example.edu/jwks",
            },
        },
    )

    calls = {"count": 0}

    def fake_verify(**kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise Exception("No JWKS entry found for LTI kid new-kid")
        assert kwargs["jwks_json"] == {"keys": [{"kid": "new-kid"}]}
        return {
            "issuer": kwargs["expected_issuer"],
            "subject": "student-123",
            "audience": [kwargs["expected_client_id"]],
            "deployment_id": kwargs["expected_deployment_id"],
            "nonce": kwargs["expected_nonce"],
            "roles": ["Learner"],
            "learner_identity": {"subject": "student-123"},
            "raw_claims": {"sub": "student-123"},
        }

    monkeypatch.setattr(canvas_routes, "verify_canvas_lti_launch", fake_verify)

    response = await canvas_routes.verify_canvas_lti_launch_route(
        connector.id,
        request=_json_request({"id_token": "header.payload.signature", "state": state}),
        repo=repo,
    )
    stored = await repo.get_canvas_connector(connector.id)

    assert response.verified is True
    assert calls["count"] == 2
    assert stored is not None
    assert stored.lti_jwks_json == {"keys": [{"kid": "new-kid"}]}
    assert stored.lti_jwks_fetched_at is not None
