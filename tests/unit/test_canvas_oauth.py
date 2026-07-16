from __future__ import annotations

import httpx
import pytest
from issuance.application.canvas_lti_services import CANVAS_TOKEN_RESPONSE_MAX_BYTES
from issuance.application.canvas_oauth import (
    CanvasOAuthError,
    canvas_oauth_authorization_url,
    canvas_oauth_scopes_for_capabilities,
    exchange_canvas_oauth_code,
    refresh_canvas_oauth_token,
    revoke_canvas_oauth_token,
)


def test_canvas_oauth_capabilities_resolve_to_fixed_least_privilege_scopes() -> None:
    scopes = canvas_oauth_scopes_for_capabilities(
        ["native_activity_scores", "course_completion", "native_activity_scores"]
    )
    assert scopes == [
        "url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id",
        "url:GET|/api/v1/courses/:course_id/users/:user_id/progress",
    ]
    with pytest.raises(CanvasOAuthError, match="Unsupported"):
        canvas_oauth_scopes_for_capabilities(["url:GET|/api/v1/accounts"])
    with pytest.raises(CanvasOAuthError, match="At least one"):
        canvas_oauth_scopes_for_capabilities([])


def test_canvas_oauth_authorization_url_requests_explicit_scopes() -> None:
    url = canvas_oauth_authorization_url(
        canvas_base_url="https://canvas.example/ignored/path?query=discarded",
        client_id="client-1",
        redirect_uri="https://issuer.example/callback",
        state="signed-state",
        scopes=["url:GET|/api/v1/courses", "url:GET|/api/v1/courses/:course_id/modules"],
    )
    assert url.startswith("https://canvas.example/login/oauth2/auth?")
    assert "/ignored/path" not in url
    assert "response_type=code" in url
    assert "scope=url%3AGET" in url


@pytest.mark.asyncio
async def test_canvas_oauth_code_exchange_returns_token_bundle() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://canvas.example/login/oauth2/token"
        return httpx.Response(200, json={"access_token": "access", "refresh_token": "refresh", "expires_in": 3600})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await exchange_canvas_oauth_code(
            client=client,
            canvas_base_url="https://canvas.example",
            client_id="client-1",
            client_secret="secret",
            code="authorization-code",
            redirect_uri="https://issuer.example/callback",
        )
    assert result["access_token"] == "access"
    assert result["refresh_token"] == "refresh"
    assert result["obtained_at"] > 0


@pytest.mark.asyncio
async def test_canvas_oauth_transport_failures_are_sanitized_for_callback_and_retry_paths() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("resolver changed while connecting", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CanvasOAuthError, match="transport failed"):
            await exchange_canvas_oauth_code(
                client=client,
                canvas_base_url="https://canvas.example",
                client_id="client-1",
                client_secret="secret",
                code="authorization-code",
                redirect_uri="https://issuer.example/callback",
            )
        with pytest.raises(CanvasOAuthError, match="transport failed"):
            await revoke_canvas_oauth_token(
                client=client,
                canvas_base_url="https://canvas.example",
                access_token="access-token",
            )


@pytest.mark.asyncio
async def test_canvas_oauth_authenticated_endpoints_reject_redirects() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"Location": "https://attacker.example/collect"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CanvasOAuthError, match="redirect"):
            await exchange_canvas_oauth_code(
                client=client,
                canvas_base_url="https://canvas.example",
                client_id="client-1",
                client_secret="secret",
                code="authorization-code",
                redirect_uri="https://issuer.example/callback",
            )
        with pytest.raises(CanvasOAuthError, match="redirect"):
            await refresh_canvas_oauth_token(
                client=client,
                canvas_base_url="https://canvas.example",
                client_id="client-1",
                client_secret="secret",
                refresh_token="refresh-token",
            )
        with pytest.raises(CanvasOAuthError, match="redirect"):
            await revoke_canvas_oauth_token(
                client=client,
                canvas_base_url="https://canvas.example",
                access_token="access-token",
            )

    assert len(requests) == 3
    assert all(request.url.host == "canvas.example" for request in requests)


@pytest.mark.asyncio
async def test_canvas_oauth_token_response_body_is_bounded() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": str(CANVAS_TOKEN_RESPONSE_MAX_BYTES + 1)},
            content=b"{}",
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CanvasOAuthError, match="safely"):
            await exchange_canvas_oauth_code(
                client=client,
                canvas_base_url="https://canvas.example",
                client_id="client-1",
                client_secret="secret",
                code="authorization-code",
                redirect_uri="https://issuer.example/callback",
            )


@pytest.mark.asyncio
async def test_canvas_oauth_invalid_refresh_keeps_stable_reauthorization_marker() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CanvasOAuthError, match="HTTP 400"):
            await refresh_canvas_oauth_token(
                client=client,
                canvas_base_url="https://canvas.example",
                client_id="client-1",
                client_secret="secret",
                refresh_token="expired-refresh-token",
            )
