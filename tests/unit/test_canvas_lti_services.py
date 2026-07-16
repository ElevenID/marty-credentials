from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from issuance.application.canvas_lti_services import (
    CANVAS_COLLECTION_PAGE_MAX_BYTES,
    CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
    CANVAS_TOKEN_RESPONSE_MAX_BYTES,
    CanvasLtiServiceError,
    PinnedCanvasAsyncTransport,
    canvas_lti_trust_profile,
    hosted_canvas_lti_profile,
    parse_canvas_retry_after,
    probe_canvas_lti_platform,
    read_ags_results,
    read_nrps_memberships,
    request_lti_access_token,
    resolve_canvas_lti_trust_profile,
    validate_canvas_origin,
    validate_lti_service_url,
)


def _dns_answer(address: str, port: int = 443) -> list[tuple[object, ...]]:
    return [(2, 1, 6, "", (address, port))]


def test_lti_service_url_must_be_https_and_match_platform_origin() -> None:
    assert validate_lti_service_url(
        "https://canvas.example/api/lti/courses/1/line_items/2/results",
        expected_origin="https://canvas.example",
    ).endswith("/results")

    with pytest.raises(CanvasLtiServiceError, match="HTTPS"):
        validate_lti_service_url("http://canvas.example/results")
    with pytest.raises(CanvasLtiServiceError, match="origin"):
        validate_lti_service_url(
            "https://attacker.example/results",
            expected_origin="https://canvas.example",
        )


def test_private_canvas_origin_requires_exact_operator_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(CanvasLtiServiceError, match="exact"):
        validate_canvas_origin("https://127.0.0.1:8443")

    monkeypatch.setenv("CANVAS_PRIVATE_ORIGIN_ALLOWLIST", "https://127.0.0.1:8443")
    assert validate_canvas_origin("https://127.0.0.1:8443/path") == "https://127.0.0.1:8443"
    with pytest.raises(CanvasLtiServiceError, match="exact"):
        validate_canvas_origin("https://127.0.0.1:9443")
    with pytest.raises(CanvasLtiServiceError, match="HTTPS"):
        validate_canvas_origin("http://127.0.0.1:8443")

    monkeypatch.setenv(
        "CANVAS_PRIVATE_ORIGIN_ALLOWLIST",
        "https://127.0.0.1:8443/not-an-origin",
    )
    with pytest.raises(CanvasLtiServiceError, match="exact"):
        validate_canvas_origin("https://127.0.0.1:8443")

    # Shared/non-global carrier space is not a public destination even though
    # Python's ipaddress module does not classify it as ``is_private``.
    with pytest.raises(CanvasLtiServiceError, match="exact"):
        validate_canvas_origin("https://100.64.0.1")


def test_parses_canvas_retry_after_delta_and_http_date() -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    assert parse_canvas_retry_after("37", now=now) == 37
    assert parse_canvas_retry_after("Tue, 14 Jul 2026 12:01:00 GMT", now=now) == 60
    assert parse_canvas_retry_after("invalid", now=now) is None


@pytest.mark.asyncio
async def test_pinned_transport_connects_to_checked_ip_with_original_host_and_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolutions: list[tuple[str, int]] = []
    requests: list[httpx.Request] = []

    def resolve(host: str, port: int, **_: object) -> list[tuple[object, ...]]:
        resolutions.append((host, port))
        return _dns_answer("93.184.216.34", port)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr("issuance.application.canvas_lti_services.socket.getaddrinfo", resolve)
    transport = PinnedCanvasAsyncTransport(transport=httpx.MockTransport(handler))
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("https://canvas.example/api/test", json={"safe": True})

    assert response.status_code == 200
    assert resolutions == [("canvas.example", 443)]
    assert requests[0].url.host == "93.184.216.34"
    assert requests[0].headers["host"] == "canvas.example"
    assert requests[0].extensions["sni_hostname"] == "canvas.example"


@pytest.mark.asyncio
async def test_pinned_transport_isolates_connection_pools_by_original_tls_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pools: list[list[httpx.Request]] = []

    def resolve(_host: str, port: int, **_: object) -> list[tuple[object, ...]]:
        return _dns_answer("93.184.216.34", port)

    def transport_factory(**_kwargs: object) -> httpx.AsyncBaseTransport:
        requests: list[httpx.Request] = []
        pools.append(requests)

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"ok": True})

        return httpx.MockTransport(handler)

    monkeypatch.setattr(
        "issuance.application.canvas_lti_services.socket.getaddrinfo",
        resolve,
    )
    monkeypatch.setattr(
        "issuance.application.canvas_lti_services.httpx.AsyncHTTPTransport",
        transport_factory,
    )
    transport = PinnedCanvasAsyncTransport()
    async with httpx.AsyncClient(transport=transport) as client:
        await client.get("https://canvas-a.example/api/test")
        await client.get("https://canvas-b.example/api/test")
        await client.get("https://canvas-a.example/api/test-again")

    assert len(pools) == 2
    assert [request.headers["host"] for request in pools[0]] == [
        "canvas-a.example",
        "canvas-a.example",
    ]
    assert [request.headers["host"] for request in pools[1]] == [
        "canvas-b.example"
    ]


@pytest.mark.asyncio
async def test_pinned_transport_rejects_dns_rebinding_before_sending_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter(("93.184.216.34", "127.0.0.1"))
    sent = False

    def resolve(host: str, port: int, **_: object) -> list[tuple[object, ...]]:
        return _dns_answer(next(answers), port)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal sent
        sent = True
        return httpx.Response(200)

    monkeypatch.setattr("issuance.application.canvas_lti_services.socket.getaddrinfo", resolve)
    assert validate_canvas_origin("https://canvas.example") == "https://canvas.example"
    transport = PinnedCanvasAsyncTransport(transport=httpx.MockTransport(handler))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(CanvasLtiServiceError, match="exact"):
            await client.get("https://canvas.example/api/test")
    assert sent is False


@pytest.mark.asyncio
async def test_hosted_probe_uses_documented_global_lti_profile_not_custom_well_known(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested: list[str] = []

    def resolve(host: str, port: int, **_: object) -> list[tuple[object, ...]]:
        return _dns_answer("93.184.216.34", port)

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        assert request.url == "https://sso.canvaslms.com/api/lti/security/jwks"
        return httpx.Response(200, json={"keys": [{"kty": "RSA", "kid": "canvas-key"}]})

    def client_factory(*, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=timeout)

    monkeypatch.setattr("issuance.application.canvas_lti_services.socket.getaddrinfo", resolve)
    monkeypatch.setattr(
        "issuance.application.canvas_lti_services.canvas_http_client",
        client_factory,
    )
    probe = await probe_canvas_lti_platform("https://canvas.school.example")

    assert requested == ["https://sso.canvaslms.com/api/lti/security/jwks"]
    assert probe["issuer"] == "https://canvas.instructure.com"
    assert probe["authorization_endpoint"] == (
        "https://sso.canvaslms.com/api/lti/authorize_redirect"
    )
    assert probe["token_endpoint"] == (
        "https://canvas.school.example/login/oauth2/token"
    )
    assert probe["raw_openid_configuration"]["metadata_source"] == (
        "documented_hosted_canvas_profile"
    )


def test_hosted_canvas_profile_uses_environment_specific_global_trust() -> None:
    beta = hosted_canvas_lti_profile("https://school.beta.instructure.com")
    test = hosted_canvas_lti_profile("https://school.test.instructure.com")

    assert beta["issuer"] == "https://canvas.beta.instructure.com"
    assert beta["authorization_endpoint"].startswith("https://sso.beta.canvaslms.com/")
    assert beta["jwks_uri"].startswith("https://sso.beta.canvaslms.com/")
    assert test["issuer"] == "https://canvas.test.instructure.com"
    assert test["authorization_endpoint"].startswith("https://sso.test.canvaslms.com/")
    assert test["jwks_uri"].startswith("https://sso.test.canvaslms.com/")


def test_self_managed_lti_profile_is_exact_allowlisted_and_same_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "https://canvas-test.elevenidllc.com"
    monkeypatch.setenv(
        "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST",
        f"{origin}/,https://another-canvas.example",
    )

    assert resolve_canvas_lti_trust_profile(origin) == (
        CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN
    )
    profile = canvas_lti_trust_profile(
        origin,
        CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
    )
    assert profile == {
        "trust_profile": "self_managed_same_origin",
        "environment": "self_managed",
        "issuer": origin,
        "authorization_endpoint": f"{origin}/api/lti/authorize_redirect",
        "jwks_uri": f"{origin}/api/lti/security/jwks",
        "token_endpoint": f"{origin}/login/oauth2/token",
    }

    monkeypatch.setenv("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", "")
    with pytest.raises(CanvasLtiServiceError, match="exact"):
        canvas_lti_trust_profile(
            origin,
            CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
        )


def test_private_self_managed_canvas_requires_both_operator_allowlists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "https://127.0.0.1:8443"
    monkeypatch.setenv("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", origin)

    assert resolve_canvas_lti_trust_profile(origin) == (
        CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN
    )
    with pytest.raises(CanvasLtiServiceError, match="CANVAS_PRIVATE_ORIGIN_ALLOWLIST"):
        validate_canvas_origin(origin)

    monkeypatch.setenv("CANVAS_PRIVATE_ORIGIN_ALLOWLIST", origin)
    assert validate_canvas_origin(origin) == origin
    assert canvas_lti_trust_profile(
        origin,
        CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
    )["issuer"] == origin


@pytest.mark.asyncio
async def test_self_managed_probe_reads_jwks_from_the_exact_canvas_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "https://canvas-test.elevenidllc.com"
    requested: list[str] = []

    def resolve(host: str, port: int, **_: object) -> list[tuple[object, ...]]:
        return _dns_answer("93.184.216.34", port)

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(
            200,
            json={"keys": [{"kty": "RSA", "kid": "self-managed-key"}]},
        )

    def client_factory(*, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=timeout,
        )

    monkeypatch.setenv("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST", origin)
    monkeypatch.setattr(
        "issuance.application.canvas_lti_services.socket.getaddrinfo",
        resolve,
    )
    monkeypatch.setattr(
        "issuance.application.canvas_lti_services.canvas_http_client",
        client_factory,
    )

    probe = await probe_canvas_lti_platform(origin)

    assert requested == [f"{origin}/api/lti/security/jwks"]
    assert probe["lti_trust_profile"] == "self_managed_same_origin"
    assert probe["issuer"] == origin
    assert probe["authorization_endpoint"] == (
        f"{origin}/api/lti/authorize_redirect"
    )
    assert probe["token_endpoint"] == f"{origin}/login/oauth2/token"
    assert probe["raw_openid_configuration"]["metadata_source"] == (
        "operator_allowlisted_self_managed_canvas_profile"
    )


@pytest.mark.asyncio
async def test_requests_token_and_reads_ags_results_for_launch_subject() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/login/oauth2/token":
            return httpx.Response(200, json={"access_token": "lti-token", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer lti-token"
        assert request.url.params["user_id"] == "canvas-user-7"
        return httpx.Response(
            200,
            json=[{"id": "result-1", "userId": "canvas-user-7", "resultScore": 92, "resultMaximum": 100}],
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        token = await request_lti_access_token(
            client=client,
            token_endpoint="https://canvas.example/login/oauth2/token",
            client_id="1000000001",
            client_assertion="signed-jwt",
            scopes=["result.readonly"],
            platform_issuer="https://canvas.example",
        )
        results = await read_ags_results(
            client=client,
            results_url="https://canvas.example/api/lti/courses/1/line_items/2/results",
            access_token=token.value,
            platform_issuer="https://canvas.example",
            user_id="canvas-user-7",
        )

    assert token.expires_in == 3600
    assert results[0]["resultScore"] == 92
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_lti_rate_limit_exposes_retry_after_to_durable_worker() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "73"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CanvasLtiServiceError) as captured:
            await request_lti_access_token(
                client=client,
                token_endpoint="https://canvas.example/login/oauth2/token",
                client_id="1000000001",
                client_assertion="signed-jwt",
                scopes=["result.readonly"],
                platform_issuer="https://canvas.example",
            )
    assert captured.value.retry_after_seconds == 73


@pytest.mark.asyncio
async def test_lti_transport_failure_and_redirect_fail_closed() -> None:
    def failed_transport(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection failed", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(failed_transport)) as client:
        with pytest.raises(CanvasLtiServiceError, match="transport failed"):
            await request_lti_access_token(
                client=client,
                token_endpoint="https://canvas.example/login/oauth2/token",
                client_id="1000000001",
                client_assertion="signed-jwt",
                scopes=["result.readonly"],
                platform_issuer="https://canvas.instructure.com",
            )

    def redirect_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://attacker.example/token"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(redirect_transport)) as client:
        with pytest.raises(CanvasLtiServiceError, match="redirect"):
            await request_lti_access_token(
                client=client,
                token_endpoint="https://canvas.example/login/oauth2/token",
                client_id="1000000001",
                client_assertion="signed-jwt",
                scopes=["result.readonly"],
                platform_issuer="https://canvas.instructure.com",
            )


@pytest.mark.asyncio
async def test_lti_token_response_body_is_bounded_before_json_decode() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": str(CANVAS_TOKEN_RESPONSE_MAX_BYTES + 1)},
            content=b"{}",
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CanvasLtiServiceError, match="size limit"):
            await request_lti_access_token(
                client=client,
                token_endpoint="https://canvas.example/login/oauth2/token",
                client_id="1000000001",
                client_assertion="signed-jwt",
                scopes=["result.readonly"],
                platform_issuer="https://canvas.instructure.com",
            )

@pytest.mark.asyncio
async def test_reads_nrps_members_from_wrapped_response_and_follows_safe_pagination() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"members": [{"user_id": "user-2", "status": "Active"}]})
        return httpx.Response(
            200,
            json={"members": [{"user_id": "user-1", "status": "Active"}]},
            headers={"Link": '<https://canvas.example/api/lti/memberships?page=2>; rel="next"'},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        members = await read_nrps_memberships(
            client=client,
            memberships_url="https://canvas.example/api/lti/memberships",
            access_token="lti-token",
            platform_issuer="https://canvas.example",
        )

    assert [member["user_id"] for member in members] == ["user-1", "user-2"]


@pytest.mark.asyncio
async def test_lti_pagination_never_forwards_bearer_token_across_origins() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"members": [{"user_id": "user-1", "status": "Active"}]},
            headers={
                "Link": '<https://attacker.example/collect>; rel="next"'
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CanvasLtiServiceError, match="changed origin"):
            await read_nrps_memberships(
                client=client,
                memberships_url="https://canvas.example/api/lti/memberships",
                access_token="lti-token",
                platform_issuer="https://canvas.instructure.com",
            )

    assert len(requests) == 1
    assert requests[0].url.host == "canvas.example"


@pytest.mark.asyncio
async def test_lti_collection_rejects_repeated_pages_and_bounded_bodies() -> None:
    calls = 0

    def repeated_page(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={"members": [{"user_id": "user-1", "status": "Active"}]},
            headers={
                "Link": '<https://canvas.example/api/lti/memberships>; rel="next"'
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(repeated_page)
    ) as client:
        with pytest.raises(CanvasLtiServiceError, match="repeated a page"):
            await read_nrps_memberships(
                client=client,
                memberships_url="https://canvas.example/api/lti/memberships",
                access_token="lti-token",
                platform_issuer="https://canvas.instructure.com",
            )
    assert calls == 1

    def oversized_page(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": str(CANVAS_COLLECTION_PAGE_MAX_BYTES + 1)},
            content=b"[]",
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(oversized_page)
    ) as client:
        with pytest.raises(CanvasLtiServiceError, match="size limit"):
            await read_nrps_memberships(
                client=client,
                memberships_url="https://canvas.example/api/lti/memberships",
                access_token="lti-token",
                platform_issuer="https://canvas.instructure.com",
            )


@pytest.mark.asyncio
async def test_lti_collection_rejects_authoritative_truncation() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"members": [{"user_id": "user-1", "status": "Active"}]},
            headers={"Link": '<https://canvas.example/api/lti/memberships?page=2>; rel="next"'},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CanvasLtiServiceError, match="completeness limit"):
            await read_nrps_memberships(
                client=client,
                memberships_url="https://canvas.example/api/lti/memberships",
                access_token="lti-token",
                platform_issuer="https://canvas.instructure.com",
                limit=1,
            )


@pytest.mark.asyncio
async def test_lti_collection_does_not_turn_malformed_object_into_negative_observation() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={"unexpected": []}))
    ) as client:
        with pytest.raises(CanvasLtiServiceError, match="unexpected collection"):
            await read_nrps_memberships(
                client=client,
                memberships_url="https://canvas.example/api/lti/memberships",
                access_token="lti-token",
                platform_issuer="https://canvas.instructure.com",
            )
