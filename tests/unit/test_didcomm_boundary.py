from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from issuance.infrastructure.api import routes
from pydantic import ValidationError
from starlette.requests import Request


def _request(organization_id: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/issuance/didcomm/deliver",
            "headers": [(b"x-organization-id", organization_id.encode())],
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
    )


def test_delivery_contract_rejects_caller_selected_resolver() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        routes.DidcommDeliverRequest(
            organization_id="org-a",
            transaction_id="tx-a",
            holder_did="did:peer:2.EzExample",
            universal_resolver_url="https://attacker.example/resolve",
        )


@pytest.mark.asyncio
async def test_native_owner_delegates_delivery_without_touching_python_crypto_or_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")
    monkeypatch.setenv("HTTP_PROXY", "http://ambient-proxy.example:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy.example:8080")
    observed: dict[str, object] = {}
    ambient_proxy_received: list[dict[str, object]] = []

    class Client:
        def __init__(self, **options: object) -> None:
            observed["options"] = options

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, url: str, **options: object):
            client_options = observed["options"]
            assert isinstance(client_options, dict)
            if client_options.get("trust_env") is not False:
                ambient_proxy_received.append({"url": url, **options})
            observed["url"] = url
            observed["request"] = options
            return routes.httpx.Response(
                200,
                request=routes.httpx.Request("POST", url),
                json={
                    "transaction_id": "tx-a",
                    "credential_id": "credential-a",
                    "holder_did": "did:peer:2.EzExample",
                    "service_endpoint": "https://wallet.example/inbox",
                    "didcomm_message_id": "message-a",
                    "status": "delivered",
                    "error": None,
                },
            )

    monkeypatch.setattr(routes.httpx, "AsyncClient", Client)
    repo = SimpleNamespace(get_transaction=AsyncMock())
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/issuance/didcomm/deliver",
            "headers": [
                (b"x-api-key", b"management-secret"),
                (b"x-organization-id", b"org-a"),
                (b"idempotency-key", b"idempotency-secret"),
                (b"authorization", b"Bearer must-not-forward"),
            ],
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
    )

    response = await routes.didcomm_deliver(
        routes.DidcommDeliverRequest(
            organization_id="org-a",
            transaction_id="tx-a",
            holder_did="did:peer:2.EzExample",
        ),
        request,
        repo,
    )

    assert response.status == "delivered"
    assert observed["url"] == "http://issuance-native:8005/v1/issuance/didcomm/deliver"
    assert observed["options"] == {
        "timeout": routes.httpx.Timeout(30.0, connect=5.0),
        "follow_redirects": False,
        "trust_env": False,
    }
    assert ambient_proxy_received == []
    forwarded = observed["request"]
    assert isinstance(forwarded, dict)
    assert forwarded["headers"] == {
        "x-api-key": "management-secret",
        "x-organization-id": "org-a",
        "idempotency-key": "idempotency-secret",
    }
    assert forwarded["json"] == {
        "organization_id": "org-a",
        "transaction_id": "tx-a",
        "holder_did": "did:peer:2.EzExample",
    }
    repo.get_transaction.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        routes.httpx.InvalidURL("native request URL includes private detail"),
        ValueError("native request construction includes private detail"),
    ],
)
async def test_native_owner_sanitizes_request_construction_failures_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure: Exception,
) -> None:
    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")

    class Client:
        def __init__(self, **_options: object) -> None:
            pass

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, _url: str, **_options: object):
            raise failure

    monkeypatch.setattr(routes.httpx, "AsyncClient", Client)
    repo = SimpleNamespace(get_transaction=AsyncMock())

    with caplog.at_level(logging.ERROR), pytest.raises(HTTPException) as exc:
        await routes.didcomm_deliver(
            routes.DidcommDeliverRequest(
                organization_id="org-a",
                transaction_id="tx-a",
                holder_did="did:peer:2.EzExample",
            ),
            _request("org-a"),
            repo,
        )

    assert exc.value.status_code == 503
    assert exc.value.detail == "Native issuance service is unavailable"
    assert "private detail" not in caplog.text
    repo.get_transaction.assert_not_awaited()


@pytest.mark.asyncio
async def test_native_owner_unavailable_fails_closed_without_legacy_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")

    class Client:
        def __init__(self, **_options: object) -> None:
            pass

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, url: str, **_options: object):
            request = routes.httpx.Request("POST", url)
            raise routes.httpx.ConnectError("native internal detail", request=request)

    monkeypatch.setattr(routes.httpx, "AsyncClient", Client)
    repo = SimpleNamespace(get_transaction=AsyncMock())

    with pytest.raises(HTTPException) as exc:
        await routes.didcomm_deliver(
            routes.DidcommDeliverRequest(
                organization_id="org-a",
                transaction_id="tx-a",
                holder_did="did:peer:2.EzExample",
            ),
            _request("org-a"),
            repo,
        )

    assert exc.value.status_code == 503
    assert exc.value.detail == "Native issuance service is unavailable"
    assert "internal detail" not in str(exc.value.detail)
    repo.get_transaction.assert_not_awaited()


@pytest.mark.asyncio
async def test_native_owner_preserves_structured_upstream_error_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")

    class Client:
        def __init__(self, **_options: object) -> None:
            pass

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, url: str, **_options: object):
            return routes.httpx.Response(
                422,
                request=routes.httpx.Request("POST", url),
                json={"detail": "private-upstream-detail"},
            )

    monkeypatch.setattr(routes.httpx, "AsyncClient", Client)
    repo = SimpleNamespace(get_transaction=AsyncMock())

    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as exc:
        await routes.didcomm_deliver(
            routes.DidcommDeliverRequest(
                organization_id="org-a",
                transaction_id="tx-a",
                holder_did="did:peer:2.EzExample",
            ),
            _request("org-a"),
            repo,
        )

    assert exc.value.status_code == 422
    assert exc.value.detail == "private-upstream-detail"
    records = [
        record
        for record in caplog.records
        if record.name == routes.__name__
        and record.msg == "Native issuance owner rejected request (HTTP %d)"
    ]
    assert len(records) == 1
    assert records[0].args == (422,)
    assert "private-upstream-detail" not in caplog.text
    repo.get_transaction.assert_not_awaited()


@pytest.mark.asyncio
async def test_native_owner_logs_status_without_non_json_error_body(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")

    class Client:
        def __init__(self, **_options: object) -> None:
            pass

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, url: str, **_options: object):
            return routes.httpx.Response(
                502,
                request=routes.httpx.Request("POST", url),
                text="private-native-error-body",
            )

    monkeypatch.setattr(routes.httpx, "AsyncClient", Client)

    with caplog.at_level(logging.WARNING), pytest.raises(HTTPException) as exc:
        await routes._post_to_native_issuance(
            "/v1/didcomm/deliver",
            {},
            _request("org-a"),
            routes.DidcommDeliveryResponse,
        )

    assert exc.value.status_code == 503
    assert exc.value.detail == "Native issuance service returned an invalid response"
    assert "private-native-error-body" not in caplog.text
    records = [
        record
        for record in caplog.records
        if record.name == routes.__name__
        and record.msg == "Native issuance owner rejected request (HTTP %d)"
    ]
    assert len(records) == 1
    assert records[0].args == (502,)


@pytest.mark.asyncio
async def test_native_owner_delegates_automatic_initiation_before_python_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")
    response = routes.IssuanceResponse(
        id="tx-a",
        organization_id="org-a",
        credential_template_id="template-a",
        status="issued",
        credential_offer_uri="openid-credential-offer://synthetic",
        credential_offer_uris={"didcomm": "didcomm://https://wallet.example/inbox"},
        credential_offer_labels={"didcomm": "DIDComm Wallet"},
        pre_auth_code="pre-auth-a",
        expires_at="2026-09-21T00:00:00+00:00",
    )
    forward = AsyncMock(return_value=response)
    monkeypatch.setattr(routes, "_post_to_native_issuance", forward)
    repo = SimpleNamespace(recover_transaction_idempotently=AsyncMock())
    http_request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/issuance/initiate",
            "headers": [
                (b"x-api-key", b"management-secret"),
                (b"x-organization-id", b"org-a"),
            ],
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
    )
    request = routes.InitiateIssuanceRequest(
        organization_id="org-a",
        issuer_did="did:web:issuer.example",
        credential_template_id="template-a",
        holder_did="did:peer:2.EzExample",
    )

    actual = await routes.initiate_issuance(request, http_request=http_request, repo=repo)

    assert actual == response
    forward.assert_awaited_once_with(
        "/v1/issuance/initiate",
        {
            "organization_id": "org-a",
            "issuer_did": "did:web:issuer.example",
            "credential_template_id": "template-a",
            "holder_did": "did:peer:2.EzExample",
        },
        http_request,
        routes.IssuanceResponse,
    )
    repo.recover_transaction_idempotently.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forbidden_header",
    [
        "x-signing-service-id",
        "x-signing-key-reference",
        "x-key-reference",
        "x-issuer-profile-id",
        "x-issuer-mode",
        "x-issuer-did",
    ],
)
async def test_native_owner_rejects_direct_signing_headers_before_delegation(
    monkeypatch: pytest.MonkeyPatch,
    forbidden_header: str,
) -> None:
    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")
    forward = AsyncMock()
    monkeypatch.setattr(routes, "_post_to_native_issuance", forward)
    repo = SimpleNamespace(
        recover_transaction_idempotently=AsyncMock(),
        reserve_transaction_idempotently=AsyncMock(),
    )
    http_request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/issuance/initiate",
            "headers": [
                (b"x-api-key", b"management-secret"),
                (b"x-organization-id", b"org-a"),
                (forbidden_header.encode("ascii"), b"caller-selected"),
            ],
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
    )
    request = routes.InitiateIssuanceRequest(
        organization_id="org-a",
        issuer_did="did:web:issuer.example",
        credential_template_id="template-a",
        holder_did="did:peer:2.EzExample",
    )

    with pytest.raises(HTTPException) as exc:
        await routes.initiate_issuance(request, http_request=http_request, repo=repo)

    assert (exc.value.status_code, exc.value.detail) == (
        422,
        "Direct signing or issuer-profile selection is not allowed; "
        "supply issuer_did in the request body.",
    )
    forward.assert_not_awaited()
    repo.recover_transaction_idempotently.assert_not_awaited()
    repo.reserve_transaction_idempotently.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("idempotency_key", "expected_detail"),
    [
        (
            " padded",
            "idempotency key must not contain surrounding whitespace",
        ),
        (
            "valid-key",
            "Invalid delivery_mode 'direct-kms'. Must be one of "
            "['wallet_only', 'wallet_plus_canvas_mirror']",
        ),
    ],
)
async def test_native_owner_preserves_combined_invalid_precheck_precedence(
    monkeypatch: pytest.MonkeyPatch,
    idempotency_key: str,
    expected_detail: str,
) -> None:
    monkeypatch.setenv("DIDCOMM_DELIVERY_OWNER", "native")
    monkeypatch.setenv("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")
    forward = AsyncMock()
    monkeypatch.setattr(routes, "_post_to_native_issuance", forward)
    repo = SimpleNamespace(
        recover_transaction_idempotently=AsyncMock(),
        reserve_transaction_idempotently=AsyncMock(),
    )
    http_request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/issuance/initiate",
            "headers": [
                (b"x-api-key", b"management-secret"),
                (b"x-organization-id", b"org-a"),
                (b"idempotency-key", idempotency_key.encode("ascii")),
                (b"x-issuer-mode", b"caller-selected"),
            ],
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
    )
    request = routes.InitiateIssuanceRequest(
        organization_id="org-a",
        issuer_did="did:web:issuer.example",
        credential_template_id="template-a",
        holder_did="did:peer:2.EzExample",
        delivery_mode="direct-kms",
    )

    with pytest.raises(HTTPException) as exc:
        await routes.initiate_issuance(request, http_request=http_request, repo=repo)

    assert (exc.value.status_code, exc.value.detail) == (422, expected_detail)
    forward.assert_not_awaited()
    repo.recover_transaction_idempotently.assert_not_awaited()
    repo.reserve_transaction_idempotently.assert_not_awaited()


@pytest.mark.asyncio
async def test_delivery_rejects_claimed_tenant_before_transaction_lookup() -> None:
    repo = SimpleNamespace(get_transaction=AsyncMock())

    with pytest.raises(HTTPException) as exc:
        await routes.didcomm_deliver(
            routes.DidcommDeliverRequest(
                organization_id="org-b",
                transaction_id="tx-b",
                holder_did="did:peer:2.EzExample",
            ),
            _request("org-a"),
            repo,
        )

    assert exc.value.status_code == 404
    repo.get_transaction.assert_not_awaited()
