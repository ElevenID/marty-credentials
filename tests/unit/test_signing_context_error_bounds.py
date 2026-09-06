"""Bound diagnostic detail consistently without changing short error semantics."""

from __future__ import annotations

import httpx
import pytest
from issuance.infrastructure.api import signing_context


@pytest.mark.parametrize("field", ["detail", "error_description", "error"])
@pytest.mark.parametrize("size", [0, 1, 499, 500, 501, 900])
@pytest.mark.parametrize("object_detail", [False, True])
def test_json_error_detail_has_the_same_bound_as_text(
    field: str, size: int, object_detail: bool
) -> None:
    # Non-ASCII characters make the existing 500-character (not byte) limit explicit.
    text = ("é🙂" * ((size + 1) // 2))[:size]
    detail = {"reason": text} if object_detail else f"  {text}  "
    response = httpx.Response(503, json={field: detail})
    expected = str(detail) if object_detail else text or response.text.strip()
    assert signing_context._response_error_detail(response) == expected[:500]


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"detail": " first ", "error_description": "second"}, "first"),
        ({"detail": "", "error_description": "second"}, "second"),
        ({"detail": None, "error": "third"}, "third"),
        ({"detail": {"reason": "short"}}, "{'reason': 'short'}"),
    ],
)
def test_short_detail_selection_is_preserved(payload: dict, expected: str) -> None:
    assert signing_context._response_error_detail(httpx.Response(503, json=payload)) == expected


@pytest.mark.parametrize("body", ["", "   ", " x ", "é🙂" * 600, "{invalid-json"])
def test_text_and_empty_body_behavior_is_preserved(body: str) -> None:
    response = httpx.Response(503, text=body)
    assert signing_context._response_error_detail(response) == (
        body.strip()[:500] if body.strip() else "Service Unavailable"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["context", "resolve", "sign"])
@pytest.mark.parametrize("status", [401, 503])
async def test_remote_operations_use_the_shared_bound_without_changing_status_handling(
    operation: str, status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    client_type = httpx.AsyncClient
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(status, json={"detail": "x" * 501 + "synthetic-tail"})

    monkeypatch.setattr(
        signing_context.httpx,
        "AsyncClient",
        lambda **kwargs: client_type(transport=httpx.MockTransport(respond), **kwargs),
    )
    with pytest.raises(RuntimeError) as caught:
        if operation == "context":
            await signing_context.resolve_remote_issuer_context("synthetic-org")
        elif operation == "resolve":
            await signing_context.resolve_remote_issuer_did(
                organization_id="synthetic-org", issuer_did="did:example:issuer",
            )
        else:
            await signing_context.sign_payload_with_issuer_did(
                organization_id="synthetic-org",
                issuer_did="did:example:issuer",
                credential_format="jwt_vc_json",
                key_purpose="credential_signing",
                payload=b"synthetic-payload",
                algorithm="ES256",
            )
    assert len(requests) == 1
    if status == 401:
        assert str(caught.value) == "Internal signing API rejected the service API key"
    else:
        prefix = {
            "context": "DID issuer context resolution failed",
            "resolve": "Issuer DID resolution failed",
            "sign": "DID-mediated signing failed",
        }[operation]
        assert str(caught.value) == f"{prefix} (HTTP 503): " + "x" * 500
