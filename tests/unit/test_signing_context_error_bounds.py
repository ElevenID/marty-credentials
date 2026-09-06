"""Bound diagnostic detail consistently without changing short error semantics."""

from __future__ import annotations

import json

import httpx
import pytest
from issuance.infrastructure.api import signing_context


@pytest.fixture(autouse=True)
def _synthetic_signing_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_URL", "https://signing.example.invalid/internal")
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "synthetic-test-only")


def _json_response(status: int, payload: dict) -> httpx.Response:
    # Freeze our supplied wire representation, not HTTPX-version-specific JSON spacing.
    return httpx.Response(
        status,
        content=json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8"),
        headers={"content-type": "application/json"},
    )


def _assert_detail(response: httpx.Response, expected: str, record_property) -> None:
    observed = signing_context._response_error_detail(response)
    assert observed == expected
    record_property("canvas_privacy", {
        "boundary": "signing_error_detail",
        "input": {"status": response.status_code, "body": response.text},
        "observed": observed,
    })


@pytest.mark.parametrize("field", ["detail", "error_description", "error"])
@pytest.mark.parametrize("size", [0, 1, 499, 500, 501, 900])
@pytest.mark.parametrize("object_detail", [False, True])
def test_json_error_detail_has_the_same_bound_as_text(
    field: str, size: int, object_detail: bool, record_property
) -> None:
    # Non-ASCII characters make the existing 500-character (not byte) limit explicit.
    text = ("é🙂" * ((size + 1) // 2))[:size]
    detail = {"reason": text} if object_detail else f"  {text}  "
    response = _json_response(503, {field: detail})
    expected = str(detail) if object_detail else text or response.text.strip()
    _assert_detail(response, expected[:500], record_property)


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"detail": " first ", "error_description": "second"}, "first"),
        ({"detail": "", "error_description": "second"}, "second"),
        ({"detail": None, "error": "third"}, "third"),
        ({"detail": {"reason": "short"}}, "{'reason': 'short'}"),
    ],
)
def test_short_detail_selection_is_preserved(payload: dict, expected: str, record_property) -> None:
    _assert_detail(_json_response(503, payload), expected, record_property)


@pytest.mark.parametrize(
    "body", ["", "   ", " x ", "é🙂" * 600, "{invalid-json"],
    ids=["empty", "whitespace", "short", "unicode_long", "malformed_json"],
)
def test_text_and_empty_body_behavior_is_preserved(body: str, record_property) -> None:
    response = httpx.Response(503, text=body)
    _assert_detail(
        response, body.strip()[:500] if body.strip() else "Service Unavailable", record_property,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["context", "resolve", "sign"])
@pytest.mark.parametrize("status", [401, 503])
async def test_remote_operations_use_the_shared_bound_without_changing_status_handling(
    operation: str, status: int, monkeypatch: pytest.MonkeyPatch, record_property
) -> None:
    client_type = httpx.AsyncClient
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _json_response(status, {"detail": "x" * 501 + "synthetic-tail"})

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
    record_property("canvas_privacy", {
        "boundary": "signing_operation_error",
        "input": {"operation": operation, "status": status,
                  "body": _json_response(status, {"detail": "x" * 501 + "synthetic-tail"}).text},
        "observed": {"error_class": type(caught.value).__name__, "message": str(caught.value),
                     "request_count": len(requests), "request_method": requests[0].method,
                     "request_path": requests[0].url.path},
    })
