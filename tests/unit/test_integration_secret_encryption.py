"""Remote-only integration-secret custody at the Python repository boundary."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from issuance.infrastructure.security.encryption import RemoteIntegrationSecretEncryption


@pytest.mark.asyncio
async def test_remote_envelope_binds_identity_and_preserves_secret(monkeypatch) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append((request, body))
        if request.url.path.endswith("/encrypt"):
            assert base64.b64decode(body["plaintext_b64"]) == b"secret-value"
            return httpx.Response(
                200,
                json={
                    "schema": "marty.integration-secret-envelope/v1",
                    "ciphertext": "vault:v1:opaque",
                },
            )
        return httpx.Response(
            200, json={"plaintext_b64": base64.b64encode(b"secret-value").decode()}
        )

    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    cipher = RemoteIntegrationSecretEncryption("http://signing-keys:8017/internal", "test-key")
    stored = await cipher.encrypt("org-1", "secret-1", "canvas", "oauth_client_secret", "secret-value")
    assert await cipher.decrypt(
        "org-1", "secret-1", "canvas", "oauth_client_secret", stored
    ) == "secret-value"
    assert len(calls) == 2
    for request, body in calls:
        assert request.url.params["organization_id"] == "org-1"
        assert request.headers["X-API-Key"] == "test-key"
        assert {key: body[key] for key in ("organization_id", "secret_id", "provider", "purpose")} == {
            "organization_id": "org-1",
            "secret_id": "secret-1",
            "provider": "canvas",
            "purpose": "oauth_client_secret",
        }
    assert "secret-value" not in stored


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stored",
    [
        base64.b64encode(b"old-aes-ciphertext").decode(),
        '{"schema":"wrong","ciphertext":"vault:v1:opaque"}',
        '{"schema":"marty.integration-secret-envelope/v1","ciphertext":"local-key"}',
    ],
)
async def test_legacy_or_invalid_envelopes_are_rejected_before_kms_call(stored: str) -> None:
    cipher = RemoteIntegrationSecretEncryption("http://signing-keys:8017/internal", "test-key")
    with pytest.raises(ValueError, match="envelope is invalid"):
        await cipher.decrypt("org-1", "secret-1", "canvas", "api_token", stored)


def test_raw_master_key_is_not_a_configuration_fallback(monkeypatch) -> None:
    monkeypatch.setenv("INTEGRATION_SECRET_MASTER_KEY", base64.b64encode(bytes(range(32))).decode())
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_URL", "http://signing-keys:8017/internal")
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-key")
    with pytest.raises(RuntimeError, match="Raw integration-secret master keys"):
        RemoteIntegrationSecretEncryption.from_env()
