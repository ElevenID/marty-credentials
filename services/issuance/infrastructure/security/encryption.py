"""Remote-only integration-secret envelope transport; Rust signing-keys owns crypto."""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
from urllib.parse import urlsplit

import httpx

SCHEMA = "marty.integration-secret-envelope/v1"
MAX_SECRET_BYTES = 64 * 1024
MAX_CIPHERTEXT_BYTES = 200 * 1024


class RemoteIntegrationSecretEncryption:
    def __init__(self, base_url: str, api_key: str):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or not api_key.strip()
        ):
            raise RuntimeError("Remote integration-secret KMS configuration is invalid")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key

    @classmethod
    def from_env(cls) -> RemoteIntegrationSecretEncryption:
        if any(
            os.environ.get(name)
            for name in (
                "INTEGRATION_SECRET_MASTER_KEY",
                "INTEGRATION_SECRET_MASTER_KEY_FILE",
                "INTEGRATION_SECRET_MASTER_KEY_ENV",
            )
        ):
            raise RuntimeError("Raw integration-secret master keys are not supported")
        base_url = os.environ.get("SIGNING_KEYS_INTERNAL_URL", "").strip()
        api_key = os.environ.get("SIGNING_KEYS_INTERNAL_API_KEY", "").strip()
        if not api_key:
            key_file = os.environ.get("SIGNING_KEYS_INTERNAL_API_KEY_FILE", "").strip()
            if key_file:
                try:
                    with open(key_file, encoding="utf-8") as handle:
                        api_key = handle.read().strip()
                except OSError as exc:
                    raise RuntimeError("Remote integration-secret KMS key file is unavailable") from exc
        return cls(base_url, api_key)

    async def _post(self, operation: str, organization_id: str, payload: dict) -> dict:
        try:
            async with httpx.AsyncClient(
                timeout=30.0, follow_redirects=False, trust_env=False
            ) as client:
                async with client.stream(
                    "POST",
                    f"{self._base_url}/integration-secrets/{operation}",
                    params={"organization_id": organization_id},
                    headers={"X-API-Key": self._api_key},
                    json=payload,
                ) as response:
                    response.raise_for_status()
                    chunks = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > 256 * 1024:
                            raise ValueError("Remote integration-secret KMS response is too large")
                        chunks.append(chunk)
            result = json.loads(b"".join(chunks))
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError("Remote integration-secret KMS operation failed") from exc
        if not isinstance(result, dict):
            raise ValueError("Remote integration-secret KMS response is invalid")
        return result

    async def encrypt(
        self, organization_id: str, secret_id: str, provider: str, purpose: str, plaintext: str
    ) -> str:
        if len(plaintext.encode("utf-8")) > MAX_SECRET_BYTES:
            raise ValueError("Integration secret is too large")
        envelope = await self._post(
            "encrypt",
            organization_id,
            {
                "organization_id": organization_id,
                "secret_id": secret_id,
                "provider": provider,
                "purpose": purpose,
                "plaintext_b64": base64.b64encode(plaintext.encode("utf-8")).decode("ascii"),
            },
        )
        self._validate_envelope(envelope)
        return json.dumps(envelope, sort_keys=True, separators=(",", ":"))

    async def verify_ready(self, organization_id: str) -> None:
        """Prove the configured remote route can round-trip without persistence."""
        proof = secrets.token_hex(32)
        secret_id = f"startup-{secrets.token_hex(16)}"
        envelope = await self.encrypt(
            organization_id, secret_id, "system", "startup_proof", proof
        )
        if await self.decrypt(
            organization_id, secret_id, "system", "startup_proof", envelope
        ) != proof:
            raise RuntimeError("Remote integration-secret KMS startup proof failed")

    async def decrypt(
        self, organization_id: str, secret_id: str, provider: str, purpose: str, stored: str
    ) -> str:
        if len(stored) > MAX_CIPHERTEXT_BYTES + 1024:
            raise ValueError("Integration-secret envelope is too large")
        try:
            envelope = json.loads(stored)
        except (TypeError, ValueError) as exc:
            raise ValueError("Integration-secret envelope is invalid") from exc
        self._validate_envelope(envelope)
        result = await self._post(
            "decrypt",
            organization_id,
            {
                "organization_id": organization_id,
                "secret_id": secret_id,
                "provider": provider,
                "purpose": purpose,
                "envelope": envelope,
            },
        )
        encoded = result.get("plaintext_b64")
        if not isinstance(encoded, str) or len(encoded) > (MAX_SECRET_BYTES + 2) // 3 * 4:
            raise ValueError("Remote integration-secret KMS response is invalid")
        try:
            plaintext = base64.b64decode(encoded, validate=True)
            if len(plaintext) > MAX_SECRET_BYTES:
                raise ValueError("Integration secret is too large")
            return plaintext.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("Remote integration-secret KMS response is invalid") from exc

    @staticmethod
    def _validate_envelope(envelope: object) -> None:
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"schema", "ciphertext"}
            or envelope.get("schema") != SCHEMA
            or not isinstance(envelope.get("ciphertext"), str)
            or not envelope["ciphertext"].startswith("vault:v")
            or len(envelope["ciphertext"]) > MAX_CIPHERTEXT_BYTES
        ):
            raise ValueError("Integration-secret envelope is invalid")
