"""Compatibility tests for native integration-secret encryption."""

from __future__ import annotations

import base64

import pytest
from issuance.infrastructure.security.encryption import SymmetricEncryption


def test_native_integration_secret_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    key = bytes(range(32))
    monkeypatch.setenv("TEST_INTEGRATION_SECRET_KEY", base64.b64encode(key).decode())
    encryption = SymmetricEncryption.from_env("TEST_INTEGRATION_SECRET_KEY")

    encoded = encryption.encrypt("secret-value")

    assert encryption.decrypt(encoded) == "secret-value"
    assert len(base64.b64decode(encoded)) > 12


@pytest.mark.parametrize("encoded", ["not base64!", base64.b64encode(b"short").decode()])
def test_malformed_integration_secret_fails_closed(encoded: str) -> None:
    encryption = SymmetricEncryption(bytes(range(32)))

    with pytest.raises(ValueError):
        encryption.decrypt(encoded)


def test_wrong_integration_secret_key_fails_closed() -> None:
    encoded = SymmetricEncryption(bytes(range(32))).encrypt("secret-value")

    with pytest.raises(ValueError, match="Failed to decrypt"):
        SymmetricEncryption(bytes(reversed(range(32)))).decrypt(encoded)
