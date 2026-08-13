"""Fail-closed native encryption adapter for issuance integration secrets."""

from __future__ import annotations

import base64
import binascii
import os

from marty_credentials.native_backend import require_marty_verification

_NONCE_LENGTH = 12
_native = require_marty_verification(
    ("aes_gcm_encrypt", "aes_gcm_decrypt", "generate_random_bytes")
)


class SymmetricEncryption:
    """Preserve the stored ``base64(nonce || ciphertext || tag)`` format."""

    def __init__(self, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError(f"Master key must be 32 bytes, got {len(master_key)}")
        self._master_key = master_key

    @classmethod
    def from_env(cls, env_var: str = "INTEGRATION_SECRET_MASTER_KEY") -> SymmetricEncryption:
        key_b64 = os.environ.get(env_var)
        if not key_b64:
            raise ValueError(f"Environment variable {env_var} is not set")
        try:
            master_key = base64.b64decode(key_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"Invalid base64 encoding in {env_var}") from exc
        return cls(master_key)

    def encrypt(self, plaintext: str) -> str:
        nonce = bytes(_native.generate_random_bytes(_NONCE_LENGTH))
        ciphertext = bytes(
            _native.aes_gcm_encrypt(
                self._master_key,
                nonce,
                plaintext.encode("utf-8"),
                b"",
            )
        )
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, ciphertext_b64: str) -> str:
        try:
            encrypted = base64.b64decode(ciphertext_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Encrypted integration secret is not valid base64") from exc
        if len(encrypted) <= _NONCE_LENGTH:
            raise ValueError("Encrypted integration secret is truncated")
        nonce = encrypted[:_NONCE_LENGTH]
        ciphertext = encrypted[_NONCE_LENGTH:]
        try:
            plaintext = bytes(
                _native.aes_gcm_decrypt(
                    self._master_key,
                    nonce,
                    ciphertext,
                    b"",
                )
            )
        except Exception as exc:
            raise ValueError("Failed to decrypt integration secret") from exc
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Decrypted integration secret is not UTF-8") from exc

    def encrypt_optional(self, plaintext: str | None) -> str | None:
        return self.encrypt(plaintext) if plaintext is not None else None

    def decrypt_optional(self, ciphertext: str | None) -> str | None:
        return self.decrypt(ciphertext) if ciphertext is not None else None
