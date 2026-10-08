"""Shared public-JWK boundary for Python-owned metadata ingestion."""

from collections.abc import Mapping
from typing import Any

PRIVATE_JWK_FIELDS = frozenset(
    {
        "d", "p", "q", "dp", "dq", "qi", "oth", "k", "rsa_d",
        "private_key", "private_key_pem", "private_jwk", "private_jwk_json",
        "privateKey", "privateKeyPem", "secret_key",
    }
)


def contains_private_jwk_material(value: Any) -> bool:
    """Reject private-key fields even when wrapped in JWKS extensions."""

    if isinstance(value, Mapping):
        return bool(PRIVATE_JWK_FIELDS.intersection(value)) or any(
            contains_private_jwk_material(item) for item in value.values()
        )
    if isinstance(value, list):
        return any(contains_private_jwk_material(item) for item in value)
    return (
        isinstance(value, str)
        and "-----BEGIN " in value
        and "PRIVATE KEY-----" in value
    )
