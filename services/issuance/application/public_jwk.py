"""Shared public-JWK boundary for Python-owned metadata ingestion."""

import json
from collections.abc import Mapping
from typing import Any

PRIVATE_JWK_FIELDS = frozenset(
    {
        "d", "p", "q", "dp", "dq", "qi", "oth", "k", "rsa_d",
        "private_key", "private_key_pem", "private_jwk", "private_jwk_json",
        "privateKey", "privateKeyPem", "secret_key",
    }
)


def contains_private_jwk_material(value: Any, depth: int = 0) -> bool:
    """Reject private-key fields even when wrapped in JWKS extensions."""

    if depth > 16:
        return True
    if isinstance(value, Mapping):
        return bool(PRIVATE_JWK_FIELDS.intersection(value)) or any(
            contains_private_jwk_material(item, depth + 1) for item in value.values()
        )
    if isinstance(value, list):
        return any(contains_private_jwk_material(item, depth + 1) for item in value)
    if isinstance(value, str):
        if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
            return True
        if value.lstrip().startswith(("{", "[")):
            try:
                return contains_private_jwk_material(json.loads(value), depth + 1)
            except RecursionError:
                return True
            except (ValueError, TypeError):
                return False
    return False
