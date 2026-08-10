"""OID4VCI registered-client key validation and ``private_key_jwt`` verification.

Only public wallet keys are accepted here. Issuer signing remains behind an
issuer profile and its configured custody service; this module never handles
issuer private keys or KMS selectors.
"""

from __future__ import annotations

import base64
import json
import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from issuance.application.rust_integration import verify_compact_jwt
from marty_credentials.native_backend import (
    NativeOperationError,
    require_marty_verification,
)

JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_ALLOWED_PUBLIC_JWK_FIELDS = frozenset({"alg", "crv", "key_ops", "kid", "kty", "use", "x", "y"})
_CLOCK_SKEW_SECONDS = 60
_MAX_ASSERTION_LIFETIME_SECONDS = 300

_marty_verification = require_marty_verification(("p256_public_jwk_to_pem",))


class ClientAuthenticationError(ValueError):
    """A registered wallet client could not be authenticated."""


@dataclass(frozen=True)
class VerifiedClientAssertion:
    """Security-relevant claims retained after assertion verification."""

    client_id: str
    jti: str
    expires_at: datetime
    key_id: str


class Oid4vciClientAuthRepository(Protocol):
    """Narrow persistence surface required for registered-client authentication."""

    async def get_oid4vci_client(
        self,
        organization_id: str,
        client_id: str,
    ) -> Any | None: ...

    async def claim_oid4vci_client_assertion(
        self,
        *,
        organization_id: str,
        client_id: str,
        jti: str,
        expires_at: datetime,
    ) -> bool: ...


def _decode_base64url(value: str, *, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ClientAuthenticationError(f"{field} must be non-empty base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ClientAuthenticationError(f"{field} is not valid base64url") from exc
    return decoded


def normalize_public_client_jwks(jwks: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Validate and return a canonical public ES256 JWKS.

    Private parameters are rejected rather than silently stripped so a
    management caller cannot accidentally persist wallet private key material.
    """

    if not isinstance(jwks, dict) or set(jwks) != {"keys"}:
        raise ClientAuthenticationError("jwks must contain only a keys array")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ClientAuthenticationError("jwks.keys must be a non-empty array")

    normalized: list[dict[str, Any]] = []
    seen_key_ids: set[str] = set()
    for index, raw_key in enumerate(keys):
        if not isinstance(raw_key, dict):
            raise ClientAuthenticationError(f"jwks.keys[{index}] must be an object")
        private_fields = set(raw_key) & {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
        if private_fields:
            raise ClientAuthenticationError(f"jwks.keys[{index}] contains private key material")
        unknown_fields = set(raw_key) - _ALLOWED_PUBLIC_JWK_FIELDS
        if unknown_fields:
            raise ClientAuthenticationError(f"jwks.keys[{index}] contains unsupported fields")
        if raw_key.get("kty") != "EC" or raw_key.get("crv") != "P-256":
            raise ClientAuthenticationError(f"jwks.keys[{index}] must be an EC P-256 public key")
        if raw_key.get("alg") not in (None, "ES256"):
            raise ClientAuthenticationError(f"jwks.keys[{index}] must use ES256")
        if raw_key.get("use") not in (None, "sig"):
            raise ClientAuthenticationError(f"jwks.keys[{index}] must be a signing key")
        key_ops = raw_key.get("key_ops")
        if key_ops is not None and (
            not isinstance(key_ops, list)
            or "verify" not in key_ops
            or any(operation != "verify" for operation in key_ops)
        ):
            raise ClientAuthenticationError(f"jwks.keys[{index}].key_ops must contain only verify")
        key_id = raw_key.get("kid")
        if not isinstance(key_id, str) or not key_id.strip() or len(key_id) > 256:
            raise ClientAuthenticationError(f"jwks.keys[{index}].kid must be a non-empty string")
        if key_id in seen_key_ids:
            raise ClientAuthenticationError("jwks key ids must be unique")
        seen_key_ids.add(key_id)
        x = _decode_base64url(raw_key.get("x"), field=f"jwks.keys[{index}].x")
        y = _decode_base64url(raw_key.get("y"), field=f"jwks.keys[{index}].y")
        if len(x) != 32 or len(y) != 32:
            raise ClientAuthenticationError(
                f"jwks.keys[{index}] P-256 coordinates must be 32 bytes"
            )
        try:
            _marty_verification.p256_public_jwk_to_pem(
                json.dumps(raw_key, separators=(",", ":"), sort_keys=True)
            )
        except (RuntimeError, TypeError, ValueError) as exc:
            raise ClientAuthenticationError(
                f"jwks.keys[{index}] is not a valid P-256 public key"
            ) from exc

        normalized_key: dict[str, Any] = {
            "kty": "EC",
            "crv": "P-256",
            "kid": key_id,
            "alg": "ES256",
            "use": "sig",
            "x": raw_key["x"],
            "y": raw_key["y"],
        }
        if key_ops is not None:
            normalized_key["key_ops"] = ["verify"]
        normalized.append(normalized_key)

    return {"keys": normalized}


def _numeric_date(claims: dict[str, Any], name: str, *, required: bool = True) -> int | None:
    value = claims.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ClientAuthenticationError(f"client assertion {name} must be a NumericDate")
    return int(value)


def _audience_matches(value: Any, expected: set[str]) -> bool:
    if isinstance(value, str):
        audiences = {value.rstrip("/")}
    elif isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        audiences = {item.rstrip("/") for item in value}
    else:
        return False
    return bool(audiences & expected)


def verify_private_key_jwt(
    assertion: str,
    *,
    client_id: str,
    public_jwks: dict[str, Any],
    allowed_audiences: Iterable[str],
    now: datetime | None = None,
) -> VerifiedClientAssertion:
    """Verify a registered client's RFC 7523 assertion using its public JWKS."""

    if not isinstance(assertion, str):
        raise ClientAuthenticationError("client_assertion is required")
    parts = assertion.split(".")
    if len(parts) != 3 or not all(parts):
        raise ClientAuthenticationError("client_assertion must be a compact JWT")
    normalized_jwks = normalize_public_client_jwks(public_jwks)
    verified_candidates: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for key in normalized_jwks["keys"]:
        try:
            header, claims = verify_compact_jwt(assertion, key, "ES256")
        except NativeOperationError:
            continue
        if header.get("kid") == key["kid"]:
            verified_candidates.append((header, claims, key))
    if len(verified_candidates) != 1:
        raise ClientAuthenticationError(
            "client assertion signature verification failed or JWT is malformed"
        )
    header, claims, key = verified_candidates[0]
    if "jwk" in header or "jku" in header or "x5u" in header:
        raise ClientAuthenticationError("client assertion must select a registered key by kid")
    if header.get("crit") or header.get("b64") is False:
        raise ClientAuthenticationError("client assertion uses unsupported JOSE extensions")
    if header.get("typ") not in (None, "JWT"):
        raise ClientAuthenticationError("client assertion typ must be JWT when present")
    key_id = key["kid"]

    if claims.get("iss") != client_id or claims.get("sub") != client_id:
        raise ClientAuthenticationError(
            "client assertion iss and sub must equal the registered client_id"
        )
    expected_audiences = {item.rstrip("/") for item in allowed_audiences if item}
    if not expected_audiences or not _audience_matches(claims.get("aud"), expected_audiences):
        raise ClientAuthenticationError("client assertion audience is invalid")

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now_seconds = int(current.timestamp())
    issued_at = _numeric_date(claims, "iat")
    expires_at = _numeric_date(claims, "exp")
    not_before = _numeric_date(claims, "nbf", required=False)
    assert issued_at is not None and expires_at is not None
    if issued_at > now_seconds + _CLOCK_SKEW_SECONDS:
        raise ClientAuthenticationError("client assertion iat is in the future")
    if issued_at < now_seconds - _MAX_ASSERTION_LIFETIME_SECONDS - _CLOCK_SKEW_SECONDS:
        raise ClientAuthenticationError("client assertion iat is too old")
    if expires_at <= now_seconds - _CLOCK_SKEW_SECONDS:
        raise ClientAuthenticationError("client assertion is expired")
    if expires_at <= issued_at:
        raise ClientAuthenticationError("client assertion exp must be after iat")
    if expires_at > issued_at + _MAX_ASSERTION_LIFETIME_SECONDS:
        raise ClientAuthenticationError("client assertion lifetime exceeds five minutes")
    if not_before is not None and not_before > now_seconds + _CLOCK_SKEW_SECONDS:
        raise ClientAuthenticationError("client assertion is not yet valid")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti.strip() or len(jti) > 256:
        raise ClientAuthenticationError("client assertion jti is required")

    return VerifiedClientAssertion(
        client_id=client_id,
        jti=jti,
        expires_at=datetime.fromtimestamp(expires_at, tz=UTC),
        key_id=key_id,
    )


async def authenticate_oid4vci_client(
    *,
    repo: Oid4vciClientAuthRepository,
    organization_id: str | None,
    expected_client_id: str | None,
    client_id: str | None,
    client_assertion_type: str | None,
    client_assertion: str | None,
    allowed_audiences: Iterable[str],
    registration_required: bool,
) -> None:
    """Authenticate one tenant-owned wallet client and consume its assertion JTI.

    An unbound public offer may use the OAuth ``none`` method. Once an issuance
    or authorization session is bound to a registered client, every transport
    must present the same registered ``private_key_jwt`` proof.
    """

    supplied_authentication = bool(client_assertion_type or client_assertion)
    if not organization_id or not expected_client_id:
        if supplied_authentication:
            raise ClientAuthenticationError("client authentication is not valid for this offer")
        return

    registered = await repo.get_oid4vci_client(organization_id, expected_client_id)
    if registered is None:
        if registration_required or supplied_authentication:
            raise ClientAuthenticationError("registered client was not found")
        return
    if not registered.active:
        raise ClientAuthenticationError("registered client is inactive")
    if registered.token_endpoint_auth_method != "private_key_jwt":
        raise ClientAuthenticationError("registered client authentication method is unsupported")
    # RFC 7523 client assertions identify the client through their signed
    # ``iss`` and ``sub`` claims.  Some interoperable wallets therefore omit
    # the redundant OAuth form ``client_id``.  The issuance transaction is
    # already bound to exactly one tenant-owned registration, so verify the
    # assertion against that registration and treat a supplied form value only
    # as an additional consistency check.
    if client_id is not None and client_id != registered.client_id:
        raise ClientAuthenticationError("client_id does not match the registered client")
    if client_assertion_type != JWT_BEARER_ASSERTION_TYPE or not client_assertion:
        raise ClientAuthenticationError("registered client assertion is required")

    verified = verify_private_key_jwt(
        client_assertion,
        client_id=registered.client_id,
        public_jwks=registered.jwks,
        allowed_audiences=allowed_audiences,
    )
    claimed = await repo.claim_oid4vci_client_assertion(
        organization_id=organization_id,
        client_id=registered.client_id,
        jti=verified.jti,
        expires_at=verified.expires_at,
    )
    if not claimed:
        raise ClientAuthenticationError("registered client assertion was already used")
