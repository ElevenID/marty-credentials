"""DID resolver supporting did:web, did:key, and did:jwk methods.

Resolves a DID to its DID Document, extracting verification methods
with public key material.  Used by the verification service to look up
issuer keys for credential signature validation.
"""

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import socket
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, unquote, urlsplit

import httpx

logger = logging.getLogger(__name__)

_MAX_DID_DOCUMENT_BYTES = 1024 * 1024
_DID_DOCUMENT_CONTENT_TYPES = {
    "application/did+json",
    "application/json",
    "application/ld+json",
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def resolve_did(did: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Resolve a DID to its DID Document.

    Supports did:web, did:key (Ed25519/P-256), and did:jwk.
    Returns a DID Document dict or raises ``ValueError`` on failure.
    """
    if not did or not isinstance(did, str):
        raise ValueError("DID must be a non-empty string")

    if did.startswith("did:web:"):
        return await resolve_did_web(did, timeout=timeout)
    if did.startswith("did:key:"):
        return resolve_did_key(did)
    if did.startswith("did:jwk:"):
        return resolve_did_jwk(did)

    raise ValueError(f"Unsupported DID method: {did.split(':')[1] if ':' in did else 'unknown'}")


def normalize_verification_method_id(did: str, value: Any) -> str | None:
    """Normalize a DID verification method reference to an absolute DID URL."""
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.startswith("#"):
        return f"{did}{candidate}"
    if candidate.startswith("did:"):
        return candidate
    if "#" not in candidate:
        return f"{did}#{candidate}"
    return candidate


def extract_public_key_jwk(
    did_document: dict[str, Any],
    verification_method_id: str | None = None,
) -> dict[str, Any] | None:
    """Extract a verification-method public key as a JWK dict.

    Looks in ``verificationMethod`` entries for ``publicKeyJwk``.  Falls back
    to ``publicKeyMultibase`` decoding for Ed25519 keys.  When
    ``verification_method_id`` is supplied, only that DID URL/fragment is
    accepted; this prevents credentials from being verified with the first key
    in a DID document after rotation.
    """
    methods = did_document.get("verificationMethod", [])
    did = str(did_document.get("id") or "")
    target = normalize_verification_method_id(did, verification_method_id)
    if target and not target.startswith(f"{did}#"):
        return None

    assertion_methods = _verification_relationship_ids(did_document, "assertionMethod")

    for method in methods:
        if not isinstance(method, dict):
            continue
        method_id = normalize_verification_method_id(did, method.get("id"))
        if target and method_id != target:
            continue
        if method_id not in assertion_methods:
            continue

        jwk = method.get("publicKeyJwk")
        if jwk:
            sanitized = {
                k: v
                for k, v in jwk.items()
                if k not in {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
            }
            if method_id and not sanitized.get("kid"):
                sanitized["kid"] = method_id
            return sanitized

        multibase = method.get("publicKeyMultibase")
        if multibase and multibase.startswith("z"):
            # Ed25519 multibase: z + base58btc
            try:
                raw = _base58btc_decode(multibase[1:])
                # Multicodec prefix for Ed25519 public key: 0xed01
                if len(raw) >= 2 and raw[0] == 0xED and raw[1] == 0x01:
                    raw = raw[2:]
                jwk = {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
                }
                if method_id:
                    jwk["kid"] = method_id
                return jwk
            except Exception:
                continue

    return None


def extract_credential_verification_method(credential: dict[str, Any]) -> str | None:
    """Extract the issuer verification method/kid from a credential proof."""
    proof = credential.get("proof") if isinstance(credential, dict) else None
    if isinstance(proof, dict):
        for field in ("verificationMethod", "verification_method", "kid"):
            value = proof.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _assert_jwk_algorithm(jwk: dict[str, Any], algorithm: str | None) -> None:
    if not algorithm:
        return

    declared_algorithm = jwk.get("alg")
    if declared_algorithm and declared_algorithm != algorithm:
        raise ValueError("Resolved issuer key algorithm does not match the requested algorithm")

    key_type = jwk.get("kty")
    curve = jwk.get("crv")
    compatible = {
        "ES256": key_type == "EC" and curve == "P-256",
        "ES384": key_type == "EC" and curve == "P-384",
        "ES512": key_type == "EC" and curve == "P-521",
        "EdDSA": key_type == "OKP" and curve in {"Ed25519", "Ed448"},
        "RS256": key_type == "RSA",
        "RS384": key_type == "RSA",
        "RS512": key_type == "RSA",
        "PS256": key_type == "RSA",
        "PS384": key_type == "RSA",
        "PS512": key_type == "RSA",
    }.get(algorithm)
    if compatible is not True:
        raise ValueError("Resolved issuer key is not compatible with the requested algorithm")


def _assertion_key_ids(did_document: dict[str, Any]) -> list[str]:
    did = str(did_document.get("id") or "")
    assertion_methods = _verification_relationship_ids(did_document, "assertionMethod")
    result: list[str] = []
    for method in did_document.get("verificationMethod", []):
        if not isinstance(method, dict):
            continue
        method_id = normalize_verification_method_id(did, method.get("id"))
        if method_id in assertion_methods and (
            isinstance(method.get("publicKeyJwk"), dict)
            or isinstance(method.get("publicKeyMultibase"), str)
        ):
            result.append(method_id)
    return result


def _read_secret_value(name: str) -> str:
    direct = os.environ.get(name)
    if direct:
        return direct
    file_path = os.environ.get(f"{name}_FILE")
    if not file_path:
        return ""
    try:
        with open(file_path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _internal_signing_base_url() -> str:
    return os.environ.get(
        "SIGNING_KEYS_INTERNAL_URL", "http://gateway:8000/internal/signing-keys"
    ).rstrip("/")


def _internal_headers() -> dict[str, str]:
    api_key = _read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value(
        "VERIFICATION_API_KEY"
    )
    return {"X-API-Key": api_key} if api_key else {}


def _response_error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = None

    if isinstance(payload, dict):
        detail = payload.get("detail") or payload.get("error_description") or payload.get("error")
        if isinstance(detail, str) and detail.strip():
            return detail.strip()
        if isinstance(detail, dict):
            return str(detail)

    text = response.text.strip()
    return text[:500] if text else response.reason_phrase


async def _resolve_issuer_did_via_org_registry(
    *,
    issuer_did: str,
    organization_id: str,
    verification_method_id: str | None = None,
    credential_format: str | None = None,
    key_purpose: str | None = None,
    algorithm: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    params: dict[str, str] = {
        "organization_id": organization_id,
        "issuer_did": issuer_did,
    }
    if verification_method_id:
        params["verification_method_id"] = verification_method_id
    if credential_format:
        params["credential_format"] = credential_format
    if key_purpose:
        params["key_purpose"] = key_purpose
    if algorithm:
        params["algorithm"] = algorithm

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(
            f"{_internal_signing_base_url()}/resolve-issuer-did",
            params=params,
            headers=_internal_headers(),
        )

    if response.status_code >= 400:
        raise ValueError(
            f"Org-scoped DID resolution failed for {issuer_did} "
            f"(HTTP {response.status_code}): {_response_error_detail(response)}"
        )
    data = response.json()
    if not isinstance(data, dict) or not data.get("ok"):
        raise ValueError(f"Org-scoped DID resolver returned an invalid response for {issuer_did}")
    return data


async def resolve_issuer_did(
    issuer_did: str,
    *,
    organization_id: str | None = None,
    verification_method_id: str | None = None,
    trusted_issuers: list[str] | None = None,
    credential_format: str | None = None,
    key_purpose: str | None = None,
    algorithm: str | None = None,
    allow_public_fallback: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Resolve an issuer DID using org-scoped registry before public DID lookup."""
    if trusted_issuers and issuer_did not in trusted_issuers:
        raise ValueError(f"Issuer {issuer_did} not trusted")

    if organization_id:
        try:
            resolved = await _resolve_issuer_did_via_org_registry(
                issuer_did=issuer_did,
                organization_id=organization_id,
                verification_method_id=verification_method_id,
                credential_format=credential_format,
                key_purpose=key_purpose,
                algorithm=algorithm,
                timeout=timeout,
            )
            public_jwk = (
                resolved.get("public_jwk") if isinstance(resolved.get("public_jwk"), dict) else None
            )
            if public_jwk is None:
                did_doc_value = resolved.get("did_document")
                did_doc: dict[str, Any] = did_doc_value if isinstance(did_doc_value, dict) else {}
                public_jwk = extract_public_key_jwk(
                    did_doc, resolved.get("verification_method_id") or verification_method_id
                )
            if public_jwk is None:
                raise ValueError(f"Org-scoped DID resolver returned no public key for {issuer_did}")
            _assert_jwk_algorithm(public_jwk, algorithm)
            return {**resolved, "public_jwk": public_jwk}
        except ValueError:
            if not allow_public_fallback:
                raise
            logger.warning("Falling back to public DID resolution for issuer %s", issuer_did)

    if not allow_public_fallback:
        raise ValueError("Public DID resolution was not explicitly authorized")
    if not trusted_issuers or issuer_did not in trusted_issuers:
        raise ValueError("Public DID resolution requires an explicitly trusted issuer")

    did_document = await resolve_did(issuer_did, timeout=timeout)
    selected_verification_method = verification_method_id
    if selected_verification_method is None:
        assertion_key_ids = _assertion_key_ids(did_document)
        if len(assertion_key_ids) != 1:
            raise ValueError("Public DID resolution requires an unambiguous assertion key")
        selected_verification_method = assertion_key_ids[0]

    public_jwk = extract_public_key_jwk(did_document, selected_verification_method)
    if public_jwk is None:
        raise ValueError(f"No public key matched issuer DID {issuer_did}")
    _assert_jwk_algorithm(public_jwk, algorithm)
    normalized_vm = normalize_verification_method_id(issuer_did, selected_verification_method)
    return {
        "ok": True,
        "issuer_did": issuer_did,
        "verification_method_id": normalized_vm or public_jwk.get("kid"),
        "did_document": did_document,
        "public_jwk": public_jwk,
        "resolver": {
            "type": "public_did_resolution",
            "public_fallback_used": bool(organization_id),
            "requested_algorithm": algorithm,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "did_document_sha256": hashlib.sha256(
                json.dumps(did_document, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        },
    }


# ---------------------------------------------------------------------------
# did:web
# ---------------------------------------------------------------------------


def _did_web_url(did: str) -> tuple[str, str, int]:
    """Build a canonical did:web URL and reject URL parser ambiguities."""
    if not did.startswith("did:web:"):
        raise ValueError(f"Not a did:web DID: {did}")

    parts = did.split(":")
    if len(parts) < 3 or not parts[2]:
        raise ValueError(f"Malformed did:web DID: {did}")

    authority = unquote(parts[2])
    if any(char in authority for char in "/\\@?#") or any(ord(char) < 0x20 for char in authority):
        raise ValueError(f"Malformed did:web authority: {did}")

    try:
        parsed = urlsplit(f"https://{authority}")
        host = parsed.hostname
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError(f"Malformed did:web authority: {did}") from exc

    if (
        not host
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"Malformed did:web authority: {did}")

    host = host.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("did:web host is not publicly routable")
    try:
        host_address = ipaddress.ip_address(host)
    except ValueError:
        host_address = None
    if host_address is not None:
        raise ValueError("did:web IP literals are not permitted")

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Malformed did:web host: {did}") from exc

    configured_hosts = {
        value.strip().lower().rstrip(".")
        for value in os.environ.get("DID_WEB_ALLOWED_HOSTS", "").split(",")
        if value.strip()
    }
    environment = os.environ.get("ENVIRONMENT", os.environ.get("APP_ENV", "development")).lower()
    if environment in {"production", "prod"} and not configured_hosts:
        raise ValueError("Production did:web resolution requires a configured egress allowlist")
    if environment in {"production", "prod"} and port != 443:
        raise ValueError("Production did:web resolution requires the default HTTPS port")
    if configured_hosts and ascii_host not in configured_hosts:
        raise ValueError("did:web host is not in the configured egress allowlist")

    path_segments: list[str] = []
    for raw_segment in parts[3:]:
        segment = unquote(raw_segment)
        if (
            not segment
            or segment in {".", ".."}
            or any(char in segment for char in "/\\?#")
            or any(ord(char) < 0x20 for char in segment)
        ):
            raise ValueError(f"Malformed did:web path: {did}")
        path_segments.append(quote(segment, safe="-._~"))

    url_authority = ascii_host if port == 443 else f"{ascii_host}:{port}"
    if path_segments:
        url = f"https://{url_authority}/{'/'.join(path_segments)}/did.json"
    else:
        url = f"https://{url_authority}/.well-known/did.json"
    return url, ascii_host, port


async def _require_public_dns(host: str, port: int) -> tuple[str, ...]:
    """Resolve a did:web host and reject every non-public address."""
    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise ValueError("Could not resolve did:web host") from exc

    resolved = sorted({str(item[4][0]).split("%", 1)[0] for item in addresses})
    if not resolved:
        raise ValueError("Could not resolve did:web host")
    for address in resolved:
        try:
            public = ipaddress.ip_address(address).is_global
        except ValueError as exc:
            raise ValueError("did:web DNS returned an invalid address") from exc
        if not public:
            raise ValueError("did:web DNS resolved to a non-public address")
    return tuple(resolved)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON member in DID document: {key}")
        result[key] = value
    return result


def _verification_relationship_ids(
    did_document: dict[str, Any],
    relationship: str,
) -> set[str]:
    did = str(did_document.get("id") or "")
    entries = did_document.get(relationship)
    if not isinstance(entries, list):
        return set()

    result: set[str] = set()
    for entry in entries:
        value = entry.get("id") if isinstance(entry, dict) else entry
        normalized = normalize_verification_method_id(did, value)
        if normalized:
            result.add(normalized)
    return result


def _validate_did_document(doc: Any, did: str) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise ValueError("DID document must be a JSON object")
    if doc.get("id") != did:
        raise ValueError("DID document id does not match the requested DID")

    methods = doc.get("verificationMethod")
    if not isinstance(methods, list) or not methods:
        raise ValueError("DID document has no verification methods")

    method_ids: set[str] = set()
    for method in methods:
        if not isinstance(method, dict):
            raise ValueError("DID document contains an invalid verification method")
        method_id = normalize_verification_method_id(did, method.get("id"))
        if not method_id or not method_id.startswith(f"{did}#"):
            raise ValueError("DID verification method is not controlled by the requested DID")
        if method_id in method_ids:
            raise ValueError("DID document contains duplicate verification method ids")
        if method.get("controller") != did:
            raise ValueError("DID verification method controller does not match the requested DID")
        method_ids.add(method_id)

    assertion_methods = _verification_relationship_ids(doc, "assertionMethod")
    if not assertion_methods or not assertion_methods.issubset(method_ids):
        raise ValueError("DID document has an invalid assertionMethod relationship")
    return doc


async def _resolve_did_web_hardened(did: str, *, timeout: float) -> dict[str, Any]:
    url, host, port = _did_web_url(did)
    await _require_public_dns(host, port)

    try:
        async with (
            httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client,
            client.stream(
                "GET",
                url,
                headers={"Accept": "application/did+json, application/json"},
            ) as resp,
        ):
            if 300 <= resp.status_code < 400:
                raise ValueError("DID document redirects are not permitted")
            if resp.status_code != 200:
                raise ValueError(f"DID document fetch failed with HTTP {resp.status_code}")

            content_type = resp.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type not in _DID_DOCUMENT_CONTENT_TYPES:
                raise ValueError("DID document response has an unsupported content type")

            content_length = resp.headers.get("content-length")
            if content_length:
                try:
                    length = int(content_length)
                except ValueError as exc:
                    raise ValueError("DID document response has an invalid content length") from exc
                if length < 0:
                    raise ValueError("DID document response has an invalid content length")
                if length > _MAX_DID_DOCUMENT_BYTES:
                    raise ValueError("DID document exceeds the maximum response size")

            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body.extend(chunk)
                if len(body) > _MAX_DID_DOCUMENT_BYTES:
                    raise ValueError("DID document exceeds the maximum response size")

        doc = json.loads(body.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except httpx.RequestError as exc:
        raise ValueError("Could not reach DID document") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("DID document response is not valid UTF-8 JSON") from exc

    return _validate_did_document(doc, did)


async def resolve_did_web(did: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Resolve a did:web document through bounded, public-only HTTPS egress."""
    return await _resolve_did_web_hardened(did, timeout=timeout)


# ---------------------------------------------------------------------------
# did:key (Ed25519 and P-256)
# ---------------------------------------------------------------------------

# Multicodec prefixes
_ED25519_PREFIX = bytes([0xED, 0x01])
_P256_PREFIX = bytes([0x80, 0x24])


def resolve_did_key(did: str) -> dict[str, Any]:
    """Resolve a did:key DID to a synthetic DID Document.

    Supports Ed25519 (z6Mk...) and P-256 (zDn...) public keys.
    """
    if not did.startswith("did:key:"):
        raise ValueError(f"Not a did:key DID: {did}")

    multibase_value = did[len("did:key:") :]
    if not multibase_value.startswith("z"):
        raise ValueError(f"Unsupported multibase encoding (expected base58btc 'z'): {did}")

    raw = _base58btc_decode(multibase_value[1:])

    if raw[:2] == _ED25519_PREFIX:
        pub_bytes = raw[2:]
        if len(pub_bytes) != 32:
            raise ValueError(f"Invalid Ed25519 public key length: {len(pub_bytes)}")
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(pub_bytes),
        }
        key_type = "Ed25519VerificationKey2020"
    elif raw[:2] == _P256_PREFIX:
        pub_bytes = raw[2:]
        # Compressed P-256 key (33 bytes) or uncompressed (65 bytes)
        if len(pub_bytes) == 33:
            x_bytes, y_bytes = _decompress_p256(pub_bytes)
        elif len(pub_bytes) == 65 and pub_bytes[0] == 0x04:
            x_bytes = pub_bytes[1:33]
            y_bytes = pub_bytes[33:65]
        else:
            raise ValueError(f"Invalid P-256 public key length: {len(pub_bytes)}")
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(x_bytes),
            "y": _b64url(y_bytes),
        }
        key_type = "JsonWebKey2020"
    else:
        raise ValueError(f"Unsupported did:key codec: 0x{raw[0]:02x}{raw[1]:02x}")

    vm_id = f"{did}#{multibase_value}"
    return {
        "id": did,
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "verificationMethod": [
            {
                "id": vm_id,
                "type": key_type,
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    }


# ---------------------------------------------------------------------------
# did:jwk
# ---------------------------------------------------------------------------


def resolve_did_jwk(did: str) -> dict[str, Any]:
    """Resolve a did:jwk DID to a synthetic DID Document.

    did:jwk:<base64url-encoded JWK>
    """
    if not did.startswith("did:jwk:"):
        raise ValueError(f"Not a did:jwk DID: {did}")

    b64_part = did[len("did:jwk:") :]
    # Add padding
    padding = 4 - len(b64_part) % 4
    if padding != 4:
        b64_part += "=" * padding

    try:
        jwk = json.loads(base64.urlsafe_b64decode(b64_part))
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"Invalid did:jwk — cannot decode JWK: {exc}") from exc

    if "kty" not in jwk:
        raise ValueError("Invalid JWK: missing 'kty' field")

    # Strip private key material if accidentally included
    jwk.pop("d", None)

    vm_id = f"{did}#0"
    return {
        "id": did,
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_decode(s: str) -> bytes:
    """Decode a base58btc string to bytes."""
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.index(ord(ch))
        n = n * 58 + idx
    # Count leading '1's → leading zero bytes
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + result


def _b64url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decompress_p256(compressed: bytes) -> tuple[bytes, bytes]:
    """Decompress a P-256 compressed public key to (x, y) coordinates.

    Uses the secp256r1 curve equation: y² = x³ + ax + b (mod p)
    """
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b_coeff = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    prefix = compressed[0]
    x = int.from_bytes(compressed[1:33], "big")

    y_sq = (pow(x, 3, p) + a * x + b_coeff) % p
    y = pow(y_sq, (p + 1) // 4, p)

    if (y % 2) != (prefix - 2):
        y = p - y

    return x.to_bytes(32, "big"), y.to_bytes(32, "big")
