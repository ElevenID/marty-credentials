"""Rust integration for credential signing operations."""

import base64
import hashlib
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from issuance.infrastructure.models import issuer_signing_keys_table
from status_list.infrastructure.security.encryption import SymmetricEncryption

logger = logging.getLogger(__name__)

_issuer_key_session_factory: async_sessionmaker[AsyncSession] | None = None
_issuer_key_encryption: SymmetricEncryption | None = None


# ---------------------------------------------------------------------------
# Base58btc helpers (needed for did:key encoding — no stdlib support)
# ---------------------------------------------------------------------------

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_encode(data: bytes) -> str:
    """Encode bytes as base58btc (no multibase prefix)."""
    n_zeros = len(data) - len(data.lstrip(b"\x00"))
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(_BASE58_ALPHABET[rem])
    result.extend([_BASE58_ALPHABET[0]] * n_zeros)
    result.reverse()
    return bytes(result).decode("ascii")


def _did_key_from_ed25519(public_key: bytes) -> str:
    """Compute did:key from a raw Ed25519 public key (32 bytes).

    Multicodec prefix for Ed25519: 0xed 0x01.
    Encoded as base58btc with multibase prefix 'z'.
    Produces the well-known did:key:z6Mk... format that all wallets can
    resolve without any network call (the public key is embedded in the DID).
    """
    prefixed = bytes([0xED, 0x01]) + public_key
    return f"did:key:z{_base58btc_encode(prefixed)}"


def base64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def base64url_decode(data: str) -> bytes:
    """Decode base64url string with optional omitted padding."""
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


# base64url_decode removed — PKCE verification now delegated to Rust.


# ---------------------------------------------------------------------------
# Issuer key management
# ---------------------------------------------------------------------------

# In-process cache so every credential for the same org has the same issuer DID.
# In production this should be backed by the database / a KMS.
_org_keys: dict = {}


def configure_issuer_key_store(
    session_factory: async_sessionmaker[AsyncSession] | None,
) -> None:
    """Configure database-backed encrypted issuer key persistence."""
    global _issuer_key_session_factory
    _issuer_key_session_factory = session_factory
    if session_factory is not None:
        logger.info("Configured database-backed issuer key store")


def _persistent_key_store_available() -> bool:
    """Return True when encrypted database-backed key storage is configured."""
    return _issuer_key_session_factory is not None and bool(os.environ.get("ISSUER_KEY_MASTER_KEY"))


def _get_issuer_key_encryption() -> SymmetricEncryption:
    """Return the encryption service for persisted issuer keys."""
    global _issuer_key_encryption
    if _issuer_key_encryption is None:
        _issuer_key_encryption = SymmetricEncryption.from_env("ISSUER_KEY_MASTER_KEY")
    return _issuer_key_encryption


async def _load_persisted_issuer_key(organization_id: str) -> dict | None:
    """Load and decrypt issuer key material from PostgreSQL."""
    if not _persistent_key_store_available() or _issuer_key_session_factory is None:
        return None

    encryption = _get_issuer_key_encryption()
    async with _issuer_key_session_factory() as session:
        stmt = select(issuer_signing_keys_table).where(
            issuer_signing_keys_table.c.organization_id == organization_id
        )
        result = await session.execute(stmt)
        row = result.mappings().first()

    if row is None:
        return None

    jwk_json = encryption.decrypt(row["encrypted_jwk_json"])
    jwk = json.loads(jwk_json)
    public_key = base64url_decode(jwk["x"])
    private_key = base64url_decode(jwk["d"])
    key_info = {
        "did": row["issuer_did"],
        "private_key": private_key,
        "public_key": public_key,
        "jwk_json": jwk_json,
    }
    _org_keys[organization_id] = key_info
    logger.info("Loaded issuer signing key from database for org %r", organization_id)
    return key_info


async def _save_persisted_issuer_key(organization_id: str, key_info: dict) -> None:
    """Encrypt and persist issuer key material to PostgreSQL."""
    if not _persistent_key_store_available() or _issuer_key_session_factory is None:
        return

    encryption = _get_issuer_key_encryption()
    encrypted_jwk_json = encryption.encrypt(key_info["jwk_json"])
    now = datetime.now(timezone.utc)

    async with _issuer_key_session_factory() as session:
        stmt = select(issuer_signing_keys_table).where(
            issuer_signing_keys_table.c.organization_id == organization_id
        )
        result = await session.execute(stmt)
        existing = result.mappings().first()

        payload = {
            "organization_id": organization_id,
            "issuer_did": key_info["did"],
            "key_algorithm": "Ed25519",
            "encrypted_jwk_json": encrypted_jwk_json,
            "public_key_b64": base64url_encode(key_info["public_key"]),
            "updated_at": now,
        }

        if existing:
            update_stmt = (
                issuer_signing_keys_table.update()
                .where(issuer_signing_keys_table.c.organization_id == organization_id)
                .values(**payload)
            )
            await session.execute(update_stmt)
        else:
            payload["id"] = str(uuid.uuid4())
            payload["created_at"] = now
            insert_stmt = issuer_signing_keys_table.insert().values(**payload)
            await session.execute(insert_stmt)

        await session.commit()

    logger.info("Persisted encrypted issuer signing key for org %r", organization_id)


def get_marty_rs():
    """Import Rust bindings for credential operations.

    Raises:
        ImportError: If marty-rs bindings are not available.
    """
    try:
        from marty_rs import _marty_rs
        return _marty_rs
    except ImportError:
        pass
    try:
        import _marty_rs
        return _marty_rs
    except ImportError as e:
        logger.error("marty-rs bindings not available - credential signing will fail")
        raise ImportError(
            "marty-rs Python bindings are required for credential signing. "
            "Ensure the marty-bindings crate is built and installed."
        ) from e


async def get_or_generate_issuer_key(organization_id: str = "default") -> dict:
    """Return the KMS-backed issuer signing key for an organization.

    Loads from database-backed encrypted storage (requires ``ISSUER_KEY_MASTER_KEY``
    and a configured session factory). Raises ``RuntimeError`` when no persisted
    key is found — ephemeral software key generation is not supported.

    Returns:
        dict with 'did' (did:key:z6Mk...), 'private_key' (bytes), 'public_key' (bytes)
    """
    global _org_keys
    if organization_id in _org_keys:
        return _org_keys[organization_id]

    persisted_key = await _load_persisted_issuer_key(organization_id)
    if persisted_key is not None:
        return persisted_key

    raise RuntimeError(
        f"No signing key found for organization {organization_id!r}. "
        "Provision a KMS-backed key via the signing-keys service before issuing credentials."
    )


def _fix_mdoc_issuer_auth(credential_b64: str) -> str:
    """Fix mso_mdoc issuerAuth CBOR encoding.

    The Rust engine wraps the COSE_Sign1 issuerAuth as a CBOR byte string,
    but ISO 18013-5 requires the COSE_Sign1 array to be embedded directly
    in the IssuerSigned map (not wrapped in bstr). This function decodes
    the byte string and re-embeds the COSE_Sign1 structure.
    """
    import cbor2

    # base64url-decode (add padding)
    padding = 4 - len(credential_b64) % 4
    if padding < 4:
        credential_b64 += "=" * padding
    raw = base64.urlsafe_b64decode(credential_b64)

    issuer_signed = cbor2.loads(raw)
    auth = issuer_signed.get("issuerAuth")
    if isinstance(auth, bytes):
        decoded = cbor2.loads(auth)
        # Strip COSE tag 18 if present — Walt.id expects the raw array
        if isinstance(decoded, cbor2.CBORTag) and decoded.tag == 18:
            issuer_signed["issuerAuth"] = decoded.value
        else:
            issuer_signed["issuerAuth"] = decoded

        fixed = cbor2.dumps(issuer_signed)
        return base64.urlsafe_b64encode(fixed).rstrip(b"=").decode()

    return credential_b64


def create_verifiable_credential_wrapper(
    issuer_did: str,
    issuer_jwk_json: str,
    subject_id: str,
    credential_type: str,
    claims_json: str,
    expiration_seconds: int = 31536000,
    organization_id: str | None = None,
    format: str = "jwt_vc_json",
    selective_disclosure_claims: list[str] | None = None,
    zk_predicate_claims: list[str] | None = None,
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt",
) -> Tuple[str, str]:
    """Create a signed verifiable credential using the Rust OID4VCI engine.

    Uses the supplied issuer JWK when present, otherwise falls back to the
    in-process cache. Delegates format-aware signing entirely to the Rust
    marty-oid4vci engine. Supports jwt_vc_json, vc+sd-jwt, mso_mdoc,
    vds_nc, and zk_mdoc formats.
    """
    signing_jwk_json = issuer_jwk_json.strip() if issuer_jwk_json else ""
    if signing_jwk_json in ("", "{}"):
        issuer_key = next(
            (k for k in _org_keys.values() if k["did"] == issuer_did), None
        )
        if issuer_key is None:
            if not organization_id:
                raise RuntimeError(
                    "organization_id is required to look up the issuer key. "
                    "Pass the caller's organization_id explicitly."
                )
            raise RuntimeError(
                f"No signing key cached for issuer DID {issuer_did!r}. "
                "Call await get_or_generate_issuer_key(org_id) before issuing a credential."
            )
        signing_jwk_json = issuer_key["jwk_json"]

    marty_rs = get_marty_rs()
    result = marty_rs.oid4vci_sign_credential(
        issuer_did,
        signing_jwk_json,
        subject_id or None,
        credential_type,
        claims_json,
        expiration_seconds,
        format,
        selective_disclosure_claims or [],
        zk_predicate_claims or [],
        credential_payload_format,
    )

    # Fix mso_mdoc CBOR encoding: the Rust engine wraps issuerAuth as a CBOR
    # byte string, but ISO 18013-5 / Walt.id expect the COSE_Sign1 array
    # to be embedded directly (not wrapped in bstr).
    if credential_payload_format.lower() in ("mso_mdoc", "mdoc"):
        credential_str, credential_id = result
        credential_str = _fix_mdoc_issuer_auth(credential_str)
        return (credential_str, credential_id)

    return result


def _json_dumps_compact(value: Any) -> str:
    # ensure_ascii=True produces ASCII-safe JSON (non-ASCII escaped as \\uXXXX),
    # matching serde_json default serialization used by sd-jwt-rs and other Rust JWT libs.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _remote_issuer_kid(
    issuer_did: str,
    signing_service_id: str,
    signing_key_reference: str | None = None,
) -> str:
    if issuer_did.startswith("did:web:"):
        fragment = signing_key_reference or f"{signing_service_id}-vm"
    elif signing_key_reference:
        fragment = signing_key_reference
    elif issuer_did.startswith("did:jwk:"):
        fragment = "0"
    elif issuer_did.startswith("did:key:"):
        fragment = issuer_did.rsplit(":", 1)[-1]
    else:
        fragment = f"{signing_service_id}-vm"
    safe_fragment = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in fragment)
    return f"{issuer_did}#{safe_fragment or 'key-1'}"


async def create_sd_jwt_vc_with_remote_signing(
    *,
    issuer_did: str,
    signing_service_id: str,
    remote_sign: Callable[[bytes, str | None], Awaitable[dict[str, Any]]],
    subject_id: str | None,
    credential_type: str,
    claims_json: str,
    expiration_seconds: int = 31536000,
    selective_disclosure_claims: list[str] | None = None,
    algorithm: str | None = None,
    signing_key_reference: str | None = None,
    verification_method_id: str | None = None,
    credential_format: str | None = None,
) -> Tuple[str, str]:
    """Create an SD-JWT VC whose signature is produced by a remote KMS.

    Args:
        credential_format: OID4VCI format string (e.g. ``"spruce-vc+sd-jwt"``)
            used in the credential response metadata.  The JWT ``typ`` header
            is always ``"vc+sd-jwt"`` per RFC 9596 §3.2.1 regardless of this value.
    """
    claims = json.loads(claims_json or "{}")
    if not isinstance(claims, dict):
        raise RuntimeError("claims_json must encode an object")

    now = int(datetime.now(timezone.utc).timestamp())
    credential_id = f"urn:uuid:{uuid.uuid4()}"
    sd_claims = set(selective_disclosure_claims or [])

    payload: dict[str, Any] = {
        "iss": issuer_did,
        "iat": now,
        "nbf": now,
        "exp": now + int(expiration_seconds or 31536000),
        "jti": credential_id,
        "vct": credential_type,
    }
    if subject_id:
        payload["sub"] = subject_id
        payload["cnf"] = {"kid": subject_id}

    disclosures: list[str] = []
    sd_hashes: list[str] = []
    for key, value in claims.items():
        if key in sd_claims:
            disclosure = [base64url_encode(secrets.token_bytes(16)), key, value]
            disclosure_b64 = base64url_encode(_json_dumps_compact(disclosure).encode("utf-8"))
            sd_hashes.append(base64url_encode(hashlib.sha256(disclosure_b64.encode("ascii")).digest()))
            disclosures.append(disclosure_b64)
        else:
            payload[key] = value

    if sd_hashes:
        payload["_sd_alg"] = "sha-256"
        # Sort the _sd digests for deterministic output, matching sd-jwt-rs issuer behavior.
        payload["_sd"] = sorted(sd_hashes)

    # RFC 9596 §3.2.1: the JWT typ header MUST be "vc+sd-jwt" for SD-JWT VCs.
    # The credential_format (e.g. "spruce-vc+sd-jwt", "dc+sd-jwt") is the OID4VCI
    # format identifier used in metadata/responses, NOT the JWT typ header.
    header = {
        "alg": algorithm or "ES256",
        "typ": "vc+sd-jwt",
        "kid": verification_method_id or _remote_issuer_kid(issuer_did, signing_service_id, signing_key_reference),
    }
    encoded_header = base64url_encode(_json_dumps_compact(header).encode("utf-8"))
    encoded_payload = base64url_encode(_json_dumps_compact(payload).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")

    sign_result = await remote_sign(signing_input, algorithm)
    response_algorithm = sign_result.get("algorithm")
    signature_b64 = sign_result.get("signature_raw_b64") or sign_result.get("signature_b64")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise RuntimeError("Remote signing service returned no usable JWS signature")

    if response_algorithm and response_algorithm != header["alg"]:
        logger.debug("Remote signer returned algorithm %s for requested %s", response_algorithm, header["alg"])

    jwt = f"{encoded_header}.{encoded_payload}.{signature_b64}"
    # SD-JWT compact serialization: jwt~disc1~disc2~  (trailing ~ with no KB JWT)
    # When there are no disclosures, output jwt~ to match sd-jwt-rs issuer behavior.
    # jwt~~ would produce an empty-string disclosure that breaks sd-jwt-rs parsing.
    jwt_parts = [jwt] + disclosures
    return f"{'~'.join(jwt_parts)}~", credential_id


# ---------------------------------------------------------------------------
# OID4VCI Protocol Wrappers  (delegate to Rust — never reimplement in Python)
# ---------------------------------------------------------------------------

def oid4vci_create_credential_offer(
    issuer_url: str,
    credential_types: list[str],
    pre_authorized_code: str | None = None,
    user_pin_required: bool = False,
) -> str:
    """Create a credential offer JSON string via Rust engine."""
    marty_rs = get_marty_rs()
    return marty_rs.oid4vci_create_credential_offer(
        issuer_url, credential_types, pre_authorized_code, user_pin_required,
    )


def oid4vci_create_token_response(
    pre_authorized_code: str,
    token_lifetime_secs: int = 1800,
) -> dict:
    """Create a token response for pre-auth code exchange via Rust engine.

    Returns parsed dict with access_token, c_nonce, etc.
    """
    import json as _json
    marty_rs = get_marty_rs()
    resp_json = marty_rs.oid4vci_create_token_response(
        pre_authorized_code, token_lifetime_secs,
    )
    return _json.loads(resp_json)


def oid4vci_create_authorization_response(
    request_json: str,
    session_lifetime_secs: int = 600,
) -> tuple[dict, dict]:
    """Create an authorization response via Rust engine.

    Returns (authorization_response_dict, authorization_session_dict).
    """
    import json as _json
    marty_rs = get_marty_rs()
    resp_json, sess_json = marty_rs.oid4vci_create_authorization_response(
        request_json, session_lifetime_secs,
    )
    return _json.loads(resp_json), _json.loads(sess_json)


def oid4vci_exchange_auth_code_for_token(
    request_json: str,
    session_json: str,
    token_lifetime_secs: int = 1800,
) -> dict:
    """Exchange an auth code for a token response via Rust engine.

    Returns parsed TokenResponse dict.
    """
    import json as _json
    marty_rs = get_marty_rs()
    resp_json = marty_rs.oid4vci_exchange_auth_code_for_token(
        request_json, session_json, token_lifetime_secs,
    )
    return _json.loads(resp_json)


def oid4vci_verify_pkce_s256(code_verifier: str, code_challenge: str) -> bool:
    """Verify a PKCE S256 code_verifier against a code_challenge via Rust."""
    marty_rs = get_marty_rs()
    return marty_rs.oid4vci_verify_pkce_s256(code_verifier, code_challenge)


def canvas_normalize_base_url(base_url: str) -> str:
    """Normalize and harden a Canvas base URL via the Rust layer."""
    marty_rs = get_marty_rs()
    return marty_rs.canvas_normalize_base_url(
        base_url,
        _env_truthy("CANVAS_ALLOW_PRIVATE_BASE_URLS", default=False),
        _env_truthy("CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS", default=False),
    )


def canvas_probe_lti_platform(base_url: str, timeout_seconds: int = 5) -> dict[str, Any]:
    """Fetch and validate Canvas LTI platform metadata via the Rust layer."""
    marty_rs = get_marty_rs()
    probe_json = marty_rs.canvas_probe_lti_platform(
        base_url,
        timeout_seconds,
        _env_truthy("CANVAS_ALLOW_PRIVATE_BASE_URLS", default=False),
        _env_truthy("CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS", default=False),
    )
    return json.loads(probe_json)


def verify_canvas_lti_launch(
    *,
    id_token: str,
    expected_issuer: str,
    expected_client_id: str,
    expected_deployment_id: str,
    jwks_json: dict[str, Any] | str,
    expected_nonce: str | None = None,
    leeway_seconds: int = 120,
) -> dict[str, Any]:
    """Verify a Canvas LTI launch id_token via the Rust layer."""
    marty_rs = get_marty_rs()
    jwks_payload = jwks_json if isinstance(jwks_json, str) else json.dumps(jwks_json)
    verified_json = marty_rs.lti_verify_launch_jwt(
        id_token,
        expected_issuer,
        expected_client_id,
        expected_deployment_id,
        jwks_payload,
        expected_nonce,
        leeway_seconds,
    )
    return json.loads(verified_json)


def verify_proof_jwt(
    proof_jwt: str,
    expected_nonce: str | None,
    issuer_url: str | None = None,
) -> tuple[bool, str, str | None]:
    """Verify an OID4VCI proof JWT via Rust (full OID4VCI §8.2 verification).

    Delegates entirely to marty_rs.oid4vci_verify_proof_jwt which performs:
      - JWT structure and typ header validation
      - Cryptographic signature verification (Ed25519 / P-256)
      - did:key resolution from kid header — no network I/O
      - nonce claim match (when expected_nonce is provided)
      - aud / iat / exp validation

    Returns:
      (ok: bool, holder_did: str, error: str | None)
    """
    try:
        marty_rs = get_marty_rs()
        holder_did, _nonce = marty_rs.oid4vci_verify_proof_jwt(
            proof_jwt, expected_nonce, issuer_url,
        )
        return True, holder_did, None
    except RuntimeError as e:
        return False, "", str(e)
    except Exception as e:
        return False, "", f"proof JWT error: {e}"


# ---------------------------------------------------------------------------
# NOTE: All verifiable credential creation is handled by create_verifiable_credential_wrapper
# above, which delegates entirely to the Rust marty-oid4vci engine via oid4vci_sign_credential.
# Do NOT reimplement credential signing in Python — use create_verifiable_credential_wrapper.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# DIDComm v2 Protocol Wrappers (delegate to Rust marty-didcomm crate)
# ---------------------------------------------------------------------------

def didcomm_resolve_did(did: str, universal_resolver_url: str | None = None) -> dict:
    """Resolve a DID to its DID Document via Rust.

    Supports did:key, did:web, did:peer, did:jwk natively.
    Falls back to the Universal Resolver for unknown methods.
    """
    marty_rs = get_marty_rs()
    doc_json = marty_rs.didcomm_resolve_did(did, universal_resolver_url)
    return json.loads(doc_json)


def didcomm_extract_endpoint(did_document: dict) -> str | None:
    """Extract the DIDComm service endpoint URI from a DID Document."""
    marty_rs = get_marty_rs()
    try:
        return marty_rs.didcomm_extract_endpoint(json.dumps(did_document))
    except RuntimeError:
        return None


def didcomm_pack_credential(
    credential: str,
    credential_format: str,
    issuer_did: str,
    holder_did: str,
    thread_id: str | None = None,
    credential_id: str | None = None,
) -> str:
    """Pack a signed credential into a DIDComm v2 plaintext message.

    Returns JSON string of the DIDComm issue-credential/3.0 message.
    """
    marty_rs = get_marty_rs()
    return marty_rs.didcomm_pack_credential(
        credential, credential_format, issuer_did, holder_did,
        thread_id, credential_id,
    )


def didcomm_unpack_message(message_json: str) -> dict:
    """Parse and validate a DIDComm v2 message envelope."""
    marty_rs = get_marty_rs()
    return json.loads(marty_rs.didcomm_unpack_message(message_json))


def didcomm_encrypt(plaintext_json: str, recipient_did_document: dict) -> str:
    """Encrypt a DIDComm v2 plaintext message for a recipient (anoncrypt).

    Uses ECDH-ES+A256KW key agreement with AES-256-GCM content encryption.
    The recipient's X25519 key agreement key is extracted from their DID Document.

    Returns JWE JSON Serialization string.
    """
    marty_rs = get_marty_rs()
    return marty_rs.didcomm_encrypt(plaintext_json, json.dumps(recipient_did_document))


def didcomm_decrypt(jwe_json: str, recipient_x25519_private_key: bytes) -> dict:
    """Decrypt a DIDComm v2 JWE (anoncrypt) using the recipient's X25519 private key.

    Returns the decrypted DIDComm plaintext message as a dict.
    """
    marty_rs = get_marty_rs()
    plaintext = marty_rs.didcomm_decrypt(jwe_json, recipient_x25519_private_key)
    return json.loads(plaintext)


# ---------------------------------------------------------------------------
# mDoc BYOK (Bring Your Own Key) — prepare → external sign → assemble
# ---------------------------------------------------------------------------

async def create_mdoc_credential_byok(
    doc_type: str,
    namespaces: dict,
    validity: dict,
    kms_sign_fn,
    device_key_der: bytes | None = None,
    issuer_certificate_chain_pem: str | None = None,
    digest_algorithm: str | None = None,
) -> bytes:
    """Create an mDoc credential using remote/HSM signing (BYOK pattern).

    Follows the prepare → external sign → assemble pattern:
    1. Rust prepares the mDoc and returns the to-be-signed (TBS) bytes
    2. The caller-supplied ``kms_sign_fn`` signs the TBS bytes externally
    3. Rust completes the mDoc with the external signature

    Args:
        doc_type: mDoc document type (e.g. ``org.iso.18013.5.1.mDL``)
        namespaces: Dict of namespace → {claim_name: claim_value}
        validity: Dict with ``signed``, ``valid_from``, ``valid_until`` ISO timestamps
        kms_sign_fn: Async callable ``(bytes) -> bytes`` that returns a DER-encoded
            ECDSA signature from the remote KMS/HSM.
        device_key_der: Optional DER-encoded device public key
        issuer_certificate_chain_pem: Reserved for future X.509 chain injection
            (requires Rust-side support in the COSE_Sign1 unprotected header).
        digest_algorithm: Hash algorithm for MSO digests (default: SHA-256)

    Returns:
        CBOR-encoded mDoc credential bytes (DeviceResponse format)
    """
    marty_rs = get_marty_rs()

    # Step 1: Prepare — Rust builds the unsigned mDoc and returns TBS data
    prepared = marty_rs.prepare_mdoc_for_hsm(
        doc_type,
        namespaces,
        validity,
        device_key_der,
        digest_algorithm,
    )

    tbs_data = prepared.get_tbs_data()
    logger.info(
        "Prepared mDoc for HSM signing (doc_type=%s, tbs_size=%d)",
        doc_type, len(tbs_data),
    )

    # Step 2: Sign — external KMS/HSM signs the TBS bytes
    signature_der = await kms_sign_fn(tbs_data)

    # Step 3: Assemble — Rust completes the mDoc with the external signature
    cbor_bytes = marty_rs.complete_mdoc_with_signature(prepared, signature_der)

    logger.info(
        "Completed mDoc BYOK issuance (doc_type=%s, cbor_size=%d)",
        doc_type, len(cbor_bytes),
    )

    return bytes(cbor_bytes)
