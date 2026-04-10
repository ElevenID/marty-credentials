"""Rust integration for credential signing operations."""

import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from issuance.infrastructure.models import issuer_signing_keys_table
from status_list.infrastructure.security.encryption import SymmetricEncryption

logger = logging.getLogger(__name__)

_ephemeral_key_warning_logged = False
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
# X.509 / SD-JWT EUDI compliance helpers
# ---------------------------------------------------------------------------

# Cached per-organization: {"private_key": EC key, "x5c_b64": str}
_org_eudi_keys: dict = {}


def postprocess_sd_jwt_x5c(
    sd_jwt_compact: str,
    key_info: dict,
    organization_id: str,
    issuer_url: str,
) -> str:
    """Re-sign an SD-JWT with P-256/ES256 + X.509 cert for EUDI compliance.

    The EUDI reference verifier only supports X.509 certificate-based
    verification with P-256/ES256 (the JVM crypto stack doesn't support
    Ed25519 in X.509 certificates).

    This function post-processes an SD-JWT produced by the Rust signer to:

    1. Replace ``iss`` (and ``issuer``) with the HTTPS *issuer_url*.
    2. Switch ``alg`` from ``EdDSA`` to ``ES256`` (P-256).
    3. Add an ``x5c`` header containing a self-signed P-256 X.509 certificate.
    4. Remove ``kid`` (X.509 verification takes precedence).
    5. Re-sign the JWS with the P-256 private key.

    A P-256 key pair and self-signed cert are generated once per org and cached.
    """
    eudi_key = _get_or_generate_eudi_key(organization_id)

    # Split SD-JWT: JWS~disc1~disc2~
    first_tilde = sd_jwt_compact.find("~")
    if first_tilde == -1:
        logger.warning("SD-JWT has no disclosures separator, skipping x5c injection")
        return sd_jwt_compact
    jws = sd_jwt_compact[:first_tilde]
    disclosures_tail = sd_jwt_compact[first_tilde:]  # includes leading ~

    # Split JWS: header.payload.signature
    jws_parts = jws.split(".")
    if len(jws_parts) != 3:
        logger.warning("Malformed SD-JWT JWS (%d parts), skipping x5c injection", len(jws_parts))
        return sd_jwt_compact

    # Decode and modify header
    header = json.loads(base64url_decode(jws_parts[0]))
    header["alg"] = "ES256"
    header["typ"] = "dc+sd-jwt"
    header["x5c"] = [eudi_key["x5c_b64"]]
    header.pop("kid", None)

    # Decode and modify payload: replace iss with HTTPS URL
    payload = json.loads(base64url_decode(jws_parts[1]))
    payload["iss"] = issuer_url
    if "issuer" in payload:
        payload["issuer"] = issuer_url

    # Add cnf (confirmation) claim for holder key binding.
    # The EUDI verifier requires cnf to verify the KB-JWT signature.
    # Extract the holder's public JWK from the did:jwk:... sub claim.
    if "cnf" not in payload:
        sub = payload.get("sub", "")
        cs_sub = None
        # Check credentialSubject.id as well
        if not sub:
            cs = payload.get("credentialSubject", {})
            cs_sub = cs.get("id", "") if isinstance(cs, dict) else ""
            sub = cs_sub or ""
        if sub.startswith("did:jwk:"):
            try:
                jwk_b64 = sub[len("did:jwk:"):]
                holder_jwk = json.loads(base64url_decode(jwk_b64))
                # Strip private key parameters, keep only public
                holder_jwk.pop("d", None)
                payload["cnf"] = {"jwk": holder_jwk}
            except Exception as e:
                logger.warning("Failed to extract holder JWK from sub %r: %s", sub[:40], e)

    # Re-encode header and payload
    new_header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    # Re-sign with ES256 (P-256)
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    signing_input = f"{new_header_b64}.{new_payload_b64}".encode("ascii")
    der_sig = eudi_key["private_key"].sign(
        signing_input, ec.ECDSA(eudi_key["hash_alg"]()),
    )
    # Convert DER-encoded ECDSA signature to raw R||S (64 bytes for P-256)
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_b64 = base64url_encode(raw_sig)

    return f"{new_header_b64}.{new_payload_b64}.{sig_b64}{disclosures_tail}"


def _get_or_generate_eudi_key(organization_id: str) -> dict:
    """Get or generate a P-256 key + self-signed X.509 cert for EUDI SD-JWT.

    Returns dict with 'private_key' (EC key), 'x5c_b64' (base64 DER cert),
    and 'hash_alg' (hash algorithm class for ECDSA).
    """
    if organization_id in _org_eudi_keys:
        return _org_eudi_keys[organization_id]

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from datetime import datetime as _dt, timedelta as _td

    # Generate P-256 key pair
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Self-signed X.509 certificate
    subject = issuer_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"Marty Issuer {organization_id}"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.utcnow())
        .not_valid_after(_dt.utcnow() + _td(days=365))
        .sign(private_key, hashes.SHA256())
    )
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    x5c_b64 = base64.b64encode(der_bytes).decode("ascii")

    result = {
        "private_key": private_key,
        "x5c_b64": x5c_b64,
        "hash_alg": hashes.SHA256,
    }
    _org_eudi_keys[organization_id] = result
    logger.info("Generated P-256 EUDI signing key + X.509 cert for org %r", organization_id)
    return result


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


def _warn_ephemeral_key_storage() -> None:
    """Warn once when falling back to in-process issuer key storage."""
    global _ephemeral_key_warning_logged
    if _ephemeral_key_warning_logged:
        return
    _ephemeral_key_warning_logged = True
    logger.warning(
        "Using in-process issuer key storage; keys are not persisted and will rotate on restart. "
        "Configure database-backed or KMS-backed key storage for production deployments."
    )


def _enforce_non_ephemeral_keys_in_production() -> None:
    """Block ephemeral issuer keys in production unless explicitly allowed."""
    environment = os.environ.get("MARTY_ENVIRONMENT") or os.environ.get("ENVIRONMENT") or ""
    allow_ephemeral = os.environ.get("ALLOW_EPHEMERAL_ISSUER_KEYS", "false").lower() == "true"
    if environment.lower() == "production" and not allow_ephemeral and not _persistent_key_store_available():
        raise RuntimeError(
            "Ephemeral issuer key storage is disabled in production. "
            "Configure ISSUER_KEY_MASTER_KEY for database-backed key storage or set "
            "ALLOW_EPHEMERAL_ISSUER_KEYS=true as a temporary override."
        )


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
    """Get or generate an Ed25519 signing key for an organization.

    Prefers database-backed encrypted storage when configured via
    ``ISSUER_KEY_MASTER_KEY`` and the service session factory. Falls back to the
    in-process cache only in non-production environments.

    Returns:
        dict with 'did' (did:key:z6Mk...), 'private_key' (bytes), 'public_key' (bytes)
    """
    global _org_keys
    if organization_id in _org_keys:
        return _org_keys[organization_id]

    persisted_key = await _load_persisted_issuer_key(organization_id)
    if persisted_key is not None:
        return persisted_key

    _enforce_non_ephemeral_keys_in_production()

    marty_rs = get_marty_rs()
    private_key, public_key = marty_rs.generate_ed25519_key()
    pub_bytes = bytes(public_key)
    did = _did_key_from_ed25519(pub_bytes)

    key_info = {
        "did": did,
        "private_key": bytes(private_key),
        "public_key": pub_bytes,
        # OKP/Ed25519 JWK — used by the Rust OID4VCI signing engine.
        # d = base64url(private_seed_32_bytes), x = base64url(public_32_bytes)
        "jwk_json": json.dumps({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64url_encode(pub_bytes),
            "d": base64url_encode(bytes(private_key)),
        }),
    }

    if _persistent_key_store_available():
        await _save_persisted_issuer_key(organization_id, key_info)
    else:
        _warn_ephemeral_key_storage()

    _org_keys[organization_id] = key_info
    logger.info(f"Generated Ed25519 issuer key for org {organization_id!r}: {did}")
    return key_info


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
    marty-oid4vci engine. Supports jwt_vc_json, vc+sd-jwt, mso_mdoc, and
    zk_mdoc formats.
    """
    signing_jwk_json = issuer_jwk_json.strip() if issuer_jwk_json else ""
    if signing_jwk_json in ("", "{}"):
        issuer_key = next(
            (k for k in _org_keys.values() if k["did"] == issuer_did), None
        )
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
