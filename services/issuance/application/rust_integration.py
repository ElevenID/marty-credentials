"""Rust integration for credential signing operations."""

import base64
import json
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


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


# base64url_decode removed — PKCE verification now delegated to Rust.


# ---------------------------------------------------------------------------
# Issuer key management
# ---------------------------------------------------------------------------

# In-process cache so every credential for the same org has the same issuer DID.
# In production this should be backed by the database / a KMS.
_org_keys: dict = {}


def get_marty_rs():
    """Import Rust bindings for credential operations.

    Raises:
        ImportError: If marty-rs bindings are not available.
    """
    try:
        import _marty_rs
        return _marty_rs
    except ImportError as e:
        logger.error("marty-rs bindings not available - credential signing will fail")
        raise ImportError(
            "marty-rs Python bindings are required for credential signing. "
            "Ensure the marty-bindings crate is built and installed."
        ) from e


def get_or_generate_issuer_key(organization_id: str = "default") -> dict:
    """Get or generate an Ed25519 signing key for an organization.

    The key is cached in-process so every credential for the same org is
    signed under the same did:key DID.  The DID is self-describing
    (the public key is encoded inside it), so wallets can verify the
    credential signature without any network resolution call.

    Returns:
        dict with 'did' (did:key:z6Mk...), 'private_key' (bytes), 'public_key' (bytes)
    """
    global _org_keys
    if organization_id in _org_keys:
        return _org_keys[organization_id]

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
    _org_keys[organization_id] = key_info
    logger.info(f"Generated Ed25519 issuer key for org {organization_id!r}: {did}")
    return key_info


def create_verifiable_credential_wrapper(
    issuer_did: str,
    issuer_jwk_json: str,  # Not used - kept for API compatibility
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

    Looks up the signing key for `issuer_did` from the in-process cache and
    delegates format-aware signing entirely to the Rust marty-oid4vci engine.
    Supports jwt_vc_json, vc+sd-jwt, mso_mdoc, and zk_mdoc formats.
    """
    # Find the private key whose DID matches issuer_did.  Fall back to
    # org_id lookup if the DID isn't cached yet.
    issuer_key = next(
        (k for k in _org_keys.values() if k["did"] == issuer_did), None
    )
    if issuer_key is None:
        # Pre-populate the cache via org_id lookup and try again
        if not organization_id:
            raise RuntimeError(
                "organization_id is required to look up the issuer key. "
                "Pass the caller's organization_id explicitly."
            )
        get_or_generate_issuer_key(organization_id)
        issuer_key = next(
            (k for k in _org_keys.values() if k["did"] == issuer_did), None
        )
    if issuer_key is None:
        raise RuntimeError(
            f"No signing key cached for issuer DID {issuer_did!r}. "
            "Call get_or_generate_issuer_key(org_id) before issuing a credential."
        )

    marty_rs = get_marty_rs()
    result = marty_rs.oid4vci_sign_credential(
        issuer_did,
        issuer_key["jwk_json"],
        subject_id or None,
        credential_type,
        claims_json,
        expiration_seconds,
        format,
        selective_disclosure_claims or [],
        zk_predicate_claims or [],
        credential_payload_format,
    )

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
