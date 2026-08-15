"""Rust integration for credential signing operations."""

import base64
import json
import logging
import os
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from marty_credentials.native_backend import NativeOperationError, require_marty_rs

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
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(data: str) -> bytes:
    """Decode base64url string with optional omitted padding."""
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


# base64url_decode removed — PKCE verification now delegated to Rust.


def get_marty_rs():
    """Import Rust bindings for credential operations.

    Raises:
        ImportError: If marty-rs bindings are not available.
    """
    return require_marty_rs()


REQUIRED_MARTY_RS_CAPABILITIES = frozenset(
    {
        "canvas_normalize_base_url",
        "canvas_probe_lti_platform",
        "complete_vcdm_data_integrity_credential",
        "didcomm_decrypt",
        "didcomm_encrypt",
        "didcomm_encrypt_authcrypt",
        "didcomm_extract_endpoint",
        "didcomm_pack_credential",
        "didcomm_resolve_did",
        "didcomm_unpack_message",
        "evidence_reconciliation_plan",
        "evidence_reconciliation_stale_reasons",
        "lti_verify_launch_jwt",
        "key_attestation_policy",
        "key_attestation_route_proof",
        "key_attestation_validate",
        "key_attestation_validate_status_reference",
        "key_attestation_validate_status_token",
        # mDoc issuance never loads an issuer private key into this service.
        # It requires the authoritative marty-core prepare/sign/assemble split
        # so the KMS signs the exact COSE payload remotely.
        "oid4vci_prepare_mdoc",
        "oid4vci_normalize_ecdsa_signature",
        "oid4vci_assemble_mdoc",
        "oid4vci_prepare_sd_jwt",
        "oid4vci_assemble_sd_jwt",
        "oid4vci_prepare_jwt_vc",
        "oid4vci_prepare_open_badge_v3_jwt_vc",
        "oid4vci_assemble_jwt_vc",
        "oid4vci_create_authorization_response",
        "oid4vci_create_credential_offer",
        "oid4vci_create_token_response",
        "oid4vci_exchange_auth_code_for_token",
        "oid4vci_verify_pkce_s256",
        "oid4vci_verify_proof_jwt",
        "oid4vci_verify_key_attestation_bound_proof_jwt",
        "oid4vci_verify_compact_jwt",
        "oid4vci_verify_detached_signature",
        "prepare_vcdm_data_integrity_credential",
        "validate_vcdm_issuance_document",
        "validate_vcdm_related_resource_digests",
        "current_evidence_heads",
        "evaluate_application_evidence_policy",
    }
)


def validate_marty_rs_capabilities() -> None:
    """Fail startup when the deployed native extension is not service-compatible."""
    marty_rs = get_marty_rs()
    missing = sorted(
        capability
        for capability in REQUIRED_MARTY_RS_CAPABILITIES
        if not callable(getattr(marty_rs, capability, None))
    )
    if missing:
        from marty_credentials.native_backend import NativeBackendUnavailable

        raise NativeBackendUnavailable(
            "marty-rs native extension is missing required capabilities: " + ", ".join(missing)
        )


def _json_dumps_compact(value: Any) -> str:
    # ensure_ascii=True produces ASCII-safe JSON (non-ASCII escaped as \\uXXXX),
    # matching serde_json default serialization used by sd-jwt-rs and other Rust JWT libs.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


async def create_sd_jwt_vc_with_remote_signing(
    *,
    issuer_did: str,
    remote_sign: Callable[[bytes, str | None], Awaitable[dict[str, Any]]],
    subject_id: str | None,
    holder_jwk: dict[str, Any] | None = None,
    credential_type: str,
    claims_json: str,
    expiration_seconds: int = 31536000,
    selective_disclosure_claims: list[str] | None = None,
    algorithm: str | None = None,
    verification_method_id: str,
    credential_format: str | None = None,
    credential_id: str | None = None,
    issuer_certificate_chain: list[str] | None = None,
) -> tuple[str, str]:
    """Create an SD-JWT VC using the selected issuer profile's DID signer.

    Args:
        credential_format: OID4VCI format string (for example, ``"dc+sd-jwt"``)
        used in the credential response metadata and JWT ``typ`` header.
    """
    claims = json.loads(claims_json or "{}")
    if not isinstance(claims, dict):
        raise RuntimeError("claims_json must encode an object")
    if not isinstance(verification_method_id, str) or not verification_method_id.startswith(
        f"{issuer_did}#"
    ):
        raise RuntimeError(
            "verification_method_id must identify a key controlled by the issuer DID"
        )

    expected_algorithm = algorithm or "ES256"
    binding = get_marty_rs()
    try:
        prepared = binding.oid4vci_prepare_sd_jwt(
            issuer_did,
            verification_method_id,
            expected_algorithm,
            subject_id,
            credential_type,
            json.dumps(claims),
            int(expiration_seconds or 31536000),
            list(selective_disclosure_claims or []),
            credential_format,
            credential_id,
            json.dumps(holder_jwk) if holder_jwk is not None else None,
            list(issuer_certificate_chain or []),
        )
    except (RuntimeError, TypeError, ValueError) as exc:
        raise NativeOperationError(f"Native SD-JWT preparation failed: {exc}") from exc

    sign_result = await remote_sign(prepared.signing_input.encode("ascii"), algorithm)
    response_algorithm = sign_result.get("algorithm")
    signature_b64 = sign_result.get("signature_raw_b64") or sign_result.get("signature_b64")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise RuntimeError("Issuer-profile signer returned no usable JWS signature")

    if response_algorithm and response_algorithm != expected_algorithm:
        logger.debug(
            "Remote signer returned algorithm %s for requested %s",
            response_algorithm,
            expected_algorithm,
        )
    try:
        return binding.oid4vci_assemble_sd_jwt(prepared, signature_b64)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise NativeOperationError(f"Native SD-JWT assembly failed: {exc}") from exc


async def create_jwt_vc_with_remote_signing(
    *,
    issuer_did: str,
    remote_sign: Callable[[bytes, str | None], Awaitable[dict[str, Any]]],
    subject_id: str | None,
    credential_type: str,
    claims_json: str,
    credential_subject: dict[str, Any] | list[dict[str, Any]] | None = None,
    expiration_seconds: int = 31536000,
    algorithm: str | None = None,
    verification_method_id: str,
    credential_id: str | None = None,
    credential_profile: str | None = None,
    achievement_id: str | None = None,
) -> tuple[str, str]:
    """Create a VCDM v2 JWT VC using the selected issuer profile's DID signer.

    This is intentionally parallel to ``create_sd_jwt_vc_with_remote_signing``:
    the issuer private key never enters the service process.  ``vc+jwt`` is a
    JWS representation, not a COSE/VDS format, so the existing remote JWS
    signature contract is sufficient.
    """
    claims = json.loads(claims_json or "{}")
    if not isinstance(claims, dict):
        raise RuntimeError("claims_json must encode an object")
    if not isinstance(verification_method_id, str) or not verification_method_id.startswith(
        f"{issuer_did}#"
    ):
        raise RuntimeError(
            "verification_method_id must identify a key controlled by the issuer DID"
        )

    expected_algorithm = algorithm or "ES256"
    binding = get_marty_rs()
    try:
        prepare_args = (
            issuer_did,
            verification_method_id,
            expected_algorithm,
            subject_id,
            credential_type,
            json.dumps(claims),
            int(expiration_seconds or 31536000),
            credential_id,
            json.dumps(credential_subject) if credential_subject is not None else None,
        )
        if credential_profile is None and achievement_id is None:
            prepared = binding.oid4vci_prepare_jwt_vc(*prepare_args)
        elif credential_profile == "open_badge_v3" and achievement_id:
            prepared = binding.oid4vci_prepare_open_badge_v3_jwt_vc(
                *prepare_args,
                achievement_id=achievement_id,
            )
        elif credential_profile == "open_badge_v3":
            raise ValueError("open_badge_v3 profile requires achievement_id")
        elif credential_profile is None:
            raise ValueError(
                "achievement_id is only valid with the open_badge_v3 profile"
            )
        else:
            raise ValueError(f"Unsupported JWT-VC credential profile: {credential_profile}")
    except (RuntimeError, TypeError, ValueError) as exc:
        raise NativeOperationError(f"Native JWT-VC preparation failed: {exc}") from exc

    sign_result = await remote_sign(prepared.signing_input.encode("ascii"), algorithm)
    signature_b64 = sign_result.get("signature_raw_b64") or sign_result.get("signature_b64")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise RuntimeError("Issuer-profile signer returned no usable JWS signature")
    try:
        return binding.oid4vci_assemble_jwt_vc(prepared, signature_b64)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise NativeOperationError(f"Native JWT-VC assembly failed: {exc}") from exc


_PRIVATE_JWK_MEMBERS = frozenset(
    {
        "d",
        "p",
        "q",
        "dp",
        "dq",
        "qi",
        "oth",
        "k",
    }
)
_VCDM_CONTEXT = "https://www.w3.org/ns/credentials/v2"
_VCDM_PROTECTED_TERMS = frozenset(
    {
        "@context",
        "credentialSchema",
        "credentialStatus",
        "credentialSubject",
        "description",
        "digestMultibase",
        "digestSRI",
        "evidence",
        "id",
        "issuer",
        "name",
        "proof",
        "refreshService",
        "relatedResource",
        "termsOfUse",
        "type",
        "validFrom",
        "validUntil",
    }
)


def _json_ld_term_name(value: str) -> str:
    """Return a stable, collision-resistant IRI for a product claim term."""
    return f"https://credentials.marty.dev/claims/{base64url_encode(value.encode('utf-8'))}"


def _collect_json_ld_terms(value: Any, terms: set[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                isinstance(key, str)
                and key
                and not key.startswith("@")
                and key not in _VCDM_PROTECTED_TERMS
            ):
                terms.add(key)
            _collect_json_ld_terms(child, terms)
    elif isinstance(value, list):
        for child in value:
            _collect_json_ld_terms(child, terms)


def _data_integrity_context(
    subject: dict[str, Any] | list[dict[str, Any]],
    credential_type: str,
) -> list[Any]:
    """Build deterministic JSON-LD semantics for template-defined product claims."""
    terms: set[str] = set()
    _collect_json_ld_terms(subject, terms)
    if ":" not in credential_type and credential_type != "VerifiableCredential":
        terms.add(credential_type)
    if not terms:
        return [_VCDM_CONTEXT]
    return [
        _VCDM_CONTEXT,
        {term: _json_ld_term_name(term) for term in sorted(terms)},
    ]


def _public_ed25519_jwk(
    public_jwk: dict[str, Any],
    verification_method_id: str,
) -> dict[str, Any]:
    if not isinstance(public_jwk, dict):
        raise RuntimeError("issuer DID resolution returned no public JWK")
    private_members = sorted(_PRIVATE_JWK_MEMBERS.intersection(public_jwk))
    if private_members:
        raise RuntimeError(
            "issuer DID resolution exposed prohibited private JWK members: "
            + ", ".join(private_members)
        )
    if (
        public_jwk.get("kty") != "OKP"
        or public_jwk.get("crv") != "Ed25519"
        or not isinstance(public_jwk.get("x"), str)
        or not public_jwk["x"]
    ):
        raise RuntimeError("eddsa-rdfc-2022 requires an Ed25519 public JWK from the issuer profile")
    kid = public_jwk.get("kid")
    if kid is not None and kid != verification_method_id:
        raise RuntimeError("issuer public JWK kid does not match the DID verification method")
    return dict(public_jwk)


async def create_vcdm_data_integrity_with_remote_signing(
    *,
    issuer_did: str,
    remote_sign: Callable[[bytes, str | None], Awaitable[dict[str, Any]]],
    subject_id: str | None,
    credential_type: str,
    claims_json: str,
    public_jwk: dict[str, Any],
    credential_subject: dict[str, Any] | list[dict[str, Any]] | None = None,
    credential_document: dict[str, Any] | None = None,
    expiration_seconds: int = 31536000,
    verification_method_id: str,
    credential_id: str | None = None,
) -> tuple[str, str]:
    """Create a native VCDM v2 Data Integrity credential via issuer-DID signing.

    Marty-core owns JSON-LD canonicalization and final proof verification. This
    service supplies only public DID material to that engine and sends the
    resulting canonical bytes through the organization-scoped DID signer.
    """
    if not isinstance(issuer_did, str) or not issuer_did.startswith("did:"):
        raise RuntimeError("issuer_did must be a DID")
    if not isinstance(verification_method_id, str) or not verification_method_id.startswith(
        f"{issuer_did}#"
    ):
        raise RuntimeError(
            "verification_method_id must identify a key controlled by the issuer DID"
        )
    resolved_public_jwk = _public_ed25519_jwk(public_jwk, verification_method_id)
    claims = json.loads(claims_json or "{}")
    if not isinstance(claims, dict):
        raise RuntimeError("claims_json must encode an object")

    credential_id = credential_id or f"urn:uuid:{uuid.uuid4()}"
    credential_status = claims.pop("credentialStatus", None)
    if credential_document is not None:
        if credential_subject is not None or claims:
            raise RuntimeError("credential_document cannot be combined with subject claims")
        # JSON round-tripping gives the signing engine a private, JSON-only
        # document snapshot and prevents caller mutation during async signing.
        credential = json.loads(_json_dumps_compact(credential_document))
        if not isinstance(credential, dict) or not credential:
            raise RuntimeError("credential_document must be a non-empty object")
        if "proof" in credential:
            raise RuntimeError("credential_document must be unsigned")
        context = credential.get("@context")
        if not isinstance(context, list) or not context or context[0] != _VCDM_CONTEXT:
            raise RuntimeError("credential_document must use the VCDM v2 base context first")
        credential_types = credential.get("type")
        credential_types = (
            credential_types if isinstance(credential_types, list) else [credential_types]
        )
        if "VerifiableCredential" not in credential_types:
            raise RuntimeError("credential_document type must include VerifiableCredential")
        subject = credential.get("credentialSubject")
        subject_values = subject if isinstance(subject, list) else [subject]
        if not subject_values or not all(
            isinstance(item, dict) and item for item in subject_values
        ):
            raise RuntimeError("credential_document must contain a non-empty credentialSubject")
        document_issuer = credential.get("issuer")
        document_issuer_id = (
            document_issuer.get("id") if isinstance(document_issuer, dict) else document_issuer
        )
        if document_issuer_id is None:
            credential["issuer"] = issuer_did
        elif document_issuer_id != issuer_did:
            raise RuntimeError("credential_document issuer does not match the resolved issuer DID")
        document_id = credential.get("id")
        if document_id is None:
            credential["id"] = credential_id
        elif document_id != credential_id:
            raise RuntimeError("credential_document id does not match the reserved credential ID")
        now = datetime.now(UTC)
        credential.setdefault("validFrom", now.isoformat().replace("+00:00", "Z"))
        credential.setdefault(
            "validUntil",
            datetime.fromtimestamp(
                now.timestamp() + int(expiration_seconds or 31536000),
                UTC,
            )
            .isoformat()
            .replace("+00:00", "Z"),
        )
        if credential_status is not None:
            if not isinstance(credential_status, (dict, list)):
                raise RuntimeError("credentialStatus must be an object or list")
            credential["credentialStatus"] = credential_status
    elif credential_subject is None:
        subject: dict[str, Any] | list[dict[str, Any]] = dict(claims)
        if subject_id:
            subject.setdefault("id", subject_id)
    else:
        if claims:
            raise RuntimeError("explicit credential_subject cannot be combined with subject claims")
        if isinstance(credential_subject, dict) and credential_subject:
            subject = dict(credential_subject)
        elif (
            isinstance(credential_subject, list)
            and credential_subject
            and all(isinstance(item, dict) and item for item in credential_subject)
        ):
            subject = [dict(item) for item in credential_subject]
        else:
            raise RuntimeError(
                "credential_subject must be a non-empty object or list of non-empty objects"
            )

    if credential_document is None:
        now = datetime.now(UTC)
        types = ["VerifiableCredential"]
        if credential_type and credential_type != "VerifiableCredential":
            types.append(credential_type)
        credential = {
            "@context": _data_integrity_context(subject, credential_type),
            "id": credential_id,
            "type": types,
            "issuer": issuer_did,
            "validFrom": now.isoformat().replace("+00:00", "Z"),
            "validUntil": datetime.fromtimestamp(
                now.timestamp() + int(expiration_seconds or 31536000),
                UTC,
            )
            .isoformat()
            .replace("+00:00", "Z"),
            "credentialSubject": subject,
        }
        if credential_status is not None:
            if not isinstance(credential_status, (dict, list)):
                raise RuntimeError("credentialStatus must be an object or list")
            credential["credentialStatus"] = credential_status

    binding = get_marty_rs()
    prepared_json = binding.prepare_vcdm_data_integrity_credential(
        _json_dumps_compact(
            {
                "credential": credential,
                "issuer_did": issuer_did,
                "verification_method_id": verification_method_id,
                "public_jwk": resolved_public_jwk,
            }
        )
    )
    prepared = json.loads(prepared_json)
    if not isinstance(prepared, dict) or prepared.get("algorithm") != "EdDSA":
        raise RuntimeError("Marty Data Integrity engine returned an invalid signing request")
    signing_input_b64 = prepared.get("signing_input_b64")
    if not isinstance(signing_input_b64, str) or not signing_input_b64:
        raise RuntimeError("Marty Data Integrity engine returned no canonical signing input")

    sign_result = await remote_sign(base64url_decode(signing_input_b64), "EdDSA")
    response_algorithm = sign_result.get("algorithm")
    if response_algorithm and response_algorithm != "EdDSA":
        raise RuntimeError("issuer-DID signer returned a different signing algorithm")
    signature_b64 = sign_result.get("signature_raw_b64") or sign_result.get("signature_b64")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise RuntimeError("issuer-DID signer returned no usable EdDSA signature")

    completed_json = binding.complete_vcdm_data_integrity_credential(
        _json_dumps_compact(
            {
                "prepared": prepared,
                "signature_b64": signature_b64,
            }
        )
    )
    completed = json.loads(completed_json)
    completed_issuer = completed.get("issuer") if isinstance(completed, dict) else None
    completed_issuer_id = (
        completed_issuer.get("id") if isinstance(completed_issuer, dict) else completed_issuer
    )
    if (
        not isinstance(completed, dict)
        or completed.get("id") != credential_id
        or completed_issuer_id != issuer_did
        or not isinstance(completed.get("proof"), dict)
        or completed["proof"].get("cryptosuite") != "eddsa-rdfc-2022"
        or completed["proof"].get("verificationMethod") != verification_method_id
    ):
        raise RuntimeError("completed Data Integrity credential changed its signed identity")
    return _json_dumps_compact(completed), credential_id


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
        issuer_url,
        credential_types,
        pre_authorized_code,
        user_pin_required,
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
        pre_authorized_code,
        token_lifetime_secs,
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
        request_json,
        session_lifetime_secs,
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
        request_json,
        session_json,
        token_lifetime_secs,
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
) -> tuple[bool, str, dict[str, Any] | None, str | None]:
    """Verify an OID4VCI proof JWT via Rust (full OID4VCI §8.2 verification).

    Delegates entirely to marty_rs.oid4vci_verify_proof_jwt which performs:
      - JWT structure and typ header validation
      - Cryptographic signature verification (Ed25519 / P-256)
      - did:key resolution from kid header — no network I/O
      - nonce claim match (when expected_nonce is provided)
      - aud / iat / exp validation

    Returns:
      (ok: bool, holder_did: str, holder_public_jwk: dict | None, error: str | None)
    """
    try:
        marty_rs = get_marty_rs()
        holder_did, _nonce, holder_jwk_json = marty_rs.oid4vci_verify_proof_jwt(
            proof_jwt,
            expected_nonce,
            issuer_url,
        )
        holder_jwk = json.loads(holder_jwk_json) if holder_jwk_json else None
        return True, holder_did, holder_jwk, None
    except RuntimeError as e:
        return False, "", None, str(e)
    except Exception as e:
        return False, "", None, f"proof JWT error: {e}"


def verify_key_attestation_bound_proof_jwt(
    proof_jwt: str,
    validated_key_attestation_jwt: str,
    expected_nonce: str | None,
    issuer_url: str | None = None,
) -> tuple[bool, str, dict[str, Any] | None, str | None]:
    """Verify a proof against the exact product-validated key attestation.

    Certificate, assurance, status, and tenant policy are validated by the
    issuance application before this call.  Marty Core independently parses
    the same compact attestation, selects the numeric ``kid`` entry, and
    cryptographically binds the proof signature to that attested public key.
    """
    try:
        marty_rs = get_marty_rs()
        holder_did, _nonce, holder_jwk_json = (
            marty_rs.oid4vci_verify_key_attestation_bound_proof_jwt(
                proof_jwt,
                validated_key_attestation_jwt,
                expected_nonce,
                issuer_url,
            )
        )
        holder_jwk = json.loads(holder_jwk_json) if holder_jwk_json else None
        return True, holder_did, holder_jwk, None
    except RuntimeError as e:
        return False, "", None, str(e)
    except Exception as e:
        return False, "", None, f"key-attestation-bound proof JWT error: {e}"


def verify_compact_jwt(
    compact_jwt: str,
    public_jwk: dict[str, Any],
    expected_algorithm: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify a compact JWT signature through the canonical Rust backend."""
    marty_rs = get_marty_rs()
    try:
        header_json, claims_json = marty_rs.oid4vci_verify_compact_jwt(
            compact_jwt,
            json.dumps(public_jwk, separators=(",", ":"), sort_keys=True),
            expected_algorithm,
        )
        header = json.loads(header_json)
        claims = json.loads(claims_json)
    except (RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise NativeOperationError("compact JWT verification failed") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise NativeOperationError("native compact JWT verification returned invalid JSON")
    return header, claims


def verify_detached_signature(
    message: bytes,
    signature: bytes,
    public_jwk: Mapping[str, Any],
    expected_algorithm: str,
) -> bool:
    """Verify a provider/KMS signature through the canonical Rust backend."""
    marty_rs = get_marty_rs()
    try:
        return bool(
            marty_rs.oid4vci_verify_detached_signature(
                message,
                signature,
                json.dumps(dict(public_jwk), separators=(",", ":"), sort_keys=True),
                expected_algorithm,
            )
        )
    except (RuntimeError, TypeError, ValueError) as exc:
        raise NativeOperationError("detached signature verification failed") from exc


def normalize_ecdsa_signature(signature: bytes, expected_algorithm: str) -> bytes:
    """Normalize a provider ECDSA signature in the canonical Rust backend."""
    marty_rs = get_marty_rs()
    try:
        return bytes(
            marty_rs.oid4vci_normalize_ecdsa_signature(signature, expected_algorithm)
        )
    except (RuntimeError, TypeError, ValueError) as exc:
        raise NativeOperationError("ECDSA signature normalization failed") from exc


# ---------------------------------------------------------------------------
# DIDComm v2 Protocol Wrappers (delegate to Rust marty-didcomm crate)
# ---------------------------------------------------------------------------


def didcomm_resolve_did(did: str) -> dict:
    """Resolve a DID to its DID Document via Rust.

    Supports did:key, did:web, did:peer, did:jwk natively.
    Falls back to the deployment-managed Universal Resolver for unknown methods.
    Resolver infrastructure is configuration, never caller-controlled protocol input.
    """
    marty_rs = get_marty_rs()
    resolver_url = (
        os.environ.get("DIDCOMM_UNIVERSAL_RESOLVER_URL", "").strip()
        or os.environ.get("UNIVERSAL_RESOLVER_URL", "").strip()
        or None
    )
    doc_json = marty_rs.didcomm_resolve_did(did, resolver_url)
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
        credential,
        credential_format,
        issuer_did,
        holder_did,
        thread_id,
        credential_id,
    )


def didcomm_unpack_message(message_json: str) -> dict:
    """Parse and validate a DIDComm v2 message envelope."""
    marty_rs = get_marty_rs()
    return json.loads(marty_rs.didcomm_unpack_message(message_json))


def didcomm_encrypt(plaintext_json: str, recipient_did_document: dict) -> str:
    """Encrypt a DIDComm v2 plaintext message for a recipient (anoncrypt).

    Uses the X25519 DIDComm Messaging 2.1 credential-delivery profile with
    ECDH-ES+A256KW key wrapping and required A256CBC-HS512 content encryption.
    The recipient key is extracted from their DID Document.

    Returns JWE JSON Serialization string.
    """
    marty_rs = get_marty_rs()
    return marty_rs.didcomm_encrypt(plaintext_json, json.dumps(recipient_did_document))


def didcomm_encrypt_authcrypt(
    plaintext_json: str,
    sender_did_document: dict,
    sender_x25519_private_key: bytes,
    recipient_did_document: dict,
) -> str:
    """Encrypt and authenticate a DIDComm message through canonical Rust."""

    marty_rs = get_marty_rs()
    return marty_rs.didcomm_encrypt_authcrypt(
        plaintext_json,
        json.dumps(sender_did_document),
        sender_x25519_private_key,
        json.dumps(recipient_did_document),
    )


class DidcommEncryptionPolicyError(RuntimeError):
    """The deployment-managed DIDComm encryption policy is unusable."""


class DidcommAuthcryptError(RuntimeError):
    """Configured authcrypt delivery could not be completed safely."""


@dataclass(frozen=True)
class _DidcommIssuerEncryptionPolicy:
    mode: Literal["anoncrypt", "authcrypt"]
    sender_x25519_private_key: bytes | None = None


_DIDCOMM_POLICY_MAX_BYTES = 64 * 1024
_DIDCOMM_POLICY_MAX_ISSUERS = 1000
_DIDCOMM_POLICY_FIELDS = frozenset({"version", "issuers"})


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise DidcommEncryptionPolicyError(
                "DIDComm encryption policy contains a duplicate JSON member"
            )
        value[key] = member
    return value


def _decode_x25519_private_key(value: Any) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise DidcommEncryptionPolicyError(
            "DIDComm authcrypt private key must be canonical unpadded base64url"
        )
    try:
        encoded = value.encode("ascii")
        padding = b"=" * ((4 - len(encoded) % 4) % 4)
        private_key = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise DidcommEncryptionPolicyError(
            "DIDComm authcrypt private key must be canonical unpadded base64url"
        ) from exc
    if len(private_key) != 32 or base64url_encode(private_key) != value:
        raise DidcommEncryptionPolicyError(
            "DIDComm authcrypt private key must encode exactly 32 bytes"
        )
    return private_key


def _parse_didcomm_issuer_encryption_policy(
    issuer_policy: Any,
) -> _DidcommIssuerEncryptionPolicy:
    if not isinstance(issuer_policy, dict):
        raise DidcommEncryptionPolicyError(
            "DIDComm encryption policy issuer entry must be an object"
        )
    mode = issuer_policy.get("mode")
    if mode == "anoncrypt" and set(issuer_policy) == {"mode"}:
        return _DidcommIssuerEncryptionPolicy(mode="anoncrypt")
    if mode == "authcrypt" and set(issuer_policy) == {
        "mode",
        "sender_x25519_private_key",
    }:
        return _DidcommIssuerEncryptionPolicy(
            mode="authcrypt",
            sender_x25519_private_key=_decode_x25519_private_key(
                issuer_policy["sender_x25519_private_key"]
            ),
        )
    raise DidcommEncryptionPolicyError(
        "DIDComm encryption policy entry has invalid fields or mode"
    )


def _load_didcomm_issuer_encryption_policy(
    issuer_did: str,
) -> _DidcommIssuerEncryptionPolicy:
    policy_path = os.environ.get("DIDCOMM_ENCRYPTION_POLICY_FILE", "").strip()
    if not policy_path:
        return _DidcommIssuerEncryptionPolicy(mode="anoncrypt")

    try:
        with Path(policy_path).open("rb") as policy_file:
            encoded_policy = policy_file.read(_DIDCOMM_POLICY_MAX_BYTES + 1)
    except OSError as exc:
        raise DidcommEncryptionPolicyError(
            "DIDComm encryption policy could not be loaded"
        ) from exc
    if len(encoded_policy) > _DIDCOMM_POLICY_MAX_BYTES:
        raise DidcommEncryptionPolicyError("DIDComm encryption policy exceeds the size limit")

    try:
        policy = json.loads(
            encoded_policy.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except DidcommEncryptionPolicyError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise DidcommEncryptionPolicyError(
            "DIDComm encryption policy is not valid JSON"
        ) from exc

    if not isinstance(policy, dict) or set(policy) != _DIDCOMM_POLICY_FIELDS:
        raise DidcommEncryptionPolicyError(
            "DIDComm encryption policy must contain exactly version and issuers"
        )
    if type(policy["version"]) is not int or policy["version"] != 1:
        raise DidcommEncryptionPolicyError("DIDComm encryption policy version is unsupported")
    issuers = policy["issuers"]
    if not isinstance(issuers, dict) or len(issuers) > _DIDCOMM_POLICY_MAX_ISSUERS:
        raise DidcommEncryptionPolicyError("DIDComm encryption policy issuers are invalid")
    if any(
        not isinstance(configured_did, str)
        or not configured_did.startswith("did:")
        or len(configured_did) > 2048
        for configured_did in issuers
    ):
        raise DidcommEncryptionPolicyError(
            "DIDComm encryption policy contains an invalid issuer DID"
        )

    resolved_policies: dict[str, _DidcommIssuerEncryptionPolicy] = {}
    authcrypt_keys: set[bytes] = set()
    for configured_did, configured_policy in issuers.items():
        resolved_policy = _parse_didcomm_issuer_encryption_policy(configured_policy)
        if resolved_policy.sender_x25519_private_key is not None:
            if resolved_policy.sender_x25519_private_key in authcrypt_keys:
                raise DidcommEncryptionPolicyError(
                    "DIDComm authcrypt private keys must not be reused across issuers"
                )
            authcrypt_keys.add(resolved_policy.sender_x25519_private_key)
        resolved_policies[configured_did] = resolved_policy

    issuer_policy = resolved_policies.get(issuer_did)
    if issuer_policy is None:
        raise DidcommEncryptionPolicyError(
            "DIDComm encryption policy has no entry for the active issuer"
        )
    return issuer_policy


def didcomm_encrypt_delivery(
    plaintext_json: str,
    issuer_did: str,
    recipient_did_document: dict,
) -> str:
    """Apply the deployment's exhaustive per-issuer encryption policy."""

    policy = _load_didcomm_issuer_encryption_policy(issuer_did)
    if policy.mode == "anoncrypt":
        return didcomm_encrypt(plaintext_json, recipient_did_document)

    try:
        sender_did_document = didcomm_resolve_did(issuer_did)
        if policy.sender_x25519_private_key is None:  # Defensive invariant.
            raise DidcommEncryptionPolicyError(
                "DIDComm authcrypt policy is missing sender key material"
            )
        return didcomm_encrypt_authcrypt(
            plaintext_json,
            sender_did_document,
            policy.sender_x25519_private_key,
            recipient_did_document,
        )
    except DidcommEncryptionPolicyError:
        raise
    except Exception as exc:
        raise DidcommAuthcryptError(
            "DIDComm authcrypt encryption failed without fallback"
        ) from exc


def didcomm_decrypt(jwe_json: str, recipient_x25519_private_key: bytes) -> dict:
    """Decrypt a DIDComm v2 JWE (anoncrypt) using the recipient's X25519 private key.

    Returns the decrypted DIDComm plaintext message as a dict.
    """
    marty_rs = get_marty_rs()
    plaintext = marty_rs.didcomm_decrypt(jwe_json, recipient_x25519_private_key)
    return json.loads(plaintext)


# ---------------------------------------------------------------------------
# mDoc issuer-profile signing is implemented by the authoritative marty-core binding.
# ---------------------------------------------------------------------------


async def create_mdoc_credential_with_issuer_profile_signing(
    *,
    issuer_did: str,
    algorithm: str,
    doc_type: str,
    namespace: str,
    claims_json: str,
    expiration_seconds: int,
    credential_id: str,
    holder_jwk: dict[str, Any],
    certificate_chain: list[str] | None,
    profile_sign: Callable[[bytes, str | None], Awaitable[bytes]],
) -> tuple[str, str]:
    """Issue an mDoc through the authoritative issuer-profile split API.

    The PyO3 object preserves the protected COSE header, MSO and issuer-signed
    items between preparation and assembly. The issuer profile signs the exact
    Sig_structure as its DID; KMS remains an implementation detail of profile
    key custody. The holder's proof public key is bound into the MSO for later
    DeviceAuthentication verification; no holder private material is retained.
    Python never synthesizes the final credential state.
    """
    try:
        claims = json.loads(claims_json)
    except json.JSONDecodeError as exc:
        raise ValueError("mDoc claims must be a JSON object") from exc
    if not isinstance(claims, dict):
        raise ValueError("mDoc claims must be a JSON object")
    # Certificate material is issuer-controlled. Never allow a request claim
    # to select the COSE x5chain used to authenticate an mdoc issuer.
    claims.pop("_mdoc_x5c", None)
    if certificate_chain:
        claims["_mdoc_x5c"] = certificate_chain

    marty_rs = get_marty_rs()
    prepared = marty_rs.oid4vci_prepare_mdoc(
        issuer_did,
        algorithm,
        doc_type,
        namespace,
        json.dumps(claims),
        expiration_seconds,
        credential_id,
        json.dumps(
            {
                key: value
                for key, value in holder_jwk.items()
                if key not in {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
            }
        ),
    )
    signature = await profile_sign(bytes(prepared.tbs_data), algorithm)
    credential, credential_id = marty_rs.oid4vci_assemble_mdoc(prepared, signature)
    if not isinstance(credential, str) or not credential:
        raise RuntimeError("marty-rs returned an empty issuer-profile-signed mDoc")
    return credential, credential_id
