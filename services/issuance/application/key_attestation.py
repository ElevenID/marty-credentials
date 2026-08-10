"""Tenant-policy validation for OID4VCI key attestation JWTs."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import socket
import ssl
import zlib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from marty_credentials.native_backend import require_marty_verification

_marty_verification = require_marty_verification(
    (
        "ChainValidator",
        "ValidationConfig",
        "certificate_der_to_pem",
        "get_certificate_public_key",
        "verify_signature",
    )
)


class KeyAttestationError(ValueError):
    """A key attestation or its issuer-profile policy is invalid."""


StatusValidator = Callable[[Mapping[str, Any]], Awaitable[bool]]
ProofVerifier = Callable[
    [str, str | None, str | None],
    tuple[bool, str, dict[str, Any] | None, str | None],
]
BoundProofVerifier = Callable[
    [str, str, str | None, str | None],
    tuple[bool, str, dict[str, Any] | None, str | None],
]


@dataclass(frozen=True)
class KeyAttestationPolicy:
    mode: Literal["disabled", "optional", "required"]
    trusted_root_certificates_pem: tuple[str, ...]
    allowed_algorithms: frozenset[str]
    required_key_storage: frozenset[str]
    required_user_authentication: frozenset[str]
    max_age_seconds: int
    require_nonce: bool
    status_validation: Literal["disabled", "if_present", "required"]
    status_list_allowed_origins: tuple[str, ...]
    status_list_trusted_root_certificates_pem: tuple[str, ...]
    status_list_allowed_algorithms: frozenset[str]
    status_list_max_age_seconds: int
    status_list_allow_private_hosts: bool
    status_list_tls_ca_certificates_pem: tuple[str, ...]

    @classmethod
    def from_issuer_context(
        cls,
        issuer_context: Mapping[str, Any],
        *,
        organization_id: str,
    ) -> KeyAttestationPolicy:
        profile = issuer_context.get("issuer_profile")
        if not isinstance(profile, Mapping):
            raise KeyAttestationError("Resolved issuer context has no issuer profile")
        context_org = str(
            issuer_context.get("organization_id") or profile.get("organization_id") or ""
        ).strip()
        if not context_org or context_org != organization_id:
            raise KeyAttestationError("Issuer-profile key attestation policy is not tenant-bound")
        raw = profile.get("key_attestation_policy")
        if raw is None:
            return cls(
                mode="disabled",
                trusted_root_certificates_pem=(),
                allowed_algorithms=frozenset(),
                required_key_storage=frozenset(),
                required_user_authentication=frozenset(),
                max_age_seconds=300,
                require_nonce=True,
                status_validation="required",
                status_list_allowed_origins=(),
                status_list_trusted_root_certificates_pem=(),
                status_list_allowed_algorithms=frozenset(),
                status_list_max_age_seconds=86400,
                status_list_allow_private_hosts=False,
                status_list_tls_ca_certificates_pem=(),
            )
        if not isinstance(raw, Mapping):
            raise KeyAttestationError("Issuer-profile key attestation policy must be an object")

        mode = str(raw.get("mode") or "disabled")
        if mode not in {"disabled", "optional", "required"}:
            raise KeyAttestationError(f"Unsupported key attestation policy mode {mode!r}")
        status_validation = str(raw.get("status_validation") or "required")
        if status_validation not in {"disabled", "if_present", "required"}:
            raise KeyAttestationError(
                f"Unsupported key attestation status policy {status_validation!r}"
            )
        roots = _string_tuple(raw.get("trusted_root_certificates_pem"))
        algorithms = frozenset(_string_tuple(raw.get("allowed_algorithms")))
        max_age = raw.get("max_age_seconds", 300)
        if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= 86400:
            raise KeyAttestationError("max_age_seconds must be an integer from 1 through 86400")
        status_max_age = raw.get("status_list_max_age_seconds", 86400)
        if (
            isinstance(status_max_age, bool)
            or not isinstance(status_max_age, int)
            or not 1 <= status_max_age <= 604800
        ):
            raise KeyAttestationError(
                "status_list_max_age_seconds must be an integer from 1 through 604800"
            )
        if mode != "disabled" and (not roots or not algorithms):
            raise KeyAttestationError(
                "Enabled key attestation policy requires trusted roots and allowed algorithms"
            )
        allow_private_status_hosts = raw.get("status_list_allow_private_hosts", False)
        if not isinstance(allow_private_status_hosts, bool):
            raise KeyAttestationError("status_list_allow_private_hosts must be a boolean")
        require_nonce = raw.get("require_nonce", True)
        if not isinstance(require_nonce, bool):
            raise KeyAttestationError("require_nonce must be a boolean")
        status_origins = tuple(
            _normalize_https_origin(value)
            for value in _string_tuple(raw.get("status_list_allowed_origins"))
        )
        status_roots = _string_tuple(raw.get("status_list_trusted_root_certificates_pem")) or roots
        status_algorithms = (
            frozenset(_string_tuple(raw.get("status_list_allowed_algorithms"))) or algorithms
        )
        if mode != "disabled" and status_validation != "disabled" and not status_origins:
            raise KeyAttestationError(
                "Enabled status validation requires an HTTPS status-list origin allowlist"
            )
        return cls(
            mode=mode,  # type: ignore[arg-type]
            trusted_root_certificates_pem=roots,
            allowed_algorithms=algorithms,
            required_key_storage=frozenset(_string_tuple(raw.get("required_key_storage"))),
            required_user_authentication=frozenset(
                _string_tuple(raw.get("required_user_authentication"))
            ),
            max_age_seconds=max_age,
            require_nonce=require_nonce,
            status_validation=status_validation,  # type: ignore[arg-type]
            status_list_allowed_origins=status_origins,
            status_list_trusted_root_certificates_pem=status_roots,
            status_list_allowed_algorithms=status_algorithms,
            status_list_max_age_seconds=status_max_age,
            status_list_allow_private_hosts=allow_private_status_hosts,
            status_list_tls_ca_certificates_pem=_string_tuple(
                raw.get("status_list_tls_ca_certificates_pem")
            ),
        )


@dataclass(frozen=True)
class ValidatedKeyAttestation:
    jwt: str
    attested_keys: tuple[dict[str, Any], ...]
    claims: Mapping[str, Any]


def _proof_header(proof_jwt: str) -> dict[str, Any]:
    parts = proof_jwt.split(".")
    if len(parts) != 3:
        raise KeyAttestationError("Proof JWT must have exactly three parts")
    try:
        return _decode_json_part(parts[0], "proof header")
    except KeyAttestationError as exc:
        raise KeyAttestationError("Proof JWT has an invalid JOSE header") from exc


def _string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise KeyAttestationError("Key attestation policy list field must be an array")
    result = tuple(str(item).strip() for item in value)
    if any(not item for item in result):
        raise KeyAttestationError("Key attestation policy list values must be non-empty strings")
    return result


def _normalize_https_origin(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise KeyAttestationError(
            "Status-list allowed origins must be HTTPS origins without paths or credentials"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise KeyAttestationError("Status-list allowed origin has an invalid port") from exc
    host = parsed.hostname.lower()
    host_display = f"[{host}]" if ":" in host else host
    return f"https://{host_display}{f':{port}' if port and port != 443 else ''}"


def _b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise KeyAttestationError("JWT contains invalid base64url") from exc


def _decode_json_part(value: str, name: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64url_decode(value))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeyAttestationError(f"Key attestation has invalid {name} JSON") from exc
    if not isinstance(decoded, dict):
        raise KeyAttestationError(f"Key attestation {name} must be a JSON object")
    return decoded


def _verify_signature_with_certificate(
    leaf_certificate_der: bytes,
    signature: bytes,
    message: bytes,
    algorithm: str,
) -> None:
    try:
        public_key_der = bytes(_marty_verification.get_certificate_public_key(leaf_certificate_der))
        valid = _marty_verification.verify_signature(
            algorithm,
            public_key_der,
            message,
            signature,
        )
    except Exception as exc:
        raise KeyAttestationError(
            "Key attestation algorithm does not match certificate key"
        ) from exc
    if not valid:
        raise KeyAttestationError("Key attestation signature verification failed")


def _validate_certificate_chain(
    encoded_chain: Sequence[Any],
    trusted_roots_pem: Sequence[str],
    now: datetime,
) -> bytes:
    if not encoded_chain or any(not isinstance(item, str) or not item for item in encoded_chain):
        raise KeyAttestationError("Key attestation x5c must be a non-empty certificate array")
    try:
        chain = [base64.b64decode(item, validate=True) for item in encoded_chain]
    except (ValueError, TypeError) as exc:
        raise KeyAttestationError("Key attestation certificate encoding is invalid") from exc
    if not trusted_roots_pem:
        raise KeyAttestationError("Key attestation policy has no trusted roots")
    try:
        config = _marty_verification.ValidationConfig(
            check_crl=False,
            check_ocsp=False,
            revocation_mode="hard_fail",
            validation_moment=now.isoformat(),
            required_key_usage=["digital_signature"],
            certificate_type="any",
        )
        validator = _marty_verification.ChainValidator.with_config(config)
        for root in trusted_roots_pem:
            validator.add_trust_anchor(root)
        chain_pem = [
            _marty_verification.certificate_der_to_pem(certificate) for certificate in chain
        ]
        result = validator.validate_chain(chain_pem)
    except Exception as exc:
        raise KeyAttestationError("Key attestation certificate encoding is invalid") from exc
    if not result.valid:
        detail = "; ".join(result.errors) if result.errors else "native chain validation failed"
        raise KeyAttestationError(
            f"Key attestation certificate chain is not trusted by issuer profile: {detail}"
        )
    return chain[0]


def _required_timestamp(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise KeyAttestationError(f"Key attestation requires integer {name} claim")
    return value


def _status_list_value(
    token: str,
    *,
    uri: str,
    index: int,
    policy: KeyAttestationPolicy,
    now: datetime,
) -> int:
    parts = token.split(".")
    if len(parts) != 3:
        raise KeyAttestationError("Status List Token JWT must have exactly three parts")
    header = _decode_json_part(parts[0], "status-list header")
    claims = _decode_json_part(parts[1], "status-list claims")
    if header.get("typ") != "statuslist+jwt":
        raise KeyAttestationError("Status List Token typ must be statuslist+jwt")
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in policy.status_list_allowed_algorithms:
        raise KeyAttestationError("Status List Token algorithm is not allowed by issuer profile")
    leaf = _validate_certificate_chain(
        header.get("x5c") if isinstance(header.get("x5c"), list) else [],
        policy.status_list_trusted_root_certificates_pem,
        now,
    )
    _verify_signature_with_certificate(
        leaf,
        _b64url_decode(parts[2]),
        f"{parts[0]}.{parts[1]}".encode("ascii"),
        algorithm,
    )

    if claims.get("sub") != uri:
        raise KeyAttestationError("Status List Token subject does not match referenced URI")
    iat = _required_timestamp(claims, "iat")
    now_timestamp = int(now.timestamp())
    if iat > now_timestamp + 30:
        raise KeyAttestationError("Status List Token iat is in the future")
    if now_timestamp - iat > policy.status_list_max_age_seconds:
        raise KeyAttestationError("Status List Token is older than issuer policy allows")
    exp = claims.get("exp")
    if exp is not None:
        if isinstance(exp, bool) or not isinstance(exp, int):
            raise KeyAttestationError("Status List Token exp must be an integer")
        if exp <= now_timestamp:
            raise KeyAttestationError("Status List Token has expired")
    ttl = claims.get("ttl")
    if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0):
        raise KeyAttestationError("Status List Token ttl must be a positive integer")

    status_list = claims.get("status_list")
    if not isinstance(status_list, Mapping):
        raise KeyAttestationError("Status List Token requires a status_list object")
    bits = status_list.get("bits")
    encoded_list = status_list.get("lst")
    if bits not in {1, 2, 4, 8} or isinstance(bits, bool):
        raise KeyAttestationError("Status List Token bits must be one of 1, 2, 4, or 8")
    if not isinstance(encoded_list, str) or not encoded_list:
        raise KeyAttestationError("Status List Token lst must be base64url data")
    try:
        compressed = _b64url_decode(encoded_list)
        decompressor = zlib.decompressobj()
        status_bytes = decompressor.decompress(compressed, 1_048_577)
        if (
            len(status_bytes) > 1_048_576
            or decompressor.unconsumed_tail
            or not decompressor.eof
            or decompressor.unused_data
        ):
            raise KeyAttestationError("Status List Token expands beyond the safe size limit")
    except zlib.error as exc:
        raise KeyAttestationError("Status List Token lst is not valid ZLIB data") from exc

    byte_index = (index * bits) // 8
    if byte_index >= len(status_bytes):
        raise KeyAttestationError("Status List Token index is out of bounds")
    bit_offset = (index * bits) % 8
    return (status_bytes[byte_index] >> bit_offset) & ((1 << bits) - 1)


async def validate_token_status_list_entry(
    status: Mapping[str, Any],
    policy: KeyAttestationPolicy,
    *,
    client: httpx.AsyncClient | None = None,
    now: datetime | None = None,
) -> bool:
    """Fetch and validate an IETF Token Status List JWT entry.

    URLs are profile-allowlisted, redirects are disabled, private network
    destinations require an explicit profile opt-in, response sizes are
    bounded, and the returned list must be signed under the profile's status
    trust roots. Only status value 0 (VALID) is accepted.
    """
    reference = status.get("status_list")
    if not isinstance(reference, Mapping):
        raise KeyAttestationError("Status claim requires a status_list object")
    index = reference.get("idx")
    uri = reference.get("uri")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise KeyAttestationError("Status-list idx must be a non-negative integer")
    if not isinstance(uri, str) or not uri:
        raise KeyAttestationError("Status-list uri must be a non-empty string")
    parsed = urlparse(uri)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise KeyAttestationError("Status-list uri must be an HTTPS URL without credentials")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise KeyAttestationError("Status-list uri has an invalid port") from exc
    host = parsed.hostname.lower()
    host_display = f"[{host}]" if ":" in host else host
    origin = f"https://{host_display}{f':{port}' if port != 443 else ''}"
    if origin not in policy.status_list_allowed_origins:
        raise KeyAttestationError("Status-list uri origin is not allowed by issuer profile")

    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(
            parsed.hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise KeyAttestationError("Status-list hostname could not be resolved") from exc
    try:
        resolved_ips = {ipaddress.ip_address(item[4][0]) for item in addresses}
    except ValueError as exc:
        raise KeyAttestationError("Status-list hostname resolved to an invalid address") from exc
    if not resolved_ips:
        raise KeyAttestationError("Status-list hostname resolved to no addresses")
    if not policy.status_list_allow_private_hosts and any(
        not address.is_global for address in resolved_ips
    ):
        raise KeyAttestationError("Status-list hostname resolves to a non-public address")

    owned_client = client is None
    if owned_client:
        tls_context = ssl.create_default_context()
        for certificate in policy.status_list_tls_ca_certificates_pem:
            try:
                tls_context.load_verify_locations(cadata=certificate)
            except ssl.SSLError as exc:
                raise KeyAttestationError("Status-list TLS CA certificate is invalid") from exc
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
            verify=tls_context,
        )
    assert client is not None
    try:
        async with client.stream(
            "GET",
            uri,
            headers={"Accept": "application/statuslist+jwt"},
        ) as response:
            if not 200 <= response.status_code < 300:
                raise KeyAttestationError(
                    f"Status-list endpoint returned HTTP {response.status_code}"
                )
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
            if content_type != "application/statuslist+jwt":
                raise KeyAttestationError(
                    "Status-list endpoint did not return application/statuslist+jwt"
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 1_048_576:
                    raise KeyAttestationError("Status List Token response is too large")
    except httpx.HTTPError as exc:
        raise KeyAttestationError("Status-list endpoint request failed") from exc
    finally:
        if owned_client:
            await client.aclose()

    try:
        token = bytes(body).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise KeyAttestationError("Status List Token response is not ASCII") from exc
    return (
        _status_list_value(
            token,
            uri=uri,
            index=index,
            policy=policy,
            now=now or datetime.now(UTC),
        )
        == 0
    )


async def validate_key_attestation_jwt(
    jwt: str,
    policy: KeyAttestationPolicy,
    *,
    expected_nonce: str | None,
    status_validator: StatusValidator | None = None,
    now: datetime | None = None,
) -> ValidatedKeyAttestation:
    """Validate a key attestation using one issuer profile's trust policy."""
    if policy.mode == "disabled":
        raise KeyAttestationError("Issuer profile does not allow key-attestation-bound proofs")
    parts = jwt.split(".")
    if len(parts) != 3:
        raise KeyAttestationError("Key attestation JWT must have exactly three parts")
    header = _decode_json_part(parts[0], "header")
    claims = _decode_json_part(parts[1], "claims")
    if header.get("typ") != "key-attestation+jwt":
        raise KeyAttestationError("Key attestation typ must be key-attestation+jwt")
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in policy.allowed_algorithms:
        raise KeyAttestationError("Key attestation algorithm is not allowed by issuer profile")

    current = now or datetime.now(UTC)
    leaf = _validate_certificate_chain(
        header.get("x5c") if isinstance(header.get("x5c"), list) else [],
        policy.trusted_root_certificates_pem,
        current,
    )
    _verify_signature_with_certificate(
        leaf,
        _b64url_decode(parts[2]),
        f"{parts[0]}.{parts[1]}".encode("ascii"),
        algorithm,
    )

    iat = _required_timestamp(claims, "iat")
    exp = _required_timestamp(claims, "exp")
    now_timestamp = int(current.timestamp())
    if iat > now_timestamp + 30:
        raise KeyAttestationError("Key attestation iat is in the future")
    if now_timestamp - iat > policy.max_age_seconds:
        raise KeyAttestationError("Key attestation is older than issuer policy allows")
    if exp <= now_timestamp:
        raise KeyAttestationError("Key attestation has expired")
    if exp <= iat:
        raise KeyAttestationError("Key attestation exp must be later than iat")
    if policy.require_nonce and (not expected_nonce or claims.get("nonce") != expected_nonce):
        raise KeyAttestationError("Key attestation nonce does not match issuance nonce")

    keys = claims.get("attested_keys")
    if not isinstance(keys, list) or not keys or any(not isinstance(key, dict) for key in keys):
        raise KeyAttestationError("Key attestation requires a non-empty attested_keys array")
    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    if any(private_fields.intersection(key) for key in keys):
        raise KeyAttestationError("Key attestation contains private key material")

    key_storage = claims.get("key_storage")
    user_authentication = claims.get("user_authentication")
    if key_storage is not None and (
        not isinstance(key_storage, list)
        or not key_storage
        or any(not isinstance(value, str) or not value for value in key_storage)
    ):
        raise KeyAttestationError("Key attestation key_storage must be a non-empty string array")
    if policy.required_key_storage and (
        not isinstance(key_storage, list) or not policy.required_key_storage.issubset(key_storage)
    ):
        raise KeyAttestationError("Key attestation does not meet key-storage requirements")
    if user_authentication is not None and (
        not isinstance(user_authentication, list)
        or not user_authentication
        or any(not isinstance(value, str) or not value for value in user_authentication)
    ):
        raise KeyAttestationError(
            "Key attestation user_authentication must be a non-empty string array"
        )
    if policy.required_user_authentication and (
        not isinstance(user_authentication, list)
        or not policy.required_user_authentication.issubset(user_authentication)
    ):
        raise KeyAttestationError("Key attestation does not meet user-authentication requirements")
    certification = claims.get("certification")
    if certification is not None and (
        not isinstance(certification, str) or not certification.startswith("https://")
    ):
        raise KeyAttestationError("Key attestation certification must be an HTTPS URL")

    statuses: list[Mapping[str, Any]] = []
    status = claims.get("status")
    if status is not None and not isinstance(status, Mapping):
        raise KeyAttestationError("Key attestation status must be an object")
    if isinstance(status, Mapping):
        statuses.append(status)
    storage_status = claims.get("key_storage_status")
    if storage_status is not None and not isinstance(storage_status, Mapping):
        raise KeyAttestationError("Key attestation key_storage_status must be an object")
    if isinstance(storage_status, Mapping):
        storage_exp = _required_timestamp(storage_status, "exp")
        if storage_exp <= now_timestamp:
            raise KeyAttestationError("Key storage status has expired")
        nested = storage_status.get("status")
        if nested is not None and not isinstance(nested, Mapping):
            raise KeyAttestationError("Key storage status status claim must be an object")
        if isinstance(nested, Mapping):
            statuses.append(nested)
    if policy.status_validation == "required" and not statuses:
        raise KeyAttestationError("Issuer policy requires key attestation status information")
    if statuses and policy.status_validation != "disabled":
        if status_validator is None:
            raise KeyAttestationError("No production status validator is configured")
        for entry in statuses:
            if not await status_validator(entry):
                raise KeyAttestationError("Key attestation status is revoked or invalid")

    return ValidatedKeyAttestation(
        jwt=jwt,
        attested_keys=tuple(dict(key) for key in keys),
        claims=claims,
    )


async def verify_oid4vci_proof_with_issuer_policy(
    proof_jwt: str,
    *,
    issuer_context: Mapping[str, Any] | None,
    organization_id: str,
    expected_nonce: str | None,
    proof_verifier: ProofVerifier,
    bound_proof_verifier: BoundProofVerifier,
    issuer_url: str | None = None,
    status_validator: StatusValidator | None = None,
) -> tuple[bool, str, dict[str, Any] | None, str | None]:
    """Verify an OID4VCI proof through its resolved issuer-profile policy.

    The product boundary validates tenant ownership, wallet-provider trust,
    assurance claims, freshness, and status.  Only the exact compact
    attestation that passed those checks is then passed to marty-core, which
    binds the proof signature to the selected attested public key.

    A missing issuer context is tolerated only for an ordinary proof.  A
    proof carrying a key attestation can never create its own trust policy.
    """
    try:
        header = _proof_header(proof_jwt)
        raw_attestation = header.get("key_attestation")

        policy: KeyAttestationPolicy | None = None
        if issuer_context is not None and isinstance(issuer_context.get("issuer_profile"), Mapping):
            policy = KeyAttestationPolicy.from_issuer_context(
                issuer_context,
                organization_id=organization_id,
            )

        if raw_attestation is None:
            if policy is not None and policy.mode == "required":
                raise KeyAttestationError("Issuer profile requires a key-attestation-bound proof")
            return proof_verifier(proof_jwt, expected_nonce, issuer_url)

        if not isinstance(raw_attestation, str) or not raw_attestation:
            raise KeyAttestationError("Proof key_attestation header must be a compact JWT")
        if policy is None:
            raise KeyAttestationError(
                "Key-attestation-bound proof has no resolved tenant issuer policy"
            )
        if policy.mode == "disabled":
            raise KeyAttestationError("Issuer profile does not allow key-attestation-bound proofs")

        effective_status_validator = status_validator
        if effective_status_validator is None and policy.status_validation != "disabled":

            async def validate_status(entry: Mapping[str, Any]) -> bool:
                return await validate_token_status_list_entry(entry, policy)

            effective_status_validator = validate_status

        validated = await validate_key_attestation_jwt(
            raw_attestation,
            policy,
            expected_nonce=expected_nonce,
            status_validator=effective_status_validator,
        )
        return bound_proof_verifier(
            proof_jwt,
            validated.jwt,
            expected_nonce,
            issuer_url,
        )
    except KeyAttestationError as exc:
        return False, "", None, str(exc)
