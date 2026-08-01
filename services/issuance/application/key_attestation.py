"""Tenant-policy validation for OID4VCI key attestation JWTs."""

from __future__ import annotations

import base64
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class KeyAttestationError(ValueError):
    """A key attestation or its issuer-profile policy is invalid."""


StatusValidator = Callable[[Mapping[str, Any]], Awaitable[bool]]


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
        if mode != "disabled" and (not roots or not algorithms):
            raise KeyAttestationError(
                "Enabled key attestation policy requires trusted roots and allowed algorithms"
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
            require_nonce=bool(raw.get("require_nonce", True)),
            status_validation=status_validation,  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class ValidatedKeyAttestation:
    jwt: str
    attested_keys: tuple[dict[str, Any], ...]
    claims: Mapping[str, Any]


def _string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise KeyAttestationError("Key attestation policy list field must be an array")
    result = tuple(str(item).strip() for item in value)
    if any(not item for item in result):
        raise KeyAttestationError("Key attestation policy list values must be non-empty strings")
    return result


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


def _verify_signature_with_key(
    public_key: Any,
    signature: bytes,
    message: bytes,
    algorithm: str,
) -> None:
    try:
        if algorithm in {"ES256", "ES384"}:
            coordinate_size = {"ES256": 32, "ES384": 48}[algorithm]
            curve = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1}[algorithm]
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
                public_key.curve, curve
            ):
                raise KeyAttestationError(
                    "Key attestation algorithm does not match certificate key"
                )
            if len(signature) != coordinate_size * 2:
                raise KeyAttestationError("Key attestation has invalid ECDSA signature length")
            r = int.from_bytes(signature[:coordinate_size], "big")
            s = int.from_bytes(signature[coordinate_size:], "big")
            digest = hashes.SHA256() if algorithm == "ES256" else hashes.SHA384()
            public_key.verify(encode_dss_signature(r, s), message, ec.ECDSA(digest))
        elif algorithm == "EdDSA":
            if not isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                raise KeyAttestationError(
                    "Key attestation algorithm does not match certificate key"
                )
            public_key.verify(signature, message)
        elif algorithm in {"RS256", "PS256"}:
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise KeyAttestationError(
                    "Key attestation algorithm does not match certificate key"
                )
            rsa_padding: padding.AsymmetricPadding
            if algorithm == "RS256":
                rsa_padding = padding.PKCS1v15()
            else:
                rsa_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            public_key.verify(signature, message, rsa_padding, hashes.SHA256())
        else:
            raise KeyAttestationError(f"Unsupported key attestation algorithm {algorithm!r}")
    except KeyAttestationError:
        raise
    except Exception as exc:  # cryptography exposes algorithm-specific exceptions
        raise KeyAttestationError("Key attestation signature verification failed") from exc


def _verify_certificate_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    key = issuer.public_key()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(child.signature, child.tbs_certificate_bytes)
        else:
            raise KeyAttestationError("Unsupported certificate issuer public key")
    except KeyAttestationError:
        raise
    except Exception as exc:
        raise KeyAttestationError("Key attestation certificate chain signature is invalid") from exc


def _validate_certificate_chain(
    encoded_chain: Sequence[Any],
    trusted_roots_pem: Sequence[str],
    now: datetime,
) -> x509.Certificate:
    if not encoded_chain or any(not isinstance(item, str) or not item for item in encoded_chain):
        raise KeyAttestationError("Key attestation x5c must be a non-empty certificate array")
    try:
        chain = [
            x509.load_der_x509_certificate(base64.b64decode(item, validate=True))
            for item in encoded_chain
        ]
        roots = [x509.load_pem_x509_certificate(item.encode("utf-8")) for item in trusted_roots_pem]
    except (ValueError, TypeError) as exc:
        raise KeyAttestationError("Key attestation certificate encoding is invalid") from exc
    if not roots:
        raise KeyAttestationError("Key attestation policy has no trusted roots")

    for certificate in chain:
        if now < certificate.not_valid_before_utc or now > certificate.not_valid_after_utc:
            raise KeyAttestationError("Key attestation certificate is outside its validity period")
    for child, issuer in zip(chain, chain[1:], strict=False):
        if child.issuer != issuer.subject:
            raise KeyAttestationError("Key attestation certificate chain issuer does not match")
        _verify_certificate_signature(child, issuer)

    terminal = chain[-1]
    for root in roots:
        if now < root.not_valid_before_utc or now > root.not_valid_after_utc:
            continue
        if terminal.fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()):
            return chain[0]
        if terminal.issuer == root.subject:
            try:
                _verify_certificate_signature(terminal, root)
                return chain[0]
            except KeyAttestationError:
                continue
    raise KeyAttestationError("Key attestation certificate chain is not trusted by issuer profile")


def _required_timestamp(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise KeyAttestationError(f"Key attestation requires integer {name} claim")
    return value


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
    _verify_signature_with_key(
        leaf.public_key(),
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
    if not isinstance(key_storage, list) or not policy.required_key_storage.issubset(key_storage):
        raise KeyAttestationError("Key attestation does not meet key-storage requirements")
    if not isinstance(
        user_authentication, list
    ) or not policy.required_user_authentication.issubset(user_authentication):
        raise KeyAttestationError("Key attestation does not meet user-authentication requirements")
    certification = claims.get("certification")
    if not isinstance(certification, str) or not certification.startswith("https://"):
        raise KeyAttestationError("Key attestation certification must be an HTTPS URL")

    statuses: list[Mapping[str, Any]] = []
    status = claims.get("status")
    if isinstance(status, Mapping):
        statuses.append(status)
    storage_status = claims.get("key_storage_status")
    if isinstance(storage_status, Mapping):
        storage_exp = _required_timestamp(storage_status, "exp")
        if storage_exp <= now_timestamp:
            raise KeyAttestationError("Key storage status has expired")
        nested = storage_status.get("status")
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
