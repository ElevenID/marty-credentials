from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from issuance.application.key_attestation import (
    KeyAttestationError,
    KeyAttestationPolicy,
    validate_key_attestation_jwt,
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _attestation_material(now: datetime) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wallet Provider Attestation")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _public_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def _sign_attestation(
    key: ec.EllipticCurvePrivateKey,
    certificate: x509.Certificate,
    claims: dict[str, Any],
) -> str:
    header = {
        "alg": "ES256",
        "typ": "key-attestation+jwt",
        "x5c": [base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()],
    }
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_claims = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    der_signature = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input.decode()}.{_b64url(signature)}"


def _context(certificate: x509.Certificate, organization_id: str = "org-a") -> dict[str, Any]:
    root_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return {
        "organization_id": organization_id,
        "issuer_profile": {
            "id": "profile-a",
            "organization_id": organization_id,
            "key_attestation_policy": {
                "mode": "required",
                "trusted_root_certificates_pem": [root_pem],
                "allowed_algorithms": ["ES256"],
                "required_key_storage": ["iso_18045_high"],
                "required_user_authentication": ["iso_18045_high"],
                "max_age_seconds": 300,
                "require_nonce": True,
                "status_validation": "required",
            },
        },
    }


def _claims(now: datetime, holder_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    return {
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "attested_keys": [_public_jwk(holder_key)],
        "key_storage": ["iso_18045_high"],
        "user_authentication": ["iso_18045_high"],
        "certification": "https://wallet-provider.example/certification",
        "nonce": "nonce-1",
        "key_storage_status": {
            "status": {"status_list": {"idx": 7, "uri": "https://status.example/list"}},
            "exp": int((now + timedelta(hours=1)).timestamp()),
        },
    }


@pytest.mark.asyncio
async def test_validates_trusted_tenant_policy_and_returns_only_public_keys() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    attestation_key, certificate = _attestation_material(now)
    holder_key = ec.generate_private_key(ec.SECP256R1())
    jwt = _sign_attestation(attestation_key, certificate, _claims(now, holder_key))
    policy = KeyAttestationPolicy.from_issuer_context(
        _context(certificate), organization_id="org-a"
    )
    checked_statuses: list[dict[str, Any]] = []

    async def validate_status(status: dict[str, Any]) -> bool:
        checked_statuses.append(status)
        return True

    result = await validate_key_attestation_jwt(
        jwt,
        policy,
        expected_nonce="nonce-1",
        status_validator=validate_status,
        now=now,
    )

    assert result.jwt == jwt
    assert result.attested_keys == (_public_jwk(holder_key),)
    assert checked_statuses == [{"status_list": {"idx": 7, "uri": "https://status.example/list"}}]


def test_rejects_cross_tenant_policy_substitution() -> None:
    now = datetime.now(UTC)
    _, certificate = _attestation_material(now)
    with pytest.raises(KeyAttestationError, match="not tenant-bound"):
        KeyAttestationPolicy.from_issuer_context(_context(certificate), organization_id="org-b")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda claims: claims.update(nonce="wrong"), "nonce does not match"),
        (lambda claims: claims.update(exp=claims["iat"] - 1), "expired"),
        (
            lambda claims: claims["attested_keys"][0].update(d="private"),
            "private key material",
        ),
        (lambda claims: claims.update(key_storage=[]), "key-storage requirements"),
    ],
)
async def test_rejects_invalid_attestation_claims(mutation: Any, message: str) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    attestation_key, certificate = _attestation_material(now)
    claims = _claims(now, ec.generate_private_key(ec.SECP256R1()))
    mutation(claims)
    jwt = _sign_attestation(attestation_key, certificate, claims)
    policy = KeyAttestationPolicy.from_issuer_context(
        _context(certificate), organization_id="org-a"
    )

    async def valid_status(_: dict[str, Any]) -> bool:
        return True

    with pytest.raises(KeyAttestationError, match=message):
        await validate_key_attestation_jwt(
            jwt,
            policy,
            expected_nonce="nonce-1",
            status_validator=valid_status,
            now=now,
        )


@pytest.mark.asyncio
async def test_rejects_untrusted_tampered_and_revoked_attestations() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    attestation_key, certificate = _attestation_material(now)
    _, different_certificate = _attestation_material(now)
    claims = _claims(now, ec.generate_private_key(ec.SECP256R1()))
    jwt = _sign_attestation(attestation_key, certificate, claims)
    untrusted_policy = KeyAttestationPolicy.from_issuer_context(
        _context(different_certificate), organization_id="org-a"
    )

    async def valid_status(_: dict[str, Any]) -> bool:
        return True

    with pytest.raises(KeyAttestationError, match="not trusted"):
        await validate_key_attestation_jwt(
            jwt,
            untrusted_policy,
            expected_nonce="nonce-1",
            status_validator=valid_status,
            now=now,
        )

    policy = KeyAttestationPolicy.from_issuer_context(
        _context(certificate), organization_id="org-a"
    )
    tampered = f"{jwt[:-1]}{'A' if jwt[-1] != 'A' else 'B'}"
    with pytest.raises(KeyAttestationError, match="signature verification failed"):
        await validate_key_attestation_jwt(
            tampered,
            policy,
            expected_nonce="nonce-1",
            status_validator=valid_status,
            now=now,
        )

    async def revoked_status(_: dict[str, Any]) -> bool:
        return False

    with pytest.raises(KeyAttestationError, match="revoked or invalid"):
        await validate_key_attestation_jwt(
            jwt,
            policy,
            expected_nonce="nonce-1",
            status_validator=revoked_status,
            now=now,
        )


@pytest.mark.asyncio
async def test_status_claim_fails_closed_without_production_validator() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    attestation_key, certificate = _attestation_material(now)
    jwt = _sign_attestation(
        attestation_key,
        certificate,
        _claims(now, ec.generate_private_key(ec.SECP256R1())),
    )
    policy = KeyAttestationPolicy.from_issuer_context(
        _context(certificate), organization_id="org-a"
    )

    with pytest.raises(KeyAttestationError, match="No production status validator"):
        await validate_key_attestation_jwt(
            jwt,
            policy,
            expected_nonce="nonce-1",
            now=now,
        )
