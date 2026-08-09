from __future__ import annotations

import base64
import json
import zlib
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
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
    validate_token_status_list_entry,
    verify_oid4vci_proof_with_issuer_policy,
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


def _sign_proof(
    key: ec.EllipticCurvePrivateKey,
    key_attestation: str | None,
) -> str:
    header: dict[str, Any] = {
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt",
        "kid": "0",
    }
    if key_attestation is not None:
        header["key_attestation"] = key_attestation
    payload = {
        "aud": "https://issuer.example/org/org-a",
        "iat": 1,
        "nonce": "nonce-1",
    }
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    der_signature = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input.decode()}.{_b64url(signature)}"


def _sign_status_list(
    key: ec.EllipticCurvePrivateKey,
    certificate: x509.Certificate,
    *,
    uri: str,
    now: datetime,
    status_byte: int,
) -> str:
    header = {
        "alg": "ES256",
        "typ": "statuslist+jwt",
        "x5c": [base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()],
    }
    claims = {
        "sub": uri,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "ttl": 60,
        "status_list": {
            "bits": 1,
            "lst": _b64url(zlib.compress(bytes([status_byte]), level=9)),
        },
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
                "status_list_allowed_origins": ["https://status.example"],
                "status_list_allow_private_hosts": False,
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
        (lambda claims: claims.update(key_storage=[]), "key_storage"),
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
    encoded_header, encoded_claims, encoded_signature = jwt.split(".")
    tampered_signature = bytearray(
        base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
    )
    tampered_signature[0] ^= 1
    tampered = f"{encoded_header}.{encoded_claims}.{_b64url(bytes(tampered_signature))}"
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
async def test_rejects_attestation_algorithm_that_mismatches_certificate_key() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    attestation_key, certificate = _attestation_material(now)
    jwt = _sign_attestation(
        attestation_key,
        certificate,
        _claims(now, ec.generate_private_key(ec.SECP256R1())),
    )
    encoded_header, encoded_claims, encoded_signature = jwt.split(".")
    header = json.loads(base64.urlsafe_b64decode(encoded_header + "=" * (-len(encoded_header) % 4)))
    header["alg"] = "EdDSA"
    mismatched = (
        f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}."
        f"{encoded_claims}.{encoded_signature}"
    )
    context = _context(certificate)
    context["issuer_profile"]["key_attestation_policy"]["allowed_algorithms"] = ["EdDSA"]
    policy = KeyAttestationPolicy.from_issuer_context(
        context,
        organization_id="org-a",
    )

    with pytest.raises(
        KeyAttestationError,
        match="algorithm does not match certificate key",
    ):
        await validate_key_attestation_jwt(
            mismatched,
            policy,
            expected_nonce="nonce-1",
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_byte", "expected"),
    [(0x00, True), (0x80, False)],
)
async def test_fetches_and_verifies_profile_allowlisted_token_status_list(
    status_byte: int,
    expected: bool,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    status_key, certificate = _attestation_material(now)
    uri = "https://localhost/statuslists/wallet-provider"
    token = _sign_status_list(
        status_key,
        certificate,
        uri=uri,
        now=now,
        status_byte=status_byte,
    )
    context = _context(certificate)
    policy_config = context["issuer_profile"]["key_attestation_policy"]
    policy_config["status_list_allowed_origins"] = ["https://localhost"]
    policy_config["status_list_allow_private_hosts"] = True
    policy = KeyAttestationPolicy.from_issuer_context(context, organization_id="org-a")

    async def response(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/statuslist+jwt"},
            text=token,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        result = await validate_token_status_list_entry(
            {"status_list": {"idx": 7, "uri": uri}},
            policy,
            client=client,
            now=now,
        )

    assert result is expected


@pytest.mark.asyncio
async def test_rejects_status_list_origin_not_owned_by_profile_policy() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    _, certificate = _attestation_material(now)
    policy = KeyAttestationPolicy.from_issuer_context(
        _context(certificate), organization_id="org-a"
    )

    with pytest.raises(KeyAttestationError, match="origin is not allowed"):
        await validate_token_status_list_entry(
            {
                "status_list": {
                    "idx": 7,
                    "uri": "https://attacker.example/statuslists/3",
                }
            },
            policy,
            now=now,
        )


@pytest.mark.asyncio
async def test_accepts_spec_optional_assurance_and_status_claims_when_not_required() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    attestation_key, certificate = _attestation_material(now)
    claims = _claims(now, ec.generate_private_key(ec.SECP256R1()))
    for optional_claim in (
        "key_storage",
        "user_authentication",
        "certification",
        "key_storage_status",
    ):
        claims.pop(optional_claim)
    context = _context(certificate)
    policy_config = context["issuer_profile"]["key_attestation_policy"]
    policy_config["required_key_storage"] = []
    policy_config["required_user_authentication"] = []
    policy_config["status_validation"] = "disabled"

    result = await validate_key_attestation_jwt(
        _sign_attestation(attestation_key, certificate, claims),
        KeyAttestationPolicy.from_issuer_context(context, organization_id="org-a"),
        expected_nonce="nonce-1",
        now=now,
    )

    assert result.attested_keys


@pytest.mark.asyncio
async def test_routes_exact_validated_attestation_to_core_binding() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    attestation_key, certificate = _attestation_material(now)
    holder_key = ec.generate_private_key(ec.SECP256R1())
    attestation = _sign_attestation(
        attestation_key,
        certificate,
        _claims(now, holder_key),
    )
    proof = _sign_proof(holder_key, attestation)
    calls: list[tuple[str, str, str | None, str | None]] = []

    def ordinary_verifier(
        _proof: str, _nonce: str | None, _issuer_url: str | None
    ) -> tuple[bool, str, dict[str, Any] | None, str | None]:
        raise AssertionError("key-attestation proof must not use the ordinary verifier")

    def bound_verifier(
        checked_proof: str,
        checked_attestation: str,
        nonce: str | None,
        issuer_url: str | None,
    ) -> tuple[bool, str, dict[str, Any] | None, str | None]:
        calls.append((checked_proof, checked_attestation, nonce, issuer_url))
        return True, "", _public_jwk(holder_key), None

    async def valid_status(_status: dict[str, Any]) -> bool:
        return True

    result = await verify_oid4vci_proof_with_issuer_policy(
        proof,
        issuer_context=_context(certificate),
        organization_id="org-a",
        expected_nonce="nonce-1",
        issuer_url="https://issuer.example/org/org-a",
        proof_verifier=ordinary_verifier,
        bound_proof_verifier=bound_verifier,
        status_validator=valid_status,
    )

    assert result == (True, "", _public_jwk(holder_key), None)
    assert calls == [
        (
            proof,
            attestation,
            "nonce-1",
            "https://issuer.example/org/org-a",
        )
    ]


@pytest.mark.asyncio
async def test_required_policy_rejects_ordinary_proof_before_core() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    _, certificate = _attestation_material(now)
    proof = _sign_proof(ec.generate_private_key(ec.SECP256R1()), None)
    called = False

    def ordinary_verifier(
        _proof: str, _nonce: str | None, _issuer_url: str | None
    ) -> tuple[bool, str, dict[str, Any] | None, str | None]:
        nonlocal called
        called = True
        return True, "did:key:unexpected", {}, None

    result = await verify_oid4vci_proof_with_issuer_policy(
        proof,
        issuer_context=_context(certificate),
        organization_id="org-a",
        expected_nonce="nonce-1",
        proof_verifier=ordinary_verifier,
        bound_proof_verifier=lambda *_args: (True, "", {}, None),
    )

    assert result[0] is False
    assert result[3] == "Issuer profile requires a key-attestation-bound proof"
    assert called is False


@pytest.mark.asyncio
async def test_attested_proof_cannot_supply_policy_without_resolved_profile() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    attestation_key, certificate = _attestation_material(now)
    holder_key = ec.generate_private_key(ec.SECP256R1())
    attestation = _sign_attestation(
        attestation_key,
        certificate,
        _claims(now, holder_key),
    )

    result = await verify_oid4vci_proof_with_issuer_policy(
        _sign_proof(holder_key, attestation),
        issuer_context=None,
        organization_id="org-a",
        expected_nonce="nonce-1",
        proof_verifier=lambda *_args: (True, "", {}, None),
        bound_proof_verifier=lambda *_args: (True, "", {}, None),
    )

    assert result[0] is False
    assert result[3] == "Key-attestation-bound proof has no resolved tenant issuer policy"
