from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from issuance.application.oid4vci_client_auth import (
    JWT_BEARER_ASSERTION_TYPE,
    ClientAuthenticationError,
    normalize_public_client_jwks,
    verify_private_key_jwt,
)
from issuance.domain.entities import (
    IssuanceStatus,
    IssuanceTransaction,
    Oid4vciRegisteredClient,
)
from issuance.infrastructure.adapters.memory_repository import (
    InMemoryIssuanceRepository,
)
from issuance.infrastructure.api import routes
from issuance.infrastructure.api.routes import _authenticate_oid4vci_client
from starlette.requests import Request

CLIENT_ID = "marty-official-wallet-00000000-0000-0000-0000-000000000001"
AUDIENCE = "https://issuer.example/org/00000000-0000-0000-0000-000000000001"
NOW = datetime(2026, 7, 27, 6, 0, tzinfo=UTC)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _key_material():
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": "wallet-key-1",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }
    return private_key, public_jwk


def _assertion(
    private_key,
    *,
    header: dict | None = None,
    claims: dict | None = None,
    now: datetime = NOW,
) -> str:
    effective_header = {"alg": "ES256", "kid": "wallet-key-1", **(header or {})}
    effective_claims = {
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": AUDIENCE,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=60)).timestamp()),
        "jti": "assertion-1",
        **(claims or {}),
    }
    encoded_header = _b64url(json.dumps(effective_header, separators=(",", ":")).encode())
    encoded_claims = _b64url(json.dumps(effective_claims, separators=(",", ":")).encode())
    der_signature = private_key.sign(
        f"{encoded_header}.{encoded_claims}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(der_signature)
    signature = _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"{encoded_header}.{encoded_claims}.{signature}"


def test_normalize_public_client_jwks_accepts_public_es256_key() -> None:
    _, public_jwk = _key_material()

    result = normalize_public_client_jwks({"keys": [public_jwk]})

    assert result == {"keys": [public_jwk]}


@pytest.mark.parametrize("private_field", ["d", "p", "q", "k"])
def test_normalize_public_client_jwks_rejects_private_material(
    private_field: str,
) -> None:
    _, public_jwk = _key_material()
    public_jwk[private_field] = "must-never-be-stored"

    with pytest.raises(ClientAuthenticationError, match="private key material"):
        normalize_public_client_jwks({"keys": [public_jwk]})


def test_verify_private_key_jwt_accepts_registered_oidf_shape() -> None:
    private_key, public_jwk = _key_material()

    result = verify_private_key_jwt(
        _assertion(private_key),
        client_id=CLIENT_ID,
        public_jwks={"keys": [public_jwk]},
        allowed_audiences=[AUDIENCE],
        now=NOW,
    )

    assert result.client_id == CLIENT_ID
    assert result.jti == "assertion-1"
    assert result.key_id == "wallet-key-1"
    assert result.expires_at == NOW + timedelta(seconds=60)


def test_verify_private_key_jwt_accepts_audience_array() -> None:
    private_key, public_jwk = _key_material()

    result = verify_private_key_jwt(
        _assertion(private_key, claims={"aud": ["https://other.example", AUDIENCE]}),
        client_id=CLIENT_ID,
        public_jwks={"keys": [public_jwk]},
        allowed_audiences=[AUDIENCE],
        now=NOW,
    )

    assert result.client_id == CLIENT_ID


def test_verify_private_key_jwt_rejects_embedded_unregistered_key() -> None:
    private_key, public_jwk = _key_material()

    with pytest.raises(ClientAuthenticationError, match="registered key by kid"):
        verify_private_key_jwt(
            _assertion(private_key, header={"jwk": public_jwk}),
            client_id=CLIENT_ID,
            public_jwks={"keys": [public_jwk]},
            allowed_audiences=[AUDIENCE],
            now=NOW,
        )


def test_verify_private_key_jwt_rejects_signature_from_another_key() -> None:
    registered_private_key, public_jwk = _key_material()
    attacker_private_key, _ = _key_material()
    del registered_private_key

    with pytest.raises(ClientAuthenticationError, match="signature verification failed"):
        verify_private_key_jwt(
            _assertion(attacker_private_key),
            client_id=CLIENT_ID,
            public_jwks={"keys": [public_jwk]},
            allowed_audiences=[AUDIENCE],
            now=NOW,
        )


@pytest.mark.parametrize(
    ("claims", "message"),
    [
        ({"iss": "other-client"}, "iss and sub"),
        ({"sub": "other-client"}, "iss and sub"),
        ({"aud": "https://other.example"}, "audience"),
        ({"exp": int((NOW - timedelta(seconds=61)).timestamp())}, "expired"),
        (
            {
                "iat": int((NOW - timedelta(minutes=10)).timestamp()),
                "exp": int((NOW - timedelta(minutes=9)).timestamp()),
            },
            "iat is too old",
        ),
        ({"exp": int((NOW + timedelta(minutes=6)).timestamp())}, "lifetime"),
        (
            {
                "iat": int(NOW.timestamp()),
                "exp": int(NOW.timestamp()),
            },
            "exp must be after iat",
        ),
        ({"exp": float("nan")}, "exp must be a NumericDate"),
        ({"nbf": int((NOW + timedelta(minutes=2)).timestamp())}, "not yet valid"),
        ({"jti": ""}, "jti is required"),
    ],
)
def test_verify_private_key_jwt_rejects_invalid_security_claims(
    claims: dict,
    message: str,
) -> None:
    private_key, public_jwk = _key_material()

    with pytest.raises(ClientAuthenticationError, match=message):
        verify_private_key_jwt(
            _assertion(private_key, claims=claims),
            client_id=CLIENT_ID,
            public_jwks={"keys": [public_jwk]},
            allowed_audiences=[AUDIENCE],
            now=NOW,
        )


@pytest.mark.asyncio
async def test_registered_client_authentication_is_tenant_bound_and_one_time() -> None:
    private_key, public_jwk = _key_material()
    repo = InMemoryIssuanceRepository()
    await repo.save_oid4vci_client(
        Oid4vciRegisteredClient(
            organization_id="org-a",
            client_id=CLIENT_ID,
            jwks={"keys": [public_jwk]},
        )
    )
    assertion = _assertion(private_key, now=datetime.now(UTC))

    accepted = await _authenticate_oid4vci_client(
        repo=repo,
        organization_id="org-a",
        expected_client_id=CLIENT_ID,
        client_id=CLIENT_ID,
        client_assertion_type=JWT_BEARER_ASSERTION_TYPE,
        client_assertion=assertion,
        allowed_audiences=[AUDIENCE],
        registration_required=True,
    )
    replay = await _authenticate_oid4vci_client(
        repo=repo,
        organization_id="org-a",
        expected_client_id=CLIENT_ID,
        client_id=CLIENT_ID,
        client_assertion_type=JWT_BEARER_ASSERTION_TYPE,
        client_assertion=assertion,
        allowed_audiences=[AUDIENCE],
        registration_required=True,
    )
    cross_tenant = await _authenticate_oid4vci_client(
        repo=repo,
        organization_id="org-b",
        expected_client_id=CLIENT_ID,
        client_id=CLIENT_ID,
        client_assertion_type=JWT_BEARER_ASSERTION_TYPE,
        client_assertion=_assertion(private_key, now=datetime.now(UTC)),
        allowed_audiences=[AUDIENCE],
        registration_required=True,
    )

    assert accepted is None
    assert replay is not None
    assert replay.status_code == 401
    assert cross_tenant is not None
    assert cross_tenant.status_code == 401


@pytest.mark.asyncio
async def test_unbound_public_offer_accepts_none_but_rejects_unsolicited_assertion() -> None:
    private_key, _ = _key_material()
    repo = InMemoryIssuanceRepository()

    anonymous = await _authenticate_oid4vci_client(
        repo=repo,
        organization_id="org-a",
        expected_client_id=None,
        client_id="public-wallet",
        client_assertion_type=None,
        client_assertion=None,
        allowed_audiences=[AUDIENCE],
        registration_required=False,
    )
    unsolicited = await _authenticate_oid4vci_client(
        repo=repo,
        organization_id="org-a",
        expected_client_id=None,
        client_id=CLIENT_ID,
        client_assertion_type=JWT_BEARER_ASSERTION_TYPE,
        client_assertion=_assertion(private_key, now=datetime.now(UTC)),
        allowed_audiences=[AUDIENCE],
        registration_required=False,
    )

    assert anonymous is None
    assert unsolicited is not None
    assert unsolicited.status_code == 401


def _token_request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("issuer.example", 443),
            "path": "/v1/issuance/token",
            "query_string": b"",
            "headers": [(b"host", b"issuer.example")],
        }
    )


@pytest.mark.asyncio
async def test_token_endpoint_requires_bound_client_and_preserves_pending_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key, public_jwk = _key_material()
    repo = InMemoryIssuanceRepository()
    await repo.save_oid4vci_client(
        Oid4vciRegisteredClient(
            organization_id="org-a",
            client_id=CLIENT_ID,
            jwks={"keys": [public_jwk]},
        )
    )
    transaction = IssuanceTransaction(
        organization_id="org-a",
        credential_template_id="template-a",
        oid4vci_client_id=CLIENT_ID,
    )
    await repo.save_transaction(transaction)
    monkeypatch.setattr(
        routes,
        "oid4vci_create_token_response",
        lambda _code, _lifetime: {
            "access_token": "access-token",
            "expires_in": 1800,
        },
    )

    missing = await routes.exchange_token(
        http_request=_token_request(),
        grant_type="urn:ietf:params:oauth:grant-type:pre-authorized_code",
        pre_authorized_code=transaction.pre_auth_code,
        code=None,
        redirect_uri=None,
        client_id=CLIENT_ID,
        code_verifier=None,
        client_assertion_type=None,
        client_assertion=None,
        repo=repo,
    )
    still_pending = await repo.get_transaction(transaction.id)
    audience = routes.org_issuer_url("org-a")
    accepted = await routes.exchange_token(
        http_request=_token_request(),
        grant_type="urn:ietf:params:oauth:grant-type:pre-authorized_code",
        pre_authorized_code=transaction.pre_auth_code,
        code=None,
        redirect_uri=None,
        client_id=CLIENT_ID,
        code_verifier=None,
        client_assertion_type=JWT_BEARER_ASSERTION_TYPE,
        client_assertion=_assertion(
            private_key,
            claims={"aud": audience},
            now=datetime.now(UTC),
        ),
        repo=repo,
    )
    authorized = await repo.get_transaction(transaction.id)

    assert missing.status_code == 401
    assert still_pending is not None
    assert still_pending.status == IssuanceStatus.PENDING
    assert accepted.access_token == "access-token"
    assert authorized is not None
    assert authorized.status == IssuanceStatus.AUTHORIZED
