"""Credential port interfaces for marty-credentials.

Inlined from mmf.core.credentials.ports to avoid requiring
the full marty-microservices-framework as a dependency.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class CredentialFormat(Enum):
    """Supported credential formats."""

    JWT_VC = "jwt_vc_json"
    JWT_VC_JSON_LD = "jwt_vc_json-ld"
    LDP_VC = "ldp_vc"
    SD_JWT_VC = "vc+sd-jwt"
    MDOC = "mso_mdoc"


class KeyAlgorithm(Enum):
    """Supported key algorithms."""

    ES256 = "ES256"
    ES256K = "ES256K"
    EDDSA = "EdDSA"


@dataclass
class KeyPair:
    """Represents a cryptographic key pair."""

    did: str
    jwk_json: str
    algorithm: KeyAlgorithm
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CredentialSubject:
    """Credential subject with claims."""

    id: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class CredentialData:
    """Verifiable Credential data."""

    id: str
    types: list[str]
    issuer: str
    subject: CredentialSubject
    issuance_date: datetime
    expiration_date: datetime | None = None
    jwt: str | None = None


@dataclass
class CredentialOffer:
    """OID4VCI credential offer."""

    credential_issuer: str
    credential_types: list[str]
    offer_id: str
    pre_authorized_code: str | None = None
    user_pin_required: bool = False
    offer_uri: str | None = None
    offer_json: str | None = None


@dataclass
class PresentationRequest:
    """Presentation request from a verifier."""

    request_id: str
    verifier: str
    requested_credentials: list[str]
    nonce: str
    audience: str


@dataclass
class VerificationResult:
    """Result of credential or presentation verification."""

    valid: bool
    claims: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    issuer: str | None = None


@dataclass
class ZkChallengeSession:
    """Zero-knowledge proof challenge session."""

    session_id: str
    nonce: bytes
    doctype: str
    expires_at: datetime
    verifier_id: str


@runtime_checkable
class IKeyManager(Protocol):
    """Interface for cryptographic key management."""

    def generate_key(self, algorithm: KeyAlgorithm = KeyAlgorithm.ES256) -> KeyPair: ...
    def store_key(self, key_id: str, key_pair: KeyPair) -> None: ...
    def get_key(self, key_id: str) -> KeyPair | None: ...
    def list_keys(self) -> list[str]: ...


@runtime_checkable
class ICredentialIssuer(Protocol):
    """Interface for credential issuance."""

    def create_credential(
        self,
        issuer_key: KeyPair,
        credential_type: str,
        subject: CredentialSubject,
        expiration_seconds: int | None = None,
    ) -> CredentialData: ...

    def create_offer(
        self,
        issuer_url: str,
        credential_types: list[str],
        pre_authorized: bool = True,
        user_pin_required: bool = False,
        wallet_format: str = "standard",
    ) -> CredentialOffer: ...

    def generate_issuer_metadata(
        self,
        issuer_url: str,
        issuer_name: str,
        supported_credentials: list[dict[str, Any]],
    ) -> str: ...


@runtime_checkable
class ICredentialWallet(Protocol):
    """Interface for credential wallet operations."""

    def store_credential(self, credential: CredentialData) -> str: ...
    def get_credential(self, credential_id: str) -> CredentialData | None: ...
    def list_credentials(self, credential_type: str | None = None) -> list[CredentialData]: ...

    def create_presentation(
        self,
        holder_key: KeyPair,
        credentials: list[CredentialData],
        audience: str,
        nonce: str | None = None,
    ) -> str: ...

    def redeem_offer(self, offer_uri: str, holder_key: KeyPair) -> CredentialData: ...


@runtime_checkable
class ICredentialVerifier(Protocol):
    """Interface for credential verification."""

    def verify_credential(
        self,
        credential_jwt: str,
        expected_issuer: str | None = None,
    ) -> VerificationResult: ...

    def verify_presentation(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None,
    ) -> VerificationResult: ...

    def create_presentation_request(
        self,
        verifier_id: str,
        requested_credentials: list[str],
    ) -> PresentationRequest: ...
