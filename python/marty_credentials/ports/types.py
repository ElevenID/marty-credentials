"""
Core types for credential operations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class CredentialFormat(Enum):
    """Supported credential formats."""

    JWT_VC = "jwt_vc_json"
    JWT_VC_JSON_LD = "jwt_vc_json-ld"
    LDP_VC = "ldp_vc"
    SD_JWT_VC = "vc+sd-jwt"
    MDOC = "mso_mdoc"


class KeyAlgorithm(Enum):
    """Supported key algorithms."""

    # ECDSA algorithms
    ES256 = "ES256"  # P-256
    ES256K = "ES256K"  # secp256k1
    ES384 = "ES384"  # P-384
    ES512 = "ES512"  # P-521
    
    # EdDSA
    EDDSA = "EdDSA"  # Ed25519
    
    # RSA PKCS#1 v1.5 algorithms
    RS256 = "RS256"  # RSA 2048-bit with SHA-256
    RS384 = "RS384"  # RSA 3072-bit with SHA-384
    RS512 = "RS512"  # RSA 4096-bit with SHA-512
    
    # RSA-PSS algorithms
    PS256 = "PS256"  # RSA-PSS 2048-bit with SHA-256
    PS384 = "PS384"  # RSA-PSS 3072-bit with SHA-384
    PS512 = "PS512"  # RSA-PSS 4096-bit with SHA-512


@dataclass
class KeyPair:
    """Represents a cryptographic key pair."""

    did: str
    """Decentralized identifier derived from the key."""

    jwk_json: str
    """JWK representation of the key pair (includes private key)."""

    algorithm: KeyAlgorithm
    """Signing algorithm for this key."""

    created_at: datetime = field(default_factory=datetime.utcnow)
    """When the key was created."""


@dataclass
class CredentialSubject:
    """Credential subject with claims."""

    id: str | None = None
    """Subject identifier (usually a DID)."""

    claims: dict[str, Any] = field(default_factory=dict)
    """Claims about the subject."""


@dataclass
class CredentialData:
    """Verifiable Credential data."""

    id: str
    """Unique credential identifier (urn:uuid:...)."""

    types: list[str]
    """Credential types (always includes VerifiableCredential)."""

    issuer: str
    """Issuer DID."""

    subject: CredentialSubject
    """Credential subject and claims."""

    issuance_date: datetime
    """When the credential was issued."""

    expiration_date: datetime | None = None
    """When the credential expires (optional)."""

    jwt: str | None = None
    """Signed JWT representation."""


@dataclass
class CredentialOffer:
    """OID4VCI credential offer."""

    credential_issuer: str
    """URL of the credential issuer."""

    credential_types: list[str]
    """Types of credentials offered."""

    offer_id: str
    """Unique offer identifier."""

    pre_authorized_code: str | None = None
    """Pre-authorized code for direct issuance."""

    user_pin_required: bool = False
    """Whether a user PIN is required."""

    offer_uri: str | None = None
    """Full offer URI for QR code."""

    offer_json: str | None = None
    """Full offer JSON."""


@dataclass
class PresentationRequest:
    """Presentation request from a verifier."""

    request_id: str
    """Unique request identifier."""

    verifier: str
    """Verifier identifier."""

    requested_credentials: list[str]
    """Types of credentials requested."""

    nonce: str
    """Cryptographic nonce."""

    audience: str
    """Expected audience for the presentation."""


@dataclass
class VerificationResult:
    """Result of credential or presentation verification."""

    valid: bool
    """Whether verification succeeded."""

    claims: dict[str, Any] = field(default_factory=dict)
    """Extracted claims from the verified credential."""

    error: str | None = None
    """Error message if verification failed."""

    issuer: str | None = None
    """Verified issuer if available."""
    
    verification_method: str | None = None
    """Verification method used (e.g., 'zk_ligero', 'ecdsa_p256')."""


@dataclass
class ZkChallengeSession:
    """ZK proof challenge session for interactive verification."""

    session_id: str
    """Unique session identifier."""

    nonce: bytes
    """Cryptographic nonce for the proof."""

    doctype: str
    """mDoc document type (e.g., 'org.iso.18013.5.1.mDL')."""

    expires_at: datetime
    """When this challenge session expires."""

    verifier_id: str | None = None
    """Verifier who initiated the challenge."""

    created_at: datetime = field(default_factory=datetime.utcnow)
    """When the session was created."""

    used: bool = False
    """Whether the nonce has been consumed."""
