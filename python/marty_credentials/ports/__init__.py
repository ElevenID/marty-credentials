"""
Credential Ports

Port interfaces and domain types for credential operations.
"""

from marty_credentials.ports.types import (
    CredentialData,
    CredentialFormat,
    CredentialOffer,
    CredentialSubject,
    KeyAlgorithm,
    KeyPair,
    PresentationRequest,
    VerificationResult,
    ZkChallengeSession,
)
from marty_credentials.ports.issuer import ICredentialIssuer
from marty_credentials.ports.key_manager import IKeyManager
from marty_credentials.ports.verifier import ICredentialVerifier
from marty_credentials.ports.wallet import ICredentialWallet

__all__ = [
    # Types
    "CredentialData",
    "CredentialFormat",
    "CredentialOffer",
    "CredentialSubject",
    "KeyAlgorithm",
    "KeyPair",
    "PresentationRequest",
    "VerificationResult",
    "ZkChallengeSession",
    # Ports
    "ICredentialIssuer",
    "ICredentialVerifier",
    "ICredentialWallet",
    "IKeyManager",
]
