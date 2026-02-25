"""
Credential Ports

Re-exported from mmf.core.credentials — MMF is the single source of truth
for port interfaces and domain types. This module provides backward compatibility
for existing imports from marty_credentials.ports.
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
