"""
Marty Credentials

Credential domain logic and adapters for the Marty ecosystem.
"""

from marty_credentials.ports import (
    CredentialData,
    CredentialFormat,
    CredentialOffer,
    CredentialSubject,
    ICredentialIssuer,
    ICredentialVerifier,
    ICredentialWallet,
    IKeyManager,
    KeyAlgorithm,
    KeyPair,
    PresentationRequest,
    VerificationResult,
)

__all__ = [
    # Core types
    "CredentialData",
    "CredentialFormat",
    "CredentialOffer",
    "CredentialSubject",
    "KeyAlgorithm",
    "KeyPair",
    "PresentationRequest",
    "VerificationResult",
    # Port interfaces
    "ICredentialIssuer",
    "ICredentialVerifier",
    "ICredentialWallet",
    "IKeyManager",
]

__version__ = "0.1.0"
