"""
Credential Ports

This module defines the interfaces for OID4VC credential operations following hexagonal architecture.
These ports define the boundary between the application core and external adapters (like SpruceID).
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
    # Ports
    "ICredentialIssuer",
    "ICredentialVerifier",
    "ICredentialWallet",
    "IKeyManager",
]
