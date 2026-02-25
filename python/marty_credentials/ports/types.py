"""
Core types for credential operations.

Re-exported from mmf.core.credentials.ports — MMF is the single source of truth
for port interfaces and domain types. This module provides backward compatibility.
"""

# Re-export all types from MMF to maintain backward compatibility
from mmf.core.credentials.ports import (  # noqa: F401
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

__all__ = [
    "CredentialData",
    "CredentialFormat",
    "CredentialOffer",
    "CredentialSubject",
    "KeyAlgorithm",
    "KeyPair",
    "PresentationRequest",
    "VerificationResult",
    "ZkChallengeSession",
]
