"""
Multipaz Adapter

Credential adapters for mDoc/mDL credentials (ISO 18013-5) using real
cryptographic operations compatible with OpenWallet Foundation Multipaz SDK.
"""

from marty_credentials.adapters.multipaz.adapter import (
    MultipazCredentialIssuer,
    MultipazCredentialVerifier,
    MultipazCredentialWallet,
    MultipazKeyManager,
    create_multipaz_adapters,
    get_issuer,
    get_key_manager,
    get_verifier,
    get_wallet,
)

__all__ = [
    "MultipazKeyManager",
    "MultipazCredentialIssuer",
    "MultipazCredentialWallet",
    "MultipazCredentialVerifier",
    "create_multipaz_adapters",
    "get_key_manager",
    "get_issuer",
    "get_wallet",
    "get_verifier",
]
