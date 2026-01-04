"""
Rust Adapter

This module provides adapters implementing the credential ports using the
marty-rs Rust library via PyO3 bindings.

The Rust implementation provides high-performance cryptographic operations
for OID4VCI/OID4VP credential flows using the SSI library.
"""

from marty_credentials.adapters.rust.adapter import (
    RustCredentialIssuer,
    RustCredentialVerifier,
    RustCredentialWallet,
    RustKeyManager,
    get_issuer,
    get_key_manager,
    get_verifier,
    get_wallet,
)

__all__ = [
    "RustKeyManager",
    "RustCredentialIssuer",
    "RustCredentialWallet",
    "RustCredentialVerifier",
    "get_key_manager",
    "get_issuer",
    "get_wallet",
    "get_verifier",
]
