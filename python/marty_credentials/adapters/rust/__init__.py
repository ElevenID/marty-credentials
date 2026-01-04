"""
Rust Adapter

This module provides adapters implementing the credential ports using the
marty-rs Rust library via PyO3 bindings.

The Rust implementation provides high-performance cryptographic operations
for OID4VCI/OID4VP credential flows using the SSI library, as well as
ISO 18013-5 mDoc/mDL issuance and presentation.
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
from marty_credentials.adapters.rust.mdoc import (
    MdocCredential,
    PreparedMdoc,
    RustMdocIssuer,
    RustMdocPresenter,
    get_mdoc_issuer,
    get_mdoc_presenter,
)

__all__ = [
    # OID4VCI/OID4VP adapters
    "RustKeyManager",
    "RustCredentialIssuer",
    "RustCredentialWallet",
    "RustCredentialVerifier",
    "get_key_manager",
    "get_issuer",
    "get_wallet",
    "get_verifier",
    # mDoc/mDL adapters
    "MdocCredential",
    "PreparedMdoc",
    "RustMdocIssuer",
    "RustMdocPresenter",
    "get_mdoc_issuer",
    "get_mdoc_presenter",
]
