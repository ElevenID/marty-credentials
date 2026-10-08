"""
Rust Adapter

This module provides adapters implementing the credential ports using the
marty-rs Rust library via PyO3 bindings.

The Rust implementation provides OID4VCI/OID4VP credential adapters and
legacy mDoc presentation request helpers.
"""

from marty_credentials.adapters.rust.adapter import (
    RustCredentialVerifier,
    RustCredentialWallet,
    get_verifier,
    get_wallet,
)
from marty_credentials.adapters.rust.mdoc import (
    MdocCredential,
    RustMdocPresenter,
    get_mdoc_presenter,
)

__all__ = [
    # OID4VCI/OID4VP adapters
    "RustCredentialWallet",
    "RustCredentialVerifier",
    "get_wallet",
    "get_verifier",
    # mDoc/mDL adapters
    "MdocCredential",
    "RustMdocPresenter",
    "get_mdoc_presenter",
]
