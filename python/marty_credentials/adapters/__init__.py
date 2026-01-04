"""
Credential Adapters

Concrete implementations of credential ports for various libraries and services.

Available adapters:
- rust: High-performance OID4VCI/OID4VP and mDoc/mDL via marty-rs (Rust FFI)
- persistence: SQLAlchemy database layer (wraps other adapters)
"""

# Adapters are imported as needed to avoid heavy dependencies
# from marty_credentials.adapters.rust import RustKeyManager, RustCredentialIssuer
# from marty_credentials.adapters.rust import RustMdocIssuer, RustMdocPresenter
# from marty_credentials.adapters.persistence import SQLAlchemyCredentialWallet

__all__: list[str] = []
