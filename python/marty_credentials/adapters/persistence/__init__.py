"""
Persistence Adapter

SQLAlchemy-based persistence for credential management.
Wraps other adapters to add database persistence.
"""

from marty_credentials.adapters.persistence.adapter import (
    Base,
    CredentialModel,
    SQLAlchemyCredentialWallet,
)

__all__ = [
    "Base",
    "CredentialModel",
    "SQLAlchemyCredentialWallet",
]
