"""
Credential Adapters - Marty Application Layer

This module provides credential adapter implementations for the Marty credential manager.
The Python adapter factory only provides wallet and verifier helpers. Issuer
signing belongs to the remote-KMS-backed native service.
"""

import logging
import os
from enum import Enum

logger = logging.getLogger(__name__)


class AdapterMode(Enum):
    SPRUCEID = "spruceid"
    MULTIPAZ = "multipaz"


def get_adapter_mode() -> AdapterMode:
    """Get the configured adapter mode."""
    mode = os.getenv("ADAPTER_MODE", "spruceid").lower()
    if mode == "multipaz":
        return AdapterMode.MULTIPAZ
    return AdapterMode.SPRUCEID


def get_storage_mode() -> str:
    """Get the configured storage mode."""
    return os.getenv("STORAGE_MODE", "memory").lower()


# Lazy imports to avoid circular dependencies and optional dependency issues
_spruceid_loaded = False
_multipaz_loaded = False
_persistence_loaded = False

_SpruceIDCredentialWallet = None
_SpruceIDCredentialVerifier = None

_MultipazCredentialWallet = None
_MultipazCredentialVerifier = None

_SQLAlchemyCredentialWallet = None


def _load_spruceid():
    """Lazy load SpruceID adapters."""
    global _spruceid_loaded
    global _SpruceIDCredentialWallet, _SpruceIDCredentialVerifier

    if _spruceid_loaded:
        return True

    try:
        from .spruceid import (
            SpruceIDCredentialVerifier,
            SpruceIDCredentialWallet,
        )

        _SpruceIDCredentialWallet = SpruceIDCredentialWallet
        _SpruceIDCredentialVerifier = SpruceIDCredentialVerifier
        _spruceid_loaded = True
        return True
    except ImportError as e:
        logger.warning(f"SpruceID adapters not available: {e}")
        return False


def _load_multipaz():
    """Lazy load Multipaz adapters."""
    global _multipaz_loaded
    global _MultipazCredentialWallet, _MultipazCredentialVerifier

    if _multipaz_loaded:
        return True

    try:
        from .multipaz import (
            MultipazCredentialVerifier,
            MultipazCredentialWallet,
        )

        _MultipazCredentialWallet = MultipazCredentialWallet
        _MultipazCredentialVerifier = MultipazCredentialVerifier
        _multipaz_loaded = True
        return True
    except ImportError as e:
        logger.debug(f"Multipaz adapters not available: {e}")
        return False


def _load_persistence():
    """Lazy load persistence adapters."""
    global _persistence_loaded
    global _SQLAlchemyCredentialWallet

    if _persistence_loaded:
        return True

    try:
        from .persistence import SQLAlchemyCredentialWallet

        _SQLAlchemyCredentialWallet = SQLAlchemyCredentialWallet
        _persistence_loaded = True
        return True
    except ImportError as e:
        logger.debug(f"Persistence adapters not available: {e}")
        return False


# Singleton instances for wallet and verifier helpers
_wallet = None
_verifier = None


def _create_adapters():
    """Create adapter instances based on configuration."""
    mode = get_adapter_mode()

    if mode == AdapterMode.MULTIPAZ:
        if _load_multipaz():
            return _MultipazCredentialWallet(), _MultipazCredentialVerifier()
        raise RuntimeError("Multipaz adapters are unavailable")

    if _load_spruceid():
        return _SpruceIDCredentialWallet(), _SpruceIDCredentialVerifier()

    raise RuntimeError(
        "No credential adapters available. Install SpruceID or Multipaz dependencies."
    )


def _initialize_adapters():
    """Initialize singleton adapter instances."""
    global _wallet, _verifier

    if _wallet is not None:
        return

    mode = get_adapter_mode()
    storage = get_storage_mode()

    logger.info(f"Initializing credential adapters in {mode.value} mode with {storage} storage")

    _wallet, _verifier = _create_adapters()

    # TODO: Wrap with persistence if enabled
    if storage == "postgres" and _load_persistence():
        logger.info("Postgres storage available but not wired (requires session factory)")


def get_wallet():
    """Get the configured credential wallet instance."""
    _initialize_adapters()
    return _wallet


def get_verifier():
    """Get the configured credential verifier instance."""
    _initialize_adapters()
    return _verifier


# Factory functions for explicit instantiation
def create_wallet(mode: AdapterMode | None = None):
    """Create a new credential wallet instance."""
    mode = mode or get_adapter_mode()
    if mode == AdapterMode.MULTIPAZ:
        if _load_multipaz():
            return _MultipazCredentialWallet()
        raise RuntimeError("Multipaz wallet adapter is unavailable")
    if _load_spruceid():
        return _SpruceIDCredentialWallet()
    raise RuntimeError("No credential adapters available")


def create_verifier(mode: AdapterMode | None = None):
    """Create a new credential verifier instance."""
    mode = mode or get_adapter_mode()
    if mode == AdapterMode.MULTIPAZ:
        if _load_multipaz():
            return _MultipazCredentialVerifier()
        raise RuntimeError("Multipaz verifier adapter is unavailable")
    if _load_spruceid():
        return _SpruceIDCredentialVerifier()
    raise RuntimeError("No credential adapters available")


__all__ = [
    # Enums
    "AdapterMode",
    # Configuration
    "get_adapter_mode",
    "get_storage_mode",
    # Singleton accessors
    "get_wallet",
    "get_verifier",
    # Factory functions
    "create_wallet",
    "create_verifier",
]
