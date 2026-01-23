"""
Credential Adapters - Marty Application Layer

This module provides credential adapter implementations for the Marty credential manager.
These are vendor-specific implementations (SpruceID, Multipaz) that implement
MMF's credential port interfaces.

Architecture:
- MMF owns: IKeyManager, ICredentialIssuer, ICredentialWallet, ICredentialVerifier (ports)
- Marty owns: SpruceID, Multipaz implementations (adapters)

Key ID Namespacing:
- auth:* - MMF authentication keys (device identity, sessions)
- cred:* - Marty credential keys (issuer signing, holder binding)
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

_SpruceIDKeyManager = None
_SpruceIDCredentialIssuer = None
_SpruceIDCredentialWallet = None
_SpruceIDCredentialVerifier = None

_MultipazKeyManager = None
_MultipazCredentialIssuer = None
_MultipazCredentialWallet = None
_MultipazCredentialVerifier = None

_SQLAlchemyCredentialWallet = None
_SQLAlchemyKeyManager = None


def _load_spruceid():
    """Lazy load SpruceID adapters."""
    global _spruceid_loaded
    global _SpruceIDKeyManager, _SpruceIDCredentialIssuer
    global _SpruceIDCredentialWallet, _SpruceIDCredentialVerifier

    if _spruceid_loaded:
        return True

    try:
        from .spruceid import (
            SpruceIDCredentialIssuer,
            SpruceIDCredentialVerifier,
            SpruceIDCredentialWallet,
            SpruceIDKeyManager,
        )

        _SpruceIDKeyManager = SpruceIDKeyManager
        _SpruceIDCredentialIssuer = SpruceIDCredentialIssuer
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
    global _MultipazKeyManager, _MultipazCredentialIssuer
    global _MultipazCredentialWallet, _MultipazCredentialVerifier

    if _multipaz_loaded:
        return True

    try:
        from .multipaz import (
            MultipazCredentialIssuer,
            MultipazCredentialVerifier,
            MultipazCredentialWallet,
            MultipazKeyManager,
        )

        _MultipazKeyManager = MultipazKeyManager
        _MultipazCredentialIssuer = MultipazCredentialIssuer
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
    global _SQLAlchemyCredentialWallet, _SQLAlchemyKeyManager

    if _persistence_loaded:
        return True

    try:
        from .persistence import SQLAlchemyCredentialWallet, SQLAlchemyKeyManager

        _SQLAlchemyCredentialWallet = SQLAlchemyCredentialWallet
        _SQLAlchemyKeyManager = SQLAlchemyKeyManager
        _persistence_loaded = True
        return True
    except ImportError as e:
        logger.debug(f"Persistence adapters not available: {e}")
        return False


# Singleton instances for backward compatibility
_key_manager = None
_issuer = None
_wallet = None
_verifier = None


def _create_adapters():
    """Create adapter instances based on configuration."""
    mode = get_adapter_mode()

    if mode == AdapterMode.MULTIPAZ and _load_multipaz():
        return (
            _MultipazKeyManager(),
            _MultipazCredentialIssuer(),
            _MultipazCredentialWallet(),
            _MultipazCredentialVerifier(),
        )

    # Default to SpruceID
    if _load_spruceid():
        return (
            _SpruceIDKeyManager(),
            _SpruceIDCredentialIssuer(),
            _SpruceIDCredentialWallet(),
            _SpruceIDCredentialVerifier(),
        )

    raise RuntimeError("No credential adapters available. Install SpruceID or Multipaz dependencies.")


def _initialize_adapters():
    """Initialize singleton adapter instances."""
    global _key_manager, _issuer, _wallet, _verifier

    if _key_manager is not None:
        return

    mode = get_adapter_mode()
    storage = get_storage_mode()

    logger.info(f"Initializing credential adapters in {mode.value} mode with {storage} storage")

    _key_manager, _issuer, _wallet, _verifier = _create_adapters()

    # TODO: Wrap with persistence if enabled
    if storage == "postgres" and _load_persistence():
        logger.info("Postgres storage available but not wired (requires session factory)")


def get_key_manager():
    """Get the configured key manager instance."""
    _initialize_adapters()
    return _key_manager


def get_issuer():
    """Get the configured credential issuer instance."""
    _initialize_adapters()
    return _issuer


def get_wallet():
    """Get the configured credential wallet instance."""
    _initialize_adapters()
    return _wallet


def get_verifier():
    """Get the configured credential verifier instance."""
    _initialize_adapters()
    return _verifier


# Factory functions for explicit instantiation (preferred over singletons)
def create_key_manager(mode: AdapterMode | None = None):
    """Create a new key manager instance."""
    mode = mode or get_adapter_mode()
    if mode == AdapterMode.MULTIPAZ and _load_multipaz():
        return _MultipazKeyManager()
    if _load_spruceid():
        return _SpruceIDKeyManager()
    raise RuntimeError("No credential adapters available")


def create_issuer(mode: AdapterMode | None = None):
    """Create a new credential issuer instance."""
    mode = mode or get_adapter_mode()
    if mode == AdapterMode.MULTIPAZ and _load_multipaz():
        return _MultipazCredentialIssuer()
    if _load_spruceid():
        return _SpruceIDCredentialIssuer()
    raise RuntimeError("No credential adapters available")


def create_wallet(mode: AdapterMode | None = None):
    """Create a new credential wallet instance."""
    mode = mode or get_adapter_mode()
    if mode == AdapterMode.MULTIPAZ and _load_multipaz():
        return _MultipazCredentialWallet()
    if _load_spruceid():
        return _SpruceIDCredentialWallet()
    raise RuntimeError("No credential adapters available")


def create_verifier(mode: AdapterMode | None = None):
    """Create a new credential verifier instance."""
    mode = mode or get_adapter_mode()
    if mode == AdapterMode.MULTIPAZ and _load_multipaz():
        return _MultipazCredentialVerifier()
    if _load_spruceid():
        return _SpruceIDCredentialVerifier()
    raise RuntimeError("No credential adapters available")


__all__ = [
    # Enums
    "AdapterMode",
    # Configuration
    "get_adapter_mode",
    "get_storage_mode",
    # Singleton accessors (legacy compatibility)
    "get_key_manager",
    "get_issuer",
    "get_wallet",
    "get_verifier",
    # Factory functions (preferred)
    "create_key_manager",
    "create_issuer",
    "create_wallet",
    "create_verifier",
]
