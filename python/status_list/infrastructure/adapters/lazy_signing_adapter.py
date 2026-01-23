"""Lazy-loading wrapper for signing adapter.

Implements the SigningServicePort protocol with on-demand key loading
from the issuer key registry. Follows the lazy-loading pattern from
marty_plugin/adapters/__init__.py for consistency with codebase patterns.
"""

import logging
from typing import Callable, Dict, Optional

from status_list.application.ports.outbound import SigningServicePort
from status_list.infrastructure.adapters.issuer_key_registry import IssuerKeyRegistry
from status_list.infrastructure.adapters.signing_adapter import RustSigningAdapter

logger = logging.getLogger(__name__)


class LazySigningAdapter(SigningServicePort):
    """Lazy-loading wrapper for RustSigningAdapter.
    
    Loads issuer keys on-demand from IssuerKeyRegistry when signing
    operations are requested. Caches keys in the underlying adapter
    for subsequent operations.
    
    Pattern: Follows lazy-loading decorator pattern used throughout
    the codebase (see marty_plugin/adapters, integration services).
    
    Example:
        def create_registry() -> IssuerKeyRegistry:
            return IssuerKeyRegistry(session_factory, encryption)
        
        adapter = LazySigningAdapter(
            key_registry_factory=create_registry,
            default_cryptosuite="eddsa-rdfc-2022",
        )
        
        signed = await adapter.sign_credential(credential, "did:web:example.com")
    """
    
    def __init__(
        self,
        key_registry_factory: Callable[[], IssuerKeyRegistry],
        default_proof_type: str = "DataIntegrityProof",
        default_cryptosuite: str = "eddsa-rdfc-2022",
    ):
        """Initialize lazy signing adapter.
        
        Args:
            key_registry_factory: Factory function to create key registry
            default_proof_type: Default proof type for signatures
            default_cryptosuite: Default cryptographic suite
        """
        self._key_registry_factory = key_registry_factory
        self._key_registry: Optional[IssuerKeyRegistry] = None
        self._issuer_cache: Dict[str, Dict] = {}  # Shared with RustSigningAdapter
        
        # Underlying adapter (created lazily)
        self._adapter: Optional[RustSigningAdapter] = None
        self._default_proof_type = default_proof_type
        self._default_cryptosuite = default_cryptosuite
        
        logger.info("Lazy signing adapter initialized with on-demand key loading")
    
    def _ensure_key_registry(self) -> IssuerKeyRegistry:
        """Lazy-create key registry on first use.
        
        Returns:
            IssuerKeyRegistry instance
        """
        if self._key_registry is None:
            self._key_registry = self._key_registry_factory()
            logger.debug("Key registry created via factory")
        return self._key_registry
    
    def _ensure_adapter(self) -> RustSigningAdapter:
        """Lazy-create underlying adapter with shared registry.
        
        Returns:
            RustSigningAdapter instance
        """
        if self._adapter is None:
            self._adapter = RustSigningAdapter(
                issuer_registry=self._issuer_cache,  # Shared dict
                default_proof_type=self._default_proof_type,
                default_cryptosuite=self._default_cryptosuite,
            )
            logger.debug("Rust signing adapter created")
        return self._adapter
    
    async def _load_issuer_key(self, issuer_id: str) -> None:
        """Load issuer key on-demand from registry.
        
        Keys are loaded once and cached in the shared issuer_cache
        dictionary that the underlying RustSigningAdapter uses.
        
        Args:
            issuer_id: Issuer identifier (DID or organization ID)
            
        Raises:
            ValueError: If key not found or loading fails
        """
        # Check if already loaded
        if issuer_id in self._issuer_cache:
            logger.debug(f"Issuer key already loaded: {issuer_id}")
            return
        
        logger.info(f"Loading issuer key on-demand: {issuer_id}")
        
        # Get key registry
        registry = self._ensure_key_registry()
        
        # Load key material from registry
        try:
            key_material = await registry.get_key_for_issuer(issuer_id)
        except Exception as e:
            logger.error(f"Failed to load key for issuer {issuer_id}: {e}")
            raise ValueError(f"Failed to load signing key: {e}")
        
        # Populate shared cache for RustSigningAdapter
        self._issuer_cache[issuer_id] = {
            "did": key_material["did"],
            "private_key": key_material["private_key"],
            "default_key_id": key_material.get("default_key_id", "key-1"),
        }
        
        logger.info(f"Issuer key loaded and cached: {issuer_id}")
    
    async def sign_credential(
        self,
        credential: dict,
        issuer_id: str,
        key_id: Optional[str] = None,
    ) -> dict:
        """Sign credential with lazy key loading.
        
        Args:
            credential: Unsigned credential dictionary
            issuer_id: Issuer identifier for key lookup
            key_id: Optional specific key ID (uses default if not provided)
            
        Returns:
            Signed credential with Data Integrity proof
            
        Raises:
            ValueError: If key not found or signing fails
        """
        # Load key if not already cached
        await self._load_issuer_key(issuer_id)
        
        # Delegate to underlying adapter
        adapter = self._ensure_adapter()
        return await adapter.sign_credential(credential, issuer_id, key_id)
    
    async def get_issuer_did(self, issuer_id: str) -> str:
        """Get issuer DID with lazy loading.
        
        Args:
            issuer_id: Issuer identifier
            
        Returns:
            DID string
        """
        await self._load_issuer_key(issuer_id)
        adapter = self._ensure_adapter()
        return await adapter.get_issuer_did(issuer_id)
    
    async def get_verification_method(
        self,
        issuer_id: str,
        key_id: Optional[str] = None,
    ) -> str:
        """Get verification method with lazy loading.
        
        Args:
            issuer_id: Issuer identifier
            key_id: Optional specific key ID
            
        Returns:
            Verification method URI
        """
        await self._load_issuer_key(issuer_id)
        adapter = self._ensure_adapter()
        return await adapter.get_verification_method(issuer_id, key_id)
    
    def get_cached_issuer_ids(self) -> list[str]:
        """Get list of issuer IDs currently loaded.
        
        Returns:
            List of cached issuer IDs
        """
        return list(self._issuer_cache.keys())
    
    def clear_cache(self, issuer_id: Optional[str] = None) -> None:
        """Clear cached keys.
        
        Args:
            issuer_id: If provided, clear only this issuer. Otherwise clear all.
        """
        if issuer_id:
            self._issuer_cache.pop(issuer_id, None)
            logger.info(f"Cleared cache for issuer: {issuer_id}")
        else:
            self._issuer_cache.clear()
            logger.info("Cleared all cached issuer keys")
        
        # Also clear registry cache if available
        if self._key_registry:
            self._key_registry.clear_cache(issuer_id)
