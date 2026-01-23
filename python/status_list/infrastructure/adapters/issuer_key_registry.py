"""Issuer key registry for lazy-loading signing keys from database.

Provides on-demand loading and caching of issuer keys for status list signing.
Keys are loaded from IssuerKeyConfig table and decrypted as needed.
"""

import json
import logging
from typing import Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from status_list.infrastructure.security import SymmetricEncryption

logger = logging.getLogger(__name__)


class IssuerKeyRegistry:
    """Lazy-loading registry for issuer signing keys.
    
    Loads keys from IssuerKeyConfig table on-demand and caches them
    in memory for subsequent signing operations.
    
    Example:
        registry = IssuerKeyRegistry(session_factory, encryption_service)
        key_material = await registry.get_key_for_issuer("did:web:example.com")
    """
    
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        encryption_service: SymmetricEncryption,
    ):
        """Initialize registry with database and encryption services.
        
        Args:
            session_factory: Async session factory for database access
            encryption_service: Service for decrypting private keys
        """
        self._session_factory = session_factory
        self._encryption = encryption_service
        self._cache: Dict[str, Dict] = {}  # issuer_id -> key material
        logger.info("Issuer key registry initialized")
    
    async def get_key_for_issuer(self, issuer_id: str) -> Dict:
        """Get key material for issuer (lazy-loaded and cached).
        
        Args:
            issuer_id: Issuer identifier (typically DID or organization ID)
            
        Returns:
            Dictionary with key material:
            {
                "did": "did:web:example.com",
                "private_key": {"kty": "EC", "d": "...", ...},
                "public_key": {"kty": "EC", "x": "...", ...},
                "default_key_id": "key-1"
            }
            
        Raises:
            ValueError: If no key found for issuer or decryption fails
        """
        # Check memory cache first
        if issuer_id in self._cache:
            logger.debug(f"Cache hit for issuer: {issuer_id}")
            return self._cache[issuer_id]
        
        # Load from database
        logger.info(f"Loading key from database for issuer: {issuer_id}")
        key_material = await self._load_from_database(issuer_id)
        
        # Cache for future use
        self._cache[issuer_id] = key_material
        return key_material
    
    async def _load_from_database(self, issuer_id: str) -> Dict:
        """Load issuer key from IssuerKeyConfig table.
        
        Args:
            issuer_id: Issuer DID to look up
            
        Returns:
            Key material dictionary
            
        Raises:
            ValueError: If key not found or invalid
        """
        # Import here to avoid circular dependencies
        from subscription.models import IssuerKeyConfig
        
        async with self._session_factory() as session:
            # Query by issuer_did field
            stmt = select(IssuerKeyConfig).where(
                IssuerKeyConfig.did == issuer_id,
                IssuerKeyConfig.is_active == True,
            )
            result = await session.execute(stmt)
            config = result.scalar_one_or_none()
            
            if not config:
                raise ValueError(
                    f"No active key configuration found for issuer: {issuer_id}"
                )
            
            # Decrypt private key
            if not config.jwk_private_encrypted:
                raise ValueError(
                    f"No encrypted private key found for issuer: {issuer_id}"
                )
            
            try:
                private_jwk_json = self._encryption.decrypt(config.jwk_private_encrypted)
                private_jwk = json.loads(private_jwk_json)
            except Exception as e:
                logger.error(f"Failed to decrypt private key for {issuer_id}: {e}")
                raise ValueError(f"Failed to decrypt private key: {e}")
            
            # Return key material in expected format
            return {
                "did": config.did,
                "private_key": private_jwk,
                "public_key": config.jwk_public or {},
                "default_key_id": config.key_id or "key-1",
            }
    
    def clear_cache(self, issuer_id: Optional[str] = None) -> None:
        """Clear cached keys.
        
        Args:
            issuer_id: If provided, clear only this issuer. Otherwise clear all.
        """
        if issuer_id:
            self._cache.pop(issuer_id, None)
            logger.info(f"Cleared cache for issuer: {issuer_id}")
        else:
            self._cache.clear()
            logger.info("Cleared all cached issuer keys")
    
    def get_cached_issuer_ids(self) -> list[str]:
        """Get list of issuer IDs currently in cache.
        
        Returns:
            List of cached issuer IDs
        """
        return list(self._cache.keys())
