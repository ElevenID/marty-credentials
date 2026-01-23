"""
Status List Credential Service - Application Service

Handles generation and publishing of BitstringStatusListCredential
documents that verifiers fetch to check credential status.

This service creates signed Verifiable Credentials containing
the status list bitstring per W3C Bitstring Status List v1.0.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from status_list.domain.entities import Shard
from status_list.domain.value_objects import StatusPurpose, ShardConfig
from status_list.domain.events import StatusListPublishedEvent
from status_list.application.ports.outbound import (
    StatusListRepositoryPort,
    SigningServicePort,
    EventPublisherPort,
    CachePort,
    ObjectStoragePort,
)

logger = logging.getLogger(__name__)


# JSON-LD contexts for status list credentials
STATUS_LIST_CONTEXTS = [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/vc/status-list/2021/v1",
]


class StatusListCredentialService:
    """
    Application service for status list credential operations.
    
    Generates and publishes BitstringStatusListCredential documents
    that verifiers use to check the status of issued credentials.
    
    Attributes:
        _status_list_repo: Repository for status lists
        _signing_service: Service for signing credentials
        _event_publisher: Publisher for domain events
        _cache: Optional cache for signed credentials
        _storage: Optional object storage for persistence
        _base_url: Base URL for status list endpoints
        _config: Shard configuration
    """
    
    def __init__(
        self,
        status_list_repository: StatusListRepositoryPort,
        signing_service: SigningServicePort,
        base_url: str,
        event_publisher: Optional[EventPublisherPort] = None,
        cache: Optional[CachePort] = None,
        storage: Optional[ObjectStoragePort] = None,
        config: Optional[ShardConfig] = None,
    ) -> None:
        """
        Initialize the service.
        
        Args:
            status_list_repository: Repository for status lists
            signing_service: Service for signing credentials
            base_url: Base URL for status list endpoints
            event_publisher: Optional event publisher
            cache: Optional cache for signed credentials
            storage: Optional object storage
            config: Optional shard configuration
        """
        self._status_list_repo = status_list_repository
        self._signing_service = signing_service
        self._base_url = base_url.rstrip("/")
        self._event_publisher = event_publisher
        self._cache = cache
        self._storage = storage
        self._config = config or ShardConfig()
    
    def _build_credential_id(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> str:
        """Build the credential ID URL."""
        return f"{self._base_url}/v3/status/{issuer_id}/{purpose.value}/{shard_index}"
    
    def _build_cache_key(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> str:
        """Build the cache key for a status list credential."""
        return f"status_list:{issuer_id}:{purpose.value}:{shard_index}"
    
    def _build_storage_key(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> str:
        """Build the storage key for a status list credential."""
        return f"status/{issuer_id}/{purpose.value}/{shard_index}.json"
    
    async def generate_status_list_credential(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> dict:
        """
        Generate a signed status list credential.
        
        Creates a BitstringStatusListCredential containing the
        current state of the specified shard, signed with
        Data Integrity proof.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            Signed BitstringStatusListCredential as dict
            
        Raises:
            ValueError: If shard not found
        """
        # Get the shard
        shard = await self._status_list_repo.get_shard(
            issuer_id, purpose, shard_index
        )
        if shard is None:
            raise ValueError(
                f"Shard {shard_index} not found for issuer {issuer_id} "
                f"purpose {purpose}"
            )
        
        # Build the unsigned credential
        credential_id = self._build_credential_id(issuer_id, purpose, shard_index)
        issuer_did = await self._signing_service.get_issuer_did(issuer_id)
        
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(seconds=self._config.cache_ttl_seconds * 2)
        
        unsigned_credential = {
            "@context": STATUS_LIST_CONTEXTS,
            "id": credential_id,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": issuer_did,
            "validFrom": now.isoformat(),
            "validUntil": valid_until.isoformat(),
            "credentialSubject": {
                "id": f"{credential_id}#list",
                "type": "BitstringStatusList",
                "statusPurpose": str(purpose),
                "encodedList": shard.encoded_list,
            },
        }
        
        # Sign the credential
        signed_credential = await self._signing_service.sign_credential(
            credential=unsigned_credential,
            issuer_id=issuer_id,
        )
        
        logger.debug(
            "Generated status list credential for issuer %s purpose %s shard %d",
            issuer_id,
            purpose,
            shard_index,
        )
        
        return signed_credential
    
    async def publish_status_list_credential(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> str:
        """
        Publish an updated status list credential.
        
        Generates a new signed credential, caches it, and optionally
        stores it in object storage for durability.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            URL where the credential is published
        """
        # Generate the signed credential
        credential = await self.generate_status_list_credential(
            issuer_id, purpose, shard_index
        )
        
        credential_json = json.dumps(credential, separators=(",", ":"))
        credential_bytes = credential_json.encode("utf-8")
        
        # Cache the credential
        if self._cache:
            cache_key = self._build_cache_key(issuer_id, purpose, shard_index)
            await self._cache.set(
                key=cache_key,
                value=credential_bytes,
                ttl_seconds=self._config.cache_ttl_seconds,
            )
            logger.debug("Cached status list credential at %s", cache_key)
        
        # Store in object storage
        if self._storage:
            storage_key = self._build_storage_key(issuer_id, purpose, shard_index)
            await self._storage.put(
                bucket="status-lists",
                key=storage_key,
                data=credential_bytes,
                content_type="application/json",
                metadata={
                    "issuer_id": issuer_id,
                    "purpose": str(purpose),
                    "shard_index": str(shard_index),
                },
            )
            logger.debug("Stored status list credential at %s", storage_key)
        
        # Get shard for version info
        shard = await self._status_list_repo.get_shard(
            issuer_id, purpose, shard_index
        )
        
        # Publish event
        if self._event_publisher:
            credential_url = self._build_credential_id(issuer_id, purpose, shard_index)
            event = StatusListPublishedEvent(
                status_list_id=f"{issuer_id}:{purpose.value}",
                issuer_id=issuer_id,
                purpose=purpose,
                shard_index=shard_index,
                credential_url=credential_url,
                version=shard.version if shard else 1,
            )
            await self._event_publisher.publish(event)
        
        url = self._build_credential_id(issuer_id, purpose, shard_index)
        logger.info("Published status list credential at %s", url)
        
        return url
    
    async def get_published_credential(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> Optional[dict]:
        """
        Get a previously published status list credential.
        
        Checks cache first, then storage, then generates fresh
        if not found.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            The published credential if found, None if shard doesn't exist
        """
        # Try cache first
        if self._cache:
            cache_key = self._build_cache_key(issuer_id, purpose, shard_index)
            cached = await self._cache.get(cache_key)
            if cached:
                logger.debug("Cache hit for status list credential %s", cache_key)
                return json.loads(cached.decode("utf-8"))
        
        # Try storage
        if self._storage:
            storage_key = self._build_storage_key(issuer_id, purpose, shard_index)
            stored = await self._storage.get("status-lists", storage_key)
            if stored:
                logger.debug("Storage hit for status list credential %s", storage_key)
                credential = json.loads(stored.decode("utf-8"))
                
                # Refresh cache
                if self._cache:
                    cache_key = self._build_cache_key(issuer_id, purpose, shard_index)
                    await self._cache.set(
                        key=cache_key,
                        value=stored,
                        ttl_seconds=self._config.cache_ttl_seconds,
                    )
                
                return credential
        
        # Generate fresh if shard exists
        shard = await self._status_list_repo.get_shard(
            issuer_id, purpose, shard_index
        )
        if shard is None:
            return None
        
        logger.debug(
            "Generating fresh status list credential for %s/%s/%d",
            issuer_id,
            purpose,
            shard_index,
        )
        
        return await self.generate_status_list_credential(
            issuer_id, purpose, shard_index
        )
    
    async def invalidate_cached_credential(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> bool:
        """
        Invalidate a cached status list credential.
        
        Called when status is updated to ensure fresh credential
        is served on next request.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            True if invalidated, False if not cached
        """
        if not self._cache:
            return False
        
        cache_key = self._build_cache_key(issuer_id, purpose, shard_index)
        return await self._cache.delete(cache_key)
