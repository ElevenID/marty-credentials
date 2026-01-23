"""
Outbound Ports (Driven Ports) for Status List

These protocols define the interfaces that the application layer
requires from infrastructure adapters (repositories, external services, etc.).
"""

from __future__ import annotations

from typing import Protocol, Optional, Any, runtime_checkable
from datetime import datetime

from status_list.domain.entities import StatusList, StatusEntry, Shard
from status_list.domain.value_objects import StatusPurpose
from status_list.domain.events import DomainEvent


@runtime_checkable
class StatusListRepositoryPort(Protocol):
    """
    Repository port for StatusList aggregate persistence.
    
    Handles storage and retrieval of StatusList aggregates
    including their shards.
    """
    
    async def save(self, status_list: StatusList) -> None:
        """
        Save a status list (create or update).
        
        Args:
            status_list: The StatusList to save
        """
        ...
    
    async def get(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
    ) -> Optional[StatusList]:
        """
        Get a status list by issuer and purpose.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            
        Returns:
            StatusList if found, None otherwise
        """
        ...
    
    async def get_by_id(self, status_list_id: str) -> Optional[StatusList]:
        """
        Get a status list by its ID.
        
        Args:
            status_list_id: The status list ID
            
        Returns:
            StatusList if found, None otherwise
        """
        ...
    
    async def list_by_issuer(self, issuer_id: str) -> list[StatusList]:
        """
        List all status lists for an issuer.
        
        Args:
            issuer_id: ID of the issuer
            
        Returns:
            List of StatusLists for the issuer
        """
        ...
    
    async def update_shard(self, shard: Shard) -> None:
        """
        Update a specific shard.
        
        Args:
            shard: The Shard to update
        """
        ...
    
    async def get_shard(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> Optional[Shard]:
        """
        Get a specific shard.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            Shard if found, None otherwise
        """
        ...


@runtime_checkable
class StatusEntryRepositoryPort(Protocol):
    """
    Repository port for StatusEntry persistence.
    
    Handles the mapping between credentials and their
    positions in status lists.
    """
    
    async def save(self, entry: StatusEntry) -> None:
        """
        Save a status entry.
        
        Args:
            entry: The StatusEntry to save
        """
        ...
    
    async def get_by_credential(
        self,
        credential_id: str,
        purpose: StatusPurpose,
    ) -> Optional[StatusEntry]:
        """
        Get a status entry by credential ID and purpose.
        
        Args:
            credential_id: ID of the credential
            purpose: revocation or suspension
            
        Returns:
            StatusEntry if found, None otherwise
        """
        ...
    
    async def get_all_for_credential(
        self,
        credential_id: str,
    ) -> list[StatusEntry]:
        """
        Get all status entries for a credential.
        
        Args:
            credential_id: ID of the credential
            
        Returns:
            List of StatusEntries (typically one per purpose)
        """
        ...
    
    async def list_by_shard(
        self,
        shard_id: str,
    ) -> list[StatusEntry]:
        """
        List all entries in a shard.
        
        Args:
            shard_id: ID of the shard
            
        Returns:
            List of StatusEntries in the shard
        """
        ...
    
    async def delete(self, entry_id: str) -> bool:
        """
        Delete a status entry.
        
        Args:
            entry_id: ID of the entry to delete
            
        Returns:
            True if deleted, False if not found
        """
        ...


@runtime_checkable
class SigningServicePort(Protocol):
    """
    Port for credential signing operations.
    
    Used to sign status list credentials with Data Integrity proofs.
    """
    
    async def sign_credential(
        self,
        credential: dict,
        issuer_id: str,
        key_id: Optional[str] = None,
    ) -> dict:
        """
        Sign a verifiable credential.
        
        Args:
            credential: The unsigned credential
            issuer_id: ID of the issuer
            key_id: Optional specific key to use
            
        Returns:
            The signed credential with proof
        """
        ...
    
    async def get_issuer_did(self, issuer_id: str) -> str:
        """
        Get the DID for an issuer.
        
        Args:
            issuer_id: ID of the issuer
            
        Returns:
            The issuer's DID
        """
        ...
    
    async def get_verification_method(
        self,
        issuer_id: str,
        key_id: Optional[str] = None,
    ) -> str:
        """
        Get the verification method URI for signing.
        
        Args:
            issuer_id: ID of the issuer
            key_id: Optional specific key
            
        Returns:
            Verification method URI
        """
        ...


@runtime_checkable
class EventPublisherPort(Protocol):
    """
    Port for publishing domain events.
    
    Enables loose coupling between the status list module
    and other parts of the system.
    """
    
    async def publish(self, event: DomainEvent) -> None:
        """
        Publish a domain event.
        
        Args:
            event: The event to publish
        """
        ...
    
    async def publish_batch(self, events: list[DomainEvent]) -> None:
        """
        Publish multiple events.
        
        Args:
            events: List of events to publish
        """
        ...


@runtime_checkable
class CachePort(Protocol):
    """
    Port for caching operations.
    
    Used to cache signed status list credentials for
    efficient serving to verifiers.
    """
    
    async def get(self, key: str) -> Optional[bytes]:
        """
        Get a cached value.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value if found, None otherwise
        """
        ...
    
    async def set(
        self,
        key: str,
        value: bytes,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """
        Set a cached value.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl_seconds: Optional TTL in seconds
        """
        ...
    
    async def delete(self, key: str) -> bool:
        """
        Delete a cached value.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted, False if not found
        """
        ...
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate all keys matching a pattern.
        
        Args:
            pattern: Key pattern (e.g., "status:issuer123:*")
            
        Returns:
            Number of keys invalidated
        """
        ...


@runtime_checkable
class ObjectStoragePort(Protocol):
    """
    Port for object storage operations.
    
    Used to store and retrieve status list credentials
    for long-term persistence and serving.
    """
    
    async def put(
        self,
        bucket: str,
        key: str,
        data: bytes,
        content_type: str = "application/json",
        metadata: Optional[dict[str, str]] = None,
    ) -> str:
        """
        Store an object.
        
        Args:
            bucket: Storage bucket
            key: Object key
            data: Object data
            content_type: MIME type
            metadata: Optional metadata
            
        Returns:
            URL of the stored object
        """
        ...
    
    async def get(self, bucket: str, key: str) -> Optional[bytes]:
        """
        Retrieve an object.
        
        Args:
            bucket: Storage bucket
            key: Object key
            
        Returns:
            Object data if found, None otherwise
        """
        ...
    
    async def delete(self, bucket: str, key: str) -> bool:
        """
        Delete an object.
        
        Args:
            bucket: Storage bucket
            key: Object key
            
        Returns:
            True if deleted, False if not found
        """
        ...
    
    async def get_url(self, bucket: str, key: str) -> str:
        """
        Get the public URL for an object.
        
        Args:
            bucket: Storage bucket
            key: Object key
            
        Returns:
            Public URL
        """
        ...
