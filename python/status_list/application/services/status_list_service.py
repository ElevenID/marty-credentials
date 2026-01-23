"""
Status List Service - Core Application Service

Implements the main use cases for status list management:
- Creating and managing status lists
- Allocating status entries for credentials
- Updating credential status (revoke/suspend/unsuspend)
- Checking credential status
"""

from __future__ import annotations

import logging
from typing import Optional

from status_list.domain.entities import StatusList, StatusEntry, Shard
from status_list.domain.value_objects import StatusPurpose, ShardConfig
from status_list.domain.events import (
    StatusUpdatedEvent,
    ShardCreatedEvent,
    StatusEntryAllocatedEvent,
)
from status_list.application.ports.outbound import (
    StatusListRepositoryPort,
    StatusEntryRepositoryPort,
    EventPublisherPort,
)

logger = logging.getLogger(__name__)


class StatusListService:
    """
    Application service for status list management.
    
    This service implements the core use cases for managing
    status lists following the hexagonal architecture pattern.
    All dependencies are injected via ports.
    
    Attributes:
        _status_list_repo: Repository for StatusList persistence
        _status_entry_repo: Repository for StatusEntry persistence
        _event_publisher: Publisher for domain events
        _default_config: Default shard configuration
    """
    
    def __init__(
        self,
        status_list_repository: StatusListRepositoryPort,
        status_entry_repository: StatusEntryRepositoryPort,
        event_publisher: Optional[EventPublisherPort] = None,
        default_config: Optional[ShardConfig] = None,
    ) -> None:
        """
        Initialize the service with required ports.
        
        Args:
            status_list_repository: Repository for status lists
            status_entry_repository: Repository for status entries
            event_publisher: Optional event publisher
            default_config: Optional default shard configuration
        """
        self._status_list_repo = status_list_repository
        self._status_entry_repo = status_entry_repository
        self._event_publisher = event_publisher
        self._default_config = default_config or ShardConfig()
    
    async def create_status_list(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        config: Optional[ShardConfig] = None,
    ) -> StatusList:
        """
        Create a new status list for an issuer.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            config: Optional shard configuration
            
        Returns:
            The created StatusList
            
        Raises:
            ValueError: If a status list already exists for this issuer/purpose
        """
        # Check if already exists
        existing = await self._status_list_repo.get(issuer_id, purpose)
        if existing is not None:
            raise ValueError(
                f"Status list already exists for issuer {issuer_id} "
                f"with purpose {purpose}"
            )
        
        # Create new status list with initial shard
        cfg = config or self._default_config
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=purpose,
            config=cfg,
        )
        
        # Persist
        await self._status_list_repo.save(status_list)
        
        # Publish shard created event
        if self._event_publisher and status_list.shards:
            initial_shard = status_list.shards[0]
            event = ShardCreatedEvent(
                shard_id=initial_shard.id,
                issuer_id=issuer_id,
                purpose=purpose,
                shard_index=0,
                size_bits=cfg.size_bits,
            )
            await self._event_publisher.publish(event)
        
        logger.info(
            "Created status list for issuer %s with purpose %s",
            issuer_id,
            purpose,
        )
        
        return status_list
    
    async def get_status_list(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
    ) -> Optional[StatusList]:
        """
        Get an existing status list.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            
        Returns:
            StatusList if found, None otherwise
        """
        return await self._status_list_repo.get(issuer_id, purpose)
    
    async def get_or_create_status_list(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        config: Optional[ShardConfig] = None,
    ) -> StatusList:
        """
        Get or create a status list for an issuer.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            config: Optional shard configuration (used if creating)
            
        Returns:
            Existing or newly created StatusList
        """
        existing = await self._status_list_repo.get(issuer_id, purpose)
        if existing is not None:
            return existing
        
        return await self.create_status_list(issuer_id, purpose, config)
    
    async def allocate_status_entry(
        self,
        credential_id: str,
        issuer_id: str,
        purpose: StatusPurpose,
    ) -> StatusEntry:
        """
        Allocate a new status entry for a credential.
        
        This assigns a position (shard + bit index) in the status list
        for tracking the credential's status.
        
        Args:
            credential_id: ID of the credential
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            
        Returns:
            The allocated StatusEntry
        """
        # Get or create the status list
        status_list = await self.get_or_create_status_list(issuer_id, purpose)
        
        # Check if credential already has an entry
        existing = await self._status_entry_repo.get_by_credential(
            credential_id, purpose
        )
        if existing is not None:
            logger.warning(
                "Credential %s already has status entry for purpose %s",
                credential_id,
                purpose,
            )
            return existing
        
        # Check if we need a new shard
        current_shard = status_list.get_current_shard()
        shard_was_created = len(status_list.shards) > 1 and current_shard.next_available_index == 0
        
        # Allocate entry in the status list
        entry = status_list.allocate_entry(credential_id)
        
        # Persist the entry
        await self._status_entry_repo.save(entry)
        
        # Update the status list (shard may have been modified)
        await self._status_list_repo.save(status_list)
        
        # Publish events
        if self._event_publisher:
            # Entry allocated event
            allocated_event = StatusEntryAllocatedEvent(
                entry_id=entry.id,
                credential_id=credential_id,
                issuer_id=issuer_id,
                purpose=purpose,
                shard_index=entry.shard_index,
                bit_index=entry.bit_index,
            )
            await self._event_publisher.publish(allocated_event)
            
            # New shard event if applicable
            if shard_was_created:
                shard_event = ShardCreatedEvent(
                    shard_id=current_shard.id,
                    issuer_id=issuer_id,
                    purpose=purpose,
                    shard_index=current_shard.index,
                    size_bits=status_list.config.size_bits,
                )
                await self._event_publisher.publish(shard_event)
        
        logger.debug(
            "Allocated status entry for credential %s at shard %d index %d",
            credential_id,
            entry.shard_index,
            entry.bit_index,
        )
        
        return entry
    
    async def update_status(
        self,
        credential_id: str,
        purpose: StatusPurpose,
        status: int,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Update the status of a credential.
        
        Args:
            credential_id: ID of the credential
            purpose: revocation or suspension
            status: New status value (0=valid, 1=invalid)
            reason: Optional reason for the change
            
        Returns:
            True if status was updated, False if credential not found
        """
        # Get the status entry for this credential
        entry = await self._status_entry_repo.get_by_credential(credential_id, purpose)
        if entry is None:
            logger.warning(
                "No status entry found for credential %s with purpose %s",
                credential_id,
                purpose,
            )
            return False
        
        # Get the status list and shard
        status_list = await self._status_list_repo.get(entry.issuer_id, purpose)
        if status_list is None:
            logger.error(
                "Status list not found for issuer %s purpose %s",
                entry.issuer_id,
                purpose,
            )
            return False
        
        # Get current status
        old_status = status_list.get_status(entry.shard_index, entry.bit_index)
        
        if old_status == status:
            logger.debug(
                "Status for credential %s is already %d",
                credential_id,
                status,
            )
            return True
        
        # Update the status
        status_list.set_status(entry.shard_index, entry.bit_index, status)
        
        # Persist
        shard = status_list.get_shard_by_index(entry.shard_index)
        if shard:
            await self._status_list_repo.update_shard(shard)
        
        # Publish event
        if self._event_publisher:
            event = StatusUpdatedEvent(
                credential_id=credential_id,
                issuer_id=entry.issuer_id,
                purpose=purpose,
                shard_index=entry.shard_index,
                bit_index=entry.bit_index,
                old_value=old_status,
                new_value=status,
                reason=reason,
            )
            await self._event_publisher.publish(event)
        
        logger.info(
            "Updated status for credential %s: %d -> %d (purpose: %s, reason: %s)",
            credential_id,
            old_status,
            status,
            purpose,
            reason,
        )
        
        return True
    
    async def check_status(
        self,
        credential_id: str,
        purpose: StatusPurpose,
    ) -> Optional[int]:
        """
        Check the current status of a credential.
        
        Args:
            credential_id: ID of the credential
            purpose: revocation or suspension
            
        Returns:
            Status value if found, None if credential has no status entry
        """
        # Get the status entry
        entry = await self._status_entry_repo.get_by_credential(credential_id, purpose)
        if entry is None:
            return None
        
        # Get the status list
        status_list = await self._status_list_repo.get(entry.issuer_id, purpose)
        if status_list is None:
            logger.error(
                "Status list not found for entry %s",
                entry.id,
            )
            return None
        
        return status_list.get_status(entry.shard_index, entry.bit_index)
    
    async def get_shard(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
    ) -> Optional[Shard]:
        """
        Get a specific shard from a status list.
        
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            shard_index: Index of the shard
            
        Returns:
            Shard if found, None otherwise
        """
        return await self._status_list_repo.get_shard(issuer_id, purpose, shard_index)
