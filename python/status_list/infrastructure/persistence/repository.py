"""
Repository Implementations for Status List

SQLAlchemy-based repository implementations that satisfy the
outbound port protocols defined in the application layer.
"""

from __future__ import annotations

import logging
from typing import Optional, List

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from status_list.domain.entities import StatusList, StatusEntry, Shard
from status_list.domain.value_objects import (
    StatusPurpose,
    StatusListFormat,
    ShardConfig,
)
from status_list.infrastructure.persistence.models import (
    StatusListModel,
    ShardModel,
    StatusEntryModel,
)

logger = logging.getLogger(__name__)


class StatusListRepository:
    """
    Repository for StatusList aggregate persistence.
    
    Implements StatusListRepositoryPort protocol using SQLAlchemy
    for database operations.
    
    Attributes:
        _session_factory: SQLAlchemy async session factory
    """
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """
        Initialize the repository.
        
        Args:
            session_factory: SQLAlchemy async session factory
        """
        self._session_factory = session_factory
    
    async def save(self, status_list: StatusList) -> None:
        """
        Save a status list (create or update).
        
        Args:
            status_list: The StatusList to save
        """
        async with self._session_factory() as session:
            # Check if exists
            existing = await self._get_model_with_session(session, status_list.issuer_id, status_list.purpose)
        
        if existing:
            # Update existing
            existing.format = status_list.format.value
            existing.shard_size_bits = status_list.config.size_bits
            existing.cache_ttl_seconds = status_list.config.cache_ttl_seconds
            existing.status_size = status_list.config.status_size
            existing.updated_at = status_list.updated_at
            
            # Update/add shards
            existing_shard_ids = {s.id for s in existing.shards}
            for shard in status_list.shards:
                if shard.id in existing_shard_ids:
                    # Update existing shard
                    for existing_shard in existing.shards:
                        if existing_shard.id == shard.id:
                            existing_shard.encoded_list = shard.encoded_list
                            existing_shard.next_available_index = shard.next_available_index
                            existing_shard.version = shard.version
                            existing_shard.updated_at = shard.updated_at
                            break
                else:
                    # Add new shard
                    shard_model = self._shard_to_model(shard, status_list.id)
                    existing.shards.append(shard_model)
            else:
                # Create new
                model = self._domain_to_model(status_list)
                session.add(model)
            
            await session.commit()
            logger.debug("Saved status list %s", status_list.id)
    
    async def get(
        self,
        issuer_id: str,
        purpose: StatusPurpose,
    ) -> Optional[StatusList]:
        """
        Get a status list by issuer and purpose.
        \
        Args:
            issuer_id: ID of the issuer
            purpose: revocation or suspension
            
        Returns:
            StatusList if found, None otherwise
        """
        async with self._session_factory() as session:
            model = await self._get_model_with_session(session, issuer_id, purpose)
            if model is None:
                return None
            
            return self._model_to_domain(model)
    
    async def get_by_id(self, status_list_id: str) -> Optional[StatusList]:
        """
        Get a status list by its ID.
        
        Args:
            status_list_id: The status list ID
            
        Returns:
            StatusList if found, None otherwise
        """
        stmt = (
            select(StatusListModel)
            .options(selectinload(StatusListModel.shards))
            .where(StatusListModel.id == status_list_id)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        
        if model is None:
            return None
        
        return self._model_to_domain(model)
    
    async def list_by_issuer(self, issuer_id: str) -> List[StatusList]:
        """
        List all status lists for an issuer.
        
        Args:
            issuer_id: ID of the issuer
            
        Returns:
            List of StatusLists for the issuer
        """
        stmt = (
            select(StatusListModel)
            .options(selectinload(StatusListModel.shards))
            .where(StatusListModel.issuer_id == issuer_id)
        )
        result = await self._session.execute(stmt)
        models = result.scalars().all()
        
        return [self._model_to_domain(m) for m in models]
    
    async def update_shard(self, shard: Shard) -> None:
        """
        Update a specific shard.
        
        Args:
            shard: The Shard to update
        """
        stmt = select(ShardModel).where(ShardModel.id == shard.id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        
        if model is None:
            logger.warning("Shard %s not found for update", shard.id)
            return
        
        model.encoded_list = shard.encoded_list
        model.next_available_index = shard.next_available_index
        model.version = shard.version
        model.updated_at = shard.updated_at
        
        await self._session.flush()
        logger.debug("Updated shard %s", shard.id)
    
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
        # First get the status list
        status_list = await self.get(issuer_id, purpose)
        if status_list is None:
            return None
        
        return status_list.get_shard_by_index(shard_index)
    
    async def _get_model_with_session(
        self,
        session: AsyncSession,
        issuer_id: str,
        purpose: StatusPurpose,
    ) -> Optional[StatusListModel]:
        """Get the SQLAlchemy model by issuer and purpose."""
        stmt = (
            select(StatusListModel)
            .options(selectinload(StatusListModel.shards))
            .where(
                and_(
                    StatusListModel.issuer_id == issuer_id,
                    StatusListModel.purpose == purpose.value,
                )
            )
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
    
    def _domain_to_model(self, status_list: StatusList) -> StatusListModel:
        """Convert domain entity to SQLAlchemy model."""
        model = StatusListModel(
            id=status_list.id,
            issuer_id=status_list.issuer_id,
            purpose=status_list.purpose.value,
            format=status_list.format.value,
            shard_size_bits=status_list.config.size_bits,
            cache_ttl_seconds=status_list.config.cache_ttl_seconds,
            status_size=status_list.config.status_size,
            created_at=status_list.created_at,
            updated_at=status_list.updated_at,
        )
        
        for shard in status_list.shards:
            shard_model = self._shard_to_model(shard, status_list.id)
            model.shards.append(shard_model)
        
        return model
    
    def _shard_to_model(self, shard: Shard, status_list_id: str) -> ShardModel:
        """Convert shard domain entity to SQLAlchemy model."""
        return ShardModel(
            id=shard.id,
            status_list_id=status_list_id,
            index=shard.index,
            encoded_list=shard.encoded_list,
            next_available_index=shard.next_available_index,
            version=shard.version,
            created_at=shard.created_at,
            updated_at=shard.updated_at,
        )
    
    def _model_to_domain(self, model: StatusListModel) -> StatusList:
        """Convert SQLAlchemy model to domain entity."""
        config = ShardConfig(
            size_bits=model.shard_size_bits,
            cache_ttl_seconds=model.cache_ttl_seconds,
            status_size=model.status_size,
        )
        
        shards = [
            self._shard_model_to_domain(s, model.issuer_id, model.purpose, config)
            for s in sorted(model.shards, key=lambda s: s.index)
        ]
        
        return StatusList(
            id=model.id,
            issuer_id=model.issuer_id,
            purpose=StatusPurpose(model.purpose),
            format=StatusListFormat(model.format),
            shards=shards,
            config=config,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )
    
    def _shard_model_to_domain(
        self,
        model: ShardModel,
        issuer_id: str,
        purpose: str,
        config: ShardConfig,
    ) -> Shard:
        """Convert shard SQLAlchemy model to domain entity."""
        return Shard(
            id=model.id,
            index=model.index,
            issuer_id=issuer_id,
            purpose=StatusPurpose(purpose),
            encoded_list=model.encoded_list,
            next_available_index=model.next_available_index,
            config=config,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.version,
        )


class StatusEntryRepository:
    """
    Repository for StatusEntry persistence.
    
    Implements StatusEntryRepositoryPort protocol using SQLAlchemy.
    
    Attributes:
        _session_factory: SQLAlchemy async session factory
    """
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """
        Initialize the repository.
        
        Args:
            session_factory: SQLAlchemy async session factory
        """
        self._session_factory = session_factory
    
    async def save(self, entry: StatusEntry) -> None:
        """
        Save a status entry.
        
        Args:
            entry: The StatusEntry to save
        """
        async with self._session_factory() as session:
            # Check if exists
            existing = await self._get_model_with_session(session, entry.credential_id, entry.purpose)
        
        if existing:
            # Update (though entries shouldn't typically change)
            existing.shard_id = entry.shard_id
            existing.shard_index = entry.shard_index
            existing.bit_index = entry.bit_index
        else:
            # Create new
            model = StatusEntryModel(
                id=entry.id,
                credential_id=entry.credential_id,
                shard_id=entry.shard_id,
                shard_index=entry.shard_index,
                bit_index=entry.bit_index,
                purpose=entry.purpose.value,
                issuer_id=entry.issuer_id,
                created_at=entry.created_at,
            )
            session.add(model)
        
        await session.commit()
        logger.debug("Saved status entry %s for credential %s", entry.id, entry.credential_id)
    
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
        async with self._session_factory() as session:
            model = await self._get_model_with_session(session, credential_id, purpose)
            if model is None:
                return None
            
            return self._model_to_domain(model)
    
    async def get_all_for_credential(
        self,
        credential_id: str,
    ) -> List[StatusEntry]:
        """
        Get all status entries for a credential.
        
        Args:
            credential_id: ID of the credential
            
        Returns:
            List of StatusEntries (typically one per purpose)
        """
        stmt = select(StatusEntryModel).where(
            StatusEntryModel.credential_id == credential_id
        )
        result = await self._session.execute(stmt)
        models = result.scalars().all()
        
        return [self._model_to_domain(m) for m in models]
    
    async def list_by_shard(
        self,
        shard_id: str,
    ) -> List[StatusEntry]:
        """
        List all entries in a shard.
        
        Args:
            shard_id: ID of the shard
            
        Returns:
            List of StatusEntries in the shard
        """
        stmt = select(StatusEntryModel).where(
            StatusEntryModel.shard_id == shard_id
        )
        result = await self._session.execute(stmt)
        models = result.scalars().all()
        
        return [self._model_to_domain(m) for m in models]
    
    async def delete(self, entry_id: str) -> bool:
        """
        Delete a status entry.
        
        Args:
            entry_id: ID of the entry to delete
            
        Returns:
            True if deleted, False if not found
        """
        stmt = select(StatusEntryModel).where(StatusEntryModel.id == entry_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        
        if model is None:
            return False
        
        await self._session.delete(model)
        await self._session.flush()
        logger.debug("Deleted status entry %s", entry_id)
        return True
    
    async def _get_model_with_session(
        self,
        session: AsyncSession,
        credential_id: str,
        purpose: StatusPurpose,
    ) -> Optional[StatusEntryModel]:
        """Get the SQLAlchemy model by credential and purpose."""
        stmt = select(StatusEntryModel).where(
            and_(
                StatusEntryModel.credential_id == credential_id,
                StatusEntryModel.purpose == purpose.value,
            )
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
    
    def _model_to_domain(self, model: StatusEntryModel) -> StatusEntry:
        """Convert SQLAlchemy model to domain entity."""
        return StatusEntry(
            id=model.id,
            credential_id=model.credential_id,
            shard_id=model.shard_id,
            shard_index=model.shard_index,
            bit_index=model.bit_index,
            purpose=StatusPurpose(model.purpose),
            issuer_id=model.issuer_id,
            created_at=model.created_at,
        )
