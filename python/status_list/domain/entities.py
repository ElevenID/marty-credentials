"""
Domain Entities for Status List

Core domain entities representing status lists, shards, and entries.
These are the aggregate roots and entities in our domain model.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from status_list.domain.value_objects import (
    StatusPurpose,
    StatusListFormat,
    StatusCode,
    ShardConfig,
    BitstringStatusListEntry,
    DEFAULT_SHARD_SIZE_BITS,
)


@dataclass
class Shard:
    """
    A shard of a status list containing a portion of the bitstring.
    
    Each shard holds a fixed-size bitstring (default 16KB = 131,072 bits)
    that can represent the status of up to 131,072 credentials.
    
    The bitstring is stored compressed (gzip + base64) per spec.
    
    Attributes:
        id: Unique shard identifier
        index: Sequential index for this shard (0, 1, 2, ...)
        issuer_id: ID of the issuer this shard belongs to
        purpose: Status purpose (revocation or suspension)
        encoded_list: GZIP + Base64 encoded bitstring
        next_available_index: Next unassigned bit index in this shard
        config: Shard configuration
        created_at: Timestamp when shard was created
        updated_at: Timestamp of last status update
        version: Optimistic locking version
    """
    
    id: str
    index: int
    issuer_id: str
    purpose: StatusPurpose
    encoded_list: str
    next_available_index: int = 0
    config: ShardConfig = field(default_factory=ShardConfig)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = 1
    
    @classmethod
    def create_empty(
        cls,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
        config: Optional[ShardConfig] = None,
    ) -> Shard:
        """
        Create a new empty shard with all bits set to 0 (valid).
        
        Args:
            issuer_id: The issuer this shard belongs to
            purpose: revocation or suspension
            shard_index: Sequential index for this shard
            config: Optional shard configuration
            
        Returns:
            New Shard instance with empty bitstring
        """
        cfg = config or ShardConfig()
        
        # Create zero-filled buffer
        buffer = bytes(cfg.size_bytes)
        
        # Compress with gzip
        compressed = gzip.compress(buffer)
        
        # Encode as base64
        import base64
        encoded = base64.b64encode(compressed).decode("ascii")
        
        return cls(
            id=str(uuid4()),
            index=shard_index,
            issuer_id=issuer_id,
            purpose=purpose,
            encoded_list=encoded,
            next_available_index=0,
            config=cfg,
        )
    
    def is_full(self) -> bool:
        """Check if this shard has no more available indices."""
        return self.next_available_index >= self.config.max_entries
    
    def allocate_index(self) -> int:
        """
        Allocate the next available index in this shard.
        
        Returns:
            The allocated index
            
        Raises:
            ValueError: If shard is full
        """
        if self.is_full():
            raise ValueError(f"Shard {self.id} is full")
        
        index = self.next_available_index
        self.next_available_index += 1
        self.updated_at = datetime.now(timezone.utc)
        return index
    
    def get_status(self, index: int) -> int:
        """
        Get the status value at a specific index.
        
        Args:
            index: The bit index to check
            
        Returns:
            Status value (0 = valid, 1 = invalid for single-bit)
        """
        import base64
        
        # Decode and decompress
        compressed = base64.b64decode(self.encoded_list)
        decompressed = gzip.decompress(compressed)
        
        # Calculate byte and bit position (MSB ordering per spec)
        byte_index = index // 8
        bit_index = 7 - (index % 8)  # MSB ordering
        
        if byte_index >= len(decompressed):
            raise IndexError(f"Index {index} out of range for shard")
        
        return (decompressed[byte_index] >> bit_index) & 1
    
    def set_status(self, index: int, value: int) -> None:
        """
        Set the status value at a specific index.
        
        Args:
            index: The bit index to update
            value: Status value (0 or 1 for single-bit status)
        """
        import base64
        
        # Decode and decompress
        compressed = base64.b64decode(self.encoded_list)
        decompressed = bytearray(gzip.decompress(compressed))
        
        # Calculate byte and bit position (MSB ordering per spec)
        byte_index = index // 8
        bit_index = 7 - (index % 8)  # MSB ordering
        
        if byte_index >= len(decompressed):
            raise IndexError(f"Index {index} out of range for shard")
        
        if value:
            decompressed[byte_index] |= (1 << bit_index)
        else:
            decompressed[byte_index] &= ~(1 << bit_index)
        
        # Recompress and encode
        compressed = gzip.compress(bytes(decompressed))
        self.encoded_list = base64.b64encode(compressed).decode("ascii")
        self.updated_at = datetime.now(timezone.utc)
        self.version += 1


@dataclass
class StatusEntry:
    """
    A status entry tracking a credential's position in a status list.
    
    This is the assignment record that maps a credential to its
    location in the status list (shard + index).
    
    Attributes:
        id: Unique entry identifier
        credential_id: ID of the credential this entry tracks
        shard_id: ID of the shard containing this entry
        shard_index: Index of the shard (for URL construction)
        bit_index: Bit position within the shard
        purpose: Status purpose (revocation or suspension)
        issuer_id: ID of the issuer
        created_at: When the entry was assigned
    """
    
    id: str
    credential_id: str
    shard_id: str
    shard_index: int
    bit_index: int
    purpose: StatusPurpose
    issuer_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def create(
        cls,
        credential_id: str,
        shard: Shard,
        bit_index: int,
    ) -> StatusEntry:
        """Create a new status entry for a credential."""
        return cls(
            id=str(uuid4()),
            credential_id=credential_id,
            shard_id=shard.id,
            shard_index=shard.index,
            bit_index=bit_index,
            purpose=shard.purpose,
            issuer_id=shard.issuer_id,
        )
    
    def to_status_list_entry(self, base_url: str) -> BitstringStatusListEntry:
        """
        Convert to a BitstringStatusListEntry for embedding in credentials.
        
        Args:
            base_url: Base URL for status list endpoints
            
        Returns:
            BitstringStatusListEntry value object
        """
        return BitstringStatusListEntry.create(
            base_url=base_url,
            issuer_id=self.issuer_id,
            purpose=self.purpose,
            shard_index=self.shard_index,
            list_index=self.bit_index,
        )


@dataclass
class StatusList:
    """
    Aggregate root for a status list.
    
    A StatusList manages multiple shards for a specific issuer and purpose.
    It handles shard allocation and provides the aggregate view of status.
    
    Attributes:
        id: Unique status list identifier
        issuer_id: ID of the issuer this list belongs to
        purpose: Status purpose (revocation or suspension)
        format: List format (bitstring or token)
        shards: List of shards in this status list
        config: Configuration for shards
        created_at: When the list was created
        updated_at: Last modification timestamp
    """
    
    id: str
    issuer_id: str
    purpose: StatusPurpose
    format: StatusListFormat = StatusListFormat.BITSTRING
    shards: list[Shard] = field(default_factory=list)
    config: ShardConfig = field(default_factory=ShardConfig)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def create(
        cls,
        issuer_id: str,
        purpose: StatusPurpose,
        config: Optional[ShardConfig] = None,
    ) -> StatusList:
        """
        Create a new status list with an initial empty shard.
        
        Args:
            issuer_id: The issuer this list belongs to
            purpose: revocation or suspension
            config: Optional configuration
            
        Returns:
            New StatusList with one empty shard
        """
        cfg = config or ShardConfig()
        
        status_list = cls(
            id=str(uuid4()),
            issuer_id=issuer_id,
            purpose=purpose,
            config=cfg,
        )
        
        # Create initial shard
        initial_shard = Shard.create_empty(
            issuer_id=issuer_id,
            purpose=purpose,
            shard_index=0,
            config=cfg,
        )
        status_list.shards.append(initial_shard)
        
        return status_list
    
    def get_current_shard(self) -> Shard:
        """Get the current (most recent non-full) shard."""
        if not self.shards:
            raise ValueError("Status list has no shards")
        
        # Find first non-full shard
        for shard in self.shards:
            if not shard.is_full():
                return shard
        
        # All shards full, create new one
        return self._create_new_shard()
    
    def _create_new_shard(self) -> Shard:
        """Create a new shard and add to the list."""
        new_index = len(self.shards)
        new_shard = Shard.create_empty(
            issuer_id=self.issuer_id,
            purpose=self.purpose,
            shard_index=new_index,
            config=self.config,
        )
        self.shards.append(new_shard)
        self.updated_at = datetime.now(timezone.utc)
        return new_shard
    
    def allocate_entry(self, credential_id: str) -> StatusEntry:
        """
        Allocate a new status entry for a credential.
        
        Args:
            credential_id: ID of the credential to allocate for
            
        Returns:
            StatusEntry with assigned shard and index
        """
        shard = self.get_current_shard()
        bit_index = shard.allocate_index()
        
        return StatusEntry.create(
            credential_id=credential_id,
            shard=shard,
            bit_index=bit_index,
        )
    
    def get_shard_by_index(self, shard_index: int) -> Optional[Shard]:
        """Get a shard by its sequential index."""
        for shard in self.shards:
            if shard.index == shard_index:
                return shard
        return None
    
    def set_status(self, shard_index: int, bit_index: int, value: int) -> None:
        """
        Set the status at a specific position.
        
        Args:
            shard_index: Index of the shard
            bit_index: Bit position within the shard
            value: Status value to set
        """
        shard = self.get_shard_by_index(shard_index)
        if shard is None:
            raise ValueError(f"Shard {shard_index} not found")
        
        shard.set_status(bit_index, value)
        self.updated_at = datetime.now(timezone.utc)
    
    def get_status(self, shard_index: int, bit_index: int) -> int:
        """
        Get the status at a specific position.
        
        Args:
            shard_index: Index of the shard
            bit_index: Bit position within the shard
            
        Returns:
            Status value at the position
        """
        shard = self.get_shard_by_index(shard_index)
        if shard is None:
            raise ValueError(f"Shard {shard_index} not found")
        
        return shard.get_status(bit_index)
