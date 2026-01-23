"""
Domain Events for Status List

Domain events emitted when significant changes occur in the status list domain.
These events enable loose coupling between the status list module and other
parts of the system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from status_list.domain.value_objects import StatusPurpose


@dataclass(frozen=True)
class DomainEvent:
    """Base class for all domain events."""
    
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @property
    def event_type(self) -> str:
        """Return the event type name."""
        return self.__class__.__name__


@dataclass(frozen=True)
class StatusUpdatedEvent(DomainEvent):
    """
    Event emitted when a credential's status is updated.
    
    This event is published when a credential is revoked or suspended,
    or when a suspension is lifted.
    
    Attributes:
        credential_id: ID of the affected credential
        issuer_id: ID of the issuer
        purpose: Status purpose (revocation or suspension)
        shard_index: Index of the shard containing the status
        bit_index: Bit position within the shard
        old_value: Previous status value
        new_value: New status value
        reason: Optional reason for the status change
    """
    
    credential_id: str = ""
    issuer_id: str = ""
    purpose: StatusPurpose = StatusPurpose.REVOCATION
    shard_index: int = 0
    bit_index: int = 0
    old_value: int = 0
    new_value: int = 1
    reason: Optional[str] = None
    
    @property
    def is_revocation(self) -> bool:
        """Check if this is a revocation (status set to invalid)."""
        return self.new_value == 1 and self.purpose == StatusPurpose.REVOCATION
    
    @property
    def is_suspension(self) -> bool:
        """Check if this is a suspension."""
        return self.new_value == 1 and self.purpose == StatusPurpose.SUSPENSION
    
    @property
    def is_unsuspension(self) -> bool:
        """Check if this is lifting a suspension."""
        return self.new_value == 0 and self.purpose == StatusPurpose.SUSPENSION


@dataclass(frozen=True)
class ShardCreatedEvent(DomainEvent):
    """
    Event emitted when a new shard is created.
    
    This indicates that a status list has grown and a new shard
    was allocated. Can trigger status list credential generation.
    
    Attributes:
        shard_id: ID of the new shard
        issuer_id: ID of the issuer
        purpose: Status purpose
        shard_index: Sequential index of the new shard
        size_bits: Size of the shard in bits
    """
    
    shard_id: str = ""
    issuer_id: str = ""
    purpose: StatusPurpose = StatusPurpose.REVOCATION
    shard_index: int = 0
    size_bits: int = 131072


@dataclass(frozen=True)
class StatusListPublishedEvent(DomainEvent):
    """
    Event emitted when a status list credential is published.
    
    This indicates that an updated status list credential has been
    signed and made available at its public URL.
    
    Attributes:
        status_list_id: ID of the status list
        issuer_id: ID of the issuer
        purpose: Status purpose
        shard_index: Index of the published shard
        credential_url: Public URL of the status list credential
        version: Version number of this publication
    """
    
    status_list_id: str = ""
    issuer_id: str = ""
    purpose: StatusPurpose = StatusPurpose.REVOCATION
    shard_index: int = 0
    credential_url: str = ""
    version: int = 1


@dataclass(frozen=True)
class StatusEntryAllocatedEvent(DomainEvent):
    """
    Event emitted when a new status entry is allocated for a credential.
    
    This tracks when credentials are assigned positions in the status list.
    
    Attributes:
        entry_id: ID of the status entry
        credential_id: ID of the credential
        issuer_id: ID of the issuer
        purpose: Status purpose
        shard_index: Shard where the entry was allocated
        bit_index: Bit position within the shard
    """
    
    entry_id: str = ""
    credential_id: str = ""
    issuer_id: str = ""
    purpose: StatusPurpose = StatusPurpose.REVOCATION
    shard_index: int = 0
    bit_index: int = 0
