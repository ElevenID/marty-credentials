"""
Domain Layer - Status List

Contains domain entities, value objects, and domain events for
the Bitstring Status List feature.
"""

from status_list.domain.entities import StatusList, StatusEntry, Shard
from status_list.domain.value_objects import (
    StatusPurpose,
    StatusListFormat,
    StatusCode,
    ShardConfig,
)
from status_list.domain.events import (
    StatusUpdatedEvent,
    ShardCreatedEvent,
    StatusListPublishedEvent,
)

__all__ = [
    # Entities
    "StatusList",
    "StatusEntry",
    "Shard",
    # Value Objects
    "StatusPurpose",
    "StatusListFormat",
    "StatusCode",
    "ShardConfig",
    # Events
    "StatusUpdatedEvent",
    "ShardCreatedEvent",
    "StatusListPublishedEvent",
]
