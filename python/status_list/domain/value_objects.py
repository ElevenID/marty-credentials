"""
Value Objects for Status List Domain

Immutable value objects representing concepts in the status list domain.
These follow W3C Bitstring Status List v1.0 specification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Final


class StatusPurpose(str, Enum):
    """
    Status purpose as defined in W3C Bitstring Status List v1.0.
    
    The specification supports multiple purposes:
    - revocation: Permanent invalidation of a credential
    - suspension: Temporary invalidation (can be reversed)
    - message: Custom status messages (future extension)
    """
    
    REVOCATION = "revocation"
    SUSPENSION = "suspension"
    
    def __str__(self) -> str:
        return self.value


class StatusListFormat(str, Enum):
    """
    Format of the status list credential.
    
    - BITSTRING: W3C Bitstring Status List (for VCs, OB3)
    - TOKEN: IETF Token Status List (for mDocs, SD-JWT)
    """
    
    BITSTRING = "bitstring"
    TOKEN = "token"
    
    def __str__(self) -> str:
        return self.value


class StatusCode(int, Enum):
    """
    Status codes for credentials in a status list.
    
    For single-bit status lists (standard):
    - 0: Valid/Active
    - 1: Revoked/Suspended (depending on purpose)
    
    Multi-bit status lists can use values 0-255 for custom states.
    """
    
    VALID = 0
    INVALID = 1
    
    # Extended status codes (for multi-bit status lists)
    ACTIVE = 0
    REVOKED = 1
    SUSPENDED = 2
    EXPIRED = 3
    
    def __int__(self) -> int:
        return self.value


# Default configuration constants
DEFAULT_SHARD_SIZE_BITS: Final[int] = 131072  # 16KB = 131,072 bits (W3C minimum)
DEFAULT_CACHE_TTL_SECONDS: Final[int] = 300  # 5 minutes
DEFAULT_FLUSH_INTERVAL_SECONDS: Final[int] = 30  # Batch publish interval
MIN_SHARD_SIZE_BITS: Final[int] = 131072  # W3C spec minimum


@dataclass(frozen=True)
class ShardConfig:
    """
    Configuration for status list shards.
    
    Immutable value object containing shard configuration parameters.
    Validates against W3C specification requirements.
    
    Attributes:
        size_bits: Number of bits per shard (minimum 131,072 per spec)
        cache_ttl_seconds: HTTP cache TTL for published status lists
        flush_interval_seconds: Batch interval for publishing updates
        status_size: Bits per status entry (1 for standard, 2-8 for extended)
    """
    
    size_bits: int = DEFAULT_SHARD_SIZE_BITS
    cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS
    flush_interval_seconds: int = DEFAULT_FLUSH_INTERVAL_SECONDS
    status_size: int = 1  # Single bit per status entry
    
    def __post_init__(self) -> None:
        """Validate configuration against spec requirements."""
        if self.size_bits < MIN_SHARD_SIZE_BITS:
            raise ValueError(
                f"Shard size must be at least {MIN_SHARD_SIZE_BITS} bits "
                f"per W3C Bitstring Status List specification"
            )
        if self.size_bits % 8 != 0:
            raise ValueError("Shard size must be a multiple of 8 bits")
        if not 1 <= self.status_size <= 8:
            raise ValueError("Status size must be between 1 and 8 bits")
        if self.cache_ttl_seconds < 0:
            raise ValueError("Cache TTL must be non-negative")
        if self.flush_interval_seconds < 0:
            raise ValueError("Flush interval must be non-negative")
    
    @property
    def size_bytes(self) -> int:
        """Size in bytes for buffer allocation."""
        return self.size_bits // 8
    
    @property
    def max_entries(self) -> int:
        """Maximum number of status entries per shard."""
        return self.size_bits // self.status_size
    
    def with_size(self, size_bits: int) -> ShardConfig:
        """Create a new config with different shard size."""
        return ShardConfig(
            size_bits=size_bits,
            cache_ttl_seconds=self.cache_ttl_seconds,
            flush_interval_seconds=self.flush_interval_seconds,
            status_size=self.status_size,
        )
    
    def with_cache_ttl(self, ttl_seconds: int) -> ShardConfig:
        """Create a new config with different cache TTL."""
        return ShardConfig(
            size_bits=self.size_bits,
            cache_ttl_seconds=ttl_seconds,
            flush_interval_seconds=self.flush_interval_seconds,
            status_size=self.status_size,
        )


@dataclass(frozen=True)
class StatusListCredentialId:
    """
    Unique identifier for a status list credential.
    
    Combines issuer, purpose, and shard index to form a unique ID.
    """
    
    issuer_id: str
    purpose: StatusPurpose
    shard_index: int
    
    def __str__(self) -> str:
        return f"{self.issuer_id}/status/{self.purpose.value}/{self.shard_index}"
    
    @property
    def url_path(self) -> str:
        """URL path component for this status list."""
        return f"status/{self.purpose.value}/{self.shard_index}"


@dataclass(frozen=True)
class BitstringStatusListEntry:
    """
    Value object representing a BitstringStatusListEntry as embedded in credentials.
    
    This is the `credentialStatus` object added to issued credentials,
    pointing to the status list where their status can be checked.
    
    Per W3C Bitstring Status List v1.0 specification.
    """
    
    id: str  # URL with fragment: {statusListCredential}#{statusListIndex}
    type: str = field(default="BitstringStatusListEntry", init=False)
    status_purpose: StatusPurpose = StatusPurpose.REVOCATION
    status_list_index: int = 0
    status_list_credential: str = ""  # URL to the StatusListCredential
    
    def to_dict(self) -> dict:
        """Convert to JSON-LD compatible dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "statusPurpose": str(self.status_purpose),
            "statusListIndex": str(self.status_list_index),
            "statusListCredential": self.status_list_credential,
        }
    
    @classmethod
    def create(
        cls,
        base_url: str,
        issuer_id: str,
        purpose: StatusPurpose,
        shard_index: int,
        list_index: int,
    ) -> BitstringStatusListEntry:
        """Factory method to create a properly formatted entry."""
        credential_url = f"{base_url}/v3/status/{issuer_id}/{purpose.value}/{shard_index}"
        entry_id = f"{credential_url}#{list_index}"
        
        return cls(
            id=entry_id,
            status_purpose=purpose,
            status_list_index=list_index,
            status_list_credential=credential_url,
        )
