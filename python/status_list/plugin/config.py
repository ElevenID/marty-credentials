"""
Status List Plugin Configuration

Pydantic configuration schema for the status list plugin.
Supports environment variable and YAML configuration.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class StatusListPluginConfig(BaseModel):
    """
    Configuration for the Status List plugin.
    
    All settings are configurable via environment variables
    with the STATUS_LIST_ prefix.
    
    Attributes:
        enabled: Whether the status list feature is enabled
        base_url: Base URL for status list endpoints
        shard_size_bits: Size of each shard in bits (min 131072)
        cache_ttl_seconds: HTTP cache TTL for status list credentials
        flush_interval_seconds: Batch interval for publishing updates
        status_size: Bits per status entry (1 for standard)
        include_revocation: Default for including revocation status
        include_suspension: Default for including suspension status
        storage_bucket: Object storage bucket for status lists
        database_schema: Database schema for status list tables
    """
    
    enabled: bool = Field(
        default=True,
        description="Enable the status list feature",
    )
    
    base_url: str = Field(
        default="https://api.example.com",
        description="Base URL for status list endpoints",
    )
    
    shard_size_bits: int = Field(
        default=131072,
        ge=131072,
        description="Size of each shard in bits (minimum 131072 per W3C spec)",
    )
    
    cache_ttl_seconds: int = Field(
        default=300,
        ge=0,
        description="HTTP cache TTL for status list credentials (seconds)",
    )
    
    flush_interval_seconds: int = Field(
        default=30,
        ge=0,
        description="Batch interval for publishing status updates (seconds)",
    )
    
    status_size: int = Field(
        default=1,
        ge=1,
        le=8,
        description="Bits per status entry (1 for standard revocation/suspension)",
    )
    
    include_revocation: bool = Field(
        default=True,
        description="Default for including revocation status in credentials",
    )
    
    include_suspension: bool = Field(
        default=True,
        description="Default for including suspension status in credentials",
    )
    
    storage_bucket: str = Field(
        default="status-lists",
        description="Object storage bucket for status list credentials",
    )
    
    database_schema: Optional[str] = Field(
        default=None,
        description="Database schema for status list tables (None for default)",
    )
    
    class Config:
        """Pydantic config."""
        
        env_prefix = "STATUS_LIST_"
        case_sensitive = False
    
    def to_shard_config(self):
        """
        Convert to ShardConfig value object.
        
        Returns:
            ShardConfig instance
        """
        from status_list.domain.value_objects import ShardConfig
        
        return ShardConfig(
            size_bits=self.shard_size_bits,
            cache_ttl_seconds=self.cache_ttl_seconds,
            flush_interval_seconds=self.flush_interval_seconds,
            status_size=self.status_size,
        )
