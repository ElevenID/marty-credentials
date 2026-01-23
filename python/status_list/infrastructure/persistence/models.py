"""
SQLAlchemy Models for Status List

Database models for persisting status lists, shards, and status entries.
These models map to the domain entities for persistence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import (
    Column,
    String,
    Integer,
    Text,
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
    Enum as SQLEnum,
)
from sqlalchemy.orm import relationship, Mapped, mapped_column, DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class StatusListModel(Base):
    """
    SQLAlchemy model for StatusList aggregate.
    
    Stores the status list metadata. Shards are stored separately
    and linked via foreign key.
    
    Table: status_lists
    """
    
    __tablename__ = "status_lists"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    issuer_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(20), nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False, default="bitstring")
    
    # Configuration (stored as JSON or individual columns)
    shard_size_bits: Mapped[int] = mapped_column(Integer, nullable=False, default=131072)
    cache_ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    status_size: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    
    # Relationships
    shards: Mapped[List["ShardModel"]] = relationship(
        "ShardModel",
        back_populates="status_list",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    
    __table_args__ = (
        UniqueConstraint("issuer_id", "purpose", name="uq_status_list_issuer_purpose"),
        Index("ix_status_list_issuer_purpose", "issuer_id", "purpose"),
    )
    
    def __repr__(self) -> str:
        return f"<StatusListModel(id={self.id}, issuer={self.issuer_id}, purpose={self.purpose})>"


class ShardModel(Base):
    """
    SQLAlchemy model for Shard entity.
    
    Stores the actual bitstring data for a portion of the status list.
    Each shard can hold up to 131,072 status entries (16KB).
    
    Table: status_list_shards
    """
    
    __tablename__ = "status_list_shards"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status_list_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("status_lists.id", ondelete="CASCADE"),
        nullable=False,
    )
    index: Mapped[int] = mapped_column(Integer, nullable=False)
    
    # The compressed and encoded bitstring
    encoded_list: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Next available bit index in this shard
    next_available_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    # Optimistic locking version
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    
    # Relationships
    status_list: Mapped["StatusListModel"] = relationship(
        "StatusListModel",
        back_populates="shards",
    )
    
    __table_args__ = (
        UniqueConstraint("status_list_id", "index", name="uq_shard_status_list_index"),
        Index("ix_shard_status_list_index", "status_list_id", "index"),
    )
    
    def __repr__(self) -> str:
        return f"<ShardModel(id={self.id}, index={self.index}, next_idx={self.next_available_index})>"


class StatusEntryModel(Base):
    """
    SQLAlchemy model for StatusEntry entity.
    
    Maps credentials to their positions in status lists.
    This is the lookup table for finding a credential's status.
    
    Table: status_list_entries
    """
    
    __tablename__ = "status_list_entries"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    credential_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    
    # Reference to the shard
    shard_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("status_list_shards.id", ondelete="CASCADE"),
        nullable=False,
    )
    
    # Position within the shard
    shard_index: Mapped[int] = mapped_column(Integer, nullable=False)
    bit_index: Mapped[int] = mapped_column(Integer, nullable=False)
    
    # Denormalized for efficient queries
    purpose: Mapped[str] = mapped_column(String(20), nullable=False)
    issuer_id: Mapped[str] = mapped_column(String(255), nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    
    __table_args__ = (
        # A credential can only have one entry per purpose
        UniqueConstraint("credential_id", "purpose", name="uq_entry_credential_purpose"),
        Index("ix_entry_credential_purpose", "credential_id", "purpose"),
        Index("ix_entry_shard", "shard_id"),
        Index("ix_entry_issuer", "issuer_id"),
    )
    
    def __repr__(self) -> str:
        return (
            f"<StatusEntryModel(id={self.id}, credential={self.credential_id}, "
            f"shard_idx={self.shard_index}, bit_idx={self.bit_index})>"
        )
