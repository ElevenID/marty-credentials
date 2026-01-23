"""
Unit Tests - Value Objects

Tests for domain value objects.
"""

from __future__ import annotations

import pytest
from status_list.domain.value_objects import (
    StatusPurpose,
    StatusListFormat,
    StatusCode,
    ShardConfig,
    BitstringStatusListEntry,
)


class TestStatusPurpose:
    """Tests for the StatusPurpose enum."""

    def test_revocation_value(self):
        """Test revocation enum value."""
        assert StatusPurpose.REVOCATION.value == "revocation"

    def test_suspension_value(self):
        """Test suspension enum value."""
        assert StatusPurpose.SUSPENSION.value == "suspension"

    def test_from_string(self):
        """Test creating from string value."""
        assert StatusPurpose("revocation") == StatusPurpose.REVOCATION
        assert StatusPurpose("suspension") == StatusPurpose.SUSPENSION

    def test_invalid_string_raises(self):
        """Test that invalid string raises ValueError."""
        with pytest.raises(ValueError):
            StatusPurpose("invalid")


class TestStatusListFormat:
    """Tests for the StatusListFormat enum."""

    def test_bitstring_format(self):
        """Test bitstring format value."""
        assert StatusListFormat.BITSTRING.value == "bitstring"

    def test_2020_format(self):
        """Test 2020 format value for backwards compat."""
        assert StatusListFormat.STATUS_LIST_2020.value == "statusList2020"


class TestStatusCode:
    """Tests for StatusCode constants."""

    def test_valid_code(self):
        """Test valid status code."""
        assert StatusCode.VALID == 0

    def test_revoked_code(self):
        """Test revoked status code."""
        assert StatusCode.REVOKED == 1

    def test_suspended_code(self):
        """Test suspended status code."""
        assert StatusCode.SUSPENDED == 1


class TestShardConfig:
    """Tests for the ShardConfig value object."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ShardConfig()
        assert config.size_bits == 131072  # 16KB * 8
        assert config.cache_ttl_seconds == 300  # 5 minutes
        assert config.flush_interval_seconds == 30

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ShardConfig(
            size_bits=65536,
            cache_ttl_seconds=600,
            flush_interval_seconds=60,
        )
        assert config.size_bits == 65536
        assert config.cache_ttl_seconds == 600
        assert config.flush_interval_seconds == 60

    def test_bytes_calculation(self):
        """Test size_bytes property."""
        config = ShardConfig(size_bits=8192)
        assert config.size_bytes == 1024  # 8192 / 8

    def test_size_bytes_default(self):
        """Test default size in bytes."""
        config = ShardConfig()
        assert config.size_bytes == 16384  # 131072 / 8

    def test_immutability(self):
        """Test that ShardConfig is immutable (frozen)."""
        config = ShardConfig()
        with pytest.raises(AttributeError):
            config.size_bits = 1024  # type: ignore


class TestBitstringStatusListEntry:
    """Tests for the BitstringStatusListEntry value object."""

    def test_create_entry(self):
        """Test creating a status list entry."""
        entry = BitstringStatusListEntry(
            id="urn:uuid:test-entry",
            status_purpose=StatusPurpose.REVOCATION,
            status_list_index=42,
            status_list_credential="https://example.com/status/revocation/0",
        )
        assert entry.id == "urn:uuid:test-entry"
        assert entry.status_purpose == StatusPurpose.REVOCATION
        assert entry.status_list_index == 42
        assert entry.status_list_credential == "https://example.com/status/revocation/0"

    def test_to_dict(self):
        """Test converting entry to dictionary."""
        entry = BitstringStatusListEntry(
            id="urn:uuid:test-entry",
            status_purpose=StatusPurpose.REVOCATION,
            status_list_index=42,
            status_list_credential="https://example.com/status/revocation/0",
        )
        d = entry.to_dict()

        assert d["id"] == "urn:uuid:test-entry"
        assert d["type"] == "BitstringStatusListEntry"
        assert d["statusPurpose"] == "revocation"
        assert d["statusListIndex"] == "42"  # String per spec
        assert d["statusListCredential"] == "https://example.com/status/revocation/0"

    def test_to_dict_suspension(self):
        """Test converting suspension entry to dictionary."""
        entry = BitstringStatusListEntry(
            id="urn:uuid:suspension-entry",
            status_purpose=StatusPurpose.SUSPENSION,
            status_list_index=100,
            status_list_credential="https://example.com/status/suspension/0",
        )
        d = entry.to_dict()

        assert d["statusPurpose"] == "suspension"

    def test_immutability(self):
        """Test that BitstringStatusListEntry is immutable."""
        entry = BitstringStatusListEntry(
            id="urn:uuid:test",
            status_purpose=StatusPurpose.REVOCATION,
            status_list_index=0,
            status_list_credential="https://example.com/status/revocation/0",
        )
        with pytest.raises(AttributeError):
            entry.status_list_index = 10  # type: ignore

    def test_entry_with_zero_index(self):
        """Test entry with zero index."""
        entry = BitstringStatusListEntry(
            id="urn:uuid:zero-entry",
            status_purpose=StatusPurpose.REVOCATION,
            status_list_index=0,
            status_list_credential="https://example.com/status/revocation/0",
        )
        d = entry.to_dict()
        assert d["statusListIndex"] == "0"

    def test_entry_with_large_index(self):
        """Test entry with large index."""
        entry = BitstringStatusListEntry(
            id="urn:uuid:large-entry",
            status_purpose=StatusPurpose.REVOCATION,
            status_list_index=131071,  # Max index for default shard
            status_list_credential="https://example.com/status/revocation/0",
        )
        d = entry.to_dict()
        assert d["statusListIndex"] == "131071"
