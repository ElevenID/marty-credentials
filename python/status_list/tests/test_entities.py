"""
Unit Tests - Status List Domain Entities

Tests for domain entities including StatusList, Shard, and StatusEntry.
"""

from __future__ import annotations

import base64
import gzip
import pytest
from datetime import datetime, timezone

from status_list.domain.entities import StatusList, StatusEntry, Shard
from status_list.domain.value_objects import StatusPurpose, ShardConfig


class TestShard:
    """Tests for the Shard entity."""

    def test_create_empty_shard(self, issuer_id: str):
        """Test creating an empty shard."""
        shard = Shard.create_empty(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
            shard_index=0,
        )

        assert shard.issuer_id == issuer_id
        assert shard.purpose == StatusPurpose.REVOCATION
        assert shard.index == 0
        assert shard.next_available_index == 0
        assert not shard.is_full()

        # Verify the encoded list decodes to zeros
        compressed = base64.b64decode(shard.encoded_list)
        decompressed = gzip.decompress(compressed)
        assert all(b == 0 for b in decompressed)

    def test_shard_allocate_index(self, empty_shard: Shard):
        """Test allocating indices in a shard."""
        idx1 = empty_shard.allocate_index()
        idx2 = empty_shard.allocate_index()
        idx3 = empty_shard.allocate_index()

        assert idx1 == 0
        assert idx2 == 1
        assert idx3 == 2
        assert empty_shard.next_available_index == 3

    def test_shard_get_status_initial(self, empty_shard: Shard):
        """Test that initial status is 0 (valid)."""
        assert empty_shard.get_status(0) == 0
        assert empty_shard.get_status(100) == 0
        assert empty_shard.get_status(1000) == 0

    def test_shard_set_status(self, empty_shard: Shard):
        """Test setting status values."""
        # Set bit at index 5 to 1 (revoked)
        empty_shard.set_status(5, 1)
        assert empty_shard.get_status(5) == 1

        # Other bits should still be 0
        assert empty_shard.get_status(4) == 0
        assert empty_shard.get_status(6) == 0

        # Set back to 0 (unsuspend)
        empty_shard.set_status(5, 0)
        assert empty_shard.get_status(5) == 0

    def test_shard_set_multiple_statuses(self, empty_shard: Shard):
        """Test setting multiple status bits."""
        indices = [0, 7, 8, 15, 16, 100, 1000]

        # Set all to 1
        for idx in indices:
            empty_shard.set_status(idx, 1)

        # Verify all are 1
        for idx in indices:
            assert empty_shard.get_status(idx) == 1

        # Verify some others are still 0
        assert empty_shard.get_status(1) == 0
        assert empty_shard.get_status(50) == 0

    def test_shard_version_increments(self, empty_shard: Shard):
        """Test that version increments on status update."""
        initial_version = empty_shard.version

        empty_shard.set_status(0, 1)
        assert empty_shard.version == initial_version + 1

        empty_shard.set_status(1, 1)
        assert empty_shard.version == initial_version + 2

    def test_shard_is_full(self, issuer_id: str):
        """Test shard full detection."""
        # Create a tiny shard for testing
        config = ShardConfig(size_bits=131072)  # Minimum size
        shard = Shard.create_empty(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
            shard_index=0,
            config=config,
        )

        assert not shard.is_full()

        # Simulate filling the shard
        shard.next_available_index = config.max_entries
        assert shard.is_full()

    def test_shard_allocate_when_full_raises(self, issuer_id: str):
        """Test that allocating from a full shard raises."""
        config = ShardConfig(size_bits=131072)
        shard = Shard.create_empty(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
            shard_index=0,
            config=config,
        )
        shard.next_available_index = config.max_entries

        with pytest.raises(ValueError, match="full"):
            shard.allocate_index()


class TestStatusList:
    """Tests for the StatusList aggregate."""

    def test_create_status_list(self, issuer_id: str, shard_config: ShardConfig):
        """Test creating a status list."""
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
            config=shard_config,
        )

        assert status_list.issuer_id == issuer_id
        assert status_list.purpose == StatusPurpose.REVOCATION
        assert len(status_list.shards) == 1
        assert status_list.shards[0].index == 0

    def test_create_status_list_for_suspension(self, issuer_id: str):
        """Test creating a suspension status list."""
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.SUSPENSION,
        )

        assert status_list.purpose == StatusPurpose.SUSPENSION

    def test_allocate_entry(self, status_list: StatusList, credential_id: str):
        """Test allocating an entry in the status list."""
        entry = status_list.allocate_entry(credential_id)

        assert entry.credential_id == credential_id
        assert entry.shard_index == 0
        assert entry.bit_index == 0
        assert entry.purpose == status_list.purpose

    def test_allocate_multiple_entries(self, status_list: StatusList):
        """Test allocating multiple entries."""
        entry1 = status_list.allocate_entry("cred-1")
        entry2 = status_list.allocate_entry("cred-2")
        entry3 = status_list.allocate_entry("cred-3")

        assert entry1.bit_index == 0
        assert entry2.bit_index == 1
        assert entry3.bit_index == 2

    def test_get_shard_by_index(self, status_list: StatusList):
        """Test getting a shard by index."""
        shard = status_list.get_shard_by_index(0)
        assert shard is not None
        assert shard.index == 0

        # Non-existent shard
        assert status_list.get_shard_by_index(999) is None

    def test_set_and_get_status(self, status_list: StatusList):
        """Test setting and getting status through the aggregate."""
        status_list.set_status(shard_index=0, bit_index=5, value=1)
        assert status_list.get_status(shard_index=0, bit_index=5) == 1
        assert status_list.get_status(shard_index=0, bit_index=4) == 0


class TestStatusEntry:
    """Tests for the StatusEntry entity."""

    def test_create_status_entry(self, empty_shard: Shard, credential_id: str):
        """Test creating a status entry."""
        bit_index = 42
        entry = StatusEntry.create(
            credential_id=credential_id,
            shard=empty_shard,
            bit_index=bit_index,
        )

        assert entry.credential_id == credential_id
        assert entry.shard_id == empty_shard.id
        assert entry.shard_index == empty_shard.index
        assert entry.bit_index == bit_index
        assert entry.purpose == empty_shard.purpose
        assert entry.issuer_id == empty_shard.issuer_id

    def test_to_status_list_entry(self, empty_shard: Shard, credential_id: str, base_url: str):
        """Test converting to BitstringStatusListEntry."""
        entry = StatusEntry.create(
            credential_id=credential_id,
            shard=empty_shard,
            bit_index=42,
        )

        status_entry = entry.to_status_list_entry(base_url)

        assert status_entry.type == "BitstringStatusListEntry"
        assert status_entry.status_purpose == StatusPurpose.REVOCATION
        assert status_entry.status_list_index == 42
        assert base_url in status_entry.status_list_credential
        assert "#42" in status_entry.id
