"""
Integration Tests - Repository Layer

Tests for persistence repositories using in-memory SQLite.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from status_list.domain.entities import StatusList, StatusEntry, Shard
from status_list.domain.value_objects import StatusPurpose, ShardConfig
from status_list.infrastructure.persistence.models import Base, StatusListModel, ShardModel, StatusEntryModel
from status_list.infrastructure.persistence.repository import StatusListRepository, StatusEntryRepository


@pytest.fixture
async def async_engine():
    """Create an async SQLite engine for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def async_session(async_engine):
    """Create an async session for testing."""
    async_session_maker = sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with async_session_maker() as session:
        yield session
        await session.rollback()


@pytest.fixture
def status_list_repo(async_session: AsyncSession) -> StatusListRepository:
    """Create a status list repository."""
    return StatusListRepository(session=async_session)


@pytest.fixture
def status_entry_repo(async_session: AsyncSession) -> StatusEntryRepository:
    """Create a status entry repository."""
    return StatusEntryRepository(session=async_session)


class TestStatusListRepository:
    """Tests for StatusListRepository."""

    @pytest.mark.asyncio
    async def test_save_and_get(
        self,
        status_list_repo: StatusListRepository,
        issuer_id: str,
    ):
        """Test saving and retrieving a status list."""
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )

        await status_list_repo.save(status_list)

        retrieved = await status_list_repo.get(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )

        assert retrieved is not None
        assert retrieved.id == status_list.id
        assert retrieved.issuer_id == issuer_id
        assert retrieved.purpose == StatusPurpose.REVOCATION

    @pytest.mark.asyncio
    async def test_get_nonexistent(
        self,
        status_list_repo: StatusListRepository,
    ):
        """Test getting a non-existent status list."""
        result = await status_list_repo.get(
            issuer_id="nonexistent",
            purpose=StatusPurpose.REVOCATION,
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_save_with_shards(
        self,
        status_list_repo: StatusListRepository,
        issuer_id: str,
    ):
        """Test saving a status list with multiple shards."""
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )

        # Add more shards
        status_list.add_shard()
        status_list.add_shard()

        await status_list_repo.save(status_list)

        retrieved = await status_list_repo.get(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )

        assert retrieved is not None
        assert len(retrieved.shards) == 3

    @pytest.mark.asyncio
    async def test_update_shard(
        self,
        status_list_repo: StatusListRepository,
        issuer_id: str,
    ):
        """Test updating a shard's bitstring."""
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )
        await status_list_repo.save(status_list)

        # Modify shard
        shard = status_list.shards[0]
        shard.set_bit(5, 1)

        await status_list_repo.update_shard(shard)

        # Retrieve and verify
        retrieved = await status_list_repo.get(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )
        assert retrieved is not None
        assert retrieved.shards[0].get_bit(5) == 1

    @pytest.mark.asyncio
    async def test_get_shard_by_index(
        self,
        status_list_repo: StatusListRepository,
        issuer_id: str,
    ):
        """Test getting a specific shard by index."""
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )
        status_list.add_shard()
        await status_list_repo.save(status_list)

        shard = await status_list_repo.get_shard(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
            shard_index=1,
        )

        assert shard is not None
        assert shard.index == 1

    @pytest.mark.asyncio
    async def test_list_by_issuer(
        self,
        status_list_repo: StatusListRepository,
        issuer_id: str,
    ):
        """Test listing all status lists for an issuer."""
        # Create revocation list
        revocation_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )
        await status_list_repo.save(revocation_list)

        # Create suspension list
        suspension_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.SUSPENSION,
        )
        await status_list_repo.save(suspension_list)

        # List all
        lists = await status_list_repo.list_by_issuer(issuer_id)

        assert len(lists) == 2
        purposes = [sl.purpose for sl in lists]
        assert StatusPurpose.REVOCATION in purposes
        assert StatusPurpose.SUSPENSION in purposes


class TestStatusEntryRepository:
    """Tests for StatusEntryRepository."""

    @pytest.mark.asyncio
    async def test_save_and_get(
        self,
        status_entry_repo: StatusEntryRepository,
        status_list_repo: StatusListRepository,
        issuer_id: str,
        credential_id: str,
    ):
        """Test saving and retrieving a status entry."""
        # First create a status list
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )
        await status_list_repo.save(status_list)

        # Create entry
        entry = StatusEntry(
            id="entry-1",
            credential_id=credential_id,
            shard_id=status_list.shards[0].id,
            shard_index=0,
            bit_index=42,
            purpose=StatusPurpose.REVOCATION,
            issuer_id=issuer_id,
        )
        await status_entry_repo.save(entry)

        # Retrieve
        retrieved = await status_entry_repo.get_by_credential(
            credential_id=credential_id,
            purpose=StatusPurpose.REVOCATION,
        )

        assert retrieved is not None
        assert retrieved.credential_id == credential_id
        assert retrieved.bit_index == 42

    @pytest.mark.asyncio
    async def test_get_by_credential_not_found(
        self,
        status_entry_repo: StatusEntryRepository,
    ):
        """Test getting entry for non-existent credential."""
        result = await status_entry_repo.get_by_credential(
            credential_id="nonexistent",
            purpose=StatusPurpose.REVOCATION,
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_save_multiple_purposes(
        self,
        status_entry_repo: StatusEntryRepository,
        status_list_repo: StatusListRepository,
        issuer_id: str,
        credential_id: str,
    ):
        """Test saving entries for multiple purposes."""
        # Create status lists
        revocation_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )
        await status_list_repo.save(revocation_list)

        suspension_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.SUSPENSION,
        )
        await status_list_repo.save(suspension_list)

        # Create entries
        revocation_entry = StatusEntry(
            id="revocation-entry",
            credential_id=credential_id,
            shard_id=revocation_list.shards[0].id,
            shard_index=0,
            bit_index=10,
            purpose=StatusPurpose.REVOCATION,
            issuer_id=issuer_id,
        )
        await status_entry_repo.save(revocation_entry)

        suspension_entry = StatusEntry(
            id="suspension-entry",
            credential_id=credential_id,
            shard_id=suspension_list.shards[0].id,
            shard_index=0,
            bit_index=20,
            purpose=StatusPurpose.SUSPENSION,
            issuer_id=issuer_id,
        )
        await status_entry_repo.save(suspension_entry)

        # Retrieve each
        rev = await status_entry_repo.get_by_credential(
            credential_id=credential_id,
            purpose=StatusPurpose.REVOCATION,
        )
        sus = await status_entry_repo.get_by_credential(
            credential_id=credential_id,
            purpose=StatusPurpose.SUSPENSION,
        )

        assert rev is not None and rev.bit_index == 10
        assert sus is not None and sus.bit_index == 20

    @pytest.mark.asyncio
    async def test_list_by_shard(
        self,
        status_entry_repo: StatusEntryRepository,
        status_list_repo: StatusListRepository,
        issuer_id: str,
    ):
        """Test listing all entries in a shard."""
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )
        await status_list_repo.save(status_list)

        shard = status_list.shards[0]

        # Create multiple entries
        for i in range(5):
            entry = StatusEntry(
                id=f"entry-{i}",
                credential_id=f"credential-{i}",
                shard_id=shard.id,
                shard_index=0,
                bit_index=i,
                purpose=StatusPurpose.REVOCATION,
                issuer_id=issuer_id,
            )
            await status_entry_repo.save(entry)

        # List by shard
        entries = await status_entry_repo.list_by_shard(shard_id=shard.id)

        assert len(entries) == 5

    @pytest.mark.asyncio
    async def test_count_by_shard(
        self,
        status_entry_repo: StatusEntryRepository,
        status_list_repo: StatusListRepository,
        issuer_id: str,
    ):
        """Test counting entries in a shard."""
        status_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )
        await status_list_repo.save(status_list)

        shard = status_list.shards[0]

        # Create some entries
        for i in range(3):
            entry = StatusEntry(
                id=f"entry-{i}",
                credential_id=f"credential-{i}",
                shard_id=shard.id,
                shard_index=0,
                bit_index=i,
                purpose=StatusPurpose.REVOCATION,
                issuer_id=issuer_id,
            )
            await status_entry_repo.save(entry)

        count = await status_entry_repo.count_by_shard(shard_id=shard.id)

        assert count == 3
