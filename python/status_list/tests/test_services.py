"""
Unit Tests - Application Services

Tests for StatusListService and CredentialStatusService.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from status_list.domain.entities import StatusList, StatusEntry, Shard
from status_list.domain.value_objects import StatusPurpose, ShardConfig, StatusCode
from status_list.application.services.status_list_service import StatusListService
from status_list.application.services.credential_status_service import CredentialStatusService


class TestStatusListService:
    """Tests for the StatusListService."""

    @pytest.fixture
    def service(
        self,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        mock_event_publisher: AsyncMock,
        shard_config: ShardConfig,
    ) -> StatusListService:
        """Create a service instance with mocks."""
        return StatusListService(
            status_list_repository=mock_status_list_repository,
            status_entry_repository=mock_status_entry_repository,
            event_publisher=mock_event_publisher,
            default_config=shard_config,
        )

    @pytest.mark.asyncio
    async def test_create_status_list(
        self,
        service: StatusListService,
        mock_status_list_repository: AsyncMock,
        issuer_id: str,
    ):
        """Test creating a new status list."""
        # Repository returns None (no existing list)
        mock_status_list_repository.get.return_value = None

        status_list = await service.create_status_list(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )

        assert status_list.issuer_id == issuer_id
        assert status_list.purpose == StatusPurpose.REVOCATION
        assert len(status_list.shards) == 1

        # Verify save was called
        mock_status_list_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_status_list_already_exists(
        self,
        service: StatusListService,
        mock_status_list_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
    ):
        """Test creating a status list when one already exists."""
        mock_status_list_repository.get.return_value = status_list

        with pytest.raises(ValueError, match="already exists"):
            await service.create_status_list(
                issuer_id=issuer_id,
                purpose=StatusPurpose.REVOCATION,
            )

    @pytest.mark.asyncio
    async def test_get_or_create_returns_existing(
        self,
        service: StatusListService,
        mock_status_list_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
    ):
        """Test get_or_create returns existing list."""
        mock_status_list_repository.get.return_value = status_list

        result = await service.get_or_create_status_list(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )

        assert result.id == status_list.id
        mock_status_list_repository.save.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_or_create_creates_new(
        self,
        service: StatusListService,
        mock_status_list_repository: AsyncMock,
        issuer_id: str,
    ):
        """Test get_or_create creates new list when none exists."""
        mock_status_list_repository.get.return_value = None

        result = await service.get_or_create_status_list(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )

        assert result.issuer_id == issuer_id
        mock_status_list_repository.save.assert_called()

    @pytest.mark.asyncio
    async def test_allocate_status_entry(
        self,
        service: StatusListService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
        credential_id: str,
    ):
        """Test allocating a status entry for a credential."""
        mock_status_list_repository.get.return_value = status_list
        mock_status_entry_repository.get_by_credential.return_value = None

        entry = await service.allocate_status_entry(
            credential_id=credential_id,
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )

        assert entry.credential_id == credential_id
        assert entry.bit_index == 0
        mock_status_entry_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_allocate_status_entry_returns_existing(
        self,
        service: StatusListService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
        credential_id: str,
    ):
        """Test that allocating for an existing credential returns existing entry."""
        existing_entry = StatusEntry(
            id="existing-entry-id",
            credential_id=credential_id,
            shard_id="shard-id",
            shard_index=0,
            bit_index=5,
            purpose=StatusPurpose.REVOCATION,
            issuer_id=issuer_id,
        )
        mock_status_list_repository.get.return_value = status_list
        mock_status_entry_repository.get_by_credential.return_value = existing_entry

        entry = await service.allocate_status_entry(
            credential_id=credential_id,
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )

        assert entry.id == existing_entry.id
        assert entry.bit_index == 5

    @pytest.mark.asyncio
    async def test_update_status(
        self,
        service: StatusListService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
        credential_id: str,
    ):
        """Test updating credential status."""
        entry = StatusEntry(
            id="entry-id",
            credential_id=credential_id,
            shard_id=status_list.shards[0].id,
            shard_index=0,
            bit_index=0,
            purpose=StatusPurpose.REVOCATION,
            issuer_id=issuer_id,
        )
        mock_status_entry_repository.get_by_credential.return_value = entry
        mock_status_list_repository.get.return_value = status_list

        result = await service.update_status(
            credential_id=credential_id,
            purpose=StatusPurpose.REVOCATION,
            status=1,
            reason="Test revocation",
        )

        assert result is True
        mock_status_list_repository.update_shard.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_status_credential_not_found(
        self,
        service: StatusListService,
        mock_status_entry_repository: AsyncMock,
        credential_id: str,
    ):
        """Test updating status for non-existent credential."""
        mock_status_entry_repository.get_by_credential.return_value = None

        result = await service.update_status(
            credential_id=credential_id,
            purpose=StatusPurpose.REVOCATION,
            status=1,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_check_status(
        self,
        service: StatusListService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
        credential_id: str,
    ):
        """Test checking credential status."""
        entry = StatusEntry(
            id="entry-id",
            credential_id=credential_id,
            shard_id=status_list.shards[0].id,
            shard_index=0,
            bit_index=0,
            purpose=StatusPurpose.REVOCATION,
            issuer_id=issuer_id,
        )
        mock_status_entry_repository.get_by_credential.return_value = entry
        mock_status_list_repository.get.return_value = status_list

        # Initial status should be 0 (valid)
        status = await service.check_status(
            credential_id=credential_id,
            purpose=StatusPurpose.REVOCATION,
        )

        assert status == 0


class TestCredentialStatusService:
    """Tests for the CredentialStatusService."""

    @pytest.fixture
    def status_list_service(
        self,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        mock_event_publisher: AsyncMock,
        shard_config: ShardConfig,
    ) -> StatusListService:
        """Create a status list service with mocks."""
        return StatusListService(
            status_list_repository=mock_status_list_repository,
            status_entry_repository=mock_status_entry_repository,
            event_publisher=mock_event_publisher,
            default_config=shard_config,
        )

    @pytest.fixture
    def service(
        self,
        status_list_service: StatusListService,
        base_url: str,
    ) -> CredentialStatusService:
        """Create a credential status service."""
        return CredentialStatusService(
            status_list_service=status_list_service,
            base_url=base_url,
        )

    @pytest.mark.asyncio
    async def test_allocate_credential_status(
        self,
        service: CredentialStatusService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
        credential_id: str,
    ):
        """Test allocating status entries for a credential."""
        # Setup for revocation list
        revocation_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.REVOCATION,
        )
        suspension_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.SUSPENSION,
        )

        def get_list(iid: str, purpose: StatusPurpose):
            if purpose == StatusPurpose.REVOCATION:
                return revocation_list
            return suspension_list

        mock_status_list_repository.get.side_effect = get_list
        mock_status_entry_repository.get_by_credential.return_value = None

        entries = await service.allocate_credential_status(
            credential_id=credential_id,
            issuer_id=issuer_id,
            include_revocation=True,
            include_suspension=True,
        )

        assert len(entries) == 2
        purposes = [e.status_purpose for e in entries]
        assert StatusPurpose.REVOCATION in purposes
        assert StatusPurpose.SUSPENSION in purposes

    @pytest.mark.asyncio
    async def test_allocate_credential_status_revocation_only(
        self,
        service: CredentialStatusService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
        credential_id: str,
    ):
        """Test allocating only revocation status."""
        mock_status_list_repository.get.return_value = status_list
        mock_status_entry_repository.get_by_credential.return_value = None

        entries = await service.allocate_credential_status(
            credential_id=credential_id,
            issuer_id=issuer_id,
            include_revocation=True,
            include_suspension=False,
        )

        assert len(entries) == 1
        assert entries[0].status_purpose == StatusPurpose.REVOCATION

    @pytest.mark.asyncio
    async def test_revoke_credential(
        self,
        service: CredentialStatusService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
        credential_id: str,
    ):
        """Test revoking a credential."""
        entry = StatusEntry(
            id="entry-id",
            credential_id=credential_id,
            shard_id=status_list.shards[0].id,
            shard_index=0,
            bit_index=0,
            purpose=StatusPurpose.REVOCATION,
            issuer_id=issuer_id,
        )
        mock_status_entry_repository.get_by_credential.return_value = entry
        mock_status_list_repository.get.return_value = status_list

        result = await service.revoke_credential(
            credential_id=credential_id,
            reason="Lost credential",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_suspend_and_unsuspend_credential(
        self,
        service: CredentialStatusService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        issuer_id: str,
        credential_id: str,
    ):
        """Test suspending and unsuspending a credential."""
        suspension_list = StatusList.create(
            issuer_id=issuer_id,
            purpose=StatusPurpose.SUSPENSION,
        )
        entry = StatusEntry(
            id="entry-id",
            credential_id=credential_id,
            shard_id=suspension_list.shards[0].id,
            shard_index=0,
            bit_index=0,
            purpose=StatusPurpose.SUSPENSION,
            issuer_id=issuer_id,
        )
        mock_status_entry_repository.get_by_credential.return_value = entry
        mock_status_list_repository.get.return_value = suspension_list

        # Suspend
        result = await service.suspend_credential(
            credential_id=credential_id,
            reason="Under review",
        )
        assert result is True

        # Check suspended
        is_suspended = await service.is_suspended(credential_id)
        assert is_suspended is True

        # Unsuspend
        result = await service.unsuspend_credential(credential_id=credential_id)
        assert result is True

    @pytest.mark.asyncio
    async def test_is_revoked(
        self,
        service: CredentialStatusService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
        credential_id: str,
    ):
        """Test checking if a credential is revoked."""
        entry = StatusEntry(
            id="entry-id",
            credential_id=credential_id,
            shard_id=status_list.shards[0].id,
            shard_index=0,
            bit_index=0,
            purpose=StatusPurpose.REVOCATION,
            issuer_id=issuer_id,
        )
        mock_status_entry_repository.get_by_credential.return_value = entry
        mock_status_list_repository.get.return_value = status_list

        # Not revoked initially
        is_revoked = await service.is_revoked(credential_id)
        assert is_revoked is False

    @pytest.mark.asyncio
    async def test_get_credential_status(
        self,
        service: CredentialStatusService,
        mock_status_list_repository: AsyncMock,
        mock_status_entry_repository: AsyncMock,
        status_list: StatusList,
        issuer_id: str,
        credential_id: str,
    ):
        """Test getting full credential status."""
        entry = StatusEntry(
            id="entry-id",
            credential_id=credential_id,
            shard_id=status_list.shards[0].id,
            shard_index=0,
            bit_index=0,
            purpose=StatusPurpose.REVOCATION,
            issuer_id=issuer_id,
        )
        mock_status_entry_repository.get_by_credential.return_value = entry
        mock_status_list_repository.get.return_value = status_list

        status = await service.get_credential_status(credential_id)

        assert "revoked" in status
        assert "suspended" in status
