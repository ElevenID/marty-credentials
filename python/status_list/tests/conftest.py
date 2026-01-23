"""
Pytest configuration for status list tests.

Provides fixtures for testing the status list feature.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone

from status_list.domain.entities import StatusList, StatusEntry, Shard
from status_list.domain.value_objects import (
    StatusPurpose,
    ShardConfig,
    BitstringStatusListEntry,
)
from status_list.application.ports.outbound import (
    StatusListRepositoryPort,
    StatusEntryRepositoryPort,
    SigningServicePort,
    EventPublisherPort,
)


@pytest.fixture
def shard_config() -> ShardConfig:
    """Default shard configuration for tests."""
    return ShardConfig(
        size_bits=131072,
        cache_ttl_seconds=300,
        flush_interval_seconds=30,
    )


@pytest.fixture
def issuer_id() -> str:
    """Test issuer ID."""
    return "test-issuer-123"


@pytest.fixture
def credential_id() -> str:
    """Test credential ID."""
    return "urn:uuid:test-credential-456"


@pytest.fixture
def empty_shard(issuer_id: str) -> Shard:
    """Create an empty shard for testing."""
    return Shard.create_empty(
        issuer_id=issuer_id,
        purpose=StatusPurpose.REVOCATION,
        shard_index=0,
    )


@pytest.fixture
def status_list(issuer_id: str, shard_config: ShardConfig) -> StatusList:
    """Create a status list for testing."""
    return StatusList.create(
        issuer_id=issuer_id,
        purpose=StatusPurpose.REVOCATION,
        config=shard_config,
    )


@pytest.fixture
def mock_status_list_repository() -> AsyncMock:
    """Mock status list repository."""
    mock = AsyncMock(spec=StatusListRepositoryPort)
    mock.get.return_value = None
    mock.get_by_id.return_value = None
    mock.list_by_issuer.return_value = []
    return mock


@pytest.fixture
def mock_status_entry_repository() -> AsyncMock:
    """Mock status entry repository."""
    mock = AsyncMock(spec=StatusEntryRepositoryPort)
    mock.get_by_credential.return_value = None
    mock.get_all_for_credential.return_value = []
    mock.list_by_shard.return_value = []
    return mock


@pytest.fixture
def mock_signing_service() -> AsyncMock:
    """Mock signing service."""
    mock = AsyncMock(spec=SigningServicePort)
    mock.get_issuer_did.return_value = "did:web:test-issuer.example.com"
    mock.get_verification_method.return_value = "did:web:test-issuer.example.com#key-1"
    mock.sign_credential.return_value = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "proof": {"type": "DataIntegrityProof"},
    }
    return mock


@pytest.fixture
def mock_event_publisher() -> AsyncMock:
    """Mock event publisher."""
    mock = AsyncMock(spec=EventPublisherPort)
    return mock


@pytest.fixture
def base_url() -> str:
    """Base URL for status list endpoints."""
    return "https://api.example.com"
