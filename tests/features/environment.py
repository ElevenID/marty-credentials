# Behave test environment setup
import os
import sys
from pathlib import Path

# Add python package to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "python"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from marty_credentials.adapters.persistence.models import Base
from unittest.mock import AsyncMock, MagicMock


def before_all(context):
    """Initialize test environment"""
    # Set up minimal environment variables for configuration
    import os
    os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
    os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
    os.environ.setdefault("DEV_MODE", "true")
    os.environ.setdefault("ENABLE_TOKEN_VALIDATION", "false")
    os.environ.setdefault("ENABLE_EVENT_PUBLISHING", "false")
    os.environ.setdefault("ENABLE_RATE_LIMITING", "false")
    
    # Create in-memory SQLite database for tests
    context.engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(context.engine)
    
    SessionLocal = sessionmaker(bind=context.engine)
    context.db_session = SessionLocal()
    
    # Initialize services (kept for backward compatibility during migration)
    from marty_credentials.adapters.services.issuance_service import IssuanceService
    from marty_credentials.adapters.services.verification_service import VerificationService
    
    context.issuance_service = IssuanceService(context.db_session)
    context.verification_service = VerificationService(context.db_session)
    
    # Always use direct service calls for business logic testing
    context.use_gateway = False
    
    # Setup status list services with mocked repositories
    from unittest.mock import AsyncMock
    from status_list.application.services.status_list_service import StatusListService
    from status_list.application.services.credential_status_service import CredentialStatusService
    from status_list.domain.value_objects import ShardConfig, StatusPurpose, BitstringStatusListEntry
    from status_list.domain.entities import StatusList, StatusEntry, Shard
    
    # Create mock repositories
    mock_status_list_repo = AsyncMock()
    mock_status_entry_repo = AsyncMock()
    mock_event_publisher = AsyncMock()
    
    # Configure default shard config
    default_shard_config = ShardConfig(
        size_bits=131072,  # 16KB list
        cache_ttl_seconds=300,
        flush_interval_seconds=30,
    )
    
    # Initialize real StatusListService with mocked repos
    context.status_list_service = StatusListService(
        status_list_repository=mock_status_list_repo,
        status_entry_repository=mock_status_entry_repo,
        event_publisher=mock_event_publisher,
        default_config=default_shard_config,
    )
    
    # Initialize CredentialStatusService
    context.credential_status_service = CredentialStatusService(
        status_list_service=context.status_list_service,
        base_url="https://api.test.marty.dev",
    )
    
    # Store mocks for test manipulation
    context.mock_status_list_repo = mock_status_list_repo
    context.mock_status_entry_repo = mock_status_entry_repo
    
    # Setup default repository behaviors
    # By default, no existing status lists or entries
    mock_status_list_repo.get.return_value = None
    mock_status_list_repo.get_by_id.return_value = None
    mock_status_list_repo.list_by_issuer.return_value = []
    mock_status_entry_repo.get_by_credential.return_value = None
    mock_status_entry_repo.get_all_for_credential.return_value = []
    mock_status_entry_repo.list_by_shard.return_value = []
    
    # Create in-memory storage for status lists and entries (for testing)
    context.status_lists = {}  # issuer_id -> {purpose -> StatusList}
    context.status_entries = {}  # credential_id -> {purpose -> StatusEntry}
    
    # Setup repository save methods to store in-memory
    async def save_status_list(status_list: StatusList):
        if status_list.issuer_id not in context.status_lists:
            context.status_lists[status_list.issuer_id] = {}
        context.status_lists[status_list.issuer_id][status_list.purpose] = status_list
    
    async def save_status_entry(entry: StatusEntry):
        if entry.credential_id not in context.status_entries:
            context.status_entries[entry.credential_id] = {}
        context.status_entries[entry.credential_id][entry.purpose] = entry
    
    async def get_status_list(issuer_id: str, purpose: StatusPurpose):
        if issuer_id in context.status_lists and purpose in context.status_lists[issuer_id]:
            return context.status_lists[issuer_id][purpose]
        return None
    
    async def get_status_entry(credential_id: str, purpose: StatusPurpose):
        if credential_id in context.status_entries and purpose in context.status_entries[credential_id]:
            return context.status_entries[credential_id][purpose]
        return None
    
    mock_status_list_repo.save.side_effect = save_status_list
    mock_status_entry_repo.save.side_effect = save_status_entry
    mock_status_list_repo.get.side_effect = get_status_list
    mock_status_entry_repo.get_by_credential.side_effect = get_status_entry
    
    # Inject credential status service into issuance service
    # Keep old mock for backward compatibility during migration
    class MockCredentialStatusService:
        async def allocate_credential_status(self, credential_id, issuer_id, include_revocation=True, include_suspension=True):
            entries = []
            if include_revocation:
                entries.append(BitstringStatusListEntry.create(
                    base_url="https://api.test.marty.dev",
                    issuer_id=issuer_id,
                    purpose=StatusPurpose.REVOCATION,
                    shard_index=0,
                    list_index=12345
                ))
            if include_suspension:
                entries.append(BitstringStatusListEntry.create(
                    base_url="https://api.test.marty.dev",
                    issuer_id=issuer_id,
                    purpose=StatusPurpose.SUSPENSION,
                    shard_index=0,
                    list_index=12346
                ))
            return entries
        
        def build_credential_status_field(self, entries):
            if not entries:
                return []
            dicts = [entry.to_dict() for entry in entries]
            return dicts[0] if len(dicts) == 1 else dicts
    
    context.mock_credential_status_service = MockCredentialStatusService()
    context.issuance_service.credential_status_service = context.mock_credential_status_service
    
    # Storage for test data
    context.test_data = {}


def before_scenario(context, scenario):
    """Setup before each scenario"""
    # No setup needed for direct service testing
    pass


def after_all(context):
    """Cleanup after all tests"""
    context.db_session.close()
    context.engine.dispose()


def after_scenario(context, scenario):
    """Cleanup after each scenario"""
    # Rollback any uncommitted changes
    context.db_session.rollback()
    # Clear test data
    context.test_data.clear()
    # Clear in-memory status lists and entries
    context.status_lists.clear()
    context.status_entries.clear()
