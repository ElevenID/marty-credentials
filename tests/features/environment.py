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
    # Create in-memory SQLite database for tests
    context.engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(context.engine)
    
    SessionLocal = sessionmaker(bind=context.engine)
    context.db_session = SessionLocal()
    
    # Initialize services
    from marty_credentials.adapters.services.issuance_service import IssuanceService
    from marty_credentials.adapters.services.verification_service import VerificationService
    
    context.issuance_service = IssuanceService(context.db_session)
    context.verification_service = VerificationService(context.db_session)
    
    # Mock status list services
    from unittest.mock import AsyncMock
    
    # Create a mock credential status service
    class MockCredentialStatusService:
        async def allocate_credential_status(self, credential_id, issuer_id, include_revocation=True, include_suspension=True):
            from status_list.domain.value_objects import BitstringStatusListEntry, StatusPurpose
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
    
    # Inject into issuance service
    context.issuance_service.credential_status_service = context.mock_credential_status_service
    
    # Storage for test data
    context.test_data = {}


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
