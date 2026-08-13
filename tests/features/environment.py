# Behave test environment setup
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from uuid import uuid4

# Add python package to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "python"))

from marty_credentials.adapters.persistence.models import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


class StatusPurpose(str, Enum):
    REVOCATION = "revocation"
    SUSPENSION = "suspension"


class StatusCode(int, Enum):
    VALID = 0
    ACTIVE = 0
    INVALID = 1
    REVOKED = 1
    SUSPENDED = 2


@dataclass
class BitstringStatusListEntry:
    id: str
    status_purpose: StatusPurpose
    status_list_index: int
    status_list_credential: str

    @classmethod
    def create(cls, base_url, issuer_id, purpose, shard_index, list_index):
        credential = f"{base_url}/v3/status/{issuer_id}/{purpose.value}/{shard_index}"
        return cls(f"{credential}#{list_index}", purpose, list_index, credential)

    def to_dict(self):
        return {
            "id": self.id,
            "type": "BitstringStatusListEntry",
            "statusPurpose": self.status_purpose.value,
            "statusListIndex": str(self.status_list_index),
            "statusListCredential": self.status_list_credential,
        }


@dataclass
class StatusList:
    id: str
    issuer_id: str
    purpose: StatusPurpose


@dataclass
class StatusEntry:
    credential_id: str
    issuer_id: str
    purpose: StatusPurpose
    bit_index: int
    shard_index: int = 0
    status: StatusCode = StatusCode.VALID


class FakeCanonicalStatusClient:
    """Test double for the separately contracted Rust revocation service."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.lists = {}
        self.entries = {}

    async def create_status_list(self, issuer_id, purpose):
        status_list = StatusList(str(uuid4()), issuer_id, purpose)
        self.lists[(issuer_id, purpose)] = status_list
        return status_list

    async def allocate_status_entry(self, credential_id, issuer_id, purpose):
        key = (credential_id, purpose)
        if key not in self.entries:
            self.entries[key] = StatusEntry(
                credential_id,
                issuer_id,
                purpose,
                sum(entry.purpose == purpose for entry in self.entries.values()),
            )
        return self.entries[key]

    async def update_status(self, credential_id, purpose, status, reason=None):
        del reason
        entry = self.entries.get((credential_id, purpose))
        if entry is None:
            return False
        entry.status = status
        return True

    async def check_status(self, credential_id, purpose):
        entry = self.entries.get((credential_id, purpose))
        return entry.status if entry else None


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
    
    # The deployed status implementation is the Rust revocation service. These
    # legacy Behave scenarios use a transport-level test double instead of
    # carrying another status-list algorithm in Python.
    context.status_list_service = FakeCanonicalStatusClient()
    context.StatusPurpose = StatusPurpose
    context.StatusCode = StatusCode

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
    context.status_list_service.reset()
