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
