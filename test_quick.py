"""Quick test of the issuance service"""
import sys
sys.path.insert(0, "/Volumes/Heart of Gold/Github/work/marty-credentials/python")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from marty_credentials.adapters.persistence.models import Base
from marty_credentials.adapters.services.issuance_service import IssuanceService

# Create in-memory database
engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)
db_session = SessionLocal()

# Create issuance service
issuance_service = IssuanceService(db_session)

# Test W3C VC issuance
print("Testing W3C VC issuance...")
try:
    result = issuance_service.issue_w3c_vc(
        issuer_did="did:example:issuer123",
        subject_did="did:example:subject456",
        credential_type="IdentityCredential",
        claims={"name": "Alice", "age": 30}
    )
    print(f"✓ Successfully issued W3C VC:")
    print(f"  - Credential ID: {result['credential_id']}")
    print(f"  - Format: {result['format']}")
    print(f"  - Has JWT: {'jwt' in result}")
    print(f"  - Credential keys: {list(result['credential'].keys())}")
except Exception as e:
    print(f"✗ Failed to issue W3C VC: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*50 + "\n")

# Close database
db_session.close()
engine.dispose()

print("Test completed!")
