import base64
import sys
from behave import given, when, then
from unittest.mock import MagicMock

# Mock the rust binding BEFORE importing service
if 'marty_verification_py' not in sys.modules:
    mock_verif = MagicMock()
    sys.modules['marty_verification_py'] = mock_verif

    def mock_verify_age_zkp(nonce, mso, proof):
        """
        Mock verification logic for testing:
        - Proof is considered 'valid' only if it contains the nonce.
        - This simulates the ZK property of being bound to the session nonce.
        """
        if not proof or not nonce:
            return False
        return nonce in proof

    mock_verif.verify_age_zkp = mock_verify_age_zkp

if '_marty_rs' not in sys.modules:
    mock_rs = MagicMock()
    sys.modules['_marty_rs'] = mock_rs
    # Also mock internal types if needed
    mock_rs.SdJwtVerifier = MagicMock()


from marty_credentials.adapters.services.verification_service import VerificationService
from marty_credentials.ports.types import VerificationResult as PortVerificationResult
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from marty_credentials.adapters.persistence.models import Base

@given('a ZK verification service is initialized')
def step_impl(context):
    # Setup in-memory DB
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    context.db_session = Session()
    context.zk_service = VerificationService(context.db_session)

@given('a valid Age Over 18 mDoc credential is available')
def step_impl(context):
    # Mock data
    context.mso_bytes = b"mock_mso_data"
    context.valid_birth_date = "1990-01-01"

@given('a fresh ZK challenge session is created for "{doctype}"')
def step_impl(context, doctype):
    context.current_session = context.zk_service.create_zk_challenge(doctype=doctype)
    context.session_id = context.current_session.session_id
    context.nonce = context.current_session.nonce

@given('another separate ZK challenge session exists')
def step_impl(context):
    context.other_session = context.zk_service.create_zk_challenge(doctype="org.iso.18013.5.1.mDL")

@when('I generate a valid Age Over 18 proof for the session nonce')
def step_impl(context):
    # Simulate proof generation: embed nonce to pass our mock verification
    # Proof = Nonce + "proof_data"
    context.proof_bytes = context.nonce + b"_proof_data"

@when('I generate a valid Age Over 18 proof for the OTHER session nonce')
def step_impl(context):
    # Embed the OTHER nonce
    context.proof_bytes = context.other_session.nonce + b"_proof_data"

@when('I submit the proof and MSO for verification')
def step_impl(context):
    context.verification_result = context.zk_service.verify_zk_proof(
        session_id=context.session_id,
        proof=context.proof_bytes,
        mso=context.mso_bytes
    )

@when('I submit the proof to the FIRST session')
def step_impl(context):
    # context.session_id refers to the FIRST session created
    context.verification_result = context.zk_service.verify_zk_proof(
        session_id=context.session_id,
        proof=context.proof_bytes,
        mso=context.mso_bytes
    )

@when('I submit an invalid proof with random bytes')
def step_impl(context):
    context.proof_bytes = b"random_invalid_bytes"
    context.verification_result = context.zk_service.verify_zk_proof(
        session_id=context.session_id,
        proof=context.proof_bytes,
        mso=context.mso_bytes
    )

@then('the ZK verification should succeed')
def step_impl(context):
    assert context.verification_result.valid is True, f"Verification failed: {context.verification_result.error}"

@then('the ZK verification should fail')
def step_impl(context):
    assert context.verification_result.valid is False, "Verification succeeded but should have failed"

@then('the verification result should contain claim "{claim}" as true')
def step_impl(context, claim):
    claims = context.verification_result.claims
    assert claims.get(claim) is True, f"Claim {claim} not found or not True"

@then('the ZK error should indicate "{error_msg}"')
def step_impl(context, error_msg):
    assert error_msg in context.verification_result.error, \
        f"Expected error '{error_msg}', got '{context.verification_result.error}'"
