"""
Step definitions for ZK proof tests

Supports two modes:
1. Direct service calls (legacy, USE_GATEWAY_TESTS=false)
2. Gateway HTTP calls via Pact mock (default, USE_GATEWAY_TESTS=true)
"""
import base64
import sys
from behave import given, when, then
from unittest.mock import MagicMock

# Import Pact interactions for gateway testing
from pact_interactions import Interactions

# NOTE: Removed global mocking of _marty_rs and marty_verification_py
# These should be available in the test environment. If ZK tests need
# specific mocking, it should be done in the test scenarios themselves,
# not globally which affects ALL tests.


from marty_credentials.adapters.services.verification_service import VerificationService
from marty_credentials.ports.types import VerificationResult as PortVerificationResult
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from marty_credentials.adapters.persistence.models import Base


def _use_gateway(context) -> bool:
    """Check if we should use gateway HTTP calls."""
    return getattr(context, 'use_gateway', False)


def _get_http_client(context):
    """Get the HTTP client for gateway calls."""
    if not hasattr(context, 'http_client'):
        raise RuntimeError("HTTP client not initialized. Ensure USE_GATEWAY_TESTS=true and before_scenario ran.")
    return context.http_client


@given('a ZK verification service is initialized')
def step_impl(context):
    # Setup in-memory DB (only for direct mode)
    if not _use_gateway(context):
        engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        context.db_session = Session()
        context.zk_service = VerificationService(context.db_session)
    # For gateway mode, the service is accessed via HTTP


@given('a valid Age Over 18 mDoc credential is available')
def step_impl(context):
    # Mock data
    context.mso_bytes = b"mock_mso_data"
    context.valid_birth_date = "1990-01-01"


@given('a fresh ZK challenge session is created for "{doctype}"')
def step_impl(context, doctype):
    if _use_gateway(context):
        # Add Pact interaction for ZK challenge creation
        interaction = Interactions.ZK.create_zk_challenge(
            doctype=doctype,
            predicate_type="age_over_18",
        )
        context.pact_provider.add_interaction(interaction)
        
        # Make HTTP call to gateway
        client = _get_http_client(context)
        response = client.post(
            "/v1/verify/zkp/challenge",
            json={
                "doctype": doctype,
                "predicate_type": "age_over_18",
            }
        )
        
        assert response.status_code == 201, f"Challenge creation failed: {response.text}"
        result = response.json()
        
        # Store session info
        context.session_id = result['session_id']
        context.nonce = result['nonce'].encode() if isinstance(result['nonce'], str) else result['nonce']
        context.current_session = type('Session', (), {
            'session_id': result['session_id'],
            'nonce': context.nonce,
        })()
    else:
        # Direct service call (legacy)
        context.current_session = context.zk_service.create_zk_challenge(doctype=doctype)
        context.session_id = context.current_session.session_id
        context.nonce = context.current_session.nonce


@given('another separate ZK challenge session exists')
def step_impl(context):
    if _use_gateway(context):
        # Add Pact interaction for second ZK challenge
        interaction = Interactions.ZK.create_zk_challenge(
            doctype="org.iso.18013.5.1.mDL",
            predicate_type="age_over_18",
        )
        context.pact_provider.add_interaction(interaction)
        
        # Make HTTP call to gateway
        client = _get_http_client(context)
        response = client.post(
            "/v1/verify/zkp/challenge",
            json={
                "doctype": "org.iso.18013.5.1.mDL",
                "predicate_type": "age_over_18",
            }
        )
        
        assert response.status_code == 201, f"Challenge creation failed: {response.text}"
        result = response.json()
        
        other_nonce = result['nonce'].encode() if isinstance(result['nonce'], str) else result['nonce']
        context.other_session = type('Session', (), {
            'session_id': result['session_id'],
            'nonce': other_nonce,
        })()
    else:
        # Direct service call (legacy)
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
    if _use_gateway(context):
        # Encode bytes for JSON transport
        proof_b64 = base64.b64encode(context.proof_bytes).decode('utf-8')
        mso_b64 = base64.b64encode(context.mso_bytes).decode('utf-8')
        
        # Add Pact interaction for ZK proof verification
        interaction = Interactions.ZK.verify_zk_proof(
            session_id=context.session_id,
            proof=proof_b64,
            mso=mso_b64,
        )
        context.pact_provider.add_interaction(interaction)
        
        # Make HTTP call to gateway
        client = _get_http_client(context)
        response = client.post(
            "/v1/verify/zkp/verify",
            json={
                "session_id": context.session_id,
                "proof": proof_b64,
                "mso": mso_b64,
            }
        )
        
        assert response.status_code == 200, f"Verification request failed: {response.text}"
        result = response.json()
        
        # Convert to expected format
        context.verification_result = type('Result', (), {
            'valid': result.get('valid', False),
            'claims': result.get('claims', {}),
            'error': result.get('error'),
        })()
    else:
        # Direct service call (legacy)
        context.verification_result = context.zk_service.verify_zk_proof(
            session_id=context.session_id,
            proof=context.proof_bytes,
            mso=context.mso_bytes
        )


@when('I submit the proof to the FIRST session')
def step_impl(context):
    if _use_gateway(context):
        # Encode bytes for JSON transport
        proof_b64 = base64.b64encode(context.proof_bytes).decode('utf-8')
        mso_b64 = base64.b64encode(context.mso_bytes).decode('utf-8')
        
        # Add Pact interaction - proof bound to OTHER session should fail on FIRST session
        interaction = Interactions.ZK.verify_zk_proof_invalid()
        context.pact_provider.add_interaction(interaction)
        
        # Make HTTP call to gateway
        client = _get_http_client(context)
        response = client.post(
            "/v1/verify/zkp/verify",
            json={
                "session_id": context.session_id,  # FIRST session
                "proof": proof_b64,
                "mso": mso_b64,
            }
        )
        
        result = response.json()
        context.verification_result = type('Result', (), {
            'valid': result.get('valid', False),
            'claims': result.get('claims', {}),
            'error': result.get('error'),
        })()
    else:
        # Direct service call (legacy)
        # context.session_id refers to the FIRST session created
        context.verification_result = context.zk_service.verify_zk_proof(
            session_id=context.session_id,
            proof=context.proof_bytes,
            mso=context.mso_bytes
        )


@when('I submit an invalid proof with random bytes')
def step_impl(context):
    context.proof_bytes = b"random_invalid_bytes"
    
    if _use_gateway(context):
        # Encode bytes for JSON transport
        proof_b64 = base64.b64encode(context.proof_bytes).decode('utf-8')
        mso_b64 = base64.b64encode(context.mso_bytes).decode('utf-8')
        
        # Add Pact interaction for invalid proof
        interaction = Interactions.ZK.verify_zk_proof_invalid()
        context.pact_provider.add_interaction(interaction)
        
        # Make HTTP call to gateway
        client = _get_http_client(context)
        response = client.post(
            "/v1/verify/zkp/verify",
            json={
                "session_id": context.session_id,
                "proof": proof_b64,
                "mso": mso_b64,
            }
        )
        
        result = response.json()
        context.verification_result = type('Result', (), {
            'valid': result.get('valid', False),
            'claims': result.get('claims', {}),
            'error': result.get('error'),
        })()
    else:
        # Direct service call (legacy)
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
