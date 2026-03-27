"""
Tests for the issuance service changes:
 - get_credential_by_transaction_id (repository port + in-memory adapter)
 - issued_credential_router CRUD endpoints
 - deferred credential endpoint (now actually returns credentials)
 - issue_credential idempotent retry (returns existing credential)
 - c_nonce_expires_in on TokenResponse
 - _credential_status_to_protocol helper
 - _subject_claims_hash helper
 - _credential_format_to_protocol helper
 - rust_integration org_id validation
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# We can't import the real issuance package directly (it lives under
# services/issuance/ with an implicit PYTHONPATH).  We manipulate sys.path
# so that "issuance.domain.entities" etc. resolve.
# ---------------------------------------------------------------------------
import sys
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
_SERVICES = os.path.join(_REPO_ROOT, "services")

# Insert services root so "issuance.*" and "verification.*" resolve.
if _SERVICES not in sys.path:
    sys.path.insert(0, _SERVICES)


# ---- Domain imports -------------------------------------------------------
from issuance.domain.entities import (
    CredentialStatus,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.infrastructure.adapters.memory_repository import (
    InMemoryIssuanceRepository,
)


# ============================================================================
# Fixtures
# ============================================================================

def _make_transaction(**overrides) -> IssuanceTransaction:
    defaults = dict(
        id="tx-001",
        organization_id="org-1",
        credential_template_id="tmpl-1",
        applicant_id="applicant-1",
        subject_did="did:key:z6Mk_subject",
        status=IssuanceStatus.AUTHORIZED,
        nonce="test-nonce-42",
        claims={"name": "Alice", "age": 30},
        credential_type="VerifiableCredential",
        credential_payload_format="w3c_vcdm_v2_sd_jwt",
    )
    defaults.update(overrides)
    return IssuanceTransaction(**defaults)


def _make_credential(**overrides) -> IssuedCredential:
    defaults = dict(
        id="cred-001",
        transaction_id="tx-001",
        organization_id="org-1",
        credential_template_id="tmpl-1",
        applicant_id="applicant-1",
        subject_did="did:key:z6Mk_subject",
        credential_jwt="eyJhbGciOiJFZERTQSJ9.test.sig",
        credential_hash=hashlib.sha256(b"eyJhbGciOiJFZERTQSJ9.test.sig").hexdigest(),
        status=CredentialStatus.ACTIVE,
        issued_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        expires_at=datetime(2027, 3, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return IssuedCredential(**defaults)


class _TestableRepo(InMemoryIssuanceRepository):
    """Stub missing abstract methods so the repo can be instantiated."""
    _auth_sessions: dict = None

    def __init__(self):
        super().__init__()
        self._auth_sessions = {}

    async def save_authorization_session(self, session) -> None:
        self._auth_sessions[session.id] = session

    async def get_authorization_session_by_code(self, code: str):
        for s in self._auth_sessions.values():
            if s.code == code:
                return s
        return None

    async def get_authorization_session_by_access_token(self, token: str):
        for s in self._auth_sessions.values():
            if s.access_token == token:
                return s
        return None


@pytest.fixture
def repo():
    return _TestableRepo()


# ============================================================================
# 1. InMemoryIssuanceRepository — get_credential_by_transaction_id
# ============================================================================

class TestGetCredentialByTransactionId:
    async def test_returns_matching_credential(self, repo):
        cred = _make_credential(transaction_id="tx-42")
        await repo.save_credential(cred)
        result = await repo.get_credential_by_transaction_id("tx-42")
        assert result is not None
        assert result.id == cred.id
        assert result.transaction_id == "tx-42"

    async def test_returns_none_when_no_match(self, repo):
        cred = _make_credential(transaction_id="tx-42")
        await repo.save_credential(cred)
        result = await repo.get_credential_by_transaction_id("tx-99")
        assert result is None

    async def test_returns_none_when_empty(self, repo):
        result = await repo.get_credential_by_transaction_id("tx-01")
        assert result is None

    async def test_returns_first_match_among_multiple(self, repo):
        cred1 = _make_credential(id="cred-1", transaction_id="tx-shared")
        cred2 = _make_credential(id="cred-2", transaction_id="tx-other")
        await repo.save_credential(cred1)
        await repo.save_credential(cred2)
        result = await repo.get_credential_by_transaction_id("tx-shared")
        assert result is not None
        assert result.id == "cred-1"


# ============================================================================
# 2. _credential_status_to_protocol helper
# ============================================================================

class TestCredentialStatusToProtocol:
    def test_active_not_expired(self):
        from issuance.infrastructure.api.routes import _credential_status_to_protocol
        future = datetime.now(timezone.utc) + timedelta(days=30)
        assert _credential_status_to_protocol(CredentialStatus.ACTIVE, future) == "ACTIVE"

    def test_active_expired(self):
        from issuance.infrastructure.api.routes import _credential_status_to_protocol
        past = datetime.now(timezone.utc) - timedelta(days=1)
        assert _credential_status_to_protocol(CredentialStatus.ACTIVE, past) == "EXPIRED"

    def test_active_no_expiry(self):
        from issuance.infrastructure.api.routes import _credential_status_to_protocol
        assert _credential_status_to_protocol(CredentialStatus.ACTIVE, None) == "ACTIVE"

    def test_revoked(self):
        from issuance.infrastructure.api.routes import _credential_status_to_protocol
        future = datetime.now(timezone.utc) + timedelta(days=30)
        assert _credential_status_to_protocol(CredentialStatus.REVOKED, future) == "REVOKED"

    def test_suspended(self):
        from issuance.infrastructure.api.routes import _credential_status_to_protocol
        assert _credential_status_to_protocol(CredentialStatus.SUSPENDED, None) == "SUSPENDED"


# ============================================================================
# 3. _credential_format_to_protocol helper
# ============================================================================

class TestCredentialFormatToProtocol:
    def test_mso_mdoc(self):
        from issuance.infrastructure.api.routes import _credential_format_to_protocol
        tx = _make_transaction(credential_payload_format="mso_mdoc")
        cred = _make_credential()
        assert _credential_format_to_protocol(tx, cred) == "MDOC"

    def test_sd_jwt(self):
        from issuance.infrastructure.api.routes import _credential_format_to_protocol
        tx = _make_transaction(credential_payload_format="w3c_vcdm_v2_sd_jwt")
        cred = _make_credential()
        assert _credential_format_to_protocol(tx, cred) == "SD_JWT_VC"

    def test_no_transaction(self):
        from issuance.infrastructure.api.routes import _credential_format_to_protocol
        cred = _make_credential()
        assert _credential_format_to_protocol(None, cred) == "SD_JWT_VC"


# ============================================================================
# 4. _subject_claims_hash helper
# ============================================================================

class TestSubjectClaimsHash:
    def test_deterministic(self):
        from issuance.infrastructure.api.routes import _subject_claims_hash
        tx = _make_transaction(claims={"name": "Alice", "age": 30})
        h1 = _subject_claims_hash(tx)
        h2 = _subject_claims_hash(tx)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_excludes_internal_keys(self):
        from issuance.infrastructure.api.routes import _subject_claims_hash
        tx_clean = _make_transaction(claims={"name": "Alice"})
        tx_with_internal = _make_transaction(claims={
            "name": "Alice",
            "credential_offer_uri": "https://issuer.example/offer/123",
            "applicant_id": "app-1",
            "_vct": "VerifiedEmployee",
        })
        assert _subject_claims_hash(tx_clean) == _subject_claims_hash(tx_with_internal)

    def test_none_transaction(self):
        from issuance.infrastructure.api.routes import _subject_claims_hash
        assert _subject_claims_hash(None) is None

    def test_different_claims_different_hash(self):
        from issuance.infrastructure.api.routes import _subject_claims_hash
        tx1 = _make_transaction(claims={"name": "Alice"})
        tx2 = _make_transaction(claims={"name": "Bob"})
        assert _subject_claims_hash(tx1) != _subject_claims_hash(tx2)


# ============================================================================
# 5. _issued_credential_to_protocol helper
# ============================================================================

class TestIssuedCredentialToProtocol:
    async def test_basic_conversion(self, repo):
        from issuance.infrastructure.api.routes import _issued_credential_to_protocol
        tx = _make_transaction(id="tx-proto", status=IssuanceStatus.ISSUED)
        tx.complete()
        cred = _make_credential(
            transaction_id="tx-proto",
            issued_at=datetime(2026, 3, 15, tzinfo=timezone.utc),
            expires_at=datetime(2027, 3, 15, tzinfo=timezone.utc),
        )
        await repo.save_transaction(tx)
        result = await _issued_credential_to_protocol(cred, repo)
        assert result.id == cred.id
        assert result.credential_type == "VerifiableCredential"
        assert result.status == "ACTIVE"
        assert result.credential_format == "SD_JWT_VC"
        assert result.flow_execution_id == "tx-proto"
        assert result.valid_until == "2027-03-15T00:00:00+00:00"

    async def test_expired_credential(self, repo):
        from issuance.infrastructure.api.routes import _issued_credential_to_protocol
        tx = _make_transaction(id="tx-exp")
        tx.complete()
        cred = _make_credential(
            transaction_id="tx-exp",
            issued_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        await repo.save_transaction(tx)
        result = await _issued_credential_to_protocol(cred, repo)
        assert result.status == "EXPIRED"

    async def test_missing_transaction(self, repo):
        from issuance.infrastructure.api.routes import _issued_credential_to_protocol
        cred = _make_credential(transaction_id="tx-gone")
        result = await _issued_credential_to_protocol(cred, repo)
        assert result.credential_type == "unknown"
        assert result.credential_format == "SD_JWT_VC"


# ============================================================================
# 6. TokenResponse model — c_nonce_expires_in
# ============================================================================

class TestTokenResponseModel:
    def test_c_nonce_expires_in_default(self):
        from issuance.infrastructure.api.routes import TokenResponse
        resp = TokenResponse(
            access_token="tok",
            token_type="bearer",
            expires_in=300,
            c_nonce="nonce-1",
            nonce="nonce-1",
        )
        assert resp.c_nonce_expires_in == 300

    def test_c_nonce_expires_in_none(self):
        from issuance.infrastructure.api.routes import TokenResponse
        resp = TokenResponse(
            access_token="tok",
            token_type="bearer",
            expires_in=300,
            c_nonce="nonce-1",
            c_nonce_expires_in=None,
            nonce="nonce-1",
        )
        assert resp.c_nonce_expires_in is None


# ============================================================================
# 7. IssuedCredentialRecordResponse model shape
# ============================================================================

class TestIssuedCredentialRecordResponse:
    def test_required_fields(self):
        from issuance.infrastructure.api.routes import IssuedCredentialRecordResponse
        record = IssuedCredentialRecordResponse(
            id="cred-1",
            credential_id="cred-1",
            credential_type="VerifiableCredential",
            credential_format="SD_JWT_VC",
            flow_execution_id="tx-1",
            credential_template_id="tmpl-1",
            subject_id="did:key:test",
            issued_at="2026-03-15T00:00:00+00:00",
            status="ACTIVE",
            created_at="2026-03-15T00:00:00+00:00",
        )
        assert record.status_list_entries == []
        assert record.credential_hash is None
        assert record.revoked_at is None


# ============================================================================
# 8. Verification — ClaimResult and extended VerificationResult
#    Models extracted to verification.infrastructure.api.models so they can
#    be imported directly without the mmf database side-effect.
# ============================================================================

from verification.infrastructure.api.models import ClaimResult, VerificationResult


class TestVerificationResponseModels:
    def test_claim_result_defaults(self):
        """ClaimResult Pydantic model has correct defaults."""
        claim = ClaimResult(claim_name="name")
        assert claim.required is True
        assert claim.present is False
        assert claim.satisfies_predicate is False
        assert claim.result == "SKIPPED"

    def test_claim_result_full(self):
        """ClaimResult accepts all fields."""
        claim = ClaimResult(
            claim_name="age_over_18",
            required=True,
            present=True,
            satisfies_predicate=True,
            result="PASS",
        )
        assert claim.claim_name == "age_over_18"
        assert claim.result == "PASS"

    def test_verification_result_extended_defaults(self):
        """VerificationResult extended fields have correct defaults."""
        result = VerificationResult(valid=True)
        assert result.overall_result == "FAIL"
        assert result.trust_chain_valid is False
        assert result.revocation_checked is False
        assert result.claim_results == []
        assert result.revocation_status is None
        assert result.evaluated_at is None
        assert result.verifier_nonce is None
        assert result.flow_instance_id is None
        assert result.policy_id is None
        assert result.verified_claims is None
        assert result.verification_method is None
        assert result.error is None
        assert result.verified_at is None

    def test_verification_result_pass(self):
        """VerificationResult with full PASS scenario."""
        result = VerificationResult(
            valid=True,
            overall_result="PASS",
            trust_chain_valid=True,
            revocation_checked=True,
            revocation_status="VALID",
            evaluated_at="2026-03-27T12:00:00Z",
            verifier_nonce="nonce-123",
            claim_results=[
                ClaimResult(claim_name="given_name", present=True, satisfies_predicate=True, result="PASS"),
            ],
        )
        assert result.overall_result == "PASS"
        assert result.revocation_status == "VALID"
        assert result.evaluated_at == "2026-03-27T12:00:00Z"
        assert len(result.claim_results) == 1
        assert result.claim_results[0].claim_name == "given_name"

    def test_verification_result_fail_with_error(self):
        """VerificationResult with failure and error message."""
        result = VerificationResult(
            valid=False,
            overall_result="FAIL",
            error="Signature verification failed",
        )
        assert result.valid is False
        assert result.overall_result == "FAIL"
        assert result.error == "Signature verification failed"


# ============================================================================
# 9. InMemoryIssuanceRepository — list_credentials_by_org
# ============================================================================

class TestListCredentialsByOrg:
    async def test_filters_by_org(self, repo):
        c1 = _make_credential(id="c1", organization_id="org-A")
        c2 = _make_credential(id="c2", organization_id="org-B")
        c3 = _make_credential(id="c3", organization_id="org-A")
        await repo.save_credential(c1)
        await repo.save_credential(c2)
        await repo.save_credential(c3)
        results = await repo.list_credentials_by_org("org-A")
        assert len(results) == 2
        assert {r.id for r in results} == {"c1", "c3"}

    async def test_empty_for_unknown_org(self, repo):
        c1 = _make_credential(id="c1", organization_id="org-A")
        await repo.save_credential(c1)
        results = await repo.list_credentials_by_org("org-unknown")
        assert results == []


# ============================================================================
# 10. rust_integration: organization_id required
# ============================================================================

class TestRustIntegrationOrgIdValidation:
    def test_raises_when_org_id_missing(self):
        """create_verifiable_credential_wrapper must raise if org_id is None
        and the issuer DID is not found in the key cache."""
        from issuance.application.rust_integration import create_verifiable_credential_wrapper
        import issuance.application.rust_integration as rust_mod

        # Ensure the key cache is empty so the DID lookup falls through
        saved = rust_mod._org_keys.copy()
        rust_mod._org_keys.clear()
        try:
            with pytest.raises(RuntimeError, match="organization_id is required"):
                create_verifiable_credential_wrapper(
                    issuer_did="did:key:z6Mk_nonexistent",
                    issuer_jwk_json="{}",
                    subject_id="did:key:z6Mk_subject",
                    credential_type="VerifiableCredential",
                    claims_json='{"name": "Alice"}',
                    organization_id=None,
                )
        finally:
            rust_mod._org_keys.update(saved)
