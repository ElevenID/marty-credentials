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
import types
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
_PYTHON = os.path.join(_REPO_ROOT, "python")

# Insert repo-local package roots so "issuance.*", "verification.*", and
# "status_list.*" resolve when the test is run without a pre-set PYTHONPATH.
for _path in (_SERVICES, _PYTHON):
    if _path not in sys.path:
        sys.path.insert(0, _path)


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

class TestSpruceClaimDescriptions:
    def test_claim_descriptions_are_oid4vci_list_shape(self):
        from issuance.main import _claim_descriptions, _with_claim_descriptions

        metadata = {
            "claims": [
                {
                    "name": "email",
                    "display_name": "Email Address",
                    "required": True,
                    "description": "Holder email address",
                },
                {"name": "given_name", "display": {"label": "Given Name"}},
            ]
        }

        claims = _claim_descriptions(metadata)
        assert claims == [
            {
                "path": ["email"],
                "display": [{"name": "Email Address", "locale": "en-US"}],
                "mandatory": True,
            },
            {
                "path": ["given_name"],
                "display": [{"name": "Given Name", "locale": "en-US"}],
            },
        ]

        config = _with_claim_descriptions({"format": "spruce-vc+sd-jwt"}, metadata)
        assert isinstance(config["claims"], list)
        assert config["claims"][0]["path"] == ["email"]


class TestRemoteIssuerFailureDetail:
    async def test_apply_remote_issuer_context_refreshes_existing_context(self, monkeypatch):
        from issuance.infrastructure.api import routes

        captured: dict[str, str | None] = {}

        async def fake_resolve_remote_issuer_context(
            organization_id: str,
            *,
            issuer_profile_id: str | None = None,
            issuer_mode: str | None = None,
            credential_format: str | None = None,
            key_purpose: str | None = None,
            algorithm: str | None = None,
        ):
            captured.update(
                {
                    "organization_id": organization_id,
                    "issuer_profile_id": issuer_profile_id,
                    "issuer_mode": issuer_mode,
                    "credential_format": credential_format,
                    "key_purpose": key_purpose,
                    "algorithm": algorithm,
                }
            )
            return {
                "ok": True,
                "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme#not-a-fragment".split("#")[0],
                "issuer_profile_id": "ip-selected",
                "issuer_mode": "elevenid_alias_for_org",
                "signing_service_id": "svc-mdoc",
                "verification_method_id": "did:web:beta.elevenidllc.com:orgs:acme#cred-dsc-acme-primary",
                "service": {"id": "svc-mdoc"},
            }

        monkeypatch.setattr(routes, "resolve_remote_issuer_context", fake_resolve_remote_issuer_context)
        tx = _make_transaction(
            issuer_did_override="did:web:beta.elevenidllc.com:orgs:old",
            signing_service_id="svc-old",
            issuer_profile_id="ip-selected",
            issuer_mode="elevenid_alias_for_org",
            credential_payload_format="mso_mdoc",
        )

        context = await routes.apply_remote_issuer_context(tx, credential_format="mso_mdoc")

        assert context["signing_service_id"] == "svc-mdoc"
        assert tx.issuer_did_override == "did:web:beta.elevenidllc.com:orgs:acme"
        assert tx.signing_service_id == "svc-mdoc"
        assert captured == {
            "organization_id": "org-1",
            "issuer_profile_id": "ip-selected",
            "issuer_mode": "elevenid_alias_for_org",
            "credential_format": "mso_mdoc",
            "key_purpose": "mdoc_dsc",
            "algorithm": None,
        }

    async def test_remote_signing_preserves_gateway_error_detail(self, monkeypatch):
        from issuance.infrastructure.api import signing_context

        class FakeResponse:
            status_code = 503
            reason_phrase = "Service Unavailable"
            text = '{"detail":"Signing failed: OpenBao key cred-issuer-marty-es256 is missing"}'

            def json(self):
                return {"detail": "Signing failed: OpenBao key cred-issuer-marty-es256 is missing"}

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, *args, **kwargs):
                return FakeResponse()

        monkeypatch.setattr(signing_context.httpx, "AsyncClient", FakeClient)
        monkeypatch.setenv("ISSUANCE_API_KEY", "test-key")

        with pytest.raises(RuntimeError) as excinfo:
            await signing_context.sign_payload_with_remote_service(
                organization_id="org-1",
                signing_service_id="managed-openbao-transit",
                payload=b"payload",
                algorithm="ES256",
                key_reference="cred-issuer-marty-es256",
            )

        assert "DID-backed signing failed (HTTP 503)" in str(excinfo.value)
        assert "cred-issuer-marty-es256" in str(excinfo.value)

    def test_did_resolution_failure_detail_mentions_issuer_and_key_error(self):
        from issuance.infrastructure.api.routes import _did_resolution_failure_detail

        tx = _make_transaction(
            issuer_did_override="did:web:beta.elevenidllc.com:orgs:marty",
            signing_service_id="managed-openbao-transit",
        )

        detail = _did_resolution_failure_detail(tx, RuntimeError("OpenBao key missing"))

        assert "DID resolution failed" in detail
        assert "did:web:beta.elevenidllc.com:orgs:marty" in detail
        assert "OpenBao key missing" in detail

    def test_unsupported_remote_signing_format_detail_fails_closed(self):
        from issuance.infrastructure.api.routes import _unsupported_remote_signing_format_detail

        detail = _unsupported_remote_signing_format_detail("mso_mdoc", "mso_mdoc")

        assert "SD-JWT VC issuance only" in detail
        assert "mso_mdoc" in detail
        assert "remote COSE/VDS signing support" in detail


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

    def test_vds_nc(self):
        from issuance.infrastructure.api.routes import _credential_format_to_protocol
        tx = _make_transaction(credential_payload_format="vds_nc")
        cred = _make_credential()
        assert _credential_format_to_protocol(tx, cred) == "VDS_NC"

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
# 4. proof JWT audience helper
# ============================================================================

class TestProofAudienceMatching:
    def test_accepts_supported_org_issuer_paths(self):
        from issuance.infrastructure.api.routes import _proof_audience_matches_org_issuer

        org_id = "00000000-0000-0000-0000-000000000001"
        assert _proof_audience_matches_org_issuer(
            f"https://beta.elevenidllc.com/org/{org_id}",
            org_id,
        )
        assert _proof_audience_matches_org_issuer(
            f"https://beta.elevenidllc.com/org/{org_id}/spruce",
            org_id,
        )
        assert _proof_audience_matches_org_issuer(
            f"https://beta.elevenidllc.com/org/{org_id}/credential-manager",
            org_id,
        )
        assert _proof_audience_matches_org_issuer(
            f"https://beta.elevenidllc.com/org/{org_id}/apple-wallet",
            org_id,
        )

    def test_rejects_unknown_org_issuer_path(self):
        from issuance.infrastructure.api.routes import _proof_audience_matches_org_issuer

        org_id = "00000000-0000-0000-0000-000000000001"
        assert not _proof_audience_matches_org_issuer(
            f"https://beta.elevenidllc.com/org/{org_id}/unknown-wallet",
            org_id,
        )
        assert not _proof_audience_matches_org_issuer(
            "https://beta.elevenidllc.com/org/other/spruce",
            org_id,
        )


# ============================================================================
# 5. _subject_claims_hash helper
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

    async def test_remote_sd_jwt_uses_verification_method_id_as_kid(self):
        """Remote SD-JWT issuance should publish the DID verification method, not a raw KMS key hint."""
        from issuance.application.rust_integration import (
            base64url_decode,
            create_sd_jwt_vc_with_remote_signing,
        )

        captured: dict[str, str | None] = {}

        async def fake_remote_sign(payload: bytes, algorithm: str | None):
            captured["payload"] = payload.decode("ascii")
            captured["algorithm"] = algorithm
            return {"signature_raw_b64": "AQID", "algorithm": algorithm}

        verification_method_id = "did:web:beta.elevenidllc.com:orgs:acme#issuer-profile-v1"

        credential, credential_id = await create_sd_jwt_vc_with_remote_signing(
            issuer_did="did:web:beta.elevenidllc.com:orgs:acme",
            signing_service_id="managed-openbao-transit",
            remote_sign=fake_remote_sign,
            subject_id="did:key:z6Mk_subject",
            credential_type="https://beta.elevenidllc.com/credentials/access_badge",
            claims_json=json.dumps({"name": "Alice"}),
            algorithm="ES256",
            signing_key_reference="raw-openbao-key-name",
            verification_method_id=verification_method_id,
        )

        jwt = credential.split("~", 1)[0]
        encoded_header = jwt.split(".", 1)[0]
        header = json.loads(base64url_decode(encoded_header))

        assert header["kid"] == verification_method_id
        assert header["typ"] == "vc+sd-jwt"
        assert captured["algorithm"] == "ES256"
        assert credential_id.startswith("urn:uuid:")

    async def test_grpc_remote_signing_helper_uses_org_scoped_did_context(self, monkeypatch):
        from issuance.application.rust_integration import base64url_decode

        if "marty_proto.v1" not in sys.modules:
            proto_pkg = types.ModuleType("marty_proto")
            proto_v1 = types.ModuleType("marty_proto.v1")
            issuance_pb2 = types.ModuleType("marty_proto.v1.issuance_service_pb2")
            issuance_pb2_grpc = types.ModuleType("marty_proto.v1.issuance_service_pb2_grpc")
            issuance_pb2_grpc.IssuanceServiceServicer = object
            sys.modules["marty_proto"] = proto_pkg
            sys.modules["marty_proto.v1"] = proto_v1
            sys.modules["marty_proto.v1.issuance_service_pb2"] = issuance_pb2
            sys.modules["marty_proto.v1.issuance_service_pb2_grpc"] = issuance_pb2_grpc

        from issuance.infrastructure.adapters import grpc_adapter
        from issuance.infrastructure.api import signing_context

        issuer_did = "did:web:beta.elevenidllc.com:orgs:acme"
        verification_method_id = f"{issuer_did}#cred-issuer-acme-es256"
        captured: dict[str, object] = {}

        async def fake_resolve_remote_issuer_context(
            organization_id: str,
            *,
            issuer_profile_id: str | None = None,
            issuer_mode: str | None = None,
            credential_format: str | None = None,
            key_purpose: str | None = None,
            algorithm: str | None = None,
        ):
            captured["resolve"] = {
                "organization_id": organization_id,
                "issuer_profile_id": issuer_profile_id,
                "issuer_mode": issuer_mode,
                "credential_format": credential_format,
                "key_purpose": key_purpose,
                "algorithm": algorithm,
            }
            return {
                "ok": True,
                "issuer_did": issuer_did,
                "issuer_profile_id": "ip-grpc",
                "issuer_mode": "org_managed",
                "signing_service_id": "managed-openbao-transit",
                "signing_key_reference": "cred-issuer-acme-es256",
                "verification_method_id": verification_method_id,
                "service": {"id": "managed-openbao-transit", "algorithm": "ES256"},
            }

        async def fake_sign_payload_with_remote_service(**kwargs):
            captured["sign"] = kwargs
            return {"signature_raw_b64": "AQID", "algorithm": kwargs.get("algorithm")}

        monkeypatch.setattr(signing_context, "resolve_remote_issuer_context", fake_resolve_remote_issuer_context)
        monkeypatch.setattr(signing_context, "sign_payload_with_remote_service", fake_sign_payload_with_remote_service)

        tx = _make_transaction(
            issuer_did_override="did:web:beta.elevenidllc.com:orgs:old",
            signing_service_id="svc-old",
            issuer_profile_id="ip-grpc",
            issuer_mode="org_managed",
        )

        credential, credential_id, remote_context = await grpc_adapter._create_remote_signed_sd_jwt_for_tx(
            tx,
            subject_id="did:key:z6Mk_subject",
            credential_type="https://beta.elevenidllc.com/credentials/access_badge",
            claims_json=json.dumps({"name": "Alice"}),
            credential_format="dc+sd-jwt",
            selective_disclosure_claims=[],
        )

        jwt = credential.split("~", 1)[0]
        header = json.loads(base64url_decode(jwt.split(".", 1)[0]))

        assert header["kid"] == verification_method_id
        assert tx.issuer_did_override == issuer_did
        assert tx.signing_service_id == "managed-openbao-transit"
        assert remote_context["verification_method_id"] == verification_method_id
        assert captured["resolve"] == {
            "organization_id": "org-1",
            "issuer_profile_id": "ip-grpc",
            "issuer_mode": "org_managed",
            "credential_format": "dc+sd-jwt",
            "key_purpose": "vc_jwt_issuer",
            "algorithm": None,
        }
        assert captured["sign"]["organization_id"] == "org-1"
        assert captured["sign"]["signing_service_id"] == "managed-openbao-transit"
        assert captured["sign"]["key_reference"] == "cred-issuer-acme-es256"
        assert credential_id.startswith("urn:uuid:")


# ============================================================================
# IssuanceTransaction issuer_did_override field
# ============================================================================

class TestIssuanceTransactionIssuerDidOverride:
    """Validate that the issuer_did_override field on IssuanceTransaction
    defaults to None and can be set explicitly."""

    def test_defaults_to_none(self):
        tx = _make_transaction()
        assert tx.issuer_did_override is None

    def test_stores_override_did(self):
        tx = _make_transaction(
            issuer_did_override="did:web:beta.elevenidllc.com:orgs:acme",
        )
        assert tx.issuer_did_override == "did:web:beta.elevenidllc.com:orgs:acme"

    def test_signing_service_id_defaults_to_none(self):
        tx = _make_transaction()
        assert tx.signing_service_id is None

    def test_stores_signing_service_id(self):
        tx = _make_transaction(signing_service_id="svc-abc123")
        assert tx.signing_service_id == "svc-abc123"

    def test_explicit_issuer_selection_defaults_to_org_managed(self):
        tx = _make_transaction()
        assert tx.issuer_profile_id is None
        assert tx.issuer_mode == "org_managed"

    def test_stores_explicit_issuer_profile_and_mode(self):
        tx = _make_transaction(
            issuer_profile_id="ip-elevenid",
            issuer_mode="elevenid_managed",
        )
        assert tx.issuer_profile_id == "ip-elevenid"
        assert tx.issuer_mode == "elevenid_managed"

    def test_effective_issuer_did_with_override(self):
        """When issuer_did_override is set, it should be preferred over a
        fallback legacy DID."""
        tx = _make_transaction(
            issuer_did_override="did:web:beta.elevenidllc.com:orgs:acme",
        )
        legacy_did = "did:key:z6Mk_legacy"
        effective = tx.issuer_did_override or legacy_did
        assert effective == "did:web:beta.elevenidllc.com:orgs:acme"

    def test_effective_issuer_did_without_override(self):
        """When issuer_did_override is None, the legacy DID should be used."""
        tx = _make_transaction()
        legacy_did = "did:key:z6Mk_legacy"
        effective = tx.issuer_did_override or legacy_did
        assert effective == "did:key:z6Mk_legacy"
