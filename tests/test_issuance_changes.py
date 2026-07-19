"""
Tests for the issuance service changes:
 - get_credential_by_transaction_id (repository port + in-memory adapter)
 - issued_credential_router CRUD endpoints
 - deferred credential endpoint (now actually returns credentials)
 - issue_credential idempotent retry (returns existing credential)
 - OID4VCI Final token and nonce response separation
 - _credential_status_to_protocol helper
 - _subject_claims_hash helper
 - _credential_format_to_protocol helper
 - rust_integration org_id validation
"""

import hashlib
import json
import logging
import types
from datetime import datetime, timedelta, timezone

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
    CredentialDeliveryRecord,
    CredentialDeliveryStatus,
    CredentialStatus,
    DeliveryTarget,
    EventType,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.infrastructure.adapters.memory_repository import (
    InMemoryIssuanceRepository,
)
from issuance.infrastructure.models import issued_credentials_table, issuance_transactions_table


def test_authorization_redirect_preserves_registered_query_parameters():
    from issuance.infrastructure.api.routes import _authorization_redirect_uri

    location = _authorization_redirect_uri(
        "https://wallet.example/callback?dummy1=lorem&dummy2=ipsum",
        {"code": "authorization-code", "iss": "https://issuer.example", "state": "caller-state"},
    )

    assert location == (
        "https://wallet.example/callback?dummy1=lorem&dummy2=ipsum"
        "&code=authorization-code&iss=https%3A%2F%2Fissuer.example&state=caller-state"
    )


def test_root_issuer_metadata_advertises_selectable_oid4vci_formats(monkeypatch):
    """The fallback issuer must not advertise less than its request path accepts."""
    monkeypatch.setenv("TOKEN_HMAC_KEY", "test-only-not-a-secret")

    from fastapi.testclient import TestClient
    from issuance.main import create_app

    response = TestClient(create_app()).get("/.well-known/openid-credential-issuer")

    assert response.status_code == 200
    configurations = response.json()["credential_configurations_supported"]
    assert configurations["default"]["format"] == "jwt_vc_json"
    assert configurations["default#credential-manager"]["format"] == "dc+sd-jwt"
    assert configurations["default#credential-manager"]["vct"].endswith("/credentials/default")
    assert configurations["default#mdoc"] == {
        "format": "mso_mdoc",
        "scope": "default",
        "doctype": "org.iso.18013.5.1.mDL",
        "cryptographic_binding_methods_supported": ["did:key", "jwk"],
        "credential_signing_alg_values_supported": [-7, -8],
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["ES256", "EdDSA"]}
        },
        "display": [{"name": "Mobile Document (mDL)", "locale": "en-US"}],
    }

    type_metadata = TestClient(create_app()).get("/credentials/default")
    assert type_metadata.status_code == 200
    assert type_metadata.json()["vct"].endswith("/credentials/default")

    type_metadata = TestClient(create_app()).get("/credentials/access_badge")
    assert type_metadata.status_code == 200
    assert type_metadata.json()["vct"].endswith("/credentials/access_badge")


def test_issuance_transaction_schema_tracks_revocation_profile():
    column = issuance_transactions_table.c.revocation_profile_id

    assert column.nullable is True
    assert column.type.python_type is str


def test_issuance_schema_tracks_credential_renewal():
    assert issuance_transactions_table.c.renewal_of_credential_id.nullable is True
    assert issuance_transactions_table.c.validity_days.type.python_type is int
    assert issuance_transactions_table.c.renewable.type.python_type is bool
    assert issued_credentials_table.c.renewed_from_credential_id.nullable is True
    assert issued_credentials_table.c.renewed_to_credential_id.nullable is True


def test_postgres_transaction_mapper_preserves_lifecycle_dependencies():
    from types import SimpleNamespace
    from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository

    source = _make_transaction(
        revocation_profile_id="revocation-profile-1",
        renewal_of_credential_id="credential-1",
    )
    row_data = {**source.__dict__, "status": source.status.value, "c_nonce": source.nonce}
    row = SimpleNamespace(**row_data)

    mapped = PostgresIssuanceRepository._row_to_transaction(row)

    assert mapped.revocation_profile_id == "revocation-profile-1"
    assert mapped.renewal_of_credential_id == "credential-1"


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


def _make_delivery_record(**overrides) -> CredentialDeliveryRecord:
    defaults = dict(
        id="delivery-001",
        credential_id="cred-001",
        transaction_id="tx-001",
        organization_id="org-1",
        delivery_target=DeliveryTarget.WALLET,
        delivery_mode="wallet_only",
        status=CredentialDeliveryStatus.DELIVERED,
        metadata={"protocol": "oid4vci"},
        created_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return CredentialDeliveryRecord(**defaults)


async def _save_canvas_program_target(
    repo,
    *,
    platform_id: str = "platform-1",
    binding_id: str = "binding-1",
    organization_id: str = "org-1",
    canvas_account_id: str = "canvas-account-1",
    credential_template_id: str = "tmpl-1",
    application_template_id: str = "tmpl-app",
    canvas_base_url: str = "https://canvas.example.test",
    platform_enabled: bool = True,
    binding_enabled: bool = True,
    canvas_credentials: dict | None = None,
):
    from issuance.domain.entities import CanvasPlatform, CanvasProgramBinding

    platform = CanvasPlatform(
        id=platform_id,
        organization_id=organization_id,
        canvas_account_id=canvas_account_id,
        canvas_base_url=canvas_base_url,
        enabled=platform_enabled,
        created_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )
    binding = CanvasProgramBinding(
        id=binding_id,
        organization_id=organization_id,
        platform_id=platform.id,
        application_template_id=application_template_id,
        credential_template_id=credential_template_id,
        delivery_mode="wallet_plus_canvas_mirror",
        canvas_credentials=canvas_credentials or {},
        enabled=binding_enabled,
        created_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )
    await repo.save_canvas_platform(platform)
    await repo.save_canvas_program_binding(binding)
    return platform, binding


def _canvas_binding_metadata(
    *,
    platform_id: str = "platform-1",
    binding_id: str = "binding-1",
    **extra,
) -> dict[str, object]:
    return {
        "queue": "canvas_credentials_mirror",
        "canvas_platform_id": platform_id,
        "canvas_program_binding_id": binding_id,
        **extra,
    }


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
    def test_sd_jwt_claims_are_oid4vci_final_descriptor_array(self):
        from issuance.main import _with_claims

        config = _with_claims(
            {"format": "dc+sd-jwt"},
            {"claims": [{"name": "email", "display_name": "Email Address", "required": True}]},
        )

        assert config["claims"] == [{
            "path": ["email"],
            "display": [{"name": "Email Address", "locale": "en-US"}],
            "mandatory": True,
        }]

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

    async def test_required_remote_issuer_context_fails_on_incomplete_kms_profile(self, monkeypatch):
        from issuance.infrastructure.api import routes

        async def incomplete_context(*args, **kwargs):
            return {
                "issuer_did": "did:web:issuer.example",
                "issuer_profile_id": "profile-1",
                "signing_service_id": "service-1",
                "verification_method_id": "did:web:issuer.example#key-1",
                "issuer_profile": {"id": "profile-1", "status": "active"},
            }

        monkeypatch.setattr(routes, "resolve_remote_issuer_context", incomplete_context)
        tx = _make_transaction()

        with pytest.raises(RuntimeError, match="signing_key_reference"):
            await routes.apply_required_remote_issuer_context(tx)

    async def test_required_remote_issuer_context_attaches_complete_kms_profile(self, monkeypatch):
        from issuance.infrastructure.api import routes

        async def complete_context(*args, **kwargs):
            return {
                "issuer_did": "did:web:issuer.example",
                "issuer_profile_id": "profile-1",
                "signing_service_id": "service-1",
                "signing_key_reference": "kms-key-1",
                "verification_method_id": "did:web:issuer.example#key-1",
                "issuer_profile": {
                    "id": "profile-1",
                    "status": "active",
                    "issuer_did": "did:web:issuer.example",
                    "signing_service_id": "service-1",
                    "signing_key_reference": "kms-key-1",
                },
            }

        monkeypatch.setattr(routes, "resolve_remote_issuer_context", complete_context)
        tx = _make_transaction()

        context = await routes.apply_required_remote_issuer_context(tx)

        assert context["signing_key_reference"] == "kms-key-1"
        assert tx.issuer_profile_id == "profile-1"
        assert tx.issuer_did_override == "did:web:issuer.example"
        assert tx.signing_service_id == "service-1"

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
        assert _proof_audience_matches_org_issuer(
            f"https://beta.elevenidllc.com/org/{org_id}/waltid",
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
        assert result.deliveries == []

    async def test_includes_delivery_records(self, repo):
        from issuance.infrastructure.api.routes import _issued_credential_to_protocol

        tx = _make_transaction(id="tx-delivery", status=IssuanceStatus.ISSUED)
        tx.complete()
        cred = _make_credential(transaction_id="tx-delivery")
        await repo.save_transaction(tx)
        await repo.save_delivery_record(
            _make_delivery_record(
                credential_id=cred.id,
                transaction_id="tx-delivery",
                delivery_target=DeliveryTarget.WALLET,
                status=CredentialDeliveryStatus.DELIVERED,
            )
        )
        await repo.save_delivery_record(
            _make_delivery_record(
                id="delivery-002",
                credential_id=cred.id,
                transaction_id="tx-delivery",
                delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
                delivery_mode="wallet_plus_canvas_mirror",
                status=CredentialDeliveryStatus.PENDING,
                canvas_account_id="canvas-account-1",
                metadata={"queue": "canvas_credentials_mirror"},
            )
        )

        result = await _issued_credential_to_protocol(cred, repo)

        assert [delivery.delivery_target for delivery in result.deliveries] == [
            "wallet",
            "canvas_credentials",
        ]
        assert result.deliveries[1].status == "pending"

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

    async def test_includes_revocation_profile_and_status_list_entries(self, repo):
        from issuance.infrastructure.api.routes import _issued_credential_to_protocol

        tx = _make_transaction(id="tx-status-list", status=IssuanceStatus.ISSUED)
        tx.complete()
        cred = _make_credential(
            transaction_id="tx-status-list",
            revocation_profile_id="rev-prof-1",
            status_list_entries=[
                {
                    "status_list_id": "rev-prof-1",
                    "index": 42,
                    "status_list_uri": "https://beta.elevenidllc.com/v1/status-list",
                    "type": "BitstringStatusListEntry",
                    "status_purpose": "revocation",
                }
            ],
        )
        await repo.save_transaction(tx)

        result = await _issued_credential_to_protocol(cred, repo)

        assert result.revocation_profile_id == "rev-prof-1"
        assert len(result.status_list_entries) == 1
        assert result.status_list_entries[0].index == 42
        assert result.status_list_entries[0].status_purpose == "revocation"


# ============================================================================
# 6. TokenResponse model — OID4VCI Final has no proof nonce
# ============================================================================

class TestTokenResponseModel:
    def test_token_response_excludes_nonce_fields(self):
        from issuance.infrastructure.api.routes import TokenResponse
        resp = TokenResponse(
            access_token="tok",
            token_type="bearer",
            expires_in=300,
        )
        assert "c_nonce" not in resp.model_dump()
        assert "c_nonce_expires_in" not in resp.model_dump()

    def test_nonce_response_contains_only_c_nonce(self):
        from issuance.infrastructure.api.routes import NonceResponse
        resp = NonceResponse(c_nonce="nonce-1")
        assert resp.model_dump() == {"c_nonce": "nonce-1"}


# ============================================================================
# 7. IssuedCredentialRecordResponse model shape
# ============================================================================

class TestIssuedCredentialRecordResponse:
    def test_required_fields(self):
        from issuance.infrastructure.api.routes import IssuedCredentialRecordResponse
        record = IssuedCredentialRecordResponse(
            id="cred-1",
            organization_id="org-1",
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
        assert record.organization_id == "org-1"
        assert record.deliveries == []
        assert record.credential_hash is None
        assert record.revoked_at is None


class TestStatusListAllocationOrganizationScope:
    async def test_rejects_allocation_without_template_revocation_profile(self, monkeypatch):
        from issuance.infrastructure.api import routes

        monkeypatch.setattr(
            routes.httpx,
            "AsyncClient",
            lambda *args, **kwargs: pytest.fail("revocation service must not be called"),
        )

        with pytest.raises(routes.HTTPException) as exc_info:
            await routes._allocate_credential_status_list_entries(
                credential_id="credential-1",
                organization_id="org-1",
                credential_format="sd_jwt_vc",
                revocation_profile_id=None,
            )

        assert exc_info.value.status_code == 422

    async def test_sends_org_scope_and_accepts_matching_allocation(self, monkeypatch):
        from issuance.infrastructure.api import routes

        captured = {}

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "organization_id": "org-1",
                    "index": 42,
                    "status_list_url": "https://issuer.example/status/1",
                }

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            async def post(self, url, json):
                captured.update({"url": url, "json": json})
                return FakeResponse()

        monkeypatch.setattr(routes.httpx, "AsyncClient", lambda *args, **kwargs: FakeClient())
        monkeypatch.setenv("REVOCATION_PROFILE_SERVICE_URL", "http://revocation-profile:8013")

        profile_id, entries = await routes._allocate_credential_status_list_entries(
            credential_id="credential-1",
            organization_id="org-1",
            credential_format="sd_jwt_vc",
            revocation_profile_id="profile-1",
        )

        assert captured["json"] == {
            "organization_id": "org-1",
            "credential_format": "sd_jwt_vc",
        }
        assert captured["url"].endswith("/internal/revocation-profiles/profile-1/allocate-index")
        assert profile_id == "profile-1"
        assert entries[0]["index"] == 42

    async def test_rejects_mismatched_allocation_response(self, monkeypatch):
        from issuance.infrastructure.api import routes

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "organization_id": "org-2",
                    "index": 42,
                    "status_list_url": "https://issuer.example/status/1",
                }

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            async def post(self, _url, json):
                return FakeResponse()

        monkeypatch.setattr(routes.httpx, "AsyncClient", lambda *args, **kwargs: FakeClient())
        monkeypatch.setenv("REVOCATION_PROFILE_SERVICE_URL", "http://revocation-profile:8013")

        with pytest.raises(routes.HTTPException) as exc_info:
            await routes._allocate_credential_status_list_entries(
                credential_id="credential-1",
                organization_id="org-1",
                credential_format="sd_jwt_vc",
                revocation_profile_id="profile-1",
            )

        assert exc_info.value.status_code == 503


class TestDeliveryRecords:
    async def test_in_memory_repo_round_trips_delivery_records(self, repo):
        delivery = _make_delivery_record(
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            canvas_account_id="canvas-account-1",
            external_credential_id="canvas-cred-1",
        )

        await repo.save_delivery_record(delivery)
        result = await repo.list_delivery_records_for_credential("cred-001")
        by_id = await repo.get_delivery_record(delivery.id)
        by_external_id = await repo.get_canvas_delivery_record_by_external_credential_id(
            "canvas-cred-1",
            canvas_account_id="canvas-account-1",
        )

        assert len(result) == 1
        assert result[0].delivery_target == DeliveryTarget.CANVAS_CREDENTIALS
        assert result[0].status == CredentialDeliveryStatus.DELIVERED
        assert by_id is not None
        assert by_id.id == delivery.id
        assert by_external_id is not None
        assert by_external_id.id == delivery.id

    async def test_post_issuance_records_wallet_and_pending_canvas_mirror(self, repo):
        from issuance.domain.entities import Application, ApplicationStatus
        from issuance.infrastructure.adapters.delivery_records import record_post_issuance_deliveries

        app = Application(
            id="app-1",
            organization_id="org-1",
            application_template_id="tmpl-app",
            applicant_identifier="applicant-1",
            status=ApplicationStatus.APPROVED,
            integration_context={
                "canvas": {
                    "canvas_platform_id": "platform-1",
                    "canvas_program_binding_id": "binding-1",
                }
            },
        )
        await repo.save_application(app)
        await _save_canvas_program_target(repo)
        tx = _make_transaction(
            id="tx-canvas-delivery",
            application_id="app-1",
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-canvas", transaction_id="tx-canvas-delivery")

        records = await record_post_issuance_deliveries(
            repo,
            tx,
            cred,
            delivered_target=DeliveryTarget.WALLET,
            delivery_metadata={"protocol": "oid4vci"},
        )

        assert [record.delivery_target for record in records] == [
            DeliveryTarget.WALLET,
            DeliveryTarget.CANVAS_CREDENTIALS,
        ]
        assert records[0].status == CredentialDeliveryStatus.DELIVERED
        assert records[1].status == CredentialDeliveryStatus.PENDING
        assert records[1].canvas_account_id == "canvas-account-1"
        assert records[1].metadata["canvas_platform_id"] == "platform-1"
        assert records[1].metadata["canvas_program_binding_id"] == "binding-1"
        assert records[1].metadata["delivery_destination_id"] == "dd-canvas-credentials-institutional"
        assert records[1].metadata["delivery_destination_mode"] == "organization_mirror"

    async def test_post_issuance_copies_binding_canvas_credentials_config(self, repo):
        from issuance.domain.entities import Application, ApplicationStatus
        from issuance.infrastructure.adapters.delivery_records import record_post_issuance_deliveries

        app = Application(
            id="app-canvas-provider-config",
            organization_id="org-1",
            application_template_id="tmpl-app",
            applicant_identifier="applicant-1",
            status=ApplicationStatus.APPROVED,
            integration_context={
                "canvas": {
                    "canvas_platform_id": "platform-1",
                    "canvas_program_binding_id": "binding-1",
                }
            },
        )
        await repo.save_application(app)
        await _save_canvas_program_target(
            repo,
            canvas_credentials={
                "provider": "badgr_api",
                "api_base_url": "https://api.canvascredentials.example",
                "issuer_id": "issuer-1",
                "badgeclass_id": "badgeclass-1",
                "api_token_env": "CANVAS_CREDENTIALS_TOKEN_ORG_1",
            },
        )
        tx = _make_transaction(
            id="tx-canvas-provider-config",
            application_id=app.id,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-canvas-provider-config", transaction_id=tx.id)

        records = await record_post_issuance_deliveries(
            repo,
            tx,
            cred,
            delivered_target=DeliveryTarget.WALLET,
        )

        canvas_record = records[1]
        assert canvas_record.status == CredentialDeliveryStatus.PENDING
        assert canvas_record.metadata["canvas_credentials"] == {
            "provider": "badgr_api",
            "api_base_url": "https://api.canvascredentials.example",
            "issuer_id": "issuer-1",
            "badgeclass_id": "badgeclass-1",
            "api_token_env": "CANVAS_CREDENTIALS_TOKEN_ORG_1",
        }

    async def test_post_issuance_blocks_canvas_mirror_when_profile_disables_publish(self, repo):
        from issuance.domain.entities import Application, ApplicationStatus
        from issuance.infrastructure.adapters.delivery_records import record_post_issuance_deliveries

        app = Application(
            id="app-profile-blocked",
            organization_id="org-1",
            application_template_id="tmpl-app",
            applicant_identifier="applicant-1",
            status=ApplicationStatus.APPROVED,
            integration_context={
                "canvas": {
                    "canvas_platform_id": "platform-1",
                    "canvas_program_binding_id": "binding-1",
                    "deployment_profile_id": "deployment-profile-1",
                    "feature_flags": {
                        "enable_canvas_mirror_publish": False,
                        "enable_canvas_mirror_ops": True,
                    },
                    "delivery_mode": "wallet_plus_canvas_mirror",
                }
            },
        )
        await repo.save_application(app)
        await _save_canvas_program_target(repo)
        tx = _make_transaction(
            id="tx-profile-blocked",
            application_id=app.id,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-profile-blocked", transaction_id=tx.id)

        records = await record_post_issuance_deliveries(
            repo,
            tx,
            cred,
            delivered_target=DeliveryTarget.WALLET,
        )

        canvas_record = records[1]
        assert canvas_record.delivery_target == DeliveryTarget.CANVAS_CREDENTIALS
        assert canvas_record.status == CredentialDeliveryStatus.FAILED
        assert canvas_record.last_error == "Canvas mirror publish is disabled by deployment profile"
        assert canvas_record.metadata["deployment_profile_id"] == "deployment-profile-1"
        assert canvas_record.metadata["canvas_program_binding_id"] == "binding-1"
        assert canvas_record.metadata["canvas_feature_flags"]["enable_canvas_mirror_publish"] is False
        assert canvas_record.metadata["canvas_feature_gate_blocked"] is True

    async def test_post_issuance_records_failed_canvas_mirror_when_binding_missing(self, repo):
        from issuance.infrastructure.adapters.delivery_records import record_post_issuance_deliveries

        tx = _make_transaction(
            id="tx-mirror-missing",
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-mirror-missing", transaction_id="tx-mirror-missing")

        records = await record_post_issuance_deliveries(
            repo,
            tx,
            cred,
            delivered_target=DeliveryTarget.WALLET,
        )

        assert records[1].delivery_target == DeliveryTarget.CANVAS_CREDENTIALS
        assert records[1].status == CredentialDeliveryStatus.FAILED
        assert "canvas_program_binding_id" in (records[1].last_error or "")


class TestCanvasMirrorPublishing:
    @pytest.fixture(autouse=True)
    def _enable_portable_canvas_pilot(self, monkeypatch):
        monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
        monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")

    async def test_publish_canvas_mirror_marks_pending_record_delivered(self, repo, monkeypatch):

        from issuance.infrastructure.adapters import canvas_credentials_adapter
        from issuance.infrastructure.api import routes

        tx = _make_transaction(
            id="tx-canvas-publish",
            status=IssuanceStatus.ISSUED,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-canvas-publish", transaction_id=tx.id)
        platform, _binding = await _save_canvas_program_target(repo)
        pending = _make_delivery_record(
            id="delivery-canvas-publish",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.PENDING,
            canvas_account_id=platform.canvas_account_id,
            metadata=_canvas_binding_metadata(),
        )

        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(pending)

        monkeypatch.setenv("CANVAS_CREDENTIALS_PUBLISH_URL", "https://canvas.example.test/api/publish")
        monkeypatch.setenv("CANVAS_CREDENTIALS_ISSUER_ID", "issuer-elevenid")
        monkeypatch.setenv("CANVAS_CREDENTIALS_API_TOKEN", "test-token")

        captured: dict[str, object] = {}

        class FakeResponse:
            status_code = 201
            headers = {"x-request-id": "req-123"}
            text = '{"id":"canvas-cred-42","issuer_id":"issuer-elevenid"}'

            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "id": "canvas-cred-42",
                    "issuer_id": "issuer-elevenid",
                    "status": "published",
                }

        class FakeClient:
            def __init__(self, *args, **kwargs):
                captured["timeout"] = kwargs.get("timeout")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, url, json=None, headers=None):
                captured["url"] = url
                captured["json"] = json
                captured["headers"] = headers
                return FakeResponse()

        monkeypatch.setattr(canvas_credentials_adapter.httpx, "AsyncClient", FakeClient)

        response = await routes.publish_issued_credential_canvas_mirror(cred.id, repo)
        records = await repo.list_delivery_records_for_credential(cred.id)
        canvas_record = next(
            record for record in records if record.delivery_target == DeliveryTarget.CANVAS_CREDENTIALS
        )

        assert response.status == "delivered"
        assert canvas_record.status == CredentialDeliveryStatus.DELIVERED
        assert canvas_record.external_credential_id == "canvas-cred-42"
        assert canvas_record.external_issuer_id == "issuer-elevenid"
        assert canvas_record.metadata["publish_attempts"] == 1
        assert canvas_record.metadata["request_id"] == "req-123"
        assert captured["url"] == "https://canvas.example.test/api/publish"
        assert captured["headers"] == {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer test-token",
        }
        assert captured["json"]["issuer_id"] == "issuer-elevenid"
        assert captured["json"]["credential"]["id"] == cred.id
        assert captured["json"]["canvas_account_id"] == "canvas-account-1"

    async def test_publish_canvas_mirror_persists_failure_and_raises(self, repo, monkeypatch):
        import httpx

        from fastapi import HTTPException

        from issuance.infrastructure.adapters import canvas_credentials_adapter
        from issuance.infrastructure.api import routes

        tx = _make_transaction(
            id="tx-canvas-failure",
            status=IssuanceStatus.ISSUED,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-canvas-failure", transaction_id=tx.id)
        platform, _binding = await _save_canvas_program_target(repo)
        pending = _make_delivery_record(
            id="delivery-canvas-failure",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.PENDING,
            canvas_account_id=platform.canvas_account_id,
            metadata=_canvas_binding_metadata(),
        )

        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(pending)

        monkeypatch.setenv("CANVAS_CREDENTIALS_PUBLISH_URL", "https://canvas.example.test/api/publish")

        class FailingClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, url, json=None, headers=None):
                request = httpx.Request("POST", url)
                raise httpx.RequestError("network down", request=request)

        monkeypatch.setattr(canvas_credentials_adapter.httpx, "AsyncClient", lambda *args, **kwargs: FailingClient())

        with pytest.raises(HTTPException) as excinfo:
            await routes.publish_issued_credential_canvas_mirror(cred.id, repo)

        records = await repo.list_delivery_records_for_credential(cred.id)
        canvas_record = next(
            record for record in records if record.delivery_target == DeliveryTarget.CANVAS_CREDENTIALS
        )

        assert excinfo.value.status_code == 502
        assert "Canvas Credentials publish request failed" in str(excinfo.value.detail)
        assert canvas_record.status == CredentialDeliveryStatus.FAILED
        assert "network down" in (canvas_record.last_error or "")
        assert canvas_record.metadata["publish_attempts"] == 1

    async def test_publish_canvas_mirror_is_idempotent_when_already_delivered(self, repo, monkeypatch):
        from issuance.infrastructure.api import routes

        tx = _make_transaction(
            id="tx-canvas-existing",
            status=IssuanceStatus.ISSUED,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-canvas-existing", transaction_id=tx.id)
        delivered = _make_delivery_record(
            id="delivery-canvas-existing",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.DELIVERED,
            canvas_account_id="canvas-account-1",
            external_credential_id="canvas-cred-existing",
            external_issuer_id="issuer-elevenid",
        )

        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(delivered)

        async def unexpected_publish(*args, **kwargs):
            raise AssertionError("publish should not be called for delivered records")

        monkeypatch.setattr(routes, "publish_canvas_credential_mirror", unexpected_publish)

        response = await routes.publish_issued_credential_canvas_mirror(cred.id, repo)

        assert response.status == "delivered"
        assert response.external_credential_id == "canvas-cred-existing"

    async def test_canvas_mirror_provenance_resolves_canonical_issuance(self, repo):
        from issuance.infrastructure.api import routes

        tx = _make_transaction(
            id="tx-canvas-provenance",
            status=IssuanceStatus.ISSUED,
            application_id="app-canvas-provenance",
            delivery_mode="wallet_plus_canvas_mirror",
            issuer_profile_id="issuer-profile-1",
            issuer_mode="org_managed",
            issuer_did_override="did:web:issuer.example",
        )
        tx.complete()
        cred = _make_credential(
            id="cred-canvas-provenance",
            transaction_id=tx.id,
            issuer_did="did:web:issuer.example",
        )
        delivered = _make_delivery_record(
            id="delivery-canvas-provenance",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.DELIVERED,
            canvas_account_id="canvas-account-1",
            external_credential_id="canvas-cred-provenance",
            external_issuer_id="canvas-issuer-1",
            metadata={
                "published_at": "2026-03-01T12:00:00+00:00",
                "request_id": "req-provenance",
                "private_note": "not returned",
            },
        )

        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(delivered)

        response = await routes.get_canvas_mirror_provenance(
            external_credential_id="canvas-cred-provenance",
            canvas_account_id="canvas-account-1",
            repo=repo,
        )

        assert response.delivery_record_id == delivered.id
        assert response.mirror["external_credential_id"] == "canvas-cred-provenance"
        assert response.mirror["metadata"] == {
            "published_at": "2026-03-01T12:00:00+00:00",
            "request_id": "req-provenance",
        }
        assert response.canonical_credential["credential_id"] == cred.id
        assert response.canonical_credential["credential_status"] == "ACTIVE"
        assert response.canonical_credential["subject_id_hash"] == hashlib.sha256(
            "did:key:z6Mk_subject".encode("utf-8")
        ).hexdigest()
        assert "subject_id" not in response.canonical_credential
        assert response.canonical_issuance["application_id"] == "app-canvas-provenance"
        assert response.issuer["issuer_did"] == "did:web:issuer.example"
        assert response.trust_basis["canonical_issuance_backed"] is True
        assert response.trust_basis["distribution_channel"] == "canvas_credentials"
        assert response.delivery_record.external_credential_id == "canvas-cred-provenance"


class TestCanvasMirrorBatchProcessing:
    @pytest.fixture(autouse=True)
    def _enable_portable_canvas_pilot(self, monkeypatch):
        monkeypatch.setenv("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
        monkeypatch.setenv("CANVAS_PILOT_ORGANIZATION_IDS", "org-1")

    async def test_batch_processor_processes_pending_records_with_limit(self, repo, monkeypatch):
        from issuance.infrastructure.adapters import canvas_credentials_adapter
        from issuance.infrastructure.api import routes

        platform, binding = await _save_canvas_program_target(repo)

        tx_one = _make_transaction(
            id="tx-batch-one",
            status=IssuanceStatus.ISSUED,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        tx_two = _make_transaction(
            id="tx-batch-two",
            status=IssuanceStatus.ISSUED,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred_one = _make_credential(id="cred-batch-one", transaction_id=tx_one.id)
        cred_two = _make_credential(id="cred-batch-two", transaction_id=tx_two.id)
        record_one = _make_delivery_record(
            id="delivery-batch-one",
            credential_id=cred_one.id,
            transaction_id=tx_one.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.PENDING,
            canvas_account_id=platform.canvas_account_id,
            metadata=_canvas_binding_metadata(binding_id=binding.id, platform_id=platform.id),
        )
        record_two = _make_delivery_record(
            id="delivery-batch-two",
            credential_id=cred_two.id,
            transaction_id=tx_two.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.PENDING,
            canvas_account_id=platform.canvas_account_id,
            metadata=_canvas_binding_metadata(binding_id=binding.id, platform_id=platform.id),
        )
        await repo.save_transaction(tx_one)
        await repo.save_transaction(tx_two)
        await repo.save_credential(cred_one)
        await repo.save_credential(cred_two)
        await repo.save_delivery_record(record_one)
        await repo.save_delivery_record(record_two)

        monkeypatch.setenv("CANVAS_CREDENTIALS_PUBLISH_URL", "https://canvas.example.test/api/publish")

        published_ids: list[str] = []

        class FakeResponse:
            status_code = 201
            headers = {}
            text = "{}"

            def __init__(self, credential_id: str):
                self._credential_id = credential_id

            def raise_for_status(self):
                return None

            def json(self):
                return {"id": f"mirror-{self._credential_id}", "issuer_id": "issuer-elevenid"}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, url, json=None, headers=None):
                credential_id = json["credential"]["id"]
                published_ids.append(credential_id)
                return FakeResponse(credential_id)

        monkeypatch.setattr(canvas_credentials_adapter.httpx, "AsyncClient", lambda *args, **kwargs: FakeClient())

        response = await routes.process_pending_canvas_mirror_deliveries(
            organization_id="org-1",
            limit=1,
            retry_failed=False,
            repo=repo,
        )

        records_one = await repo.list_delivery_records_for_credential(cred_one.id)
        records_two = await repo.list_delivery_records_for_credential(cred_two.id)

        assert response.processed_count == 1
        assert response.delivered_count == 1
        assert response.failed_count == 0
        assert response.metrics["publish.delivered"] == 1
        assert response.metrics["publish.failed"] == 0
        assert published_ids == ["cred-batch-one"]
        assert records_one[0].status == CredentialDeliveryStatus.DELIVERED
        assert records_two[0].status == CredentialDeliveryStatus.PENDING

    async def test_batch_processor_retries_failed_records_when_requested(self, repo, monkeypatch):
        from issuance.infrastructure.adapters import canvas_credentials_adapter
        from issuance.infrastructure.api import routes

        platform, binding = await _save_canvas_program_target(repo)
        tx = _make_transaction(
            id="tx-batch-retry",
            status=IssuanceStatus.ISSUED,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-batch-retry", transaction_id=tx.id)
        failed_record = _make_delivery_record(
            id="delivery-batch-retry",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.FAILED,
            canvas_account_id=platform.canvas_account_id,
            last_error="previous publish failure",
            metadata=_canvas_binding_metadata(
                binding_id=binding.id,
                platform_id=platform.id,
                publish_attempts=1,
            ),
        )
        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(failed_record)

        monkeypatch.setenv("CANVAS_CREDENTIALS_PUBLISH_URL", "https://canvas.example.test/api/publish")

        class FakeResponse:
            status_code = 201
            headers = {}
            text = "{}"

            def raise_for_status(self):
                return None

            def json(self):
                return {"id": "mirror-cred-batch-retry", "issuer_id": "issuer-elevenid"}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, url, json=None, headers=None):
                return FakeResponse()

        monkeypatch.setattr(canvas_credentials_adapter.httpx, "AsyncClient", lambda *args, **kwargs: FakeClient())

        response = await routes.process_pending_canvas_mirror_deliveries(
            organization_id="org-1",
            limit=10,
            retry_failed=True,
            repo=repo,
        )

        records = await repo.list_delivery_records_for_credential(cred.id)
        retried_record = next(
            record for record in records if record.delivery_target == DeliveryTarget.CANVAS_CREDENTIALS
        )

        assert response.processed_count == 1
        assert response.delivered_count == 1
        assert response.failed_count == 0
        assert response.metrics["publish.delivered"] == 1
        assert retried_record.status == CredentialDeliveryStatus.DELIVERED
        assert retried_record.external_credential_id == "mirror-cred-batch-retry"
        assert retried_record.metadata["publish_attempts"] == 2

    async def test_batch_processor_emits_alert_event_metrics_and_webhook_for_critical_publish_failure(self, repo, monkeypatch, caplog):
        from issuance.infrastructure.api import routes

        platform, binding = await _save_canvas_program_target(repo)
        tx = _make_transaction(
            id="tx-batch-critical-alert",
            status=IssuanceStatus.ISSUED,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-batch-critical-alert", transaction_id=tx.id)
        failed_record = _make_delivery_record(
            id="delivery-batch-critical-alert",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.FAILED,
            canvas_account_id=platform.canvas_account_id,
            last_error="previous publish failure",
            metadata=_canvas_binding_metadata(
                binding_id=binding.id,
                platform_id=platform.id,
                publish_attempts=4,
            ),
        )
        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(failed_record)

        async def failing_publish(*args, **kwargs):
            raise RuntimeError("Canvas publish still unavailable")

        webhook_payloads = []

        async def fake_webhook(**kwargs):
            webhook_payloads.append(kwargs)

        monkeypatch.setattr(routes, "publish_canvas_credential_mirror", failing_publish)
        monkeypatch.setattr(routes, "_post_canvas_mirror_alert_webhook", fake_webhook)
        caplog.set_level(logging.INFO, logger="issuance.infrastructure.api.routes")

        response = await routes.run_canvas_mirror_publish_batch(
            repo,
            organization_id="org-1",
            limit=10,
            retry_failed=True,
        )

        updated = (await repo.list_delivery_records_for_credential(cred.id))[0]
        alert_events = [
            event for event in repo._events
            if event.event_type == EventType.CANVAS_MIRROR_ALERT_EMITTED
        ]
        metric_logs = [
            record for record in caplog.records
            if getattr(record, "mip_event", None) == "canvas_mirror_metrics"
        ]
        alert_logs = [
            record for record in caplog.records
            if getattr(record, "mip_event", None) == "canvas_mirror_alert"
        ]

        assert response.processed_count == 1
        assert response.failed_count == 1
        assert response.metrics["publish.failed"] == 1
        assert updated.metadata["publish_attempts"] == 5
        assert alert_events
        assert alert_events[0].metadata["severity"] == "critical"
        assert alert_events[0].metadata["delivery_record_id"] == failed_record.id
        assert metric_logs[0].metrics["publish.failed"] == 1
        assert alert_logs[0].canvas_mirror_alert["severity"] == "critical"
        assert webhook_payloads[0]["organization_id"] == "org-1"
        assert webhook_payloads[0]["alerts"][0].delivery_record_id == failed_record.id

    async def test_batch_processor_blocks_publish_when_profile_disables_mirror_ops(self, repo, monkeypatch):
        from issuance.infrastructure.api import routes

        tx = _make_transaction(
            id="tx-batch-ops-disabled",
            status=IssuanceStatus.ISSUED,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        cred = _make_credential(id="cred-batch-ops-disabled", transaction_id=tx.id)
        pending_record = _make_delivery_record(
            id="delivery-batch-ops-disabled",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.PENDING,
            canvas_account_id="canvas-account-1",
            metadata={
                "queue": "canvas_credentials_mirror",
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "deployment_profile_id": "deployment-profile-1",
                "canvas_feature_flags": {
                    "enable_canvas_mirror_publish": True,
                    "enable_canvas_mirror_ops": False,
                },
            },
        )

        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(pending_record)

        async def unexpected_publish(*args, **kwargs):
            raise AssertionError("Canvas publish should not run when mirror ops are disabled")

        monkeypatch.setattr(routes, "publish_canvas_credential_mirror", unexpected_publish)

        response = await routes.run_canvas_mirror_publish_batch(
            repo,
            organization_id="org-1",
            limit=10,
            retry_failed=True,
        )
        updated = (await repo.list_delivery_records_for_credential(cred.id))[0]

        assert response.processed_count == 1
        assert response.delivered_count == 0
        assert response.failed_count == 1
        assert response.blocked_count == 1
        assert response.metrics["publish.blocked"] == 1
        assert updated.status == CredentialDeliveryStatus.FAILED
        assert updated.last_error == "Canvas mirror operations are disabled by deployment profile"
        assert updated.metadata["canvas_feature_gate_blocked"] is True
        assert updated.metadata["canvas_feature_gate"] == "enable_canvas_mirror_ops"
        assert updated.metadata["retryable"] is False
        assert updated.metadata.get("publish_attempts") is None


class TestCanvasMirrorOps:
    async def test_process_failed_status_syncs_retries_only_failed_records(self, repo, monkeypatch):
        from issuance.infrastructure.api import routes

        platform, binding = await _save_canvas_program_target(repo)
        tx_failed = _make_transaction(id="tx-sync-retry-failed", status=IssuanceStatus.ISSUED)
        tx_clean = _make_transaction(id="tx-sync-retry-clean", status=IssuanceStatus.ISSUED)
        cred_failed = _make_credential(
            id="cred-sync-retry-failed",
            transaction_id=tx_failed.id,
            status=CredentialStatus.SUSPENDED,
            status_updated_at=datetime(2026, 3, 2, tzinfo=timezone.utc),
        )
        cred_clean = _make_credential(
            id="cred-sync-retry-clean",
            transaction_id=tx_clean.id,
            status=CredentialStatus.ACTIVE,
            status_updated_at=datetime(2026, 3, 3, tzinfo=timezone.utc),
        )
        failed_record = _make_delivery_record(
            id="delivery-sync-retry-failed",
            credential_id=cred_failed.id,
            transaction_id=tx_failed.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.DELIVERED,
            canvas_account_id=platform.canvas_account_id,
            external_credential_id="canvas-cred-failed",
            metadata=_canvas_binding_metadata(
                binding_id=binding.id,
                platform_id=platform.id,
                **{
                "published_at": "2026-03-01T10:00:00+00:00",
                "status_sync_attempts": 1,
                "last_status_sync_action": "suspend",
                "last_status_sync_error": "Canvas status endpoint unavailable",
                "last_status_sync_error_at": "2026-03-01T11:00:00+00:00",
                },
            ),
        )
        clean_record = _make_delivery_record(
            id="delivery-sync-retry-clean",
            credential_id=cred_clean.id,
            transaction_id=tx_clean.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.DELIVERED,
            canvas_account_id=platform.canvas_account_id,
            external_credential_id="canvas-cred-clean",
            metadata=_canvas_binding_metadata(
                binding_id=binding.id,
                platform_id=platform.id,
                **{
                "published_at": "2026-03-01T09:00:00+00:00",
                "status_sync_attempts": 1,
                "last_status_sync_action": "reinstate",
                "status_synced_at": "2026-03-01T09:30:00+00:00",
                "last_status_sync_error": None,
                },
            ),
        )

        await repo.save_transaction(tx_failed)
        await repo.save_transaction(tx_clean)
        await repo.save_credential(cred_failed)
        await repo.save_credential(cred_clean)
        await repo.save_delivery_record(failed_record)
        await repo.save_delivery_record(clean_record)

        captured: list[str] = []

        async def fake_sync_canvas_credential_status(*, credential, platform, delivery_record, lifecycle_action, reason=None, secret_resolver=None):
            captured.append(delivery_record.id)
            assert lifecycle_action == "suspend"
            return types.SimpleNamespace(metadata={
                "status_sync_url": "https://canvas.example.test/status-sync",
                "status_sync_http_status": 200,
                "status_synced_at": "2026-03-02T12:00:00+00:00",
                "status_sync_response": {"ok": True},
            })

        monkeypatch.setattr(routes, "sync_canvas_credential_status", fake_sync_canvas_credential_status)

        response = await routes.process_failed_canvas_mirror_status_syncs(
            organization_id="org-1",
            limit=10,
            repo=repo,
        )

        failed_records = await repo.list_delivery_records_for_credential(cred_failed.id)
        clean_records = await repo.list_delivery_records_for_credential(cred_clean.id)
        updated_failed = failed_records[0]
        untouched_clean = clean_records[0]

        assert response.processed_count == 1
        assert response.synced_count == 1
        assert response.failed_count == 0
        assert response.metrics["status_sync.synced"] == 1
        assert response.metrics["status_sync.failed"] == 0
        assert response.metrics["status_sync.retry_succeeded"] == 1
        assert captured == ["delivery-sync-retry-failed"]
        assert updated_failed.metadata["status_sync_attempts"] == 2
        assert updated_failed.metadata["last_status_sync_error"] is None
        assert updated_failed.metadata["status_synced_at"] == "2026-03-02T12:00:00+00:00"
        assert untouched_clean.metadata["status_sync_attempts"] == 1
        assert untouched_clean.metadata["status_synced_at"] == "2026-03-01T09:30:00+00:00"

    async def test_process_failed_status_syncs_persists_retry_failure(self, repo, monkeypatch):
        from issuance.infrastructure.api import routes

        platform, binding = await _save_canvas_program_target(repo)
        tx = _make_transaction(id="tx-sync-retry-still-fails", status=IssuanceStatus.ISSUED)
        cred = _make_credential(
            id="cred-sync-retry-still-fails",
            transaction_id=tx.id,
            status=CredentialStatus.REVOKED,
            revoked_at=datetime(2026, 3, 4, tzinfo=timezone.utc),
            revocation_reason="policy violation",
            status_updated_at=datetime(2026, 3, 4, tzinfo=timezone.utc),
        )
        record = _make_delivery_record(
            id="delivery-sync-retry-still-fails",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.DELIVERED,
            canvas_account_id=platform.canvas_account_id,
            metadata=_canvas_binding_metadata(
                binding_id=binding.id,
                platform_id=platform.id,
                **{
                "status_sync_attempts": 1,
                "last_status_sync_action": "revoke",
                "last_status_sync_error": "old error",
                "last_status_sync_error_at": "2026-03-04T12:00:00+00:00",
                },
            ),
        )

        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(record)

        async def failing_sync(*args, **kwargs):
            raise RuntimeError("Canvas still unavailable")

        monkeypatch.setattr(routes, "sync_canvas_credential_status", failing_sync)

        response = await routes.process_failed_canvas_mirror_status_syncs(
            organization_id="org-1",
            limit=10,
            repo=repo,
        )

        updated = (await repo.list_delivery_records_for_credential(cred.id))[0]

        assert response.processed_count == 1
        assert response.synced_count == 0
        assert response.failed_count == 1
        assert response.metrics["status_sync.failed"] == 1
        assert response.metrics["status_sync.retry_failed"] == 1
        assert updated.metadata["status_sync_attempts"] == 2
        assert updated.metadata["last_status_sync_action"] == "revoke"
        assert updated.metadata["last_status_sync_error"] == "Canvas still unavailable"
        assert updated.last_error == "Canvas still unavailable"

    async def test_process_failed_status_syncs_blocks_when_profile_disables_mirror_ops(self, repo, monkeypatch):
        from issuance.infrastructure.api import routes

        platform, binding = await _save_canvas_program_target(repo)
        tx = _make_transaction(id="tx-sync-ops-disabled", status=IssuanceStatus.ISSUED)
        cred = _make_credential(
            id="cred-sync-ops-disabled",
            transaction_id=tx.id,
            status=CredentialStatus.SUSPENDED,
            status_updated_at=datetime(2026, 3, 8, tzinfo=timezone.utc),
        )
        record = _make_delivery_record(
            id="delivery-sync-ops-disabled",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.DELIVERED,
            canvas_account_id=platform.canvas_account_id,
            external_credential_id="canvas-sync-ops-disabled",
            metadata=_canvas_binding_metadata(
                binding_id=binding.id,
                platform_id=platform.id,
                **{
                "published_at": "2026-03-08T09:00:00+00:00",
                "last_status_sync_action": "suspend",
                "last_status_sync_error": "previous sync failure",
                "last_status_sync_error_at": "2026-03-08T10:00:00+00:00",
                "deployment_profile_id": "deployment-profile-1",
                "canvas_feature_flags": {
                    "enable_canvas_mirror_publish": True,
                    "enable_canvas_mirror_ops": False,
                },
                },
            ),
        )

        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(record)

        async def unexpected_sync(*args, **kwargs):
            raise AssertionError("Canvas lifecycle sync should not run when mirror ops are disabled")

        monkeypatch.setattr(routes, "sync_canvas_credential_status", unexpected_sync)

        response = await routes.run_canvas_mirror_status_sync_batch(
            repo,
            organization_id="org-1",
            limit=10,
        )
        updated = (await repo.list_delivery_records_for_credential(cred.id))[0]

        assert response.processed_count == 1
        assert response.synced_count == 0
        assert response.failed_count == 1
        assert response.blocked_count == 1
        assert response.metrics["status_sync.blocked"] == 1
        assert response.metrics["status_sync.retry_blocked"] == 1
        assert updated.status == CredentialDeliveryStatus.DELIVERED
        assert updated.last_error == "Canvas mirror operations are disabled by deployment profile"
        assert updated.metadata["canvas_feature_gate_blocked"] is True
        assert updated.metadata["canvas_feature_gate"] == "enable_canvas_mirror_ops"
        assert updated.metadata["last_status_sync_error"] == updated.last_error
        assert updated.metadata.get("status_sync_attempts") is None

    async def test_canvas_mirror_automation_cycle_processes_publish_and_status_sync(self, repo, monkeypatch):
        from issuance.infrastructure.api import routes

        platform, binding = await _save_canvas_program_target(repo)
        publish_tx = _make_transaction(
            id="tx-automation-publish",
            status=IssuanceStatus.ISSUED,
            delivery_mode="wallet_plus_canvas_mirror",
        )
        publish_cred = _make_credential(id="cred-automation-publish", transaction_id=publish_tx.id)
        pending_record = _make_delivery_record(
            id="delivery-automation-publish",
            credential_id=publish_cred.id,
            transaction_id=publish_tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.PENDING,
            canvas_account_id=platform.canvas_account_id,
            metadata=_canvas_binding_metadata(binding_id=binding.id, platform_id=platform.id),
        )
        sync_tx = _make_transaction(id="tx-automation-sync", status=IssuanceStatus.ISSUED)
        sync_cred = _make_credential(
            id="cred-automation-sync",
            transaction_id=sync_tx.id,
            status=CredentialStatus.SUSPENDED,
            status_updated_at=datetime(2026, 3, 7, tzinfo=timezone.utc),
        )
        failed_sync_record = _make_delivery_record(
            id="delivery-automation-sync",
            credential_id=sync_cred.id,
            transaction_id=sync_tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            delivery_mode="wallet_plus_canvas_mirror",
            status=CredentialDeliveryStatus.DELIVERED,
            canvas_account_id=platform.canvas_account_id,
            external_credential_id="canvas-automation-sync",
            metadata=_canvas_binding_metadata(
                binding_id=binding.id,
                platform_id=platform.id,
                **{
                "published_at": "2026-03-07T09:00:00+00:00",
                "last_status_sync_action": "suspend",
                "last_status_sync_error": "previous sync failure",
                "last_status_sync_error_at": "2026-03-07T10:00:00+00:00",
                },
            ),
        )

        await repo.save_transaction(publish_tx)
        await repo.save_transaction(sync_tx)
        await repo.save_credential(publish_cred)
        await repo.save_credential(sync_cred)
        await repo.save_delivery_record(pending_record)
        await repo.save_delivery_record(failed_sync_record)

        captured_publish: list[str] = []
        captured_sync: list[str] = []

        async def fake_publish_canvas_credential_mirror(*, credential, transaction, platform, delivery_record, secret_resolver=None):
            captured_publish.append(delivery_record.id)
            return types.SimpleNamespace(
                external_credential_id=f"mirror-{credential.id}",
                external_issuer_id="issuer-elevenid",
                metadata={"published_at": "2026-03-07T12:00:00+00:00"},
            )

        async def fake_sync_canvas_credential_status(*, credential, platform, delivery_record, lifecycle_action, reason=None, secret_resolver=None):
            captured_sync.append(delivery_record.id)
            assert lifecycle_action == "suspend"
            return types.SimpleNamespace(metadata={
                "status_sync_http_status": 200,
                "status_synced_at": "2026-03-07T12:05:00+00:00",
            })

        monkeypatch.setattr(routes, "publish_canvas_credential_mirror", fake_publish_canvas_credential_mirror)
        monkeypatch.setattr(routes, "sync_canvas_credential_status", fake_sync_canvas_credential_status)

        response = await routes.run_canvas_mirror_automation_cycle(
            repo,
            organization_id="org-1",
            limit=10,
            retry_failed=True,
        )

        updated_publish = (await repo.list_delivery_records_for_credential(publish_cred.id))[0]
        updated_sync = (await repo.list_delivery_records_for_credential(sync_cred.id))[0]

        assert response.organization_id == "org-1"
        assert response.processed_count == 2
        assert response.failed_count == 0
        assert response.metrics["automation.processed"] == 2
        assert response.metrics["publish.delivered"] == 1
        assert response.metrics["status_sync.synced"] == 1
        assert response.publish.processed_count == 1
        assert response.publish.delivered_count == 1
        assert response.status_sync.processed_count == 1
        assert response.status_sync.synced_count == 1
        assert captured_publish == ["delivery-automation-publish"]
        assert captured_sync == ["delivery-automation-sync"]
        assert updated_publish.status == CredentialDeliveryStatus.DELIVERED
        assert updated_publish.external_credential_id == "mirror-cred-automation-publish"
        assert updated_sync.metadata["last_status_sync_error"] is None
        assert updated_sync.metadata["status_synced_at"] == "2026-03-07T12:05:00+00:00"

    async def test_canvas_mirror_health_counts_publish_and_sync_states(self, repo):
        from issuance.infrastructure.api import routes

        pending = _make_delivery_record(
            id="delivery-health-pending",
            organization_id="org-1",
            credential_id="cred-health-pending",
            transaction_id="tx-health-pending",
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.PENDING,
            metadata={},
        )
        failed_publish = _make_delivery_record(
            id="delivery-health-failed",
            organization_id="org-1",
            credential_id="cred-health-failed",
            transaction_id="tx-health-failed",
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.FAILED,
            last_error="publish failed",
            metadata={
                "publish_attempts": 4,
                "last_error_at": "2026-03-05T08:00:00+00:00",
            },
        )
        delivered_ok = _make_delivery_record(
            id="delivery-health-ok",
            organization_id="org-1",
            credential_id="cred-health-ok",
            transaction_id="tx-health-ok",
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.DELIVERED,
            metadata={
                "published_at": "2026-03-05T09:00:00+00:00",
                "status_synced_at": "2026-03-05T10:00:00+00:00",
                "last_status_sync_error": None,
            },
        )
        delivered_sync_failed = _make_delivery_record(
            id="delivery-health-sync-failed",
            organization_id="org-1",
            credential_id="cred-health-sync-failed",
            transaction_id="tx-health-sync-failed",
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.DELIVERED,
            metadata={
                "published_at": "2026-03-05T11:00:00+00:00",
                "status_sync_attempts": 5,
                "last_status_sync_action": "suspend",
                "last_status_sync_error": "sync failed",
                "last_status_sync_error_at": "2026-03-05T12:00:00+00:00",
            },
        )
        other_org = _make_delivery_record(
            id="delivery-health-other-org",
            organization_id="org-2",
            credential_id="cred-health-other-org",
            transaction_id="tx-health-other-org",
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.DELIVERED,
            metadata={"published_at": "2026-03-06T09:00:00+00:00"},
        )

        await repo.save_delivery_record(pending)
        await repo.save_delivery_record(failed_publish)
        await repo.save_delivery_record(delivered_ok)
        await repo.save_delivery_record(delivered_sync_failed)
        await repo.save_delivery_record(other_org)

        response = await routes.get_canvas_mirror_health("org-1", repo)

        assert response.organization_id == "org-1"
        assert response.pending_publish_count == 1
        assert response.failed_publish_count == 1
        assert response.delivered_count == 2
        assert response.lifecycle_sync_failed_count == 1
        assert response.lifecycle_sync_ok_count == 1
        assert response.last_successful_publish_at == "2026-03-05T11:00:00+00:00"
        assert response.last_lifecycle_sync_failure_at == "2026-03-05T12:00:00+00:00"
        assert response.last_lifecycle_sync_success_at == "2026-03-05T10:00:00+00:00"
        assert response.alert_thresholds == {
            "warning_attempts": 3,
            "critical_attempts": 5,
        }
        assert response.repeated_publish_failure_count == 1
        assert response.repeated_lifecycle_sync_failure_count == 1
        assert response.warning_alert_count == 1
        assert response.critical_alert_count == 1
        assert response.alert_count == 2
        assert response.metrics["publish_failure_attempts_total"] == 4
        assert response.metrics["status_sync_failure_attempts_total"] == 5
        assert response.alerts[0].alert_type == "lifecycle_sync_failure"
        assert response.alerts[0].severity == "critical"
        assert response.alerts[0].attempt_count == 5
        assert response.alerts[1].alert_type == "publish_failure"
        assert response.alerts[1].severity == "warning"
        assert response.alerts[1].last_error == "publish failed"


class TestCanvasMirrorLifecycleSync:
    async def test_revoke_syncs_delivered_canvas_mirror(self, repo, monkeypatch):
        from issuance.infrastructure.api import routes

        tx = _make_transaction(id="tx-status-sync", status=IssuanceStatus.ISSUED)
        cred = _make_credential(id="cred-status-sync", transaction_id=tx.id)
        platform, binding = await _save_canvas_program_target(repo)
        delivery = _make_delivery_record(
            id="delivery-status-sync",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.DELIVERED,
            canvas_account_id=platform.canvas_account_id,
            external_credential_id="canvas-cred-1",
            external_issuer_id="issuer-elevenid",
            metadata=_canvas_binding_metadata(binding_id=binding.id, platform_id=platform.id),
        )
        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(delivery)

        captured: dict[str, object] = {}

        async def fake_delegate(*args, **kwargs):
            return {"ok": True}

        async def fake_sync_canvas_credential_status(*, credential, platform, delivery_record, lifecycle_action, reason=None, secret_resolver=None):
            captured["credential_status"] = credential.status.value
            captured["canvas_platform_id"] = platform.id
            captured["delivery_record_id"] = delivery_record.id
            captured["lifecycle_action"] = lifecycle_action
            captured["reason"] = reason
            return types.SimpleNamespace(metadata={
                "status_sync_url": "https://canvas.example.test/status-sync",
                "status_sync_http_status": 200,
                "status_sync_response": {"ok": True},
                "status_sync_request_id": "sync-req-1",
                "status_synced_at": datetime.now(timezone.utc).isoformat(),
            })

        monkeypatch.setattr(routes, "_delegate_to_revocation_profile", fake_delegate)
        monkeypatch.setattr(routes, "sync_canvas_credential_status", fake_sync_canvas_credential_status)

        response = await routes.revoke_credential(
            cred.id,
            routes.CredentialStatusRequest(reason="policy violation"),
            repo,
        )

        updated = await repo.get_credential(cred.id)
        records = await repo.list_delivery_records_for_credential(cred.id)
        synced_record = next(record for record in records if record.delivery_target == DeliveryTarget.CANVAS_CREDENTIALS)

        assert response["status"] == "revoked"
        assert updated is not None and updated.status == CredentialStatus.REVOKED
        assert captured == {
            "credential_status": "revoked",
            "canvas_platform_id": "platform-1",
            "delivery_record_id": "delivery-status-sync",
            "lifecycle_action": "revoke",
            "reason": "policy violation",
        }
        assert synced_record.status == CredentialDeliveryStatus.DELIVERED
        assert synced_record.last_error is None
        assert synced_record.metadata["status_sync_attempts"] == 1
        assert synced_record.metadata["last_status_sync_action"] == "revoke"
        assert synced_record.metadata["last_synced_credential_status"] == "revoked"
        assert synced_record.metadata["status_sync_http_status"] == 200

    async def test_suspend_keeps_canonical_state_when_canvas_sync_fails(self, repo, monkeypatch):
        from issuance.infrastructure.api import routes

        tx = _make_transaction(id="tx-status-sync-fail", status=IssuanceStatus.ISSUED)
        cred = _make_credential(id="cred-status-sync-fail", transaction_id=tx.id)
        platform, binding = await _save_canvas_program_target(repo)
        delivery = _make_delivery_record(
            id="delivery-status-sync-fail",
            credential_id=cred.id,
            transaction_id=tx.id,
            delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
            status=CredentialDeliveryStatus.DELIVERED,
            canvas_account_id=platform.canvas_account_id,
            external_credential_id="canvas-cred-2",
            metadata=_canvas_binding_metadata(binding_id=binding.id, platform_id=platform.id),
        )
        await repo.save_transaction(tx)
        await repo.save_credential(cred)
        await repo.save_delivery_record(delivery)

        async def fake_delegate(*args, **kwargs):
            return {"ok": True}

        async def failing_sync(*args, **kwargs):
            raise RuntimeError("Canvas status endpoint unavailable")

        monkeypatch.setattr(routes, "_delegate_to_revocation_profile", fake_delegate)
        monkeypatch.setattr(routes, "sync_canvas_credential_status", failing_sync)

        response = await routes.suspend_credential(
            cred.id,
            routes.CredentialStatusRequest(reason="investigating"),
            repo,
        )

        updated = await repo.get_credential(cred.id)
        records = await repo.list_delivery_records_for_credential(cred.id)
        synced_record = next(record for record in records if record.delivery_target == DeliveryTarget.CANVAS_CREDENTIALS)

        assert response["status"] == "suspended"
        assert updated is not None and updated.status == CredentialStatus.SUSPENDED
        assert synced_record.status == CredentialDeliveryStatus.DELIVERED
        assert synced_record.last_error == "Canvas status endpoint unavailable"
        assert synced_record.metadata["status_sync_attempts"] == 1
        assert synced_record.metadata["last_status_sync_action"] == "suspend"
        assert synced_record.metadata["last_synced_credential_status"] == "suspended"
        assert synced_record.metadata["last_status_sync_error"] == "Canvas status endpoint unavailable"


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
        holder_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "holder-x",
            "y": "holder-y",
            "d": "must-not-be-issued",
        }

        credential, credential_id = await create_sd_jwt_vc_with_remote_signing(
            issuer_did="did:web:beta.elevenidllc.com:orgs:acme",
            signing_service_id="managed-openbao-transit",
            remote_sign=fake_remote_sign,
            subject_id="did:key:z6Mk_subject",
            holder_jwk=holder_jwk,
            credential_type="https://beta.elevenidllc.com/credentials/access_badge",
            claims_json=json.dumps({"name": "Alice"}),
            algorithm="ES256",
            signing_key_reference="raw-openbao-key-name",
            verification_method_id=verification_method_id,
            # The final OID4VCI response selects this media type before it
            # reaches the signing adapter; exercise that public contract here.
            credential_format="dc+sd-jwt",
        )

        jwt = credential.split("~", 1)[0]
        encoded_header = jwt.split(".", 1)[0]
        encoded_payload = jwt.split(".")[1]
        header = json.loads(base64url_decode(encoded_header))
        payload = json.loads(base64url_decode(encoded_payload))

        assert header["kid"] == verification_method_id
        assert header["typ"] == "dc+sd-jwt"
        assert payload["cnf"]["jwk"] == {
            "kty": "EC",
            "crv": "P-256",
            "x": "holder-x",
            "y": "holder-y",
        }
        assert captured["algorithm"] == "ES256"
        assert credential_id.startswith("urn:uuid:")

    async def test_remote_sd_jwt_accepts_caller_supplied_credential_status(self):
        from issuance.application.rust_integration import (
            base64url_decode,
            create_sd_jwt_vc_with_remote_signing,
        )

        async def fake_remote_sign(payload: bytes, algorithm: str | None):
            return {"signature_raw_b64": "AQID", "algorithm": algorithm}

        supplied_credential_id = "urn:uuid:00000000-0000-0000-0000-000000000123"
        credential, credential_id = await create_sd_jwt_vc_with_remote_signing(
            issuer_did="did:web:beta.elevenidllc.com:orgs:acme",
            signing_service_id="managed-openbao-transit",
            remote_sign=fake_remote_sign,
            subject_id="did:key:z6Mk_subject",
            credential_type="https://beta.elevenidllc.com/credentials/access_badge",
            claims_json=json.dumps(
                {
                    "name": "Alice",
                    "credentialStatus": {
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "revocation",
                        "statusListIndex": "42",
                        "statusListCredential": "https://beta.elevenidllc.com/v1/status-list",
                    },
                }
            ),
            algorithm="ES256",
            credential_id=supplied_credential_id,
        )

        jwt = credential.split("~", 1)[0]
        encoded_payload = jwt.split(".")[1]
        payload = json.loads(base64url_decode(encoded_payload))

        assert credential_id == supplied_credential_id
        assert payload["jti"] == supplied_credential_id
        assert payload["credentialStatus"]["statusListIndex"] == "42"

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

    def test_delivery_mode_defaults_to_wallet_only(self):
        tx = _make_transaction()
        assert tx.delivery_mode == "wallet_only"

    def test_delivery_mode_stores_canvas_mirror_configuration(self):
        tx = _make_transaction(
            delivery_mode="wallet_plus_canvas_mirror",
        )
        assert tx.delivery_mode == "wallet_plus_canvas_mirror"
        assert tx.should_mirror_to_canvas is True

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


async def test_renewal_offer_links_new_transaction_to_source_credential(monkeypatch):
    from types import SimpleNamespace
    from issuance.infrastructure.api import routes

    repo = _TestableRepo()
    source_tx = _make_transaction(
        status=IssuanceStatus.ISSUED,
        renewable=True,
        renewal_window_days=7,
        validity_days=1,
    )
    source = _make_credential(
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    await repo.save_transaction(source_tx)
    await repo.save_credential(source)

    async def fake_initiate(_request, http_request, repo):
        renewal_tx = _make_transaction(
            id="tx-renewal",
            status=IssuanceStatus.PENDING,
            renewable=True,
            renewal_window_days=7,
            validity_days=1,
        )
        await repo.save_transaction(renewal_tx)
        return routes.IssuanceResponse(
            id=renewal_tx.id,
            organization_id=renewal_tx.organization_id,
            credential_template_id=renewal_tx.credential_template_id,
            status=renewal_tx.status.value,
            credential_offer_uri="openid-credential-offer://renewal",
            pre_auth_code=renewal_tx.pre_auth_code,
            expires_at=renewal_tx.expires_at.isoformat(),
        )

    monkeypatch.setattr(routes, "initiate_issuance", fake_initiate)

    result = await routes.renew_issued_credential(
        source.id,
        SimpleNamespace(headers={}),
        repo,
    )

    renewal_tx = await repo.get_transaction(result.transaction_id)
    assert result.source_credential_id == source.id
    assert result.credential_offer_uri == "openid-credential-offer://renewal"
    assert renewal_tx is not None
    assert renewal_tx.renewal_of_credential_id == source.id


async def test_completed_renewal_supersedes_source_credential(monkeypatch):
    from issuance.infrastructure.api import routes

    repo = _TestableRepo()
    source = _make_credential()
    renewed = _make_credential(id="cred-renewed", transaction_id="tx-renewed")
    renewal_tx = _make_transaction(
        id="tx-renewed",
        renewal_of_credential_id=source.id,
    )
    await repo.save_credential(source)
    await repo.save_credential(renewed)

    async def fake_revoke(credential_id, request, repo):
        credential = await repo.get_credential(credential_id)
        credential.status = CredentialStatus.REVOKED
        credential.revoked = True
        credential.revoked_at = datetime.now(timezone.utc)
        credential.revocation_reason = request.reason
        await repo.save_credential(credential)

    monkeypatch.setattr(routes, "revoke_credential", fake_revoke)

    await routes._finalize_credential_renewal(renewal_tx, renewed, repo)

    stored_source = await repo.get_credential(source.id)
    stored_renewed = await repo.get_credential(renewed.id)
    assert stored_source.status == CredentialStatus.REVOKED
    assert stored_source.renewed_to_credential_id == renewed.id
    assert stored_renewed.renewed_from_credential_id == source.id
