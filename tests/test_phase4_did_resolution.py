"""
Tests for Phase 4 — DID resolution and issued credential issuer_did field.

Covers:
 - DID resolver: did:key, did:jwk, did:web (mocked HTTP), error handling
 - IssuedCredential.issuer_did field
 - _issued_credential_to_protocol issuer_did population
 - verify_w3c_vc with DID resolution
"""

import base64
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path manipulation so that "verification.*" and "issuance.*" resolve.
# ---------------------------------------------------------------------------
import sys
import os
import types

_REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
_SERVICES = os.path.join(_REPO_ROOT, "services")

if _SERVICES not in sys.path:
    sys.path.insert(0, _SERVICES)


# ============================================================================
# 1. DID Resolver — did:key (Ed25519)
# ============================================================================

from verification.application.did_resolver import (
    extract_credential_verification_method,
    extract_public_key_jwk,
    resolve_issuer_did,
    resolve_did,
    resolve_did_jwk,
    resolve_did_key,
)


class TestResolveDidKey:
    """did:key resolution for Ed25519 public keys."""

    # Real Ed25519 did:key from W3C test vectors
    _ED25519_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

    def test_resolves_ed25519_did_key(self):
        doc = resolve_did_key(self._ED25519_DID)
        assert doc["id"] == self._ED25519_DID
        assert len(doc["verificationMethod"]) == 1
        vm = doc["verificationMethod"][0]
        assert vm["publicKeyJwk"]["kty"] == "OKP"
        assert vm["publicKeyJwk"]["crv"] == "Ed25519"
        assert "x" in vm["publicKeyJwk"]
        assert vm["controller"] == self._ED25519_DID

    def test_authentication_and_assertion_method(self):
        doc = resolve_did_key(self._ED25519_DID)
        vm_id = doc["verificationMethod"][0]["id"]
        assert vm_id in doc["authentication"]
        assert vm_id in doc["assertionMethod"]

    def test_rejects_non_did_key(self):
        with pytest.raises(ValueError, match="Not a did:key"):
            resolve_did_key("did:web:example.com")

    def test_rejects_unsupported_multibase(self):
        with pytest.raises(ValueError, match="Unsupported multibase"):
            resolve_did_key("did:key:f1234")  # 'f' prefix = hex, not supported

    def test_extract_public_key_jwk(self):
        doc = resolve_did_key(self._ED25519_DID)
        jwk = extract_public_key_jwk(doc)
        assert jwk is not None
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"

    def test_extract_public_key_jwk_matches_exact_verification_method(self):
        did = "did:web:issuer.example.com"
        doc = {
            "id": did,
            "verificationMethod": [
                {"id": f"{did}#old", "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "old", "y": "old"}},
                {"id": f"{did}#active", "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "new", "y": "new"}},
            ],
        }

        jwk = extract_public_key_jwk(doc, f"{did}#active")

        assert jwk is not None
        assert jwk["x"] == "new"
        assert jwk["kid"] == f"{did}#active"

    def test_extract_credential_verification_method_from_proof(self):
        credential = {
            "proof": {"verificationMethod": "did:web:issuer.example.com#active"}
        }

        assert extract_credential_verification_method(credential) == "did:web:issuer.example.com#active"


# ============================================================================
# 2. DID Resolver — did:jwk
# ============================================================================


class TestResolveDidJwk:
    """did:jwk resolution."""

    def _make_did_jwk(self, jwk_dict: dict) -> str:
        encoded = base64.urlsafe_b64encode(
            json.dumps(jwk_dict).encode()
        ).rstrip(b"=").decode()
        return f"did:jwk:{encoded}"

    def test_resolves_ec_jwk(self):
        jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        did = self._make_did_jwk(jwk)
        doc = resolve_did_jwk(did)
        assert doc["id"] == did
        vm = doc["verificationMethod"][0]
        assert vm["publicKeyJwk"]["kty"] == "EC"
        assert vm["publicKeyJwk"]["crv"] == "P-256"

    def test_resolves_okp_jwk(self):
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": "xyz"}
        did = self._make_did_jwk(jwk)
        doc = resolve_did_jwk(did)
        assert doc["verificationMethod"][0]["publicKeyJwk"]["crv"] == "Ed25519"

    def test_strips_private_key_material(self):
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": "xyz", "d": "SECRET"}
        did = self._make_did_jwk(jwk)
        doc = resolve_did_jwk(did)
        assert "d" not in doc["verificationMethod"][0]["publicKeyJwk"]

    def test_rejects_invalid_base64(self):
        with pytest.raises(ValueError, match="cannot decode"):
            resolve_did_jwk("did:jwk:not-valid-base64!!!")

    def test_rejects_missing_kty(self):
        encoded = base64.urlsafe_b64encode(b'{"crv":"Ed25519"}').rstrip(b"=").decode()
        with pytest.raises(ValueError, match="missing 'kty'"):
            resolve_did_jwk(f"did:jwk:{encoded}")


# ============================================================================
# 3. DID Resolver — did:web (mocked HTTP)
# ============================================================================


class TestResolveDidWeb:
    """did:web resolution with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_resolves_simple_domain(self):
        mock_doc = {
            "id": "did:web:example.com",
            "verificationMethod": [
                {"id": "did:web:example.com#key-1", "publicKeyJwk": {"kty": "OKP"}}
            ],
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_doc
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("verification.application.did_resolver.httpx.AsyncClient", return_value=mock_client):
            doc = await resolve_did("did:web:example.com")

        assert doc["id"] == "did:web:example.com"
        mock_client.get.assert_called_once_with("https://example.com/.well-known/did.json")

    @pytest.mark.asyncio
    async def test_resolves_path_based_domain(self):
        mock_doc = {"id": "did:web:example.com:orgs:acme"}
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_doc
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("verification.application.did_resolver.httpx.AsyncClient", return_value=mock_client):
            doc = await resolve_did("did:web:example.com:orgs:acme")

        mock_client.get.assert_called_once_with("https://example.com/orgs/acme/did.json")

    @pytest.mark.asyncio
    async def test_rejects_http_error(self):
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found", request=MagicMock(), response=mock_response
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("verification.application.did_resolver.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ValueError, match="HTTP 404"):
                await resolve_did("did:web:example.com")


# ============================================================================
# 4. resolve_did dispatcher
# ============================================================================


class TestResolveDid:
    """Top-level resolve_did dispatches by method."""

    @pytest.mark.asyncio
    async def test_dispatches_did_key(self):
        doc = await resolve_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        assert doc["id"].startswith("did:key:")

    @pytest.mark.asyncio
    async def test_dispatches_did_jwk(self):
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": "test"}
        b64 = base64.urlsafe_b64encode(json.dumps(jwk).encode()).rstrip(b"=").decode()
        doc = await resolve_did(f"did:jwk:{b64}")
        assert doc["id"].startswith("did:jwk:")

    @pytest.mark.asyncio
    async def test_rejects_unsupported_method(self):
        with pytest.raises(ValueError, match="Unsupported DID method"):
            await resolve_did("did:example:123")

    @pytest.mark.asyncio
    async def test_rejects_empty_string(self):
        with pytest.raises(ValueError, match="non-empty"):
            await resolve_did("")


class TestResolveIssuerDid:
    """Org-scoped issuer DID resolution client."""

    @pytest.mark.asyncio
    async def test_uses_org_registry_before_public_resolution(self, monkeypatch):
        issuer_did = "did:web:issuer.example.com:orgs:acme"
        vm_id = f"{issuer_did}#issuer-key"
        monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-key")
        monkeypatch.setenv("SIGNING_KEYS_INTERNAL_URL", "http://gateway.test/internal/signing-keys")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ok": True,
            "issuer_did": issuer_did,
            "verification_method_id": vm_id,
            "did_document": {"id": issuer_did, "verificationMethod": []},
            "public_jwk": {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def", "kid": vm_id},
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("verification.application.did_resolver.httpx.AsyncClient", return_value=mock_client):
            resolved = await resolve_issuer_did(
                issuer_did,
                organization_id="org-acme",
                verification_method_id=vm_id,
                trusted_issuers=[issuer_did],
                credential_format="dc+sd-jwt",
                key_purpose="vc_jwt_issuer",
                algorithm="ES256",
            )

        assert resolved["issuer_did"] == issuer_did
        assert resolved["public_jwk"]["kid"] == vm_id
        call = mock_client.get.call_args
        assert call.args[0] == "http://gateway.test/internal/signing-keys/resolve-issuer-did"
        assert call.kwargs["params"]["organization_id"] == "org-acme"
        assert call.kwargs["params"]["issuer_did"] == issuer_did
        assert call.kwargs["headers"] == {"X-API-Key": "test-key"}

    @pytest.mark.asyncio
    async def test_fails_closed_when_org_registry_rejects_issuer(self, monkeypatch):
        issuer_did = "did:web:issuer.example.com:orgs:acme"
        monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-key")

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.reason_phrase = "Not Found"
        mock_response.text = '{"detail":"Issuer DID is not active"}'
        mock_response.json.return_value = {"detail": "Issuer DID is not active"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("verification.application.did_resolver.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ValueError, match="Org-scoped DID resolution failed"):
                await resolve_issuer_did(issuer_did, organization_id="org-acme")

    @pytest.mark.asyncio
    async def test_rejects_untrusted_issuer_before_resolution(self):
        with pytest.raises(ValueError, match="not trusted"):
            await resolve_issuer_did(
                "did:web:issuer.example.com",
                organization_id="org-acme",
                trusted_issuers=["did:web:other.example.com"],
            )


class TestVdsNcDidResolutionRoute:
    """VDS-NC verification should support DID-backed issuer resolution."""

    @pytest.mark.asyncio
    async def test_verify_vds_nc_resolves_issuer_did_before_verifying(self, monkeypatch):
        if "mmf.infrastructure.database.session" not in sys.modules:
            mmf_module = types.ModuleType("mmf")
            mmf_core_module = types.ModuleType("mmf.core")
            mmf_exceptions_module = types.ModuleType("mmf.core.exceptions")
            mmf_infra_module = types.ModuleType("mmf.infrastructure")
            mmf_db_module = types.ModuleType("mmf.infrastructure.database")
            mmf_session_module = types.ModuleType("mmf.infrastructure.database.session")

            class ValidationError(Exception):
                pass

            mmf_exceptions_module.ValidationError = ValidationError
            mmf_session_module.get_db_session = lambda: None
            monkeypatch.setitem(sys.modules, "mmf", mmf_module)
            monkeypatch.setitem(sys.modules, "mmf.core", mmf_core_module)
            monkeypatch.setitem(sys.modules, "mmf.core.exceptions", mmf_exceptions_module)
            monkeypatch.setitem(sys.modules, "mmf.infrastructure", mmf_infra_module)
            monkeypatch.setitem(sys.modules, "mmf.infrastructure.database", mmf_db_module)
            monkeypatch.setitem(sys.modules, "mmf.infrastructure.database.session", mmf_session_module)

        postgres_repo_module = types.ModuleType("verification.infrastructure.persistence.postgres_repository")

        class PostgresVerificationRepository:
            def __init__(self, *args, **kwargs):
                pass

        postgres_repo_module.PostgresVerificationRepository = PostgresVerificationRepository
        monkeypatch.setitem(
            sys.modules,
            "verification.infrastructure.persistence.postgres_repository",
            postgres_repo_module,
        )

        from verification.infrastructure.api import routes

        issuer_did = "did:web:issuer.example.com:orgs:acme"
        vm_id = f"{issuer_did}#vdsnc-key"
        resolver = AsyncMock(
            return_value={
                "ok": True,
                "issuer_did": issuer_did,
                "verification_method_id": vm_id,
                "public_jwk": {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def", "kid": vm_id},
            }
        )
        monkeypatch.setattr(routes, "resolve_issuer_did", resolver)

        class FakeVerifier:
            def __init__(self):
                self.issuer_jwk_json = None

            async def verify_vds_nc(self, *, barcode: str, issuer_jwk_json: str):
                self.issuer_jwk_json = issuer_jwk_json
                return {"valid": True, "country": "XA", "payload": {"sub": "123"}, "signature_status": "VALID", "errors": []}

        verifier = FakeVerifier()
        result = await routes.verify_vds_nc_barcode(
            routes.VerifyVdsNcRequest(
                barcode="header~{}~sig",
                issuer_did=issuer_did,
                organization_id="org-acme",
                verification_method_id=vm_id,
                trusted_issuers=[issuer_did],
                algorithm="ES256",
            ),
            verifier=verifier,
        )

        resolver.assert_awaited_once_with(
            issuer_did,
            organization_id="org-acme",
            verification_method_id=vm_id,
            trusted_issuers=[issuer_did],
            credential_format="vds_nc",
            key_purpose="vdsnc_signing",
            algorithm="ES256",
            allow_public_fallback=False,
        )
        assert json.loads(verifier.issuer_jwk_json)["kid"] == vm_id
        assert result.valid is True
        assert result.signature_status == "VALID"


class TestRustCredentialVerifierIssuerResolution:
    """Verifier should use org-scoped issuer DID resolution."""

    @pytest.mark.asyncio
    async def test_verify_w3c_vc_passes_org_context_to_issuer_resolver(self, monkeypatch):
        from verification.application import rust_verifier

        issuer_did = "did:web:issuer.example.com:orgs:acme"
        vm_id = f"{issuer_did}#issuer-key"
        credential = {
            "issuer": issuer_did,
            "credentialSubject": {"employee_id": "E-123"},
            "proof": {"type": "JsonWebSignature2020", "verificationMethod": vm_id},
        }

        resolver = AsyncMock(
            return_value={
                "ok": True,
                "issuer_did": issuer_did,
                "verification_method_id": vm_id,
                "did_document": {"id": issuer_did},
                "public_jwk": {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def", "kid": vm_id},
            }
        )
        monkeypatch.setattr(rust_verifier, "resolve_issuer_did", resolver)

        verifier = rust_verifier.RustCredentialVerifier.__new__(rust_verifier.RustCredentialVerifier)
        verifier.marty_rs = MagicMock()
        verifier.marty_rs.verify_w3c_vc_signature.return_value = json.dumps({"valid": True})

        result = await verifier.verify_w3c_vc(
            credential,
            verifier_did="did:web:verifier.example.com",
            trusted_issuers=[issuer_did],
            organization_id="org-acme",
            credential_format="dc+sd-jwt",
            key_purpose="vc_jwt_issuer",
            algorithm="ES256",
        )

        assert result["valid"] is True
        resolver.assert_awaited_once_with(
            issuer_did,
            organization_id="org-acme",
            verification_method_id=vm_id,
            trusted_issuers=[issuer_did],
            credential_format="dc+sd-jwt",
            key_purpose="vc_jwt_issuer",
            algorithm="ES256",
            allow_public_fallback=False,
        )

    @pytest.mark.asyncio
    async def test_verify_w3c_vc_fails_closed_when_signature_binding_missing(self, monkeypatch):
        from verification.application import rust_verifier

        issuer_did = "did:web:issuer.example.com:orgs:acme"
        credential = {
            "issuer": issuer_did,
            "credentialSubject": {"employee_id": "E-123"},
            "proof": {"type": "JsonWebSignature2020", "verificationMethod": f"{issuer_did}#issuer-key"},
        }

        monkeypatch.setattr(
            rust_verifier,
            "resolve_issuer_did",
            AsyncMock(side_effect=ValueError("Issuer DID is not an active issuer identity for this organization")),
        )

        verifier = rust_verifier.RustCredentialVerifier.__new__(rust_verifier.RustCredentialVerifier)
        verifier.marty_rs = MagicMock()

        result = await verifier.verify_w3c_vc(
            credential,
            verifier_did="did:web:verifier.example.com",
            trusted_issuers=[issuer_did],
            organization_id="org-acme",
        )

        assert result["valid"] is False
        assert "not an active issuer identity" in result["error"]


class TestVerificationServiceContextPropagation:
    """Verification service should not drop org/trust context."""

    @pytest.mark.asyncio
    async def test_direct_structured_presentation_passes_org_and_trusted_issuers(self, monkeypatch):
        if "mmf.core.exceptions" not in sys.modules:
            mmf_module = types.ModuleType("mmf")
            mmf_core_module = types.ModuleType("mmf.core")
            mmf_exceptions_module = types.ModuleType("mmf.core.exceptions")

            class ValidationError(Exception):
                pass

            mmf_exceptions_module.ValidationError = ValidationError
            monkeypatch.setitem(sys.modules, "mmf", mmf_module)
            monkeypatch.setitem(sys.modules, "mmf.core", mmf_core_module)
            monkeypatch.setitem(sys.modules, "mmf.core.exceptions", mmf_exceptions_module)

        from verification.application.service import VerificationService

        class FakeVerifier:
            def __init__(self):
                self.kwargs = None

            async def verify_presentation(self, **kwargs):
                self.kwargs = kwargs
                return {"valid": True, "verified_claims": {"employee_id": "E-123"}}

        fake_verifier = FakeVerifier()
        service = VerificationService(repository=MagicMock(), verifier=fake_verifier)

        result = await service.verify_presentation_direct(
            organization_id="org-acme",
            presentation={"verifiableCredential": []},
            presentation_definition={"id": "pd-1", "input_descriptors": []},
            verifier_did="did:web:verifier.example.com",
            trusted_issuers=["did:web:issuer.example.com:orgs:acme"],
        )

        assert result["valid"] is True
        assert fake_verifier.kwargs["organization_id"] == "org-acme"
        assert fake_verifier.kwargs["trusted_issuers"] == ["did:web:issuer.example.com:orgs:acme"]


# ============================================================================
# 5. IssuedCredential.issuer_did field
# ============================================================================

from issuance.domain.entities import (
    CredentialStatus,
    IssuedCredential,
)


class TestIssuedCredentialIssuerDid:
    """Validate the issuer_did field on IssuedCredential."""

    def test_defaults_to_none(self):
        cred = IssuedCredential()
        assert cred.issuer_did is None

    def test_stores_issuer_did(self):
        cred = IssuedCredential(
            issuer_did="did:web:beta.elevenidllc.com:orgs:acme"
        )
        assert cred.issuer_did == "did:web:beta.elevenidllc.com:orgs:acme"

    def test_stores_did_key_issuer(self):
        cred = IssuedCredential(
            issuer_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        )
        assert cred.issuer_did.startswith("did:key:")
