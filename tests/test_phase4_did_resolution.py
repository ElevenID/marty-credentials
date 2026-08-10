"""
Tests for Phase 4 — DID resolution and issued credential issuer_did field.

Covers:
 - DID resolver: did:key, did:jwk, did:web (mocked HTTP), error handling
 - IssuedCredential.issuer_did field
 - _issued_credential_to_protocol issuer_did population
 - verify_w3c_vc with DID resolution
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
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
                {
                    "id": f"{did}#old",
                    "controller": did,
                    "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "old", "y": "old"},
                },
                {
                    "id": f"{did}#active",
                    "controller": did,
                    "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "new", "y": "new"},
                },
            ],
            "assertionMethod": [f"{did}#old", f"{did}#active"],
        }

        jwk = extract_public_key_jwk(doc, f"{did}#active")

        assert jwk is not None
        assert jwk["x"] == "new"
        assert jwk["kid"] == f"{did}#active"

    def test_extract_credential_verification_method_from_proof(self):
        credential = {"proof": {"verificationMethod": "did:web:issuer.example.com#active"}}

        assert (
            extract_credential_verification_method(credential)
            == "did:web:issuer.example.com#active"
        )


# ============================================================================
# 2. DID Resolver — did:jwk
# ============================================================================


class TestResolveDidJwk:
    """did:jwk resolution."""

    def _make_did_jwk(self, jwk_dict: dict) -> str:
        encoded = base64.urlsafe_b64encode(json.dumps(jwk_dict).encode()).rstrip(b"=").decode()
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

    @staticmethod
    def _document(did: str) -> dict:
        method_id = f"{did}#key-1"
        return {
            "id": did,
            "verificationMethod": [
                {
                    "id": method_id,
                    "controller": did,
                    "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"},
                }
            ],
            "assertionMethod": [method_id],
        }

    async def _resolve_with_transport(self, did: str, handler):
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with (
            patch("verification.application.did_resolver.httpx.AsyncClient", return_value=client),
            patch(
                "verification.application.did_resolver._require_public_dns",
                new=AsyncMock(return_value=("93.184.216.34",)),
            ),
        ):
            return await resolve_did(did)

    @pytest.mark.asyncio
    async def test_resolves_simple_domain(self):
        requested_urls = []

        def handler(request):
            requested_urls.append(str(request.url))
            return httpx.Response(
                200,
                json=self._document("did:web:example.com"),
                headers={"content-type": "application/did+json"},
            )

        doc = await self._resolve_with_transport("did:web:example.com", handler)

        assert doc["id"] == "did:web:example.com"
        assert requested_urls == ["https://example.com/.well-known/did.json"]

    @pytest.mark.asyncio
    async def test_resolves_path_based_domain(self):
        requested_urls = []
        did = "did:web:example.com:orgs:acme"

        def handler(request):
            requested_urls.append(str(request.url))
            return httpx.Response(
                200,
                json=self._document(did),
                headers={"content-type": "application/json"},
            )

        await self._resolve_with_transport(did, handler)

        assert requested_urls == ["https://example.com/orgs/acme/did.json"]

    @pytest.mark.asyncio
    async def test_rejects_http_error(self):
        with pytest.raises(ValueError, match="HTTP 404"):
            await self._resolve_with_transport(
                "did:web:example.com",
                lambda _request: httpx.Response(404, headers={"content-type": "application/json"}),
            )

    @pytest.mark.asyncio
    async def test_rejects_redirects(self):
        with pytest.raises(ValueError, match="redirects are not permitted"):
            await self._resolve_with_transport(
                "did:web:example.com",
                lambda _request: httpx.Response(302, headers={"location": "https://internal.test"}),
            )

    @pytest.mark.asyncio
    async def test_rejects_oversized_document(self):
        with pytest.raises(ValueError, match="maximum response size"):
            await self._resolve_with_transport(
                "did:web:example.com",
                lambda _request: httpx.Response(
                    200,
                    content=b"x" * (1024 * 1024 + 1),
                    headers={"content-type": "application/did+json"},
                ),
            )

    @pytest.mark.asyncio
    async def test_rejects_document_id_mismatch(self):
        with pytest.raises(ValueError, match="id does not match"):
            await self._resolve_with_transport(
                "did:web:example.com",
                lambda _request: httpx.Response(
                    200,
                    json=self._document("did:web:attacker.example"),
                    headers={"content-type": "application/did+json"},
                ),
            )

    @pytest.mark.asyncio
    async def test_rejects_duplicate_verification_method_ids(self):
        did = "did:web:example.com"
        document = self._document(did)
        document["verificationMethod"].append(document["verificationMethod"][0].copy())

        with pytest.raises(ValueError, match="duplicate verification method ids"):
            await self._resolve_with_transport(
                did,
                lambda _request: httpx.Response(
                    200,
                    json=document,
                    headers={"content-type": "application/did+json"},
                ),
            )

    @pytest.mark.asyncio
    async def test_rejects_private_ip_literal_without_network_request(self):
        with pytest.raises(ValueError, match="IP literals are not permitted"):
            await resolve_did("did:web:127.0.0.1")

    @pytest.mark.asyncio
    async def test_rejects_hostname_resolving_to_private_address(self):
        from verification.application import did_resolver

        loop = MagicMock()
        loop.getaddrinfo = AsyncMock(return_value=[(2, 1, 6, "", ("10.0.0.8", 443))])
        with patch.object(did_resolver.asyncio, "get_running_loop", return_value=loop):
            with pytest.raises(ValueError, match="non-public address"):
                await did_resolver._require_public_dns("example.com", 443)

    @pytest.mark.asyncio
    async def test_rejects_encoded_path_separator_without_network_request(self):
        with pytest.raises(ValueError, match="Malformed did:web path"):
            await resolve_did("did:web:example.com:orgs%2Finternal")

    @pytest.mark.asyncio
    async def test_enforces_configured_host_allowlist(self, monkeypatch):
        monkeypatch.setenv("DID_WEB_ALLOWED_HOSTS", "issuer.example.com")

        with pytest.raises(ValueError, match="egress allowlist"):
            await resolve_did("did:web:example.com")

    @pytest.mark.asyncio
    async def test_production_requires_configured_host_allowlist(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.delenv("DID_WEB_ALLOWED_HOSTS", raising=False)

        with pytest.raises(ValueError, match="requires a configured egress allowlist"):
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

        with patch(
            "verification.application.did_resolver.httpx.AsyncClient", return_value=mock_client
        ):
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

        with patch(
            "verification.application.did_resolver.httpx.AsyncClient", return_value=mock_client
        ):
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

    @pytest.mark.asyncio
    async def test_public_resolution_requires_explicit_authorization(self):
        issuer_did = "did:web:issuer.example.com"

        with pytest.raises(ValueError, match="not explicitly authorized"):
            await resolve_issuer_did(issuer_did, trusted_issuers=[issuer_did])

    @pytest.mark.asyncio
    async def test_public_resolution_requires_nonempty_trusted_issuer_list(self):
        with pytest.raises(ValueError, match="explicitly trusted issuer"):
            await resolve_issuer_did(
                "did:web:issuer.example.com",
                allow_public_fallback=True,
            )

    @pytest.mark.asyncio
    async def test_public_resolution_records_document_provenance(self):
        from verification.application import did_resolver

        issuer_did = "did:web:issuer.example.com"
        method_id = f"{issuer_did}#issuer-key"
        document = {
            "id": issuer_did,
            "verificationMethod": [
                {
                    "id": method_id,
                    "controller": issuer_did,
                    "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"},
                }
            ],
            "assertionMethod": [method_id],
        }
        expected_digest = hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        with patch.object(did_resolver, "resolve_did", new=AsyncMock(return_value=document)):
            resolved = await resolve_issuer_did(
                issuer_did,
                verification_method_id=method_id,
                trusted_issuers=[issuer_did],
                allow_public_fallback=True,
            )

        assert resolved["resolver"]["public_fallback_used"] is False
        assert resolved["resolver"]["did_document_sha256"] == expected_digest
        assert resolved["resolver"]["retrieved_at"].endswith("+00:00")

    @pytest.mark.asyncio
    async def test_public_resolution_rejects_ambiguous_assertion_keys(self):
        from verification.application import did_resolver

        issuer_did = "did:web:issuer.example.com"
        document = {
            "id": issuer_did,
            "verificationMethod": [
                {
                    "id": f"{issuer_did}#one",
                    "controller": issuer_did,
                    "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "one"},
                },
                {
                    "id": f"{issuer_did}#two",
                    "controller": issuer_did,
                    "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "two"},
                },
            ],
            "assertionMethod": [f"{issuer_did}#one", f"{issuer_did}#two"],
        }

        with (
            patch.object(did_resolver, "resolve_did", new=AsyncMock(return_value=document)),
            pytest.raises(ValueError, match="unambiguous assertion key"),
        ):
            await resolve_issuer_did(
                issuer_did,
                trusted_issuers=[issuer_did],
                allow_public_fallback=True,
            )

    @pytest.mark.asyncio
    async def test_public_resolution_rejects_requested_algorithm_mismatch(self):
        from verification.application import did_resolver

        issuer_did = "did:web:issuer.example.com"
        method_id = f"{issuer_did}#issuer-key"
        document = {
            "id": issuer_did,
            "verificationMethod": [
                {
                    "id": method_id,
                    "controller": issuer_did,
                    "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"},
                }
            ],
            "assertionMethod": [method_id],
        }

        with (
            patch.object(did_resolver, "resolve_did", new=AsyncMock(return_value=document)),
            pytest.raises(ValueError, match="not compatible"),
        ):
            await resolve_issuer_did(
                issuer_did,
                verification_method_id=method_id,
                trusted_issuers=[issuer_did],
                algorithm="ES256",
                allow_public_fallback=True,
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
            monkeypatch.setitem(
                sys.modules, "mmf.infrastructure.database.session", mmf_session_module
            )

        postgres_repo_module = types.ModuleType(
            "verification.infrastructure.persistence.postgres_repository"
        )

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
                return {
                    "valid": True,
                    "country": "XA",
                    "payload": {"sub": "123"},
                    "signature_status": "VALID",
                    "errors": [],
                }

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

        verifier = rust_verifier.RustCredentialVerifier.__new__(
            rust_verifier.RustCredentialVerifier
        )
        verifier.marty_rs = MagicMock()
        verifier.marty_rs.verify_vcdm_data_integrity.return_value = json.dumps(
            {
                "valid": True,
                "kind": "credential",
                "verified_credentials": 1,
                "errors": [],
            }
        )

        result = await verifier.verify_w3c_vc(
            credential,
            verifier_did="did:web:verifier.example.com",
            trusted_issuers=[issuer_did],
            organization_id="org-acme",
            credential_format="dc+sd-jwt",
            key_purpose="vc_jwt_issuer",
            algorithm="ES256",
        )

        assert result["valid"] is False
        assert result["cryptographic_valid"] is True
        assert result["decision_ready"] is False
        assert result["issuer_trusted"] is True
        assert result["revocation_checked"] is False
        native_request = json.loads(
            verifier.marty_rs.verify_vcdm_data_integrity.call_args.args[0]
        )
        assert native_request == {
            "document": credential,
            "resolved_verification_methods": [
                {
                    "id": vm_id,
                    "controller": issuer_did,
                    "public_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "abc",
                        "y": "def",
                        "kid": vm_id,
                    },
                }
            ],
        }
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
            "proof": {
                "type": "JsonWebSignature2020",
                "verificationMethod": f"{issuer_did}#issuer-key",
            },
        }

        monkeypatch.setattr(
            rust_verifier,
            "resolve_issuer_did",
            AsyncMock(
                side_effect=ValueError(
                    "Issuer DID is not an active issuer identity for this organization"
                )
            ),
        )

        verifier = rust_verifier.RustCredentialVerifier.__new__(
            rust_verifier.RustCredentialVerifier
        )
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
                return {
                    "valid": True,
                    "cryptographic_valid": True,
                    "trust_chain_valid": True,
                    "revocation_checked": True,
                    "revocation_status": "VALID",
                    "verified_claims": {"employee_id": "E-123"},
                }

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
        cred = IssuedCredential(issuer_did="did:web:beta.elevenidllc.com:orgs:acme")
        assert cred.issuer_did == "did:web:beta.elevenidllc.com:orgs:acme"

    def test_stores_did_key_issuer(self):
        cred = IssuedCredential(
            issuer_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        )
        assert cred.issuer_did.startswith("did:key:")
