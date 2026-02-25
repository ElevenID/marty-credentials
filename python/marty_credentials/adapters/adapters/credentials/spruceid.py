"""
SpruceID Adapter

This module provides adapters implementing the credential ports using SpruceID's SSI library
via Rust FFI bindings.
"""

import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4

from marty_credentials.config import get_config
from marty_credentials.infrastructure.auth.token_validator import (
    CredentialVerificationError,
    TokenValidator,
)

logger = logging.getLogger(__name__)
from mmf.core.credentials.ports import (
    CredentialData,
    CredentialFormat,
    CredentialOffer,
    CredentialSubject,
    ICredentialIssuer,
    ICredentialVerifier,
    ICredentialWallet,
    IKeyManager,
    KeyAlgorithm,
    KeyPair,
    PresentationRequest,
    VerificationResult,
)


def _get_marty_rs():
    """Lazy import of Rust bindings."""
    try:
        import _marty_rs

        return _marty_rs
    except ImportError:
        raise RuntimeError(
            "SpruceID bindings not available. " "Build with: cd rust && maturin develop"
        )


class SpruceIDKeyManager:
    """Key manager implementation using SpruceID's SSI library.
    
    Supports the following key algorithms:
    - ES256 (P-256): SD-JWT-VC, JWT VC JSON
    - ES384 (P-384): JWT VC with higher security
    - RS256 (RSA PKCS#1 2048-bit): JWT VC JSON
    - RS384 (RSA PKCS#1 3072-bit): JWT VC JSON
    - RS512 (RSA PKCS#1 4096-bit): JWT VC JSON
    - PS256 (RSA-PSS 2048-bit): JWT VC with PSS padding
    - PS384 (RSA-PSS 3072-bit): JWT VC with PSS padding
    - PS512 (RSA-PSS 4096-bit): JWT VC with PSS padding
    - EdDSA (Ed25519): DID-based signing
    """

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}

    def generate_key(self, algorithm: KeyAlgorithm = KeyAlgorithm.ES256) -> KeyPair:
        """Generate a new key pair using SpruceID.
        
        Args:
            algorithm: The key algorithm to use
            
        Returns:
            A KeyPair containing DID, JWK, and metadata
            
        Raises:
            ValueError: If algorithm is not supported
        """
        marty_rs = _get_marty_rs()

        if algorithm == KeyAlgorithm.ES256:
            did, jwk_json = marty_rs.generate_p256_key()
        elif algorithm == KeyAlgorithm.ES384:
            did, jwk_json = marty_rs.generate_p384_key()
        elif algorithm == KeyAlgorithm.EDDSA:
            did, jwk_json = marty_rs.generate_did_key()
        elif algorithm.value.startswith("RS"):
            # RSA with PKCS#1 padding: RS256 (2048), RS384 (3072), RS512 (4096)
            key_sizes = {"RS256": 2048, "RS384": 3072, "RS512": 4096}
            key_size = key_sizes.get(algorithm.value, 2048)
            did, jwk_json = marty_rs.generate_rsa_key(key_size=key_size, use_pss=False)
        elif algorithm.value.startswith("PS"):
            # RSA-PSS padding: PS256 (2048), PS384 (3072), PS512 (4096)
            key_sizes = {"PS256": 2048, "PS384": 3072, "PS512": 4096}
            key_size = key_sizes.get(algorithm.value, 2048)
            did, jwk_json = marty_rs.generate_rsa_key(key_size=key_size, use_pss=True)
        else:
            supported = ["ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"]
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported: {supported}")

        return KeyPair(
            did=did,
            jwk_json=jwk_json,
            algorithm=algorithm,
            created_at=datetime.utcnow(),
        )

    def store_key(self, key_id: str, key_pair: KeyPair) -> None:
        """Store a key pair in memory."""
        self._keys[key_id] = key_pair

    def get_key(self, key_id: str) -> KeyPair | None:
        """Retrieve a stored key pair."""
        return self._keys.get(key_id)

    def list_keys(self) -> list[str]:
        """List all stored key identifiers."""
        return list(self._keys.keys())


class SpruceIDCredentialIssuer:
    """Credential issuer implementation using the v2 marty-oid4vci engine.

    Supports all credential formats: jwt_vc_json, vc+sd-jwt, mso_mdoc, zk_mdoc.
    """

    def create_credential(
        self,
        issuer_key: KeyPair,
        credential_type: str,
        subject: CredentialSubject,
        expiration_seconds: int | None = None,
        credential_format: str = "jwt_vc_json",
        selective_disclosure_claims: list[str] | None = None,
        mdoc_namespace: str | None = None,
        mdoc_doctype: str | None = None,
        zk_predicate_claims: list[str] | None = None,
    ) -> CredentialData:
        """Create and sign a verifiable credential using the v2 engine.

        Args:
            issuer_key: Key pair for signing.
            credential_type: Type of credential (e.g. "UniversityDegreeCredential").
            subject: Subject and claims for the credential.
            expiration_seconds: Credential validity period in seconds.
            credential_format: Output format – "jwt_vc_json", "vc+sd-jwt",
                "mso_mdoc", or "zk_mdoc".
            selective_disclosure_claims: Claim names for SD-JWT selective disclosure.
            mdoc_namespace: Namespace for mDoc credentials.
            mdoc_doctype: Document type for mDoc credentials.
            zk_predicate_claims: Claim names for ZK predicate proofs.
        """
        marty_rs = _get_marty_rs()

        claims_json = json.dumps(subject.claims)

        credential_str, credential_id = marty_rs.create_verifiable_credential(
            issuer_did=issuer_key.did,
            issuer_jwk_json=issuer_key.jwk_json,
            subject_id=subject.id,
            credential_type=credential_type,
            claims_json=claims_json,
            format=credential_format,
            expiration_seconds=expiration_seconds,
            selective_disclosure_claims=selective_disclosure_claims,
            mdoc_namespace=mdoc_namespace,
            mdoc_doctype=mdoc_doctype,
            zk_predicate_claims=zk_predicate_claims,
        )

        now = datetime.utcnow()
        expiration = None
        if expiration_seconds:
            from datetime import timedelta

            expiration = now + timedelta(seconds=expiration_seconds)

        return CredentialData(
            id=credential_id,
            types=["VerifiableCredential", credential_type],
            issuer=issuer_key.did,
            subject=subject,
            issuance_date=now,
            expiration_date=expiration,
            jwt=credential_str,
        )

    def create_offer(
        self,
        issuer_url: str,
        credential_types: list[str],
        pre_authorized: bool = True,
        user_pin_required: bool = False,
        wallet_format: str = "standard",
    ) -> CredentialOffer:
        """Create an OID4VCI credential offer using the v2 engine."""
        marty_rs = _get_marty_rs()

        offer_id = str(uuid4())
        pre_auth_code = secrets.token_urlsafe(32) if pre_authorized else None

        offer_json = marty_rs.create_credential_offer(
            issuer_url=issuer_url,
            credential_types=credential_types,
            pre_authorized_code=pre_auth_code,
            user_pin_required=user_pin_required,
        )

        offer_uri = marty_rs.generate_offer_uri(
            issuer_url=issuer_url,
            offer_id=offer_id,
            format=wallet_format,
        )

        return CredentialOffer(
            credential_issuer=issuer_url,
            credential_types=credential_types,
            offer_id=offer_id,
            pre_authorized_code=pre_auth_code,
            user_pin_required=user_pin_required,
            offer_uri=offer_uri,
            offer_json=offer_json,
        )

    def generate_issuer_metadata(
        self,
        issuer_url: str,
        issuer_name: str,
        supported_credentials: list[dict[str, Any]],
    ) -> str:
        """Generate OID4VCI issuer metadata using the v2 engine.

        Supports multi-format metadata with per-credential-type format lists,
        doctype/vct fields, and claim definitions.
        """
        marty_rs = _get_marty_rs()

        return marty_rs.generate_issuer_metadata(
            issuer_url=issuer_url,
            issuer_name=issuer_name,
            credential_types_json=json.dumps(supported_credentials),
        )


class SpruceIDCredentialWallet:
    """Credential wallet implementation using SpruceID's SSI library."""

    def __init__(self) -> None:
        self._credentials: dict[str, CredentialData] = {}

    def store_credential(self, credential: CredentialData) -> str:
        """Store a credential in the wallet."""
        self._credentials[credential.id] = credential
        return credential.id

    def get_credential(self, credential_id: str) -> CredentialData | None:
        """Retrieve a stored credential."""
        return self._credentials.get(credential_id)

    def list_credentials(self, credential_type: str | None = None) -> list[CredentialData]:
        """List stored credentials."""
        if credential_type is None:
            return list(self._credentials.values())
        return [c for c in self._credentials.values() if credential_type in c.types]

    def create_presentation(
        self,
        holder_key: KeyPair,
        credentials: list[CredentialData],
        audience: str,
        nonce: str | None = None,
    ) -> str:
        """Create a verifiable presentation."""
        marty_rs = _get_marty_rs()

        credential_jwts = [c.jwt for c in credentials if c.jwt]

        return marty_rs.create_presentation(
            holder_did=holder_key.did,
            holder_jwk_json=holder_key.jwk_json,
            credential_jwts=credential_jwts,
            audience=audience,
            nonce=nonce,
        )

    def redeem_offer(self, offer_uri: str, holder_key: KeyPair) -> CredentialData:
        """
        Redeem a credential offer from an issuer.
        """
        from urllib.parse import parse_qs, urlparse

        import httpx

        # Parse offer URI
        parsed = urlparse(offer_uri)
        params = parse_qs(parsed.query)

        if "credential_offer_uri" in params:
            offer_endpoint = params["credential_offer_uri"][0]

            # Fetch offer details
            with httpx.Client() as client:
                try:
                    resp = client.get(offer_endpoint)
                    resp.raise_for_status()
                    offer_data = resp.json()
                except Exception:
                    # Fallback for demo if offer endpoint is not reachable or mock
                    # We assume the issuer_url is the base of offer_endpoint
                    issuer_url = offer_endpoint.split("/offers/")[0]
                    offer_data = {
                        "credential_issuer": issuer_url,
                        "credential_configuration_ids": ["UniversityDegreeCredential"],
                        "grants": {},
                    }

            issuer_url = offer_data["credential_issuer"]
            credential_configuration_ids = offer_data.get("credential_configuration_ids", [])
            if not credential_configuration_ids:
                credential_configuration_ids = ["UniversityDegreeCredential"]

            # Get issuer metadata to find endpoints
            try:
                with httpx.Client() as client:
                    resp = client.get(f"{issuer_url}/api/issuer/metadata")
                    if resp.status_code == 404:
                        # Try standard location
                        resp = client.get(f"{issuer_url}/.well-known/openid-credential-issuer")

                    if resp.status_code == 200:
                        metadata = resp.json()
                        _token_endpoint = metadata.get(
                            "token_endpoint", f"{issuer_url}/api/issuer/token"
                        )
                        credential_endpoint = metadata.get(
                            "credential_endpoint", f"{issuer_url}/api/issuer/credential"
                        )
                    else:
                        # Fallback defaults
                        _token_endpoint = f"{issuer_url}/api/issuer/token"
                        credential_endpoint = f"{issuer_url}/api/issuer/credential"
            except Exception:
                _token_endpoint = f"{issuer_url}/api/issuer/token"
                credential_endpoint = f"{issuer_url}/api/issuer/credential"

            # OAuth2 token required - raise error to indicate proper implementation needed
            # TODO: Token should be obtained from proper OAuth2 flow with issuer
            config = get_config()
            if not config.oauth_client_id or not config.oauth_client_secret:
                raise ValueError(
                    "OAuth2 credentials not configured. Set OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET"
                )
            
            # For now, raise an error indicating this flow requires proper OAuth2 implementation
            raise NotImplementedError(
                "Credential request requires OAuth2 access token from issuer. "
                "This should be obtained via proper OAuth2 authorization code flow or client credentials flow. "
                "Mock token usage has been removed for security."
            )

            # 2. Request Credential
            cred_type = credential_configuration_ids[0]

            # Create proof (using presentation as proof for now)
            proof_jwt = self.create_presentation(
                holder_key=holder_key, credentials=[], audience=issuer_url, nonce=str(uuid4())
            )

            payload = {
                "format": "jwt_vc_json",
                "credential_definition": {"type": ["VerifiableCredential", cred_type]},
                "proof": {"proof_type": "jwt", "jwt": proof_jwt},
            }

            with httpx.Client() as client:
                resp = client.post(
                    credential_endpoint,
                    json=payload,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                resp.raise_for_status()
                credential_resp = resp.json()

            credential_jwt = credential_resp.get("credential")
            if not credential_jwt:
                raise ValueError("No credential received")

            # Verify and store
            # We need to get the verifier to verify the credential
            # But we are in the wallet adapter.
            # We can use the SpruceIDCredentialVerifier directly or via factory
            verifier = SpruceIDCredentialVerifier()
            result = verifier.verify_credential(credential_jwt)

            if not result.valid:
                logger.error(
                    "Credential verification failed",
                    extra={
                        "credential_type": cred_type,
                        "issuer": issuer_url,
                        "error": result.error,
                    },
                )
                raise CredentialVerificationError(
                    f"Credential verification failed: {result.error}",
                    details={"issuer": issuer_url, "credential_type": cred_type},
                )

            credential = CredentialData(
                id=f"urn:uuid:{uuid4()}",
                types=["VerifiableCredential", cred_type],
                issuer=result.issuer or issuer_url,
                subject=CredentialSubject(claims=result.claims),
                issuance_date=datetime.utcnow(),
                jwt=credential_jwt,
            )

            self.store_credential(credential)
            return credential

        else:
            raise ValueError("Unsupported offer URI format")


class SpruceIDCredentialVerifier:
    """Credential verifier implementation using SpruceID's SSI library."""

    def verify_credential(
        self,
        credential_jwt: str,
        expected_issuer: str | None = None,
    ) -> VerificationResult:
        """Verify a credential JWT."""
        marty_rs = _get_marty_rs()

        valid, payload_json, error = marty_rs.verify_jwt(
            jwt=credential_jwt,
            expected_issuer=expected_issuer,
            expected_audience=None,
        )

        if not valid:
            return VerificationResult(
                valid=False,
                error=error,
            )

        payload = json.loads(payload_json)
        issuer = payload.get("iss")

        # Extract claims from VC
        vc = payload.get("vc", {})
        subject = vc.get("credentialSubject", {})

        return VerificationResult(
            valid=True,
            claims=subject,
            issuer=issuer,
        )

    def verify_presentation(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None,
    ) -> VerificationResult:
        """Verify a presentation JWT."""
        marty_rs = _get_marty_rs()

        valid, payload_json, error = marty_rs.verify_jwt(
            jwt=presentation_jwt,
            expected_issuer=None,
            expected_audience=expected_audience,
        )

        if not valid:
            return VerificationResult(
                valid=False,
                error=error,
            )

        payload = json.loads(payload_json)

        # Check nonce if provided
        if expected_nonce and payload.get("nonce") != expected_nonce:
            return VerificationResult(
                valid=False,
                error=f"Nonce mismatch: expected {expected_nonce}",
            )

        # Extract claims from VP
        vp = payload.get("vp", {})
        holder = vp.get("holder")
        credentials = vp.get("verifiableCredential", [])

        return VerificationResult(
            valid=True,
            claims={
                "holder": holder,
                "credential_count": len(credentials),
                "credentials": credentials,
            },
            issuer=payload.get("iss"),
        )

    def create_presentation_request(
        self,
        verifier_id: str,
        requested_credentials: list[str],
    ) -> PresentationRequest:
        """Create a presentation request for OID4VP."""
        return PresentationRequest(
            request_id=str(uuid4()),
            verifier=verifier_id,
            requested_credentials=requested_credentials,
            nonce=secrets.token_urlsafe(16),
            audience=verifier_id,
        )


# Factory function to create all adapters
def create_spruceid_adapters() -> (
    tuple[
        SpruceIDKeyManager,
        SpruceIDCredentialIssuer,
        SpruceIDCredentialWallet,
        SpruceIDCredentialVerifier,
    ]
):
    """
    Create all SpruceID adapters.

    Returns:
        Tuple of (key_manager, issuer, wallet, verifier)
    """
    return (
        SpruceIDKeyManager(),
        SpruceIDCredentialIssuer(),
        SpruceIDCredentialWallet(),
        SpruceIDCredentialVerifier(),
    )


# Singleton instances for easy access
_key_manager: SpruceIDKeyManager | None = None
_issuer: SpruceIDCredentialIssuer | None = None
_wallet: SpruceIDCredentialWallet | None = None
_verifier: SpruceIDCredentialVerifier | None = None


def get_key_manager() -> SpruceIDKeyManager:
    """Get or create the key manager singleton."""
    global _key_manager
    if _key_manager is None:
        _key_manager = SpruceIDKeyManager()
    return _key_manager


def get_issuer() -> SpruceIDCredentialIssuer:
    """Get or create the issuer singleton."""
    global _issuer
    if _issuer is None:
        _issuer = SpruceIDCredentialIssuer()
    return _issuer


def get_wallet() -> SpruceIDCredentialWallet:
    """Get or create the wallet singleton."""
    global _wallet
    if _wallet is None:
        _wallet = SpruceIDCredentialWallet()
    return _wallet


def get_verifier() -> SpruceIDCredentialVerifier:
    """Get or create the verifier singleton."""
    global _verifier
    if _verifier is None:
        _verifier = SpruceIDCredentialVerifier()
    return _verifier
