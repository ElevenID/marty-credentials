"""
SpruceID Adapter Implementation

This module provides adapters implementing the credential ports using SpruceID's SSI library
via Rust FFI bindings (marty-rs).
"""

import json
import secrets
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from marty_credentials.ports import (
    CredentialData,
    CredentialOffer,
    CredentialSubject,
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
            "SpruceID bindings not available. "
            "Install with: pip install marty-credentials[ffi]"
        )


class SpruceIDKeyManager:
    """Key manager implementation using SpruceID's SSI library."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}

    def generate_key(self, algorithm: KeyAlgorithm = KeyAlgorithm.ES256) -> KeyPair:
        """Generate a new key pair using SpruceID."""
        marty_rs = _get_marty_rs()

        if algorithm == KeyAlgorithm.ES256:
            did, jwk_json = marty_rs.generate_p256_key()
        elif algorithm == KeyAlgorithm.EDDSA:
            did, jwk_json = marty_rs.generate_did_key()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Use ES256 or EdDSA.")

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

    def delete_key(self, key_id: str) -> bool:
        """Delete a stored key pair."""
        if key_id in self._keys:
            del self._keys[key_id]
            return True
        return False


class SpruceIDCredentialIssuer:
    """Credential issuer implementation using SpruceID's SSI library."""

    def create_credential(
        self,
        issuer_key: KeyPair,
        credential_type: str,
        subject: CredentialSubject,
        expiration_seconds: int | None = None,
    ) -> CredentialData:
        """Create and sign a verifiable credential."""
        marty_rs = _get_marty_rs()

        # Convert claims to JSON
        claims_json = json.dumps(subject.claims)

        # Call Rust function
        jwt, credential_id = marty_rs.create_verifiable_credential(
            issuer_did=issuer_key.did,
            issuer_jwk_json=issuer_key.jwk_json,
            subject_id=subject.id,
            credential_type=credential_type,
            claims_json=claims_json,
            expiration_seconds=expiration_seconds,
        )

        now = datetime.utcnow()
        expiration = None
        if expiration_seconds:
            expiration = now + timedelta(seconds=expiration_seconds)

        return CredentialData(
            id=credential_id,
            types=["VerifiableCredential", credential_type],
            issuer=issuer_key.did,
            subject=subject,
            issuance_date=now,
            expiration_date=expiration,
            jwt=jwt,
        )

    def create_offer(
        self,
        issuer_url: str,
        credential_types: list[str],
        pre_authorized: bool = True,
        user_pin_required: bool = False,
        wallet_format: str = "standard",
    ) -> CredentialOffer:
        """Create an OID4VCI credential offer."""
        marty_rs = _get_marty_rs()

        offer_id = str(uuid4())
        pre_auth_code = secrets.token_urlsafe(32) if pre_authorized else None

        # Generate offer JSON
        offer_json = marty_rs.create_credential_offer(
            issuer_url=issuer_url,
            credential_types=credential_types,
            pre_authorized_code=pre_auth_code,
            user_pin_required=user_pin_required,
        )

        # Generate offer URI
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
        """Generate OID4VCI issuer metadata for discovery."""
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

    def delete_credential(self, credential_id: str) -> bool:
        """Delete a stored credential."""
        if credential_id in self._credentials:
            del self._credentials[credential_id]
            return True
        return False

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
        """Redeem a credential offer from an issuer."""
        from urllib.parse import parse_qs, urlparse

        import httpx

        # Parse offer URI
        parsed = urlparse(offer_uri)
        params = parse_qs(parsed.query)

        if "credential_offer_uri" not in params:
            raise ValueError("Unsupported offer URI format")

        offer_endpoint = params["credential_offer_uri"][0]

        # Fetch offer details
        with httpx.Client() as client:
            try:
                resp = client.get(offer_endpoint)
                resp.raise_for_status()
                offer_data = resp.json()
            except Exception:
                # Fallback for demo if offer endpoint is not reachable
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
                    resp = client.get(f"{issuer_url}/.well-known/openid-credential-issuer")

                if resp.status_code == 200:
                    metadata = resp.json()
                    credential_endpoint = metadata.get(
                        "credential_endpoint", f"{issuer_url}/api/issuer/credential"
                    )
                else:
                    credential_endpoint = f"{issuer_url}/api/issuer/credential"
        except Exception:
            credential_endpoint = f"{issuer_url}/api/issuer/credential"

        # Get Token (Mock)
        access_token = "mock_access_token"

        # Request Credential
        cred_type = credential_configuration_ids[0]

        # Create proof
        proof_jwt = self.create_presentation(
            holder_key=holder_key,
            credentials=[],
            audience=issuer_url,
            nonce=str(uuid4()),
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
        verifier = SpruceIDCredentialVerifier()
        result = verifier.verify_credential(credential_jwt)

        if not result.valid:
            print(f"Warning: Credential verification failed: {result.error}")

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
def create_spruceid_adapters() -> tuple[
    SpruceIDKeyManager,
    SpruceIDCredentialIssuer,
    SpruceIDCredentialWallet,
    SpruceIDCredentialVerifier,
]:
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
