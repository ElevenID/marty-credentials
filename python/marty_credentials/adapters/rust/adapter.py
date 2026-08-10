"""
Rust Adapter Implementation

Credential adapters using marty-rs Rust library via PyO3 bindings.
Provides high-performance OID4VCI/OID4VP operations.
"""

import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from marty_credentials.config import get_config
from marty_credentials.native_backend import (
    NativeOperationError,
    require_marty_rs,
)
from marty_credentials.ports import (
    CredentialData,
    CredentialOffer,
    CredentialSubject,
    KeyAlgorithm,
    KeyPair,
    PresentationRequest,
    VerificationResult,
)

logger = logging.getLogger(__name__)


def _get_marty_rs(capabilities: tuple[str, ...] = ()):
    """Lazy import of Rust bindings."""
    return require_marty_rs(capabilities)


class RustKeyManager:
    """Key manager implementation using marty-rs Rust library.
    
    Uses SSI library for high-performance key generation.
    """

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}

    def generate_key(self, algorithm: KeyAlgorithm = KeyAlgorithm.ES256) -> KeyPair:
        """Generate a new key pair using Rust crypto."""
        marty_rs = _get_marty_rs(("generate_p256_did_jwk",))

        if algorithm == KeyAlgorithm.ES256:
            did, jwk_json = marty_rs.generate_p256_did_jwk()
        else:
            raise NativeOperationError(
                f"The supported native key boundary does not expose {algorithm.value} generation"
            )

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


class RustCredentialIssuer:
    """Credential issuer implementation using marty-rs Rust library.

    Uses the v2 marty-oid4vci engine for all OID4VCI operations,
    supporting jwt_vc_json, vc+sd-jwt, mso_mdoc, and zk_mdoc formats.
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
        """Create and sign a verifiable credential using the v2 Rust engine.

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
        marty_rs = _get_marty_rs(("create_verifiable_credential",))

        claims_json = json.dumps(subject.claims)

        credential_str, credential_id = marty_rs.create_verifiable_credential(
            issuer_did=issuer_key.did,
            issuer_jwk_json=issuer_key.jwk_json,
            subject_id=subject.id,
            credential_type=credential_type,
            claims_json=claims_json,
            format=credential_format,
            expiration_seconds=expiration_seconds,
            selective_disclosure_claims=selective_disclosure_claims or [],
            mdoc_namespace=mdoc_namespace,
            mdoc_doctype=mdoc_doctype,
            zk_predicate_claims=zk_predicate_claims or [],
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
        marty_rs = _get_marty_rs(
            ("create_credential_offer", "generate_offer_uri")
        )

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
        marty_rs = _get_marty_rs(("generate_issuer_metadata",))

        return marty_rs.generate_issuer_metadata(
            issuer_url=issuer_url,
            issuer_name=issuer_name,
            credential_types_json=json.dumps(supported_credentials),
        )


class RustCredentialWallet:
    """Credential wallet implementation using marty-rs Rust library."""

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
        """Create a verifiable presentation using Rust."""
        raise NativeOperationError(
            "Legacy VP-JWT construction is not exposed by the supported native boundary; "
            "use the OID4VP wallet flow"
        )

    def redeem_offer(self, offer_uri: str, holder_key: KeyPair) -> CredentialData:
        """Redeem a credential offer from an issuer.
        
        Note: This method requires network access and is implemented in Python
        since the HTTP client logic is wallet-specific.
        """
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(offer_uri)
        params = parse_qs(parsed.query)

        if "credential_offer_uri" not in params:
            raise ValueError("Unsupported offer URI format")

        config = get_config()
        if not config.oauth_client_id or not config.oauth_client_secret:
            raise ValueError(
                "OAuth2 credentials not configured. Set OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET"
            )
        
        raise NativeOperationError(
            "Credential offer redemption requires the canonical OID4VCI wallet flow; "
            "the legacy implicit-token adapter is disabled"
        )


class RustCredentialVerifier:
    """Credential verifier implementation using marty-rs Rust library."""

    def verify_credential(
        self,
        credential_jwt: str,
        expected_issuer: str | None = None,
    ) -> VerificationResult:
        """Verify a credential JWT using Rust."""
        raise NativeOperationError(
            "Credential verification requires explicit issuer public key or trust-profile "
            "input; use VerificationService.verify_w3c_vc"
        )

    def verify_presentation(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None,
    ) -> VerificationResult:
        """Verify a presentation JWT using Rust."""
        raise NativeOperationError(
            "Presentation verification requires verifier-owned OID4VP request state; "
            "use the canonical OID4VP verifier flow"
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


# Singleton instances
_key_manager: RustKeyManager | None = None
_issuer: RustCredentialIssuer | None = None
_wallet: RustCredentialWallet | None = None
_verifier: RustCredentialVerifier | None = None


def get_key_manager() -> RustKeyManager:
    """Get or create the key manager singleton."""
    global _key_manager
    if _key_manager is None:
        _key_manager = RustKeyManager()
    return _key_manager


def get_issuer() -> RustCredentialIssuer:
    """Get or create the issuer singleton."""
    global _issuer
    if _issuer is None:
        _issuer = RustCredentialIssuer()
    return _issuer


def get_wallet() -> RustCredentialWallet:
    """Get or create the wallet singleton."""
    global _wallet
    if _wallet is None:
        _wallet = RustCredentialWallet()
    return _wallet


def get_verifier() -> RustCredentialVerifier:
    """Get or create the verifier singleton."""
    global _verifier
    if _verifier is None:
        _verifier = RustCredentialVerifier()
    return _verifier
