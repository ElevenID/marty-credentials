"""
mDoc/mDL Adapter Implementation

mDoc credential issuance and presentation using marty-rs Rust library.
Provides ISO 18013-5 compliant mobile document operations.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from marty_credentials.native_backend import NativeOperationError


@dataclass
class MdocCredential:
    """An issued mDoc credential."""
    
    doc_type: str
    cbor_base64: str
    credential_id: str
    issued_at: datetime
    valid_until: datetime
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "doc_type": self.doc_type,
            "cbor_base64": self.cbor_base64,
            "credential_id": self.credential_id,
            "issued_at": self.issued_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }


@dataclass  
class PreparedMdoc:
    """A prepared mDoc awaiting external signature."""
    
    signature_payload_base64: str
    prepared_state_base64: str
    doc_type: str


class RustMdocIssuer:
    """mDoc issuer implementation using marty-rs Rust library.
    
    Provides ISO 18013-5 compliant mDoc/mDL credential issuance with
    support for both local signing and HSM/remote signing workflows.
    """

    MDL_DOC_TYPE = "org.iso.18013.5.1.mDL"
    MDL_NAMESPACE = "org.iso.18013.5.1"

    def create_mdl(
        self,
        claims: dict[str, Any],
        device_key_jwk: dict[str, Any],
        issuer_cert_pem: str,
        issuer_key_pem: str,
        validity_years: int = 5,
    ) -> MdocCredential:
        """Create a mobile driver's license (mDL) credential.
        
        Args:
            claims: Claim values (family_name, given_name, birth_date, etc.)
            device_key_jwk: Holder's device public key in JWK format
            issuer_cert_pem: PEM-encoded issuer certificate chain
            issuer_key_pem: PEM-encoded issuer private key
            validity_years: How long the credential is valid
            
        Returns:
            MdocCredential with CBOR-encoded mDL
        """
        # Format claims into MDL namespace
        namespaces = {
            self.MDL_NAMESPACE: claims
        }
        
        return self.create_mdoc(
            doc_type=self.MDL_DOC_TYPE,
            namespaces=namespaces,
            device_key_jwk=device_key_jwk,
            issuer_cert_pem=issuer_cert_pem,
            issuer_key_pem=issuer_key_pem,
            validity_years=validity_years,
        )

    def create_mdoc(
        self,
        doc_type: str,
        namespaces: dict[str, dict[str, Any]],
        device_key_jwk: dict[str, Any],
        issuer_cert_pem: str,
        issuer_key_pem: str,
        validity_years: int = 5,
    ) -> MdocCredential:
        """Create a generic mDoc credential.
        
        Args:
            doc_type: Document type (e.g., "org.iso.18013.5.1.mDL")
            namespaces: Namespace-to-claims mapping
            device_key_jwk: Holder's device public key in JWK format
            issuer_cert_pem: PEM-encoded issuer certificate chain
            issuer_key_pem: PEM-encoded issuer private key
            validity_years: How long the credential is valid
            
        Returns:
            MdocCredential with CBOR-encoded mDoc
        """
        raise NativeOperationError(
            "The legacy PEM-based mDoc issuer contract is not supported by the canonical "
            "native boundary; use OID4VCI mso_mdoc issuance with a JWK issuer profile"
        )

    def prepare_mdoc_for_hsm(
        self,
        doc_type: str,
        namespaces: dict[str, dict[str, Any]],
        device_key_jwk: dict[str, Any],
        validity_years: int = 5,
    ) -> PreparedMdoc:
        """Prepare an mDoc for HSM/remote signing.
        
        Returns the signature payload that needs to be signed by an HSM
        or remote signing service.
        
        Args:
            doc_type: Document type
            namespaces: Namespace-to-claims mapping
            device_key_jwk: Holder's device public key
            validity_years: Credential validity period
            
        Returns:
            PreparedMdoc with signature payload for HSM
        """
        raise NativeOperationError(
            "The legacy mDoc HSM preparation contract is not exposed by the supported "
            "native boundary; use the canonical OID4VCI prepare/assemble flow"
        )

    def complete_mdoc_with_hsm_signature(
        self,
        prepared: PreparedMdoc,
        signature_base64: str,
        issuer_cert_pem: str,
    ) -> MdocCredential:
        """Complete an mDoc with an HSM-provided signature.
        
        Args:
            prepared: PreparedMdoc from prepare_mdoc_for_hsm()
            signature_base64: Base64-encoded signature from HSM
            issuer_cert_pem: PEM-encoded issuer certificate chain
            
        Returns:
            Completed MdocCredential
        """
        raise NativeOperationError(
            "The legacy mDoc HSM completion contract is not exposed by the supported "
            "native boundary; use the canonical OID4VCI prepare/assemble flow"
        )


class RustMdocPresenter:
    """mDoc presentation handler using marty-rs Rust library.
    
    Creates DeviceResponse presentations with selective disclosure.
    """

    def create_presentation(
        self,
        credential: MdocCredential,
        disclosed_claims: dict[str, list[str]],
        device_key_pem: str,
    ) -> str:
        """Create an mDoc presentation with selective disclosure.
        
        Args:
            credential: The mDoc to present
            disclosed_claims: Namespace-to-claims mapping for disclosure
            device_key_pem: PEM-encoded device private key
            
        Returns:
            Base64-encoded DeviceResponse CBOR
        """
        raise NativeOperationError(
            "The legacy mDoc presentation contract lacks verifier-owned session state; "
            "use the canonical ISO 18013/OID4VP wallet flow"
        )

    @staticmethod
    def age_verification_request() -> dict[str, list[str]]:
        """Standard request for age verification only."""
        return {
            "org.iso.18013.5.1": ["age_over_21", "age_over_18"]
        }

    @staticmethod
    def driving_privilege_request() -> dict[str, list[str]]:
        """Standard request for driving privileges."""
        return {
            "org.iso.18013.5.1": [
                "driving_privileges",
                "expiry_date",
                "document_number",
            ]
        }

    @staticmethod
    def full_identity_request() -> dict[str, list[str]]:
        """Standard request for full identity verification."""
        return {
            "org.iso.18013.5.1": [
                "family_name",
                "given_name",
                "birth_date",
                "portrait",
                "document_number",
                "issue_date",
                "expiry_date",
                "issuing_country",
                "issuing_authority",
            ]
        }


# Singleton instances
_mdoc_issuer: RustMdocIssuer | None = None
_mdoc_presenter: RustMdocPresenter | None = None


def get_mdoc_issuer() -> RustMdocIssuer:
    """Get or create the mDoc issuer singleton."""
    global _mdoc_issuer
    if _mdoc_issuer is None:
        _mdoc_issuer = RustMdocIssuer()
    return _mdoc_issuer


def get_mdoc_presenter() -> RustMdocPresenter:
    """Get or create the mDoc presenter singleton."""
    global _mdoc_presenter
    if _mdoc_presenter is None:
        _mdoc_presenter = RustMdocPresenter()
    return _mdoc_presenter
