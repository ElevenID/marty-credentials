"""
mDoc/mDL Adapter Implementation

mDoc presentation request helpers for the legacy Python adapter.
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
        return {"org.iso.18013.5.1": ["age_over_21", "age_over_18"]}

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
_mdoc_presenter: RustMdocPresenter | None = None


def get_mdoc_presenter() -> RustMdocPresenter:
    """Get or create the mDoc presenter singleton."""
    global _mdoc_presenter
    if _mdoc_presenter is None:
        _mdoc_presenter = RustMdocPresenter()
    return _mdoc_presenter
