"""Pydantic request/response models for the verification API.

Extracted from routes.py so they can be imported without triggering
the mmf database infrastructure side-effects.
"""

from typing import Any

from pydantic import BaseModel


# ============================================================================
# Request/Response Models
# ============================================================================

class PresentationDefinition(BaseModel):
    """OID4VP Presentation Definition."""
    id: str
    input_descriptors: list[dict[str, Any]]
    format: dict[str, Any] | None = None


class CreateSessionRequest(BaseModel):
    """Request to create a verification session."""
    organization_id: str
    verifier_did: str
    presentation_definition: PresentationDefinition
    required_credential_types: list[str] = []
    trusted_issuers: list[str] = []
    session_duration_seconds: int = 600


class SessionResponse(BaseModel):
    """Verification session response."""
    id: str
    organization_id: str
    verifier_did: str
    status: str
    request_uri: str
    nonce: str
    expires_at: str
    created_at: str


class SubmitPresentationRequest(BaseModel):
    """Request to submit a presentation."""
    presentation: dict[str, Any] | str  # Can be JWT or JSON


class ClaimResult(BaseModel):
    """MIP §26 — Per-claim verification result."""
    claim_name: str
    required: bool = True
    present: bool = False
    satisfies_predicate: bool = False
    result: str = "SKIPPED"  # PASS | FAIL | SKIPPED


class VerificationResult(BaseModel):
    """MIP §26 — Verification result response (protocol-compliant shape)."""
    # Legacy field retained for backward compatibility
    valid: bool
    # Protocol-conformant fields (MIP §26 VerificationResult)
    overall_result: str = "FAIL"  # PASS | FAIL
    claim_results: list[ClaimResult] = []
    trust_chain_valid: bool = False
    revocation_checked: bool = False
    revocation_status: str | None = None  # VALID | REVOKED | UNKNOWN | SKIPPED
    evaluated_at: str | None = None
    verifier_nonce: str | None = None
    flow_instance_id: str | None = None
    policy_id: str | None = None
    # Extended fields
    verified_claims: dict[str, Any] | None = None
    verification_method: str | None = None
    error: str | None = None
    verified_at: str | None = None


class VerifyDirectRequest(BaseModel):
    """Request for direct (stateless) verification."""
    organization_id: str
    presentation: dict[str, Any] | str
    presentation_definition: PresentationDefinition
    verifier_did: str
    trusted_issuers: list[str] = []


class VerifyVdsNcRequest(BaseModel):
    """Request to verify a VDS-NC barcode."""
    barcode: str
    issuer_jwk_json: str | None = None
    issuer_did: str | None = None
    organization_id: str | None = None
    verification_method_id: str | None = None
    trusted_issuers: list[str] = []
    credential_format: str = "vds_nc"
    key_purpose: str = "vdsnc_signing"
    algorithm: str | None = None
    allow_public_did_fallback: bool = False


class VdsNcVerificationResult(BaseModel):
    """Result of VDS-NC barcode verification."""
    valid: bool
    country: str | None = None
    payload: dict[str, Any] | None = None
    signature_status: str = "Unknown"
    errors: list[str] = []
    method: str = "vds_nc"
