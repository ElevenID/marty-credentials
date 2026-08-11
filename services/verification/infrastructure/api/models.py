"""Pydantic request/response models for the verification API.

Extracted from routes.py so they can be imported without triggering
the mmf database infrastructure side-effects.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ============================================================================
# Request/Response Models
# ============================================================================


class PresentationDefinition(BaseModel):
    """OID4VP Presentation Definition."""

    model_config = ConfigDict(extra="forbid")

    id: str
    input_descriptors: list[dict[str, Any]]
    format: dict[str, Any] | None = None


class CreateSessionRequest(BaseModel):
    """Request to create a verification session."""

    model_config = ConfigDict(extra="forbid")

    verifier_did: str
    presentation_definition: PresentationDefinition
    session_duration_seconds: int = Field(default=600, ge=30, le=3600)


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

    model_config = ConfigDict(extra="forbid")

    presentation: str


class ClaimResult(BaseModel):
    """MIP §26 — Per-claim verification result."""

    claim_name: str
    required: bool = True
    present: bool = False
    satisfies_predicate: bool = False
    result: str = "SKIPPED"  # PASS | FAIL | SKIPPED


class VerificationResult(BaseModel):
    """MIP §26 — Verification result response (protocol-compliant shape)."""

    canonical_result: dict[str, Any] | None = None
    processing_status: str = "UNAVAILABLE"
    decision: str = "INDETERMINATE"
    decision_code: str = "PROCESSING_NOT_COMPLETED"
    # Legacy projections are derived only from canonical_result.
    valid: bool
    # Protocol-conformant fields (MIP §26 VerificationResult)
    overall_result: str = "INDETERMINATE"
    claim_results: list[ClaimResult] = Field(default_factory=list)
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

    @model_validator(mode="after")
    def derive_compatibility_projection(self) -> "VerificationResult":
        """Prevent compatibility fields from claiming more than Core decided."""
        if self.canonical_result is None:
            self.processing_status = "UNAVAILABLE"
            self.decision = "INDETERMINATE"
            self.decision_code = "PROCESSING_NOT_COMPLETED"
            self.valid = False
            self.overall_result = "INDETERMINATE"
            return self
        self.processing_status = str(self.canonical_result.get("processing_status", "UNAVAILABLE"))
        self.decision = str(self.canonical_result.get("decision", "INDETERMINATE"))
        self.decision_code = str(
            self.canonical_result.get("decision_code", "PROCESSING_NOT_COMPLETED")
        )
        self.valid = self.canonical_result.get("valid") is True and self.decision == "PASS"
        self.overall_result = self.decision
        return self


class VerifyDirectRequest(BaseModel):
    """Request for direct (stateless) verification."""

    model_config = ConfigDict(extra="forbid")

    presentation: dict[str, Any] | str
    presentation_definition: PresentationDefinition
    verifier_did: str


class VerifyVdsNcRequest(BaseModel):
    """Request to verify a VDS-NC barcode."""

    model_config = ConfigDict(extra="forbid")

    barcode: str
    issuer_did: str
    verification_method_id: str | None = None
    algorithm: str | None = None
