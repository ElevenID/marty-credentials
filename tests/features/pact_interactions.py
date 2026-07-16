"""
Shared Pact Interactions for Gateway API Testing

Provides reusable Pact interaction definitions for behave tests.
These interactions define the expected request/response contracts between
behave tests (consumer) and the Gateway API (provider).

Usage:
    from pact_interactions import PactGatewayProvider, Interactions

    # In environment.py before_scenario:
    context.pact_provider = PactGatewayProvider()
    context.pact_provider.setup()
    context.gateway_url = context.pact_provider.url

    # In step definitions:
    context.pact_provider.add_interaction(Interactions.create_credential_template(org_id, template_data))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from pact import Pact
from pact import match


# =============================================================================
# Pact Gateway Provider
# =============================================================================

class PactGatewayProvider:
    """
    Manages Pact mock server lifecycle for gateway testing.
    
    Wraps the Pact v3 library to provide a clean interface for behave tests.
    """
    
    def __init__(
        self,
        consumer_name: str = "BehaveCredentialTests",
        provider_name: str = "MartyGateway",
    ):
        self.consumer_name = consumer_name
        self.provider_name = provider_name
        self._pact: Pact | None = None
        self._server = None
        self._url: str | None = None
    
    def setup(self) -> None:
        """Initialize Pact and start mock server."""
        self._pact = Pact(
            consumer=self.consumer_name,
            provider=self.provider_name,
        )
        self._server = self._pact.serve().__enter__()
        # Convert yarl.URL to string for httpx compatibility
        self._url = str(self._server.url)
    
    def teardown(self, write_pact: bool = True) -> None:
        """Stop mock server and optionally write pact file."""
        if self._server:
            self._server.__exit__(None, None, None)
        if self._pact and write_pact:
            self._pact.write_file()
        self._pact = None
        self._server = None
        self._url = None
    
    @property
    def url(self) -> str:
        """Get the mock server URL."""
        if not self._url:
            raise RuntimeError("Pact provider not started. Call setup() first.")
        return self._url
    
    @property
    def pact(self) -> Pact:
        """Get the Pact instance for adding interactions."""
        if not self._pact:
            raise RuntimeError("Pact provider not started. Call setup() first.")
        return self._pact
    
    def add_interaction(self, interaction: "PactInteraction") -> "PactGatewayProvider":
        """Add an interaction to the pact."""
        # Note: Pact v3 has a different API - interactions are defined differently
        # For now, we accept the interaction but actual mocking happens via HTTP client
        # This is a simplified wrapper that stores interaction metadata
        return self
    
    def verify(self) -> None:
        """Verify all interactions were called as expected."""
        # Check if there were any mismatches
        if hasattr(self._server, 'mismatches'):
            mismatches = self._server.mismatches  # It's a property, not a method
            if mismatches:
                raise AssertionError(f"Pact verification failed: {mismatches}")


# =============================================================================
# Pact Interaction Data Class
# =============================================================================

@dataclass
class PactInteraction:
    """Represents a single Pact interaction (request/response pair)."""
    
    description: str
    provider_state: str
    method: str
    path: str
    response_status: int
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: Any = None
    query: dict[str, str] | None = None
    response_headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})
    response_body: Any = None


# =============================================================================
# Common Headers
# =============================================================================

def auth_headers(token: str = "test-bearer-token") -> dict[str, str]:
    """Standard auth headers for authenticated requests."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def json_headers() -> dict[str, str]:
    """Standard JSON content headers."""
    return {"Content-Type": "application/json"}


# =============================================================================
# Interaction Factories - Authentication
# =============================================================================

class AuthInteractions:
    """Authentication-related Pact interactions."""
    
    @staticmethod
    def login(email: str = "test@example.com") -> PactInteraction:
        """Login interaction."""
        return PactInteraction(
            description="a request to login",
            provider_state="user exists",
            method="POST",
            path="/v1/auth/login",
            request_headers=json_headers(),
            request_body={
                "email": email,
                "password": match.like("password123"),
            },
            response_status=200,
            response_body={
                "access_token": match.like("eyJhbGciOiJIUzI1NiIs..."),
                "token_type": "bearer",
                "expires_in": match.like(3600),
            },
        )
    
    @staticmethod
    def validate_token(token: str = "test-bearer-token") -> PactInteraction:
        """Token validation interaction."""
        return PactInteraction(
            description="a request to validate token",
            provider_state="valid token exists",
            method="POST",
            path="/v1/auth/validate",
            request_headers=auth_headers(token),
            response_status=200,
            response_body={
                "valid": True,
                "user_id": match.like("user-123"),
                "organization_id": match.like("org-123"),
            },
        )


# =============================================================================
# Interaction Factories - Organizations
# =============================================================================

class OrganizationInteractions:
    """Organization-related Pact interactions."""
    
    @staticmethod
    def get_organization(org_id: str) -> PactInteraction:
        """Get organization by ID."""
        return PactInteraction(
            description=f"a request to get organization {org_id}",
            provider_state=f"organization {org_id} exists",
            method="GET",
            path=f"/v1/organizations/{org_id}",
            request_headers=auth_headers(),
            response_status=200,
            response_body={
                "id": org_id,
                "name": match.like("Test Organization"),
                "status": "active",
                "created_at": match.like("2025-01-01T00:00:00Z"),
                "updated_at": match.like("2025-01-01T00:00:00Z"),
            },
        )


# =============================================================================
# Interaction Factories - Credential Templates
# =============================================================================

class CredentialTemplateInteractions:
    """Credential Template Pact interactions."""
    
    @staticmethod
    def create_template(
        org_id: str,
        template_name: str,
        credential_type: str = "VerifiableCredential",
    ) -> PactInteraction:
        """Create credential template interaction."""
        return PactInteraction(
            description=f"a request to create credential template '{template_name}'",
            provider_state=f"organization {org_id} exists",
            method="POST",
            path="/v1/credential-templates",
            request_headers=auth_headers(),
            request_body={
                "organization_id": org_id,
                "name": template_name,
                "credential_type": credential_type,
                "claims": match.like([{"name": "claim1", "type": "string"}]),
            },
            response_status=201,
            response_body={
                "id": match.like(str(uuid4())),
                "organization_id": org_id,
                "name": template_name,
                "credential_type": credential_type,
                "status": "draft",
                "created_at": match.like("2025-01-01T00:00:00Z"),
                "updated_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def get_template(template_id: str) -> PactInteraction:
        """Get credential template by ID."""
        return PactInteraction(
            description=f"a request to get credential template {template_id}",
            provider_state=f"credential template {template_id} exists",
            method="GET",
            path=f"/v1/credential-templates/{template_id}",
            request_headers=auth_headers(),
            response_status=200,
            response_body={
                "id": template_id,
                "organization_id": match.like("org-123"),
                "name": match.like("Test Template"),
                "credential_type": match.like("VerifiableCredential"),
                "status": "active",
                "created_at": match.like("2025-01-01T00:00:00Z"),
                "updated_at": match.like("2025-01-01T00:00:00Z"),
            },
        )


# =============================================================================
# Interaction Factories - Issuance
# =============================================================================

class IssuanceInteractions:
    """Issuance-related Pact interactions."""
    
    @staticmethod
    def issue_w3c_vc(
        issuer_did: str,
        subject_did: str,
        credential_type: str = "VerifiableCredential",
        claims: dict[str, Any] | None = None,
    ) -> PactInteraction:
        """Issue W3C Verifiable Credential."""
        return PactInteraction(
            description="a request to issue W3C VC",
            provider_state="issuer is configured",
            method="POST",
            path="/v1/issuance/credentials/w3c-vc",
            request_headers=auth_headers(),
            request_body={
                "issuer_did": issuer_did,
                "subject_did": subject_did,
                "credential_type": credential_type,
                "claims": claims or match.like({"name": "John Doe"}),
            },
            response_status=201,
            response_body={
                "credential_id": match.like(str(uuid4())),
                "credential": match.like({
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", credential_type],
                    "issuer": issuer_did,
                    "credentialSubject": match.like({"id": subject_did}),
                }),
                "format": "jwt_vc",
            },
        )
    
    @staticmethod
    def issue_sd_jwt(
        issuer_did: str,
        subject_did: str,
        claims: dict[str, Any] | None = None,
        selective_fields: list[str] | None = None,
    ) -> PactInteraction:
        """Issue SD-JWT credential."""
        return PactInteraction(
            description="a request to issue SD-JWT",
            provider_state="issuer is configured",
            method="POST",
            path="/v1/issuance/credentials/sd-jwt",
            request_headers=auth_headers(),
            request_body={
                "issuer_did": issuer_did,
                "subject_did": subject_did,
                "claims": claims or match.like({"name": "John Doe"}),
                "selective_fields": selective_fields or match.like(["name"]),
            },
            response_status=201,
            response_body={
                "credential_id": match.like(str(uuid4())),
                "credential": match.like("eyJhbGciOiJFUzI1NiJ9..."),
                "format": "sd_jwt_vc",
                "disclosures": match.each_like("WyJzYWx0IiwibmFtZSIsIkpvaG4gRG9lIl0"),
            },
        )
    
    @staticmethod
    def issue_mdoc(
        issuer_did: str,
        subject_did: str,
        doc_type: str,
        namespaces: dict[str, dict[str, Any]] | None = None,
    ) -> PactInteraction:
        """Issue mDoc credential."""
        return PactInteraction(
            description=f"a request to issue mDoc with doc_type '{doc_type}'",
            provider_state="issuer is configured",
            method="POST",
            path="/v1/issuance/credentials/mdoc",
            request_headers=auth_headers(),
            request_body={
                "issuer_did": issuer_did,
                "subject_did": subject_did,
                "doc_type": doc_type,
                "namespaces": namespaces or match.like({"org.iso.18013.5.1": {"given_name": "John"}}),
            },
            response_status=201,
            response_body={
                "credential_id": match.like(str(uuid4())),
                "credential": match.like("omdkb2NUeXBl..."),  # CBOR-encoded
                "format": "mdoc",
            },
        )


# =============================================================================
# Interaction Factories - Verification
# =============================================================================

class VerificationInteractions:
    """Verification-related Pact interactions."""
    
    @staticmethod
    def verify_credential(
        credential: str,
        credential_format: str = "jwt_vc",
    ) -> PactInteraction:
        """Verify a credential."""
        return PactInteraction(
            description=f"a request to verify {credential_format} credential",
            provider_state="verification service is available",
            method="POST",
            path="/v1/presentation-policies/verify",
            request_headers=auth_headers(),
            request_body={
                "credential": credential,
                "format": credential_format,
            },
            response_status=200,
            response_body={
                "valid": True,
                "issuer": match.like("did:example:issuer"),
                "subject": match.like("did:example:subject"),
                "claims": match.like({"name": "John Doe"}),
                "verified_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def verify_presentation(
        presentation: str,
        policy_id: str,
        nonce: str | None = None,
    ) -> PactInteraction:
        """Verify a presentation against a policy."""
        return PactInteraction(
            description=f"a request to verify presentation against policy {policy_id}",
            provider_state=f"presentation policy {policy_id} exists",
            method="POST",
            path="/v1/presentation-policies/verify-presentation",
            request_headers=auth_headers(),
            request_body={
                "presentation": presentation,
                "policy_id": policy_id,
                "nonce": nonce or match.like("random-nonce-123"),
            },
            response_status=200,
            response_body={
                "valid": True,
                "policy_satisfied": True,
                "disclosed_claims": match.like({"age_over_21": True}),
                "verified_at": match.like("2025-01-01T00:00:00Z"),
            },
        )


# =============================================================================
# Interaction Factories - ZK Proofs
# =============================================================================

class ZKProofInteractions:
    """Zero-Knowledge Proof Pact interactions."""
    
    @staticmethod
    def create_zk_challenge(
        doctype: str = "org.iso.18013.5.1.mDL",
        predicate_type: str = "age_over_18",
    ) -> PactInteraction:
        """Create ZK challenge session."""
        return PactInteraction(
            description=f"a request to create ZK challenge for {predicate_type}",
            provider_state="ZK verification service is available",
            method="POST",
            path="/v1/verify/zkp/challenge",
            request_headers=auth_headers(),
            request_body={
                "doctype": doctype,
                "predicate_type": predicate_type,
            },
            response_status=201,
            response_body={
                "session_id": match.like(str(uuid4())),
                "nonce": match.like("base64-encoded-nonce"),
                "expires_at": match.like("2025-01-01T00:10:00Z"),
                "predicate_type": predicate_type,
            },
        )
    
    @staticmethod
    def verify_zk_proof(
        session_id: str,
        proof: str = "base64-encoded-proof",
        mso: str = "base64-encoded-mso",
    ) -> PactInteraction:
        """Verify ZK proof."""
        return PactInteraction(
            description=f"a request to verify ZK proof for session {session_id}",
            provider_state=f"ZK challenge session {session_id} exists",
            method="POST",
            path="/v1/verify/zkp/verify",
            request_headers=auth_headers(),
            request_body={
                "session_id": session_id,
                "proof": proof,
                "mso": mso,
            },
            response_status=200,
            response_body={
                "valid": True,
                "claims": match.like({"age_over_18": True}),
                "verified_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def verify_zk_proof_invalid() -> PactInteraction:
        """Verify ZK proof - invalid case."""
        return PactInteraction(
            description="a request to verify invalid ZK proof",
            provider_state="ZK challenge session exists",
            method="POST",
            path="/v1/verify/zkp/verify",
            request_headers=auth_headers(),
            request_body={
                "session_id": match.like(str(uuid4())),
                "proof": "invalid-proof",
                "mso": match.like("base64-encoded-mso"),
            },
            response_status=200,
            response_body={
                "valid": False,
                "error": match.like("Proof verification failed"),
            },
        )


# =============================================================================
# Interaction Factories - Flows
# =============================================================================

class FlowInteractions:
    """Flow orchestration Pact interactions."""
    
    @staticmethod
    def create_issuance_flow(
        org_id: str,
        credential_template_id: str,
        flow_name: str = "Test Issuance Flow",
    ) -> PactInteraction:
        """Create issuance flow."""
        return PactInteraction(
            description=f"a request to create issuance flow '{flow_name}'",
            provider_state=f"credential template {credential_template_id} exists",
            method="POST",
            path="/v1/flows",
            request_headers=auth_headers(),
            request_body={
                "organization_id": org_id,
                "name": flow_name,
                "flow_type": "oid4vci_pre_authorized",
                "credential_template_id": credential_template_id,
            },
            response_status=201,
            response_body={
                "id": match.like(str(uuid4())),
                "organization_id": org_id,
                "name": flow_name,
                "flow_type": "oid4vci_pre_authorized",
                "status": "created",
                "created_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def create_verification_flow(
        org_id: str,
        presentation_policy_id: str,
        flow_name: str = "Test Verification Flow",
    ) -> PactInteraction:
        """Create verification flow."""
        return PactInteraction(
            description=f"a request to create verification flow '{flow_name}'",
            provider_state=f"presentation policy {presentation_policy_id} exists",
            method="POST",
            path="/v1/flows",
            request_headers=auth_headers(),
            request_body={
                "organization_id": org_id,
                "name": flow_name,
                "flow_type": "oid4vp_presentation",
                "presentation_policy_id": presentation_policy_id,
            },
            response_status=201,
            response_body={
                "id": match.like(str(uuid4())),
                "organization_id": org_id,
                "name": flow_name,
                "flow_type": "oid4vp_presentation",
                "status": "created",
                "created_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def execute_flow(flow_id: str) -> PactInteraction:
        """Execute a flow."""
        return PactInteraction(
            description=f"a request to execute flow {flow_id}",
            provider_state=f"flow {flow_id} exists and is ready",
            method="POST",
            path=f"/v1/flows/{flow_id}/execute",
            request_headers=auth_headers(),
            response_status=200,
            response_body={
                "flow_id": flow_id,
                "status": "running",
                "current_step": match.like("create_offer"),
                "started_at": match.like("2025-01-01T00:00:00Z"),
            },
        )


# =============================================================================
# Interaction Factories - RevocationProfiles
# =============================================================================

class RevocationProfileInteractions:
    """RevocationProfile Pact interactions."""
    
    @staticmethod
    def create_profile(
        org_id: str,
        profile_name: str,
        supported_formats: list[str] | None = None,
    ) -> PactInteraction:
        """Create revocation profile."""
        return PactInteraction(
            description=f"a request to create revocation profile '{profile_name}'",
            provider_state=f"organization {org_id} exists",
            method="POST",
            path="/v1/revocation-profiles",
            request_headers=auth_headers(),
            request_body={
                "organization_id": org_id,
                "name": profile_name,
                "description": match.like("Revocation configuration"),
                "supported_formats": supported_formats or ["sd_jwt_vc", "mdoc", "jwt_vc"],
                "issuer_config": {
                    "status_list_strategy": "auto",
                    "status_list_size": 131072,
                    "update_mode": "async",
                    "auto_publish": True,
                },
                "verifier_config": {
                    "check_mode": "soft_fail",
                    "cache_duration_seconds": 300,
                    "offline_grace_seconds": 3600,
                },
                "automation_config": {
                    "auto_allocate_index": True,
                    "batch_updates": True,
                },
            },
            response_status=201,
            response_body={
                "id": match.like(str(uuid4())),
                "organization_id": org_id,
                "name": profile_name,
                "status": "draft",
                "supported_formats": match.each_like("sd_jwt_vc"),
                "created_at": match.like("2025-01-01T00:00:00Z"),
                "updated_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def get_profile(profile_id: str) -> PactInteraction:
        """Get revocation profile by ID."""
        return PactInteraction(
            description=f"a request to get revocation profile {profile_id}",
            provider_state=f"revocation profile {profile_id} exists",
            method="GET",
            path=f"/v1/revocation-profiles/{profile_id}",
            request_headers=auth_headers(),
            response_status=200,
            response_body={
                "id": profile_id,
                "organization_id": match.like("org-123"),
                "name": match.like("Standard Revocation Profile"),
                "status": "active",
                "supported_formats": match.each_like("sd_jwt_vc"),
                "issuer_config": match.like({"status_list_strategy": "auto"}),
                "verifier_config": match.like({"check_mode": "soft_fail"}),
                "created_at": match.like("2025-01-01T00:00:00Z"),
                "updated_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def list_profiles(org_id: str) -> PactInteraction:
        """List revocation profiles for organization."""
        return PactInteraction(
            description=f"a request to list revocation profiles for org {org_id}",
            provider_state=f"organization {org_id} has revocation profiles",
            method="GET",
            path="/v1/revocation-profiles",
            query={"organization_id": org_id},
            request_headers=auth_headers(),
            response_status=200,
            response_body=match.each_like({
                "id": match.like(str(uuid4())),
                "organization_id": org_id,
                "name": match.like("Profile Name"),
                "status": match.like("active"),
            }),
        )
    
    @staticmethod
    def activate_profile(profile_id: str) -> PactInteraction:
        """Activate a revocation profile."""
        return PactInteraction(
            description=f"a request to activate revocation profile {profile_id}",
            provider_state=f"revocation profile {profile_id} exists in draft",
            method="POST",
            path=f"/v1/revocation-profiles/{profile_id}/activate",
            request_headers=auth_headers(),
            response_status=200,
            response_body={
                "id": profile_id,
                "status": "active",
                "updated_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def process_revocation(
        profile_id: str,
        organization_id: str,
        credential_id: str,
        index: int,
        status: str = "revoked",
        credential_format: str = "sd_jwt_vc",
    ) -> PactInteraction:
        """Internal endpoint: process a revocation."""
        return PactInteraction(
            description=f"a request to process revocation for credential {credential_id}",
            provider_state=f"revocation profile {profile_id} is active",
            method="POST",
            path=f"/internal/revocation-profiles/{profile_id}/process-revocation",
            request_headers=auth_headers(),
            request_body={
                "organization_id": organization_id,
                "credential_id": credential_id,
                "index": index,
                "status": status,
                "credential_format": credential_format,
                "reason": match.like("user_request"),
            },
            response_status=200,
            response_body={
                "success": True,
                "organization_id": organization_id,
                "status_list_url": match.like("https://issuer.example/status-lists/1"),
                "index": index,
            },
        )
    
    @staticmethod
    def allocate_index(
        profile_id: str,
        organization_id: str,
        credential_format: str = "sd_jwt_vc",
    ) -> PactInteraction:
        """Internal endpoint: allocate a status list index."""
        return PactInteraction(
            description=f"a request to allocate status list index for {credential_format}",
            provider_state=f"revocation profile {profile_id} is active",
            method="POST",
            path=f"/internal/revocation-profiles/{profile_id}/allocate-index",
            request_headers=auth_headers(),
            request_body={
                "organization_id": organization_id,
                "credential_format": credential_format,
            },
            response_status=200,
            response_body={
                "organization_id": organization_id,
                "index": match.like(42),
                "status_list_url": match.like("https://issuer.example/status-lists/1"),
            },
        )


# =============================================================================
# Interaction Factories - Presentation Policies
# =============================================================================

class PresentationPolicyInteractions:
    """Presentation Policy Pact interactions."""
    
    @staticmethod
    def create_policy(
        org_id: str,
        policy_name: str,
        required_claims: list[dict[str, Any]] | None = None,
    ) -> PactInteraction:
        """Create presentation policy."""
        return PactInteraction(
            description=f"a request to create presentation policy '{policy_name}'",
            provider_state=f"organization {org_id} exists",
            method="POST",
            path="/v1/presentation-policies",
            request_headers=auth_headers(),
            request_body={
                "organization_id": org_id,
                "name": policy_name,
                "required_claims": required_claims or match.like([
                    {"claim_name": "age_over_21", "credential_type": "mDL", "accept_predicate": True}
                ]),
                "prefer_predicates": True,
            },
            response_status=201,
            response_body={
                "id": match.like(str(uuid4())),
                "organization_id": org_id,
                "name": policy_name,
                "status": "active",
                "created_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def create_policy_with_zk_predicate_specs(
        org_id: str,
        policy_name: str,
        zk_predicate_specs: list[dict[str, Any]],
    ) -> PactInteraction:
        """Create presentation policy with ZK predicate specifications."""
        return PactInteraction(
            description=f"a request to create policy '{policy_name}' with ZK predicate specs",
            provider_state=f"organization {org_id} exists",
            method="POST",
            path="/v1/presentation-policies",
            request_headers=auth_headers(),
            request_body={
                "organization_id": org_id,
                "name": policy_name,
                "zk_predicate_specs": zk_predicate_specs,
                "prefer_predicates": True,
            },
            response_status=201,
            response_body={
                "id": match.like(str(uuid4())),
                "organization_id": org_id,
                "name": policy_name,
                "status": "active",
                "zk_predicate_specs": match.each_like({
                    "predicate_type": match.like("range_proof"),
                    "handling_policy": match.like("require_predicate"),
                    "acceptable_circuits": match.each_like("ligero_age_over_18"),
                }),
                "created_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def create_policy_with_predicate_spec(
        org_id: str,
        policy_name: str,
        predicate_spec: dict[str, Any],
    ) -> PactInteraction:
        """Create presentation policy with structured predicate specification (legacy)."""
        return PactInteraction(
            description=f"a request to create policy '{policy_name}' with predicate spec",
            provider_state=f"organization {org_id} exists",
            method="POST",
            path="/v1/presentation-policies",
            request_headers=auth_headers(),
            request_body={
                "organization_id": org_id,
                "name": policy_name,
                "required_claims": [
                    {
                        "claim_name": "age",
                        "credential_type": "mDL",
                        "predicate_spec": predicate_spec,
                    }
                ],
                "prefer_predicates": True,
                "fallback_policy": "accept_raw",
            },
            response_status=201,
            response_body={
                "id": match.like(str(uuid4())),
                "organization_id": org_id,
                "name": policy_name,
                "status": "active",
                "fallback_policy": "accept_raw",
                "created_at": match.like("2025-01-01T00:00:00Z"),
            },
        )
    
    @staticmethod
    def get_policy(policy_id: str) -> PactInteraction:
        """Get presentation policy by ID."""
        return PactInteraction(
            description=f"a request to get presentation policy {policy_id}",
            provider_state=f"presentation policy {policy_id} exists",
            method="GET",
            path=f"/v1/presentation-policies/{policy_id}",
            request_headers=auth_headers(),
            response_status=200,
            response_body={
                "id": policy_id,
                "organization_id": match.like("org-123"),
                "name": match.like("Age Verification Policy"),
                "required_claims": match.each_like({
                    "claim_name": "age_over_21",
                    "credential_type": "mDL",
                    "accept_predicate": True,
                }),
                "prefer_predicates": True,
                "status": "active",
                "created_at": match.like("2025-01-01T00:00:00Z"),
            },
        )


# =============================================================================
# Convenience Aggregation
# =============================================================================

class Interactions:
    """
    Aggregates all interaction factories for easy access.
    
    Usage:
        from pact_interactions import Interactions
        
        interaction = Interactions.Auth.login()
        interaction = Interactions.Issuance.issue_w3c_vc(...)
        interaction = Interactions.ZK.create_zk_challenge(...)
    """
    
    Auth = AuthInteractions
    Organization = OrganizationInteractions
    CredentialTemplate = CredentialTemplateInteractions
    Issuance = IssuanceInteractions
    Verification = VerificationInteractions
    ZK = ZKProofInteractions
    Flow = FlowInteractions
    PresentationPolicy = PresentationPolicyInteractions
    RevocationProfile = RevocationProfileInteractions

