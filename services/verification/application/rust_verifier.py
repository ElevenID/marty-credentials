"""Rust-based credential verification."""

import json
import logging
from typing import Any

from marty_credentials.native_backend import require_marty_rs

from .did_resolver import extract_credential_verification_method, resolve_issuer_did

logger = logging.getLogger(__name__)


def get_marty_rs():
    """Import and return the marty-rs Python bindings."""
    return require_marty_rs()


REQUIRED_MARTY_RS_CAPABILITIES = frozenset(
    {
        "oid4vp_verify_vp_token",
        "vds_nc_verify",
        "verify_presentation_structure",
        "verify_vcdm_data_integrity",
        "verify_vcdm_jwt",
        "verification_build_decision_result",
        "governance_authorize",
        "governance_canonical_digest",
        "governance_from_snapshot",
        "governance_require_purpose",
        "governance_resume",
        "governance_validate",
        "governance_validate_request",
    }
)


def validate_marty_rs_capabilities() -> None:
    """Fail startup if credential verification cannot use its native kernels."""
    require_marty_rs(REQUIRED_MARTY_RS_CAPABILITIES)


def _verification_errors(result: dict[str, Any], fallback: str) -> str:
    """Return a stable error without treating unchecked evidence as success."""
    errors = [str(error) for error in result.get("errors", []) if error]
    errors.extend(
        str(descriptor["error"])
        for descriptor in result.get("descriptor_results", [])
        if isinstance(descriptor, dict) and descriptor.get("error")
    )
    return "; ".join(errors) if errors else fallback


def _scoped_check_passed(
    result: dict[str, Any],
    *,
    scope: str,
    evidence: tuple[str, ...],
) -> bool:
    """Require the complete low-level marty-core evidence contract."""
    recorded_evidence = result.get("evidence")
    return (
        result.get("valid") is False
        and result.get("decision_ready") is False
        and result.get("check_valid") is True
        and result.get("scope") == scope
        and isinstance(recorded_evidence, dict)
        and all(recorded_evidence.get(item) == "passed" for item in evidence)
    )


def _scoped_evidence_flag(result: dict[str, Any], name: str) -> bool | None:
    evidence = result.get("evidence")
    if not isinstance(evidence, dict) or name not in evidence:
        return None
    if evidence[name] == "passed":
        return True
    if evidence[name] == "failed":
        return False
    return None


class RustCredentialVerifier:
    """Credential verifier using Rust cryptography via PyO3 bindings."""

    def __init__(self):
        self.marty_rs = get_marty_rs()

    async def verify_w3c_vc(
        self,
        credential: dict[str, Any],
        verifier_did: str,
        trusted_issuers: list[str] | None = None,
        organization_id: str | None = None,
        credential_format: str | None = None,
        key_purpose: str | None = None,
        algorithm: str | None = None,
        allow_public_did_fallback: bool = False,
    ) -> dict[str, Any]:
        """Verify a W3C Verifiable Credential.

        1. Extracts the issuer DID from the credential.
        2. Checks against the trusted-issuer allowlist (if provided).
        3. Resolves the issuer's DID Document to obtain the public key.
        4. Returns the resolved issuer info and claims.
           Full cryptographic signature verification is delegated to the Rust
           bindings when available; otherwise the result is marked as
           ``signature_verified: false`` so callers know the trust boundary.
        """
        try:
            # Extract proof and credential data
            proof = credential.get("proof", {})
            if not proof:
                return {"valid": False, "error": "No proof found in credential"}

            # Get issuer
            issuer = credential.get("issuer")
            if isinstance(issuer, dict):
                issuer = issuer.get("id")

            if not issuer:
                return {"valid": False, "error": "No issuer found in credential"}

            verification_method_id = extract_credential_verification_method(credential)

            # Resolve the issuer DID through the org-scoped registry to obtain the exact public key.
            issuer_did_doc = None
            issuer_public_key = None
            issuer_resolution = None
            did_resolution_error = None
            try:
                issuer_resolution = await resolve_issuer_did(
                    issuer,
                    organization_id=organization_id,
                    verification_method_id=verification_method_id,
                    trusted_issuers=trusted_issuers,
                    credential_format=credential_format,
                    key_purpose=key_purpose,
                    algorithm=algorithm,
                    allow_public_fallback=allow_public_did_fallback,
                )
                issuer_did_doc = issuer_resolution.get("did_document")
                issuer_public_key = issuer_resolution.get("public_jwk")
            except ValueError as resolve_err:
                did_resolution_error = str(resolve_err)
                logger.warning("Could not resolve issuer DID %s: %s", issuer, resolve_err)
                return {
                    "valid": False,
                    "error": did_resolution_error,
                    "issuer": issuer,
                    "issuer_did_resolved": False,
                    "did_resolution_error": did_resolution_error,
                    "method": "w3c_vc",
                }

            if issuer_public_key is None:
                return {
                    "valid": False,
                    "error": f"No public key resolved for issuer {issuer}",
                    "issuer": issuer,
                    "issuer_did_resolved": issuer_did_doc is not None,
                    "did_resolution_error": did_resolution_error,
                    "method": "w3c_vc",
                }

            # Verify the exact Data Integrity document with issuer material
            # resolved by the product's organization-scoped DID resolver.
            signature_verified = False
            sig_error = None
            processing_status = None
            try:
                result_json = self.marty_rs.verify_vcdm_data_integrity(
                    json.dumps(
                        {
                            "document": credential,
                            "resolved_verification_methods": [
                                {
                                    "id": verification_method_id,
                                    "controller": issuer,
                                    "public_jwk": issuer_public_key,
                                }
                            ],
                        }
                    )
                )
                sig_result = json.loads(result_json)
                signature_verified = (
                    sig_result.get("valid") is True
                    and sig_result.get("kind") == "credential"
                    and sig_result.get("verified_credentials") == 1
                )
                if not signature_verified:
                    sig_error = _verification_errors(sig_result, "Signature invalid")
            except AttributeError:
                sig_error = "Rust verify_vcdm_data_integrity binding not available"
                processing_status = "UNAVAILABLE"
                logger.warning(
                    "W3C VC signature verification failed closed — "
                    "Rust binding not available for issuer %s",
                    issuer,
                )
            except Exception as sig_exc:
                sig_error = str(sig_exc)
                logger.warning(
                    "W3C VC signature verification failed for %s: %s",
                    issuer,
                    sig_exc,
                )

            if not signature_verified:
                failed_result = {
                    "valid": False,
                    "error": sig_error or "Signature invalid",
                    "signature_verified": False,
                    "issuer": issuer,
                    "issuer_did_resolved": issuer_did_doc is not None,
                    "issuer_public_key": issuer_public_key,
                    "did_resolution_error": did_resolution_error,
                    "signature_error": sig_error,
                    "issuer_resolution": issuer_resolution,
                    "method": "w3c_vc",
                }
                if processing_status is not None:
                    failed_result["processing_status"] = processing_status
                return failed_result

            issuer_trusted = bool(
                issuer_resolution
                and (
                    (trusted_issuers and issuer in trusted_issuers)
                    or (
                        organization_id
                        and not (
                            isinstance(issuer_resolution.get("resolver"), dict)
                            and issuer_resolution["resolver"].get("type") == "public_did_resolution"
                        )
                    )
                )
            )
            return {
                "valid": False,
                "cryptographic_valid": True,
                "signature_verified": True,
                "issuer_trusted": issuer_trusted,
                "trust_chain_valid": issuer_trusted,
                "revocation_checked": False,
                "revocation_status": "SKIPPED",
                "decision_ready": False,
                "issuer": issuer,
                "issuer_did_resolved": issuer_did_doc is not None,
                "issuer_public_key": issuer_public_key,
                "verification_method_id": issuer_resolution.get("verification_method_id")
                if isinstance(issuer_resolution, dict)
                else verification_method_id,
                "did_resolution_error": did_resolution_error,
                "signature_error": sig_error,
                "issuer_resolution": issuer_resolution,
                "claims": credential.get("credentialSubject", {}),
                "method": "w3c_vc",
                "error": "Credential status evidence is incomplete",
            }

        except Exception as e:
            logger.error(f"W3C VC verification failed: {e}")
            return {
                "valid": False,
                "processing_status": "ERROR",
                "processing_error": True,
                "error": str(e),
            }

    async def verify_jwt_vp(
        self, presentation_jwt: str, expected_audience: str, expected_nonce: str | None = None
    ) -> dict[str, Any]:
        """Verify a JWT Verifiable Presentation using the marty-oid4vci VerificationEngine.

        Validates nonce, audience, expiration, and JWT signature via the Rust
        `oid4vp_verify_vp_token` binding.  The holder's public key must be embedded
        in the JWT header (`jwk`) or in the payload (`cnf.jwk`).
        """
        try:
            nonce = expected_nonce or ""
            result_json = self.marty_rs.oid4vp_verify_vp_token(
                presentation_jwt,
                nonce,
                expected_audience,
            )
            result = json.loads(result_json)

            if not _scoped_check_passed(
                result,
                scope="presentation_proof",
                evidence=("presentation_proof", "transaction_binding"),
            ):
                failed_result: dict[str, Any] = {
                    "valid": False,
                    "error": _verification_errors(
                        result, "VP token verification evidence was incomplete"
                    ),
                }
                for field, evidence_name in (
                    ("presentation_proof_valid", "presentation_proof"),
                    ("transaction_binding_valid", "transaction_binding"),
                ):
                    value = _scoped_evidence_flag(result, evidence_name)
                    if value is not None:
                        failed_result[field] = value
                return failed_result

            # Decode payload to extract VP claims for the caller
            import base64

            parts = presentation_jwt.split(".")
            payload_b64 = parts[1] if len(parts) == 3 else ""
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            try:
                payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                logger.warning("Failed to decode JWT VP payload: %s", exc)
                payload = {}

            vp = payload.get("vp", {})
            return {
                # The outer JWT establishes only the holder presentation proof.
                # Its embedded issuer credentials still require independent
                # format verification, trust resolution, and status checks.
                "valid": False,
                "cryptographic_valid": False,
                "presentation_proof_valid": True,
                "transaction_binding_valid": True,
                "claims": [],
                "holder": payload.get("iss") or vp.get("holder"),
                "method": "jwt_vp",
                "error": (
                    "Holder presentation proof verified, but embedded credential "
                    "issuer proofs were not verified"
                ),
            }

        except Exception as e:
            logger.error(f"JWT VP verification failed: {e}")
            return {
                "valid": False,
                "processing_status": "ERROR",
                "processing_error": True,
                "error": str(e),
            }

    async def verify_presentation(
        self,
        presentation: dict[str, Any],
        presentation_definition: dict[str, Any],
        verifier_did: str,
        trusted_issuers: list[str] | None = None,
        organization_id: str | None = None,
        allow_public_did_fallback: bool = False,
    ) -> dict[str, Any]:
        """Verify a presentation against a presentation definition.

        Verifies each credential in the presentation and then validates the
        presentation against the definition's descriptor constraints via
        the Rust `verify_presentation_structure` binding.
        """
        try:
            # ── Step 1: Verify each embedded credential ───────────────
            credentials = presentation.get("verifiableCredential", [])
            if not isinstance(credentials, list):
                credentials = [credentials]
            if not credentials:
                return {
                    "valid": False,
                    "cryptographic_valid": False,
                    "credential_proofs_valid": False,
                    "error": "Presentation contains no verifiable credentials",
                }

            descriptors = presentation_definition.get("input_descriptors")
            if not isinstance(descriptors, list) or not descriptors:
                return {
                    "valid": False,
                    "cryptographic_valid": False,
                    "presentation_structure_valid": False,
                    "error": "Presentation definition contains no input descriptors",
                }

            submission = presentation.get("presentation_submission")
            if not isinstance(submission, dict):
                return {
                    "valid": False,
                    "cryptographic_valid": False,
                    "presentation_structure_valid": False,
                    "error": "Presentation submission is required",
                }

            verified_creds: list[dict[str, Any]] = []
            all_claims: dict[str, Any] = {}

            for cred in credentials:
                if not isinstance(cred, dict):
                    return {
                        "valid": False,
                        "processing_status": "UNSUPPORTED",
                        "cryptographic_valid": False,
                        "credential_proofs_valid": False,
                        "error": "Unsupported embedded credential serialization",
                    }
                cred_result = await self.verify_w3c_vc(
                    cred,
                    verifier_did,
                    trusted_issuers=trusted_issuers,
                    organization_id=organization_id,
                    allow_public_did_fallback=allow_public_did_fallback,
                )
                if cred_result.get("signature_verified") is not True:
                    return {
                        "valid": False,
                        "credential_proofs_valid": False,
                        "error": f"Credential verification failed: {cred_result.get('error')}",
                    }
                verified_creds.append(cred_result)
                if cred_result.get("claims"):
                    all_claims.update(cred_result["claims"])

            # ── Step 2: Validate presentation_definition constraints ──
            try:
                structure_result_json = self.marty_rs.verify_presentation_structure(
                    verifier_id=verifier_did,
                    response_uri=verifier_did,
                    definition_json=json.dumps(presentation_definition),
                    submission_json=json.dumps(submission),
                )
                structure_result = json.loads(structure_result_json)
                if not _scoped_check_passed(
                    structure_result,
                    scope="presentation_structure",
                    evidence=("presentation_structure",),
                ):
                    return {
                        "valid": False,
                        "cryptographic_valid": False,
                        "presentation_structure_valid": False,
                        "error": _verification_errors(
                            structure_result,
                            "Presentation structure verification evidence was incomplete",
                        ),
                    }
            except Exception as e:
                logger.warning("Presentation structure check failed: %s", e)
                return {
                    "valid": False,
                    "cryptographic_valid": False,
                    "presentation_structure_valid": False,
                    "error": f"Presentation structure verification failed: {e}",
                }

            return {
                # Credential issuer proofs and descriptor structure passed, but
                # this path has no authenticated presentation proof, holder or
                # transaction binding, constraint evaluation, or status result.
                "valid": False,
                "cryptographic_valid": False,
                "credential_proofs_valid": True,
                "presentation_structure_valid": True,
                "decision_ready": False,
                "trust_chain_valid": all(
                    cred.get("issuer_trusted") is True for cred in verified_creds
                ),
                "revocation_checked": False,
                "revocation_status": "SKIPPED",
                "verified_claims": all_claims,
                "credentials_verified": len(verified_creds),
                "method": "presentation",
                "error": (
                    "Credential proofs and presentation structure verified, but "
                    "required presentation, holder, transaction, constraint, and "
                    "status evidence is incomplete"
                ),
            }

        except Exception as e:
            logger.error(f"Presentation verification failed: {e}")
            return {
                "valid": False,
                "processing_status": "ERROR",
                "processing_error": True,
                "error": str(e),
            }

    async def verify_vds_nc(
        self,
        barcode: str,
        issuer_jwk_json: str,
    ) -> dict[str, Any]:
        """Verify a VDS-NC tilde-separated barcode against an issuer JWK.

        Uses the Rust ``vds_nc_verify`` binding which validates the header
        structure, decodes the signature, and verifies it against the supplied
        JWK public key (ES256, ES384, or EdDSA).

        Args:
            barcode: Full ``header~payload_json~signature_b64`` barcode string.
            issuer_jwk_json: Issuer public key serialised as a JWK JSON string.

        Returns:
            Dict with keys: ``valid`` (bool), ``country`` (str|None),
            ``payload`` (dict|None), ``signature_status`` (str),
            ``errors`` (list[str]).
        """
        try:
            result = self.marty_rs.vds_nc_verify(barcode, issuer_jwk_json)
            payload_raw = result.get("payload")
            payload: dict | None = None
            if payload_raw:
                try:
                    payload = (
                        json.loads(payload_raw) if isinstance(payload_raw, str) else payload_raw
                    )
                except (ValueError, TypeError):
                    payload = None

            return {
                "valid": result.get("verified", False),
                "country": result.get("country"),
                "payload": payload,
                "signature_status": result.get("signature_status", "Unknown"),
                "errors": result.get("errors", []),
                "method": "vds_nc",
            }
        except Exception as e:
            logger.error("VDS-NC verification failed: %s", e)
            return {
                "valid": False,
                "processing_status": "ERROR",
                "processing_error": True,
                "error": str(e),
                "method": "vds_nc",
            }
