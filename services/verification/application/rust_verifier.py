"""Rust-based credential verification."""

import json
import logging
from typing import Any

from .did_resolver import extract_credential_verification_method, resolve_issuer_did

logger = logging.getLogger(__name__)


def get_marty_rs():
    """Import and return the marty-rs Python bindings."""
    try:
        import _marty_rs
        return _marty_rs
    except ImportError as e:
        logger.error("marty-rs bindings not available - verification will be limited")
        raise ImportError(
            "marty-rs Python bindings are required for credential verification. "
            "Ensure the marty-bindings crate is built and installed."
        ) from e


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
                logger.warning(
                    "Could not resolve issuer DID %s: %s", issuer, resolve_err
                )
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

            # Attempt Rust-based signature verification if available
            signature_verified = False
            sig_error = None
            try:
                result_json = self.marty_rs.verify_w3c_vc_signature(
                    credential_json=json.dumps(credential),
                    public_key_jwk_json=json.dumps(issuer_public_key),
                )
                sig_result = json.loads(result_json)
                signature_verified = sig_result.get("valid", False)
                if not signature_verified:
                    sig_error = sig_result.get("error", "Signature invalid")
            except AttributeError:
                sig_error = "Rust verify_w3c_vc_signature binding not available"
                logger.warning(
                    "W3C VC signature verification failed closed — "
                    "Rust binding not available for issuer %s",
                    issuer,
                )
            except Exception as sig_exc:
                sig_error = str(sig_exc)
                logger.warning(
                    "W3C VC signature verification failed for %s: %s",
                    issuer, sig_exc,
                )

            if not signature_verified:
                return {
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

            return {
                "valid": signature_verified,
                "signature_verified": signature_verified,
                "issuer": issuer,
                "issuer_did_resolved": issuer_did_doc is not None,
                "issuer_public_key": issuer_public_key,
                "verification_method_id": issuer_resolution.get("verification_method_id") if isinstance(issuer_resolution, dict) else verification_method_id,
                "did_resolution_error": did_resolution_error,
                "signature_error": sig_error,
                "issuer_resolution": issuer_resolution,
                "claims": credential.get("credentialSubject", {}),
                "method": "w3c_vc",
            }

        except Exception as e:
            logger.error(f"W3C VC verification failed: {e}")
            return {"valid": False, "error": str(e)}
    
    async def verify_jwt_vp(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None
    ) -> dict[str, Any]:
        """Verify a JWT Verifiable Presentation using the marty-oid4vci VerificationEngine.

        Validates nonce, audience, expiration, and JWT signature via the Rust
        `verify_vp_token_jwt` binding.  The holder's public key must be embedded
        in the JWT header (`jwk`) or in the payload (`cnf.jwk`).
        """
        try:
            nonce = expected_nonce or ""
            result_json = self.marty_rs.verify_vp_token_jwt(
                verifier_id=expected_audience,
                response_uri=expected_audience,  # response_uri not relevant for verification
                vp_token=presentation_jwt,
                expected_nonce=nonce,
            )
            result = json.loads(result_json)

            if not result.get("valid"):
                errors = result.get("errors", [])
                error_msg = errors[0] if errors else "VP token verification failed"
                return {"valid": False, "error": error_msg}

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
                "valid": True,
                "claims": vp.get("verifiableCredential", []),
                "holder": payload.get("iss") or vp.get("holder"),
                "method": "jwt_vp",
            }

        except Exception as e:
            logger.error(f"JWT VP verification failed: {e}")
            return {"valid": False, "error": str(e)}
    
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

            verified_creds: list[dict[str, Any]] = []
            all_claims: dict[str, Any] = {}

            for cred in credentials:
                cred_result = await self.verify_w3c_vc(
                    cred,
                    verifier_did,
                    trusted_issuers=trusted_issuers,
                    organization_id=organization_id,
                    allow_public_did_fallback=allow_public_did_fallback,
                )
                if not cred_result.get("valid"):
                    return {
                        "valid": False,
                        "error": f"Credential verification failed: {cred_result.get('error')}",
                    }
                verified_creds.append(cred_result)
                if cred_result.get("claims"):
                    all_claims.update(cred_result["claims"])

            # ── Step 2: Validate presentation_definition constraints ──
            # Extract presentation_submission from the presentation if present
            submission = presentation.get("presentation_submission")
            if submission and presentation_definition:
                try:
                    structure_result_json = self.marty_rs.verify_presentation_structure(
                        verifier_id=verifier_did,
                        response_uri=verifier_did,
                        definition_json=json.dumps(presentation_definition),
                        submission_json=json.dumps(submission),
                    )
                    structure_result = json.loads(structure_result_json)
                    if not structure_result.get("valid"):
                        errors = structure_result.get("errors", [])
                        descriptor_errors = [
                            r.get("error")
                            for r in structure_result.get("descriptor_results", [])
                            if not r.get("valid") and r.get("error")
                        ]
                        all_errors = errors + descriptor_errors
                        error_msg = "; ".join(all_errors) if all_errors else "Presentation structure invalid"
                        return {"valid": False, "error": error_msg}
                except Exception as e:
                    logger.warning(f"Presentation structure check failed: {e}")
                    # Non-fatal: fall through without structure validation

            return {
                "valid": True,
                "verified_claims": all_claims,
                "credentials_verified": len(verified_creds),
                "method": "presentation",
            }

        except Exception as e:
            logger.error(f"Presentation verification failed: {e}")
            return {"valid": False, "error": str(e)}

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
                    payload = json.loads(payload_raw) if isinstance(payload_raw, str) else payload_raw
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
            return {"valid": False, "error": str(e), "method": "vds_nc"}
