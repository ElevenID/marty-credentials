"""Rust-based credential verification."""

import json
import logging
from typing import Any

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
        trusted_issuers: list[str] | None = None
    ) -> dict[str, Any]:
        """Verify a W3C Verifiable Credential."""
        try:
            # Extract proof and credential data
            proof = credential.get("proof", {})
            if not proof:
                return {"valid": False, "error": "No proof found in credential"}
            
            # Get issuer
            issuer = credential.get("issuer")
            if isinstance(issuer, dict):
                issuer = issuer.get("id")
            
            # Check trusted issuers if provided
            if trusted_issuers and issuer not in trusted_issuers:
                return {"valid": False, "error": f"Issuer {issuer} not trusted"}
            
            # Signature verification not yet implemented — refuse to claim validity.
            # TODO: Implement full Rust-based signature verification via marty-rs.
            logger.warning(
                "W3C VC signature verification not implemented — "
                "returning unverified result for issuer %s",
                issuer,
            )
            return {
                "valid": False,
                "error": "W3C VC signature verification not yet implemented",
                "issuer": issuer,
                "claims": credential.get("credentialSubject", {}),
                "method": "w3c_vc"
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
        verifier_did: str
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
                cred_result = await self.verify_w3c_vc(cred, verifier_did)
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
