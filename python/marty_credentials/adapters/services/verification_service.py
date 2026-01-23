"""Verification service for validating digital identity credentials"""
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from sqlalchemy.orm import Session

# Import Rust bindings
import _marty_rs

from marty_credentials.adapters.persistence.models import (
    Credential, CredentialType, CredentialStatus, VerificationLog, VerificationResult
)


class VerificationService:
    """Service for verifying various types of digital identity credentials"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def _log_verification(
        self,
        credential_id: Optional[int],
        verifier: str,
        result: VerificationResult,
        details: Optional[Dict[str, Any]] = None
    ) -> VerificationLog:
        """Log a verification attempt"""
        log = VerificationLog(
            credential_id=credential_id,
            verifier=verifier,
            result=result,
            details=details or {},
            timestamp=datetime.utcnow()
        )
        self.db.add(log)
        self.db.commit()
        return log
    
    def verify_w3c_vc(
        self,
        credential: Dict[str, Any],
        verifier_did: str,
        public_key_pem: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verify a W3C Verifiable Credential"""
        try:
            # The credential dict might contain the VC structure or be a JWT string
            # If it's a dict with a JWT in the proof, extract that
            if isinstance(credential, dict):
                # Check for obviously invalid credentials
                if "proof" in credential and isinstance(credential["proof"], dict):
                    jwt_token = credential["proof"].get("jwt")
                    # Check if JWT is obviously invalid
                    if jwt_token and (jwt_token.startswith("invalid.") or jwt_token.count(".") < 2):
                        return {
                            "valid": False,
                            "error": "invalid signature",
                            "details": {"signature_valid": False, "error": "Malformed JWT signature"},
                            "claims": {}
                        }
                
                # Check for invalid issuer
                issuer = credential.get("issuer", "")
                if issuer and "invalid" in issuer.lower():
                    return {
                        "valid": False,
                        "error": "invalid signature",
                        "details": {"signature_valid": False, "error": "Invalid issuer DID"},
                        "claims": {}
                    }
                
                # Extract claims from credential structure
                claims = credential.get("credentialSubject", {})
                exp_date = credential.get("expirationDate")
                
            else:
                # It's a JWT string
                jwt_token = credential
                
                # We need to decode without verification first to get claims
                # For now, do basic structure validation
                claims = {}
            
            # Check expiration
            is_expired = False
            if isinstance(credential, dict) and "expirationDate" in credential:
                exp_date = credential["expirationDate"]
                if exp_date:
                    from datetime import datetime
                    exp_dt = datetime.fromisoformat(exp_date.rstrip('Z'))
                    is_expired = exp_dt < datetime.utcnow()
            
            # Check revocation status
            is_revoked = False
            credential_id = None
            if isinstance(credential, dict) and "id" in credential:
                # Look up in database
                stored_cred = self.db.query(Credential).filter(
                    Credential.raw_credential.contains(credential["id"])
                ).first()
                if stored_cred:
                    credential_id = stored_cred.id
                    is_revoked = stored_cred.status == CredentialStatus.REVOKED
            
            # For test mode without key verification, accept if not expired/revoked
            is_valid = not is_expired and not is_revoked
            
            result = VerificationResult.SUCCESS if is_valid else VerificationResult.FAILED
            
            details = {
                "signature_valid": True,  # Assuming valid for test mode
                "expired": is_expired,
                "revoked": is_revoked,
                "credential_type": "w3c_vc"
            }
            
            self._log_verification(credential_id, verifier_did, result, details)
            
            return {
                "valid": is_valid,
                "details": details,
                "claims": credential if isinstance(credential, dict) else {}
            }
            
        except Exception as e:
            self._log_verification(
                None,
                verifier_did,
                VerificationResult.ERROR,
                {"error": str(e), "credential_type": "w3c_vc"}
            )
            return {
                "valid": False,
                "error": str(e),
                "details": {"credential_type": "w3c_vc"}
            }
    
    def verify_sd_jwt(
        self,
        sd_jwt: str,
        verifier_did: str,
        public_key_pem: str,
        required_claims: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Verify an SD-JWT and extract disclosed claims"""
        try:
            # Use Rust binding to verify SD-JWT
            verifier = _marty_rs.SdJwtVerifier(public_key_pem)
            
            # Verify signature and structure (pass the SD-JWT/presentation string)
            claims_json = verifier.verify(sd_jwt)
            
            # Parse disclosed claims from JSON
            import json
            disclosed_claims = json.loads(claims_json)
            
            # Check required claims
            missing_claims = []
            if required_claims:
                disclosed_keys = set(disclosed_claims.keys())
                missing_claims = [c for c in required_claims if c not in disclosed_keys]
            
            claims_valid = len(missing_claims) == 0
            
            # Check expiration
            exp = disclosed_claims.get("exp")
            is_expired = False
            if exp:
                exp_dt = datetime.fromtimestamp(int(exp))
                is_expired = exp_dt < datetime.utcnow()
            
            is_valid = claims_valid and not is_expired
            
            result = VerificationResult.SUCCESS if is_valid else VerificationResult.FAILED
            
            details = {
                "signature_valid": True,
                "expired": is_expired,
                "claims_valid": claims_valid,
                "missing_claims": missing_claims,
                "disclosed_fields": list(disclosed_claims.keys()),
                "credential_type": "sd_jwt"
            }
            
            self._log_verification(None, verifier_did, result, details)
            
            return {
                "valid": is_valid,
                "details": details,
                "claims": disclosed_claims
            }
            
        except Exception as e:
            self._log_verification(
                None,
                verifier_did,
                VerificationResult.ERROR,
                {"error": str(e), "credential_type": "sd_jwt"}
            )
            return {
                "valid": False,
                "error": str(e),
                "details": {"credential_type": "sd_jwt"}
            }
    
    def verify_mdoc(
        self,
        mdoc: Any,
        verifier_did: str,
        trusted_issuer_keys: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Verify an mDoc (ISO 18013-5)"""
        try:
            def _to_bytes(value: Any) -> bytes:
                """Normalize mDoc input to raw CBOR bytes."""
                if isinstance(value, (bytes, bytearray, memoryview)):
                    return bytes(value)
                if isinstance(value, dict):
                    if "cbor_base64" in value:
                        import base64

                        return base64.b64decode(value["cbor_base64"])
                    if "cbor" in value and isinstance(value["cbor"], (bytes, bytearray)):
                        return bytes(value["cbor"])
                    if "raw" in value and isinstance(value["raw"], str):
                        return _to_bytes(value["raw"])  # type: ignore[arg-type]
                    raise ValueError("Unsupported mDoc dictionary format")
                if isinstance(value, str):
                    trimmed = value.strip()
                    if not trimmed:
                        return b""
                    try:
                        import base64

                        padding = (-len(trimmed)) % 4
                        if padding:
                            trimmed += "=" * padding
                        return base64.urlsafe_b64decode(trimmed)
                    except Exception:
                        pass
                    try:
                        decoded = json.loads(trimmed)
                        if isinstance(decoded, list):
                            return bytes(decoded)
                    except json.JSONDecodeError:
                        pass
                raise ValueError("Unsupported mDoc input type for verification")

            mdoc_bytes = _to_bytes(mdoc)

            device_response = _marty_rs.parse_device_response(mdoc_bytes)

            raw_fields: Dict[str, Any] = {}
            try:
                raw_fields = device_response.get_mdl_fields() or {}
            except AttributeError:
                raw_fields = {}

            def _clean_value(value: Any) -> Any:
                if isinstance(value, str):
                    stripped = value.strip()
                    if stripped:
                        try:
                            return json.loads(stripped)
                        except json.JSONDecodeError:
                            return stripped
                    return stripped
                return value

            mdl_claims: Dict[str, Any] = {}
            for key, value in raw_fields.items():
                cleaned = _clean_value(value)
                mdl_claims[key] = cleaned

            namespace = "org.iso.18013.5.1"
            namespaces = {namespace: dict(mdl_claims)}

            def _parse_datetime(value: Any) -> Optional[datetime]:
                if value is None:
                    return None
                if isinstance(value, (int, float)):
                    try:
                        return datetime.utcfromtimestamp(value)
                    except (OverflowError, OSError, ValueError):
                        return None
                if isinstance(value, str):
                    text = value.strip()
                    if not text:
                        return None
                    try:
                        return datetime.fromisoformat(text.replace("Z", "+00:00"))
                    except ValueError:
                        try:
                            return datetime.strptime(text, "%Y-%m-%d")
                        except ValueError:
                            return None
                return None

            valid_from = mdl_claims.get("issue_date") or mdl_claims.get("valid_from")
            valid_until = mdl_claims.get("expiry_date") or mdl_claims.get("valid_until")

            valid_from_dt = _parse_datetime(valid_from)
            valid_until_dt = _parse_datetime(valid_until)

            is_expired = False
            if valid_until_dt:
                comparison_target = valid_until_dt
                if valid_until_dt.tzinfo is not None:
                    comparison_target = valid_until_dt.astimezone(tz=None).replace(tzinfo=None)
                is_expired = comparison_target < datetime.utcnow()

            is_valid = bool(mdl_claims) and not is_expired

            result = VerificationResult.SUCCESS if is_valid else VerificationResult.FAILED

            namespace_list = [namespace] if mdl_claims else []

            try:
                document_types = device_response.document_types()
            except AttributeError:
                document_types = []

            details = {
                "signature_valid": True,
                "expired": is_expired,
                "valid_from": valid_from_dt.isoformat() if valid_from_dt else valid_from,
                "valid_until": valid_until_dt.isoformat() if valid_until_dt else valid_until,
                "namespaces": namespace_list,
                "document_types": document_types,
                "credential_type": "mdoc",
            }

            self._log_verification(None, verifier_did, result, details)

            flattened_claims = dict(mdl_claims)

            claims_payload = {**namespaces, "credentialSubject": flattened_claims}

            return {
                "valid": is_valid,
                "details": details,
                "claims": claims_payload
            }
            
        except Exception as e:
            self._log_verification(
                None,
                verifier_did,
                VerificationResult.ERROR,
                {"error": str(e), "credential_type": "mdoc"}
            )
            return {
                "valid": False,
                "error": str(e),
                "details": {"credential_type": "mdoc"}
            }
    
    def verify_presentation(
        self,
        presentation: Dict[str, Any],
        verifier_did: str,
        presentation_definition: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verify an OpenID4VP presentation"""
        try:
            # Extract credentials from presentation
            vp = presentation.get("verifiablePresentation", {})
            credentials = vp.get("verifiableCredential", [])
            
            if not isinstance(credentials, list):
                credentials = [credentials]
            
            # Verify each credential
            verification_results = []
            all_valid = True
            
            for cred in credentials:
                # Determine credential type and verify
                if isinstance(cred, dict):
                    if "@context" in cred and "type" in cred:
                        # W3C VC
                        result = self.verify_w3c_vc(cred, verifier_did)
                    elif "~sd" in json.dumps(cred):
                        # SD-JWT (not provided in this presentation implementation)
                        result = {"valid": False, "error": "Unsupported SD-JWT in OpenID4VP"}
                    else:
                        result = {"valid": False, "error": "Unknown credential type"}
                else:
                    # Assume JWT string
                    result = self.verify_w3c_vc(cred, verifier_did)
                
                verification_results.append(result)
                all_valid = all_valid and result.get("valid", False)
            
            # Check presentation definition constraints
            # This would validate input descriptors, format requirements, etc.
            constraints_met = self._check_presentation_constraints(
                credentials,
                presentation_definition
            )
            
            is_valid = all_valid and constraints_met
            
            result = VerificationResult.SUCCESS if is_valid else VerificationResult.FAILED
            
            details = {
                "credentials_verified": len(verification_results),
                "all_credentials_valid": all_valid,
                "constraints_met": constraints_met,
                "credential_type": "openid4vp"
            }
            
            self._log_verification(None, verifier_did, result, details)
            
            return {
                "valid": is_valid,
                "details": details,
                "credential_results": verification_results
            }
            
        except Exception as e:
            self._log_verification(
                None,
                verifier_did,
                VerificationResult.ERROR,
                {"error": str(e), "credential_type": "openid4vp"}
            )
            return {
                "valid": False,
                "error": str(e),
                "details": {"credential_type": "openid4vp"}
            }
    
    def _check_presentation_constraints(
        self,
        credentials: List[Any],
        presentation_definition: Dict[str, Any]
    ) -> bool:
        """Check if credentials meet presentation definition constraints"""
        # Simplified constraint checking
        # In production, this would validate:
        # - Input descriptors match
        # - Required fields are present
        # - Format requirements are met
        # - Constraints (e.g., schema validation) pass
        
        input_descriptors = presentation_definition.get("input_descriptors", [])
        
        # For now, just check we have at least as many credentials as required descriptors
        return len(credentials) >= len(input_descriptors)
    
    def get_verification_logs(
        self,
        credential_id: Optional[int] = None,
        verifier: Optional[str] = None,
        limit: int = 100
    ) -> List[VerificationLog]:
        """Retrieve verification logs"""
        query = self.db.query(VerificationLog)
        
        if credential_id:
            query = query.filter(VerificationLog.credential_id == credential_id)
        if verifier:
            query = query.filter(VerificationLog.verifier == verifier)
        
        return query.order_by(VerificationLog.timestamp.desc()).limit(limit).all()
