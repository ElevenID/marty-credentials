"""Issuance service for creating digital identity credentials"""
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

# Import Rust bindings
import _marty_rs

from marty_credentials.adapters.persistence.models import (
    Credential, CredentialType, CredentialStatus, Holder
)


class IssuanceService:
    """Service for issuing various types of digital identity credentials"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        
    def _generate_keys(self) -> tuple[str, str]:
        """Generate a P-256 key pair for signing"""
        # Using P-256 as it's widely supported across all formats
        # Returns (did, jwk_json_string)
        did, jwk_json = _marty_rs.generate_p256_key()
        
        # Parse JWK to get key components
        import json
        jwk = json.loads(jwk_json)
        
        # Convert to PEM format for signing operations
        # For now, we'll keep the JWK format and use it directly
        # In production, convert to PEM or use JWK directly with the Rust functions
        
        # Return as tuple (private_key_jwk, public_key_jwk)
        # For the private key, we include d parameter
        # For public key, we exclude d parameter
        public_jwk = {k: v for k, v in jwk.items() if k != 'd'}
        
        return jwk_json, json.dumps(public_jwk)
    
    def _jwk_to_pem(self, jwk_json: str) -> str:
        """Convert JWK to private key PEM format"""
        import json
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        import base64
        
        jwk = json.loads(jwk_json)
        
        # Decode base64url encoded values
        def b64url_decode(data):
            padding = '=' * (4 - len(data) % 4)
            return base64.urlsafe_b64decode(data + padding)
        
        x = b64url_decode(jwk['x'])
        y = b64url_decode(jwk['y'])
        d = b64url_decode(jwk['d'])
        
        # Create EC private key
        private_numbers = ec.EllipticCurvePrivateNumbers(
            int.from_bytes(d, 'big'),
            ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, 'big'),
                int.from_bytes(y, 'big'),
                ec.SECP256R1()
            )
        )
        
        private_key = private_numbers.private_key(default_backend())
        
        # Convert to PEM
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return pem.decode('utf-8')
    
    def _jwk_to_public_pem(self, jwk_json: str) -> str:
        """Convert JWK to public key PEM format"""
        import json
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        import base64
        
        jwk = json.loads(jwk_json)
        
        # Decode base64url encoded values
        def b64url_decode(data):
            padding = '=' * (4 - len(data) % 4)
            return base64.urlsafe_b64decode(data + padding)
        
        x = b64url_decode(jwk['x'])
        y = b64url_decode(jwk['y'])
        
        # Create EC public key
        public_numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, 'big'),
            int.from_bytes(y, 'big'),
            ec.SECP256R1()
        )
        
        public_key = public_numbers.public_key(default_backend())
        
        # Convert to PEM
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return pem.decode('utf-8')

    def _private_pem_to_public_pem(self, private_key_pem: str) -> str:
        """Derive public key PEM from a private key PEM"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        key_obj = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None, backend=default_backend()
        )
        public_key = key_obj.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem.decode('utf-8')
    
    def _find_or_create_holder(self, holder_did: str) -> Holder:
        """Find existing holder or create new one"""
        holder = self.db.query(Holder).filter(Holder.did == holder_did).first()
        if not holder:
            holder = Holder(did=holder_did)
            self.db.add(holder)
            self.db.commit()
        return holder
    
    def issue_w3c_vc(
        self,
        issuer_did: str,
        subject_did: str,
        credential_type: str,
        claims: Dict[str, Any],
        expiry_hours: int = 24
    ) -> Dict[str, Any]:
        """Issue a W3C Verifiable Credential"""
        # Generate issuer keys
        private_jwk, public_jwk = self._generate_keys()
        
        # Use Rust binding to create VC
        # Note: create_verifiable_credential returns (jwt_token, credential_id)
        vc_result = _marty_rs.create_verifiable_credential(
            issuer_did=issuer_did,
            issuer_jwk_json=private_jwk,
            subject_id=subject_did,
            credential_type=credential_type,
            claims_json=json.dumps(claims),
            expiration_seconds=expiry_hours * 3600  # Convert hours to seconds
        )
        
        # Result is a tuple: (jwt_token, credential_id)
        jwt_token, credential_id = vc_result
        
        # Parse the JWT to extract the VC structure (for response)
        # JWT format is: header.payload.signature
        import base64
        parts = jwt_token.split('.')
        if len(parts) == 3:
            # Decode payload (add padding if needed)
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding
            payload_json = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_json)
            vc = payload.get('vc', {})
        else:
            # Fallback if JWT parsing fails
            vc = {
                "id": credential_id,
                "type": ["VerifiableCredential", credential_type],
                "issuer": issuer_did,
                "credentialSubject": claims
            }
        
        # Store in database
        holder = self._find_or_create_holder(subject_did)
        
        credential = Credential(
            type=CredentialType.W3C_VC,
            issuer_did=issuer_did,
            holder=holder,
            claims=claims,
            raw_credential=jwt_token,  # Store the JWT token
            status=CredentialStatus.ACTIVE,
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=expiry_hours)
        )
        
        self.db.add(credential)
        self.db.commit()
        
        return {
            "credential": vc,
            "jwt": jwt_token,
            "credential_id": credential.id,
            "format": "w3c_vc"
        }
    
    def issue_sd_jwt(
        self,
        issuer_did: str,
        subject_did: str,
        claims: Dict[str, Any],
        selective_fields: Optional[List[str]] = None,
        expiry_hours: int = 24
    ) -> Dict[str, Any]:
        """Issue an SD-JWT with selective disclosure"""
        # Generate issuer keys
        private_key_jwk, public_key = self._generate_keys()
        
        # Convert JWK to PEM
        private_key_pem = self._jwk_to_pem(private_key_jwk)
        
        # Use selective_fields to determine which claims to make selectively disclosable
        if selective_fields is None:
            # By default, make all claims except 'sub' and 'iss' selectively disclosable
            selective_fields = [k for k in claims.keys() if k not in ['sub', 'iss']]
        
        # Create SD-JWT builder with issuer
        builder = _marty_rs.SdJwtBuilder(issuer_did)
        
        # Set subject
        builder.set_subject(subject_did)
        
        # Set expiration
        builder.set_expiration(expiry_hours * 3600)  # Convert hours to seconds
        
        # Add claims with selective disclosure
        for key, value in claims.items():
            if key in selective_fields:
                builder.add_disclosable_claim(key, value)
            else:
                builder.add_claim(key, value)
        
        # Build the SD-JWT with signing
        sd_jwt_result = builder.build(private_key_pem)
        
        # Store in database
        holder = self._find_or_create_holder(subject_did)
        
        credential = Credential(
            type=CredentialType.SD_JWT,
            issuer_did=issuer_did,
            holder=holder,
            claims=claims,
            raw_credential=sd_jwt_result,
            status=CredentialStatus.ACTIVE,
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=expiry_hours),
            selective_disclosure_keys=selective_fields
        )
        
        self.db.add(credential)
        self.db.commit()
        
        # Derive public key PEM from private key for verification (avoids JWK PEM format issues)
        public_key_pem = self._private_pem_to_public_pem(private_key_pem)
        
        return {
            "credential": sd_jwt_result,
            "credential_id": credential.id,
            "format": "sd_jwt",
            "selective_fields": selective_fields,
            "public_key_pem": public_key_pem
        }
    
    def issue_mdoc(
        self,
        issuer_did: str,
        subject_did: str,
        doc_type: str,
        namespaces: Dict[str, Dict[str, Any]],
        expiry_hours: int = 24 * 365  # mDocs typically valid for 1 year
    ) -> Dict[str, Any]:
        """Issue an mDoc (ISO 18013-5 Mobile Document)"""
        # Generate issuer keys
        private_key_jwk, public_key = self._generate_keys()
        
        # Convert JWK to PEM
        private_key_pem = self._jwk_to_pem(private_key_jwk)
        
        # Calculate validity period (RFC3339 with Z)
        from datetime import timezone
        valid_from = datetime.utcnow().replace(tzinfo=timezone.utc)
        valid_until = valid_from + timedelta(hours=expiry_hours)
        signed = valid_from
        
        # Convert PEM key to DER format
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        key_obj = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None, backend=default_backend()
        )
        signing_key_der = key_obj.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create mDoc using Rust binding with correct parameters
        mdoc_result = _marty_rs.create_mdoc(
            doc_type=doc_type,
            namespaces=namespaces,  # Pass dict directly, not JSON string
            validity={
                "signed": signed.isoformat().replace("+00:00", "Z"),
                "valid_from": valid_from.isoformat().replace("+00:00", "Z"),
                "valid_until": valid_until.isoformat().replace("+00:00", "Z")
            },
            signing_key_der=list(signing_key_der),  # Convert bytes to list
            device_key_der=None,
            digest_algorithm=None  # Use default
        )
        
        # Store in database
        holder = self._find_or_create_holder(subject_did)
        
        # Flatten namespaces for claims storage
        flat_claims = {}
        for ns, ns_claims in namespaces.items():
            for key, value in ns_claims.items():
                flat_claims[f"{ns}.{key}"] = value
        
        credential = Credential(
            type=CredentialType.MDOC,
            issuer_did=issuer_did,
            holder=holder,
            claims=flat_claims,
            raw_credential=mdoc_result if isinstance(mdoc_result, str) else json.dumps(mdoc_result),
            status=CredentialStatus.ACTIVE,
            issued_at=datetime.utcnow(),
            expires_at=valid_until
        )
        
        self.db.add(credential)
        self.db.commit()
        
        return {
            "credential": mdoc_result,
            "credential_id": credential.id,
            "format": "mdoc",
            "doc_type": doc_type,
            "namespaces": list(namespaces.keys())
        }
    
    def create_sd_jwt_presentation(
        self,
        sd_jwt: str,
        disclosed_fields: List[str],
        nonce: Optional[str] = None,
        audience: Optional[str] = None
    ) -> str:
        """Create a presentation from an SD-JWT with selective disclosure"""
        presentation = _marty_rs.SdJwtPresentation(sd_jwt)
        
        # Add disclosure for selected fields by name
        for field in disclosed_fields:
            presentation.disclose_claim(field)
        
        # Create the presentation (with or without key binding)
        return presentation.create_presentation(
            holder_key_pem=None,  # No key binding for now
            nonce=nonce,
            audience=audience
        )
    
    def issue_openid4vp_request(
        self,
        verifier_did: str,
        requested_credentials: List[Dict[str, Any]],
        presentation_definition: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Issue an OpenID4VP presentation request"""
        request_id = f"vp_request_{datetime.utcnow().timestamp()}"
        
        request = {
            "request_id": request_id,
            "verifier": verifier_did,
            "requested_credentials": requested_credentials,
            "presentation_definition": presentation_definition,
            "created_at": datetime.utcnow().isoformat()
        }
        
        return request
    
    def get_credential(self, credential_id: int) -> Optional[Credential]:
        """Retrieve a credential by ID"""
        return self.db.query(Credential).filter(Credential.id == credential_id).first()
    
    def revoke_credential(self, credential_id: int) -> bool:
        """Revoke a credential"""
        credential = self.get_credential(credential_id)
        if credential:
            credential.status = CredentialStatus.REVOKED
            credential.revoked_at = datetime.utcnow()
            self.db.commit()
            return True
        return False
