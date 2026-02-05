"""Issuance service for creating digital identity credentials"""
import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

# Import Rust bindings
import _marty_rs

# Import Open Badges from marty_verification_py
try:
    from marty_verification_py import (
        open_badge_ob2_issue,
        open_badge_ob3_issue,
    )
    OPEN_BADGES_AVAILABLE = True
except ImportError:
    OPEN_BADGES_AVAILABLE = False
    open_badge_ob2_issue = None
    open_badge_ob3_issue = None

from marty_credentials.adapters.persistence.models import (
    Credential, CredentialType, CredentialStatus, Holder
)
from marty_credentials.infrastructure.observability.metrics import (
    credentials_issued_total,
    credential_issuance_duration_seconds,
)

# Optional status list service
try:
    from status_list.application.services.credential_status_service import CredentialStatusService
    STATUS_LIST_AVAILABLE = True
except ImportError:
    CredentialStatusService = None
    STATUS_LIST_AVAILABLE = False


class IssuanceService:
    """Service for issuing various types of digital identity credentials"""
    
    def __init__(self, db_session: Session, credential_status_service: Optional[CredentialStatusService] = None):
        self.db = db_session
        self.credential_status_service = credential_status_service
        
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
        start_time = time.time()
        
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
        
        # Record metrics
        duration = time.time() - start_time
        credential_issuance_duration_seconds.labels(
            credential_type=credential_type,
            format="w3c_vc"
        ).observe(duration)
        credentials_issued_total.labels(
            credential_type=credential_type,
            format="w3c_vc",
            issuer_id=issuer_did
        ).inc()
        
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
        mdoc_cbor_bytes = _marty_rs.create_mdoc(
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
        
        # The Rust function returns raw CBOR bytes
        # Wrap in dict with cbor_base64 for consistent handling
        import base64
        mdoc_result = {
            "cbor_base64": base64.b64encode(bytes(mdoc_cbor_bytes)).decode('utf-8'),
            "doc_type": doc_type,
            "format": "mdoc"
        }
        
        # Store as JSON to preserve the structure
        mdoc_stored = json.dumps(mdoc_result)
        
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
            raw_credential=mdoc_stored,
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
    
    def issue_open_badge_ob2(
        self,
        issuer_did: str,
        recipient_email: str,
        badge_class: Dict[str, Any],
        verification_method: str = "Ed25519",
        include_status_list: bool = False,
        issuer_jwk: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issue an Open Badge v2 credential with JWS signature"""
        if not OPEN_BADGES_AVAILABLE:
            raise RuntimeError("Open Badges support not available")
        
        # Generate P-256 keys (Ed25519 not available in _marty_rs yet)
        if issuer_jwk:
            jwk_str = json.dumps(issuer_jwk)
        else:
            jwk_str, _ = self._generate_keys()
        issuer_jwk = json.loads(jwk_str)
        
        # Build assertion
        assertion = {
            "@context": "https://w3id.org/openbadges/v2",
            "type": "Assertion",
            "recipient": {"type": "email", "identity": recipient_email, "hashed": False},
            "badge": {
                **badge_class,
                "issuer": {"id": issuer_did, "type": "Profile", "name": "Test Issuer"}
            },
            "issuedOn": datetime.utcnow().isoformat() + "Z",
            "verification": {"type": "JsonWebKey2020"}  # Use P-256 instead
        }
        
        # Add status list entries if requested
        if include_status_list and self.credential_status_service:
            import asyncio
            # Allocate status entries for this credential
            status_entries = asyncio.run(
                self.credential_status_service.allocate_credential_status(
                    credential_id=f"urn:credential:{recipient_email}:{datetime.utcnow().isoformat()}",
                    issuer_id=issuer_did,
                    include_revocation=True,
                    include_suspension=False,  # OB2 typically only uses revocation
                )
            )
            credential_status_entries = self.credential_status_service.build_credential_status_field(status_entries)
            
            # Add to assertion
            if credential_status_entries:
                assertion["credentialStatus"] = credential_status_entries
        
        # Issue via Rust
        issue_request = {
            "assertion": assertion, 
            "signing": {
                "jwk": issuer_jwk,
                "kid": f"{issuer_did}#key-1"
            }
        }
        result = json.loads(open_badge_ob2_issue(json.dumps(issue_request)))
        
        # Get or create holder
        holder = self.db.query(Holder).filter_by(did=recipient_email).first()
        if not holder:
            holder = Holder(did=recipient_email)
            self.db.add(holder)
            self.db.flush()
        
        # Store
        cred = Credential(
            type=CredentialType.OPEN_BADGE_V2,
            issuer_did=issuer_did,
            holder_id=holder.id,
            claims={"badge": badge_class},
            raw_credential=json.dumps(result["credential"]),
            status=CredentialStatus.ACTIVE,
            issued_at=datetime.utcnow()
        )
        self.db.add(cred)
        self.db.commit()
        
        return {"credential": result["credential"], "credential_id": cred.id}
    
    def issue_open_badge_ob3(
        self,
        issuer_did: str,
        recipient_did: str,
        badge_name: str,
        badge_description: str,
        verification_method_type: str = "JsonWebKey2020",
        include_status_list: bool = False,
        issuer_jwk: Optional[Dict[str, Any]] = None,
        x509_cert_pem: Optional[str] = None,
        x509_key_pem: Optional[str] = None
    ) -> Dict[str, Any]:
        """Issue an Open Badge v3 credential"""
        if not OPEN_BADGES_AVAILABLE:
            raise RuntimeError("Open Badges support not available")
        
        # Get or generate signing material
        if x509_cert_pem and x509_key_pem:
            # Use X509 certificate - convert RSA key to JWK format for signing
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import rsa
            import base64
            
            # Load the private key
            private_key = serialization.load_pem_private_key(
                x509_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            # Extract RSA components for JWK
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            private_numbers = private_key.private_numbers()
            
            # Convert to base64url encoding
            def int_to_base64url(n):
                byte_length = (n.bit_length() + 7) // 8
                return base64.urlsafe_b64encode(n.to_bytes(byte_length, 'big')).rstrip(b'=').decode('ascii')
            
            issuer_jwk = {
                "kty": "RSA",
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e),
                "d": int_to_base64url(private_numbers.d),
                "p": int_to_base64url(private_numbers.p),
                "q": int_to_base64url(private_numbers.q),
                "dp": int_to_base64url(private_numbers.dmp1),
                "dq": int_to_base64url(private_numbers.dmq1),
                "qi": int_to_base64url(private_numbers.iqmp)
            }
        elif issuer_jwk:
            issuer_jwk_str = json.dumps(issuer_jwk)
            issuer_jwk = json.loads(issuer_jwk_str)
        else:
            _, issuer_jwk_str = self._generate_keys()
            issuer_jwk = json.loads(issuer_jwk_str)
        
        # Build credential
        credential_data = {
            "@context": ["https://www.w3.org/ns/credentials/v2", 
                        "https://purl.imsglobal.org/spec/ob/v3p0/context.json"],
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "issuer": {"id": issuer_did, "type": "Profile"},
            "credentialSubject": {
                "id": recipient_did,
                "type": "AchievementSubject",
                "achievement": {
                    "id": f"https://example.com/achievements/{badge_name.lower().replace(' ', '-')}",
                    "type": "Achievement",
                    "name": badge_name,
                    "description": badge_description
                }
            }
        }
        
        # Add status list entries if requested
        if include_status_list and self.credential_status_service:
            import asyncio
            # Allocate status entries for this credential
            status_entries = asyncio.run(
                self.credential_status_service.allocate_credential_status(
                    credential_id=f"urn:credential:{recipient_did}:{datetime.utcnow().isoformat()}",
                    issuer_id=issuer_did,
                    include_revocation=True,
                    include_suspension=True,  # OB3 supports both revocation and suspension
                )
            )
            credential_status_entries = self.credential_status_service.build_credential_status_field(status_entries)
            
            # Add to credential
            if credential_status_entries:
                credential_data["credentialStatus"] = credential_status_entries
        
        # Issue via Rust
        issue_request = {
            "credential": credential_data,
            "signing": {"jwk": issuer_jwk, "verification_method": f"{issuer_did}#key-1"}
        }
        result = json.loads(open_badge_ob3_issue(json.dumps(issue_request)))
        
        # Get or create holder
        holder = self.db.query(Holder).filter_by(did=recipient_did).first()
        if not holder:
            holder = Holder(did=recipient_did)
            self.db.add(holder)
            self.db.flush()
        
        # Store
        cred = Credential(
            type=CredentialType.OPEN_BADGE_V3,
            issuer_did=issuer_did,
            holder_id=holder.id,
            claims={"badge_name": badge_name},
            raw_credential=json.dumps(result["credential"]),
            status=CredentialStatus.ACTIVE,
            issued_at=datetime.utcnow()
        )
        self.db.add(cred)
        self.db.commit()
        
        return {"credential": result["credential"], "credential_id": cred.id}

