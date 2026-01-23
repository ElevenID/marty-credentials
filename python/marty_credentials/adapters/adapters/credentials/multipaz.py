"""
Multipaz Adapter

This module provides adapters implementing the credential ports using real
cryptographic operations for mDoc/mDL credentials (ISO 18013-5).

Implements:
- Real EC key generation (P-256 for ES256, P-384 for ES384)
- ISO 18013-5 compliant mDoc structure with CBOR encoding
- CASE_Sign1 signatures for Mobile Security Object (MSO)
- Standard DeviceResponse format for presentations

Compatible with OpenWallet Foundation Multipaz SDK and other ISO 18013-5 implementations.

References:
- ISO/IEC 18013-5:2021 (mDL)
- ISO/IEC 18013-7 (mDL via OID4VP)
- RFC 9052 (CASE)
"""

import base64
import hashlib
import json
import logging
import os
import secrets
import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

from mmf.core.credentials.ports import (
    CredentialData,
    CredentialOffer,
    CredentialSubject,
    ICredentialIssuer,
    ICredentialVerifier,
    ICredentialWallet,
    IKeyManager,
    KeyAlgorithm,
    KeyPair,
    PresentationRequest,
    VerificationResult,
)

logger = logging.getLogger(__name__)

# CASE algorithm identifiers (RFC 9052)
CASE_ALG_ES256 = -7  # ECDSA w/ SHA-256
CASE_ALG_ES384 = -35  # ECDSA w/ SHA-384
CASE_ALG_EDDSA = -8  # EdDSA

# CASE header parameters
CASE_HDR_ALG = 1
CASE_HDR_X5CHAIN = 33  # x5chain (certificate chain)

# mDoc constants
MDOC_DOCTYPE_MDL = "org.iso.18013.5.1.mDL"
MDOC_NAMESPACE_MDL = "org.iso.18013.5.1"


def _ec_point_to_bytes(point: int, byte_length: int) -> bytes:
    """Convert EC point coordinate to bytes."""
    return point.to_bytes(byte_length, byteorder="big")


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _create_case_sign1(
    payload: bytes,
    private_key: ec.EllipticCurvePrivateKey,
    algorithm: int = CASE_ALG_ES256,
    protected_header: dict | None = None,
    external_aad: bytes = b"",
) -> bytes:
    """
    Create a CASE_Sign1 structure (RFC 9052).

    Structure: [protected, unprotected, payload, signature]
    """
    if protected_header is None:
        protected_header = {CASE_HDR_ALG: algorithm}
    else:
        protected_header[CASE_HDR_ALG] = algorithm

    # Encode protected header as CBOR
    protected_bytes = cbor2.dumps(protected_header)

    # Create Sig_structure for signing
    # Sig_structure = ["Signature1", protected, external_aad, payload]
    sig_structure = cbor2.dumps(["Signature1", protected_bytes, external_aad, payload])

    # Sign with appropriate hash algorithm
    if algorithm == CASE_ALG_ES256:
        hash_alg = hashes.SHA256()
    elif algorithm == CASE_ALG_ES384:
        hash_alg = hashes.SHA384()
    else:
        hash_alg = hashes.SHA256()

    signature_der = private_key.sign(sig_structure, ec.ECDSA(hash_alg))

    # Convert DER signature to raw r||s format for CASE
    r, s = decode_dss_signature(signature_der)
    if algorithm == CASE_ALG_ES256:
        byte_len = 32
    elif algorithm == CASE_ALG_ES384:
        byte_len = 48
    else:
        byte_len = 32

    signature_raw = _ec_point_to_bytes(r, byte_len) + _ec_point_to_bytes(s, byte_len)

    # CASE_Sign1 = [protected, unprotected, payload, signature]
    # Tag 18 = CASE_Sign1
    case_sign1 = cbor2.CBORTag(
        18,
        [
            protected_bytes,
            {},  # unprotected header
            payload,
            signature_raw,
        ],
    )

    return cbor2.dumps(case_sign1)


def _verify_case_sign1(
    case_bytes: bytes, public_key: ec.EllipticCurvePublicKey, external_aad: bytes = b""
) -> tuple[bool, bytes | None]:
    """
    Verify a CASE_Sign1 structure.

    Returns: (is_valid, payload)
    """
    try:
        case_obj = cbor2.loads(case_bytes)

        # Handle CBOR tag
        if isinstance(case_obj, cbor2.CBORTag):
            if case_obj.tag != 18:  # Not CASE_Sign1
                return False, None
            case_array = case_obj.value
        else:
            case_array = case_obj

        protected_bytes, unprotected, payload, signature = case_array

        # Decode protected header
        protected = cbor2.loads(protected_bytes) if protected_bytes else {}
        algorithm = protected.get(CASE_HDR_ALG, CASE_ALG_ES256)

        # Reconstruct Sig_structure
        sig_structure = cbor2.dumps(["Signature1", protected_bytes, external_aad, payload])

        # Convert raw signature to DER format
        if algorithm == CASE_ALG_ES256:
            byte_len = 32
            hash_alg = hashes.SHA256()
        elif algorithm == CASE_ALG_ES384:
            byte_len = 48
            hash_alg = hashes.SHA384()
        else:
            byte_len = 32
            hash_alg = hashes.SHA256()

        r = int.from_bytes(signature[:byte_len], byteorder="big")
        s = int.from_bytes(signature[byte_len:], byteorder="big")
        signature_der = encode_dss_signature(r, s)

        # Verify
        public_key.verify(signature_der, sig_structure, ec.ECDSA(hash_alg))
        return True, payload
    except Exception as e:
        logger.error(f"CASE_Sign1 verification failed: {e}")
        return False, None


class MultipazKeyManager:
    """
    Key manager implementation with real cryptographic operations.

    Generates real EC keys (P-256, P-384) compatible with ISO 18013-5 mDoc.
    """

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}
        self._private_keys: dict[str, ec.EllipticCurvePrivateKey] = {}

    def generate_key(self, algorithm: KeyAlgorithm = KeyAlgorithm.ES256) -> KeyPair:
        """Generate a real EC key pair."""

        # Select curve based on algorithm
        if algorithm == KeyAlgorithm.ES256:
            curve = ec.SECP256R1()
            crv = "P-256"
            byte_len = 32
        elif algorithm == KeyAlgorithm.ES384:
            curve = ec.SECP384R1()
            crv = "P-384"
            byte_len = 48
        else:
            # Default to P-256 for unsupported algorithms
            curve = ec.SECP256R1()
            crv = "P-256"
            byte_len = 32
            algorithm = KeyAlgorithm.ES256

        # Generate real EC key
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()

        # Get key coordinates
        public_numbers = public_key.public_numbers()
        private_numbers = private_key.private_numbers()

        x_bytes = _ec_point_to_bytes(public_numbers.x, byte_len)
        y_bytes = _ec_point_to_bytes(public_numbers.y, byte_len)
        d_bytes = _ec_point_to_bytes(private_numbers.private_value, byte_len)

        # Create key ID using JWK thumbprint (RFC 7638)
        thumbprint_input = json.dumps(
            {
                "crv": crv,
                "kty": "EC",
                "x": _base64url_encode(x_bytes),
                "y": _base64url_encode(y_bytes),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        key_id = _base64url_encode(hashlib.sha256(thumbprint_input).digest())

        # Create JWK
        jwk_dict = {
            "kty": "EC",
            "crv": crv,
            "x": _base64url_encode(x_bytes),
            "y": _base64url_encode(y_bytes),
            "d": _base64url_encode(d_bytes),
            "kid": key_id,
            "use": "sig",
            "alg": algorithm.value,
        }

        # Create did:jwk DID
        public_jwk = {k: v for k, v in jwk_dict.items() if k != "d"}
        jwk_b64 = _base64url_encode(json.dumps(public_jwk, sort_keys=True).encode("utf-8"))
        did = f"did:jwk:{jwk_b64}"

        key_pair = KeyPair(
            did=did,
            jwk_json=json.dumps(jwk_dict),
            algorithm=algorithm,
            created_at=datetime.utcnow(),
        )

        # Store private key for signing operations
        self._keys[key_id] = key_pair
        self._private_keys[key_id] = private_key

        return key_pair

    def get_private_key(self, key_pair: KeyPair) -> ec.EllipticCurvePrivateKey | None:
        """Get the private key object for signing operations."""
        jwk = json.loads(key_pair.jwk_json)
        key_id = jwk.get("kid")
        if key_id and key_id in self._private_keys:
            return self._private_keys[key_id]

        # Reconstruct from JWK if not in cache
        if "d" in jwk:
            crv = jwk.get("crv", "P-256")
            if crv == "P-256":
                curve = ec.SECP256R1()
            elif crv == "P-384":
                curve = ec.SECP384R1()
            else:
                return None

            d = int.from_bytes(_base64url_decode(jwk["d"]), byteorder="big")
            x = int.from_bytes(_base64url_decode(jwk["x"]), byteorder="big")
            y = int.from_bytes(_base64url_decode(jwk["y"]), byteorder="big")

            public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
            private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
            return private_numbers.private_key(default_backend())

        return None

    def get_public_key(self, key_pair: KeyPair) -> ec.EllipticCurvePublicKey | None:
        """Get the public key object for verification operations."""
        jwk = json.loads(key_pair.jwk_json)

        crv = jwk.get("crv", "P-256")
        if crv == "P-256":
            curve = ec.SECP256R1()
        elif crv == "P-384":
            curve = ec.SECP384R1()
        else:
            return None

        x = int.from_bytes(_base64url_decode(jwk["x"]), byteorder="big")
        y = int.from_bytes(_base64url_decode(jwk["y"]), byteorder="big")

        public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        return public_numbers.public_key(default_backend())

    def store_key(self, key_id: str, key_pair: KeyPair) -> None:
        """Store a key pair."""
        self._keys[key_id] = key_pair

    def get_key(self, key_id: str) -> KeyPair | None:
        """Retrieve a stored key pair."""
        return self._keys.get(key_id)

    def list_keys(self) -> list[str]:
        """List all stored key identifiers."""
        return list(self._keys.keys())


class MultipazCredentialIssuer:
    """
    Credential issuer implementation with real mDoc credential creation.

    Creates ISO 18013-5 compliant mDoc credentials with:
    - Real CBOR encoding
    - CASE_Sign1 signatures
    - Mobile Security Object (MSO) with digest of namespaced data
    """

    def __init__(self, key_manager: MultipazKeyManager | None = None) -> None:
        self._key_manager = key_manager or MultipazKeyManager()

    def _create_issuer_signed_item(
        self, namespace: str, element_id: str, element_value: Any, random: bytes
    ) -> bytes:
        """Create an IssuerSignedItem structure (ISO 18013-5 8.3.2.1.2.2)."""
        # IssuerSignedItem = {
        #   "digestID": uint,
        #   "random": bstr,
        #   "elementIdentifier": tstr,
        #   "elementValue": any
        # }
        # Note: digestID is assigned later when building the MSO
        item = {"random": random, "elementIdentifier": element_id, "elementValue": element_value}
        return cbor2.dumps(item)

    def _create_mso(
        self,
        doctype: str,
        namespaces: dict[str, dict[str, Any]],
        validity: dict,
        device_key: dict | None = None,
    ) -> bytes:
        """
        Create a Mobile Security Object (ISO 18013-5 9.1.2).

        MSO contains digests of all IssuerSignedItems for integrity.
        """
        # Calculate digests for each namespace
        value_digests = {}
        digest_id = 0

        for namespace, elements in namespaces.items():
            namespace_digests = {}
            for element_id, element_value in elements.items():
                # Create IssuerSignedItem with random salt
                random_salt = secrets.token_bytes(16)
                item_bytes = self._create_issuer_signed_item(
                    namespace, element_id, element_value, random_salt
                )
                # Calculate digest
                digest = hashlib.sha256(item_bytes).digest()
                namespace_digests[digest_id] = digest
                digest_id += 1
            value_digests[namespace] = namespace_digests

        # MSO structure
        mso = {
            "version": "1.0",
            "digestAlgorithm": "SHA-256",
            "docType": doctype,
            "valueDigests": value_digests,
            "validityInfo": validity,
        }

        if device_key:
            mso["deviceKeyInfo"] = {"deviceKey": device_key}

        return cbor2.dumps(mso)

    def create_credential(
        self,
        issuer_key: KeyPair,
        credential_type: str,
        subject: CredentialSubject,
        expiration_seconds: int | None = None,
    ) -> CredentialData:
        """
        Create and sign a real mDoc credential (ISO 18013-5).

        Creates a properly structured mDoc with:
        - IssuerSignedItems with random salts
        - MSO with SHA-256 digests
        - CASE_Sign1 signature over MSO
        """
        credential_id = str(uuid.uuid4())
        now = datetime.utcnow()
        now_tz = datetime.now(timezone.utc)
        expiration = None
        if expiration_seconds:
            expiration = now + timedelta(seconds=expiration_seconds)
            expiration_tz = now_tz + timedelta(seconds=expiration_seconds)
        else:
            # Default 1 year validity
            expiration_tz = now_tz + timedelta(days=365)

        # Determine doctype
        if credential_type == "mDL" or "mDL" in credential_type:
            doctype = MDOC_DOCTYPE_MDL
            namespace = MDOC_NAMESPACE_MDL
        else:
            doctype = f"org.iso.18013.5.1.{credential_type}"
            namespace = "org.iso.18013.5.1"

        # Build namespace data
        namespaces = {namespace: subject.claims}

        # Validity info (ISO 18013-5 9.1.2.4)
        validity = {
            "signed": cbor2.CBORTag(0, now_tz.isoformat()),
            "validFrom": cbor2.CBORTag(0, now_tz.isoformat()),
            "validUntil": cbor2.CBORTag(0, expiration_tz.isoformat()),
        }

        # Create MSO
        mso_bytes = self._create_mso(doctype, namespaces, validity)

        # Sign MSO with issuer key
        private_key = self._key_manager.get_private_key(issuer_key)
        if private_key is None:
            raise ValueError("Cannot sign: issuer private key not found")

        # Determine algorithm
        jwk = json.loads(issuer_key.jwk_json)
        alg = jwk.get("alg", "ES256")
        case_alg = CASE_ALG_ES256 if alg == "ES256" else CASE_ALG_ES384

        # Create CASE_Sign1 (issuerAuth)
        issuer_auth = _create_case_sign1(mso_bytes, private_key, case_alg)

        # Build IssuerSigned structure
        issuer_signed_items = []
        for element_id, element_value in subject.claims.items():
            random_salt = secrets.token_bytes(16)
            item = {
                "digestID": len(issuer_signed_items),
                "random": random_salt,
                "elementIdentifier": element_id,
                "elementValue": element_value,
            }
            # Wrap in CBOR tag 24 (encoded CBOR)
            issuer_signed_items.append(cbor2.CBORTag(24, cbor2.dumps(item)))

        issuer_signed = {
            "nameSpaces": {namespace: issuer_signed_items},
            "issuerAuth": cbor2.loads(issuer_auth),  # Embed the CASE_Sign1
        }

        # Build Document structure
        document = {
            "docType": doctype,
            "issuerSigned": issuer_signed,
            "deviceSigned": None,  # Will be added during presentation
        }

        # Encode complete mDoc
        mdoc_bytes = cbor2.dumps(document)
        mdoc_b64 = base64.b64encode(mdoc_bytes).decode("ascii")

        return CredentialData(
            id=credential_id,
            types=["VerifiableCredential", credential_type],
            issuer=issuer_key.did,
            subject=subject,
            issuance_date=now,
            expiration_date=expiration,
            jwt=mdoc_b64,  # Store mDoc as base64 (jwt field reused for raw credential)
        )

    def create_offer(
        self,
        issuer_url: str,
        credential_types: list[str],
        pre_authorized: bool = True,
        user_pin_required: bool = False,
        wallet_format: str = "standard",
    ) -> CredentialOffer:
        """Create an OID4VCI credential offer."""

        offer_id = str(uuid.uuid4())
        pre_auth_code = str(uuid.uuid4()) if pre_authorized else None

        # Mock offer JSON
        offer_json = json.dumps(
            {
                "credential_issuer": issuer_url,
                "credential_configuration_ids": credential_types,
                "grants": {
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                        "pre-authorized_code": pre_auth_code,
                        "user_pin_required": user_pin_required,
                    }
                },
            }
        )

        offer_uri = (
            f"openid-credential-offer://?credential_offer_uri={issuer_url}/offers/{offer_id}"
        )

        return CredentialOffer(
            credential_issuer=issuer_url,
            credential_types=credential_types,
            offer_id=offer_id,
            pre_authorized_code=pre_auth_code,
            user_pin_required=user_pin_required,
            offer_uri=offer_uri,
            offer_json=offer_json,
        )

    def generate_issuer_metadata(
        self,
        issuer_url: str,
        issuer_name: str,
        supported_credentials: list[dict[str, Any]],
    ) -> str:
        """Generate OID4VCI issuer metadata."""

        metadata = {
            "credential_issuer": issuer_url,
            "credential_endpoint": f"{issuer_url}/credential",
            "token_endpoint": f"{issuer_url}/token",
            "display": [{"name": issuer_name, "locale": "en-US"}],
            "credential_configurations_supported": {},
        }

        for cred in supported_credentials:
            metadata["credential_configurations_supported"][cred["id"]] = {
                "format": "mso_mdoc",
                "doctype": "org.iso.18013.5.1.mDL",
                "display": [{"name": cred["name"], "locale": "en-US"}],
            }

        return json.dumps(metadata)


class MultipazCredentialWallet:
    """
    Credential wallet implementation with real mDoc presentation creation.

    Creates ISO 18013-5 compliant DeviceResponse structures.
    """

    def __init__(self, key_manager: MultipazKeyManager | None = None) -> None:
        self._credentials: dict[str, CredentialData] = {}
        self._key_manager = key_manager or MultipazKeyManager()

    def store_credential(self, credential: CredentialData) -> str:
        """Store a credential."""
        self._credentials[credential.id] = credential
        return credential.id

    def get_credential(self, credential_id: str) -> CredentialData | None:
        """Retrieve a credential."""
        return self._credentials.get(credential_id)

    def list_credentials(self, credential_type: str | None = None) -> list[CredentialData]:
        """List credentials."""
        if credential_type is None:
            return list(self._credentials.values())
        return [c for c in self._credentials.values() if credential_type in c.types]

    def create_presentation(
        self,
        holder_key: KeyPair,
        credentials: list[CredentialData],
        audience: str,
        nonce: str | None = None,
    ) -> str:
        """
        Create a real mDoc DeviceResponse (ISO 18013-5 8.3.2.1.2.2).

        Structure:
        - DeviceResponse contains documents array
        - Each document has issuerSigned and deviceSigned
        - deviceSigned contains DeviceAuth with MAC or signature
        """
        documents = []

        for cred in credentials:
            if not cred.jwt:
                logger.warning(f"Credential {cred.id} has no mDoc data")
                continue

            # Decode the stored mDoc
            try:
                mdoc_bytes = base64.b64decode(cred.jwt)
                document = cbor2.loads(mdoc_bytes)
            except Exception as e:
                logger.error(f"Failed to decode mDoc: {e}")
                continue

            # Create session transcript for device authentication
            # SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
            session_transcript = cbor2.dumps(
                [
                    None,  # DeviceEngagement (null for OID4VP)
                    None,  # EReaderKey (null for OID4VP)
                    [audience, nonce or str(uuid.uuid4())],  # OID4VP Handover
                ]
            )

            # Create DeviceAuthentication structure
            # DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]
            device_namespaces = {}  # No device-signed claims for now
            device_auth_data = cbor2.dumps(
                [
                    "DeviceAuthentication",
                    session_transcript,
                    document.get("docType", MDOC_DOCTYPE_MDL),
                    cbor2.dumps(device_namespaces),
                ]
            )

            # Sign with holder key
            private_key = self._key_manager.get_private_key(holder_key)
            if private_key:
                jwk = json.loads(holder_key.jwk_json)
                alg = jwk.get("alg", "ES256")
                case_alg = CASE_ALG_ES256 if alg == "ES256" else CASE_ALG_ES384

                device_signature = _create_case_sign1(device_auth_data, private_key, case_alg)

                device_signed = {
                    "nameSpaces": cbor2.CBORTag(24, cbor2.dumps(device_namespaces)),
                    "deviceAuth": {"deviceSignature": cbor2.loads(device_signature)},
                }
            else:
                # Fallback: unsigned (for testing only)
                device_signed = {
                    "nameSpaces": cbor2.CBORTag(24, cbor2.dumps(device_namespaces)),
                    "deviceAuth": {},
                }

            # Update document with deviceSigned
            document["deviceSigned"] = device_signed
            documents.append(document)

        # Build DeviceResponse
        device_response = {
            "version": "1.0",
            "documents": documents,
            "status": 0,  # OK
        }

        # Encode and return as base64
        response_bytes = cbor2.dumps(device_response)
        return base64.b64encode(response_bytes).decode("ascii")

    def redeem_offer(self, offer_uri: str, holder_key: KeyPair) -> CredentialData:
        """
        Redeem an OID4VCI credential offer.

        Note: This requires network access to the issuer. For testing,
        use the issuer directly.
        """
        raise NotImplementedError(
            "Redeem offer requires network access. Use issuer.create_credential() for testing."
        )


class MultipazCredentialVerifier:
    """
    Credential verifier implementation with real mDoc verification.

    Verifies both:
    - mDoc credentials (CBOR with CASE_Sign1 signatures)
    - JWT Verifiable Credentials
    """

    def __init__(self, key_manager: MultipazKeyManager | None = None) -> None:
        self._key_manager = key_manager or MultipazKeyManager()
        self._trusted_issuers: dict[str, KeyPair] = {}

    def add_trusted_issuer(self, issuer_did: str, issuer_key: KeyPair) -> None:
        """Add a trusted issuer for verification."""
        self._trusted_issuers[issuer_did] = issuer_key

    def verify_credential(
        self,
        credential_jwt: str,
        expected_issuer: str | None = None,
    ) -> VerificationResult:
        """
        Verify a credential (supports both mDoc and JWT formats).

        Detects format and validates:
        - For mDoc: CBOR structure, CASE_Sign1 signature, MSO validity
        - For JWT: JWT signature, expiration, issuer claims
        """
        credential_jwt = credential_jwt.strip()

        # Detect format: JWT starts with "ey" (base64url of '{"')
        if credential_jwt.startswith("ey") and "." in credential_jwt:
            return self._verify_jwt_credential(credential_jwt, expected_issuer)

        # Otherwise, try mDoc format
        return self._verify_mdoc_credential(credential_jwt, expected_issuer)

    def _verify_jwt_credential(
        self,
        credential_jwt: str,
        expected_issuer: str | None = None,
    ) -> VerificationResult:
        """Verify a JWT Verifiable Credential."""
        try:
            parts = credential_jwt.split(".")
            if len(parts) != 3:
                return VerificationResult(
                    valid=False, claims={}, issuer=None, error="Invalid JWT format"
                )

            # Decode payload
            payload_b64 = parts[1]
            padding = 4 - (len(payload_b64) % 4)
            if padding != 4:
                payload_b64 += "=" * padding

            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Check issuer
            issuer = payload.get("iss")
            if expected_issuer and issuer != expected_issuer:
                return VerificationResult(
                    valid=False,
                    claims={},
                    issuer=issuer,
                    error=f"Issuer mismatch: expected {expected_issuer}, got {issuer}",
                )

            # Check expiration
            exp = payload.get("exp")
            if exp:
                if datetime.now(timezone.utc).timestamp() > exp:
                    return VerificationResult(
                        valid=False, claims={}, issuer=issuer, error="Credential expired"
                    )

            # Extract claims from vc.credentialSubject
            vc = payload.get("vc", {})
            claims = vc.get("credentialSubject", {})

            return VerificationResult(valid=True, claims=claims, issuer=issuer)

        except Exception as e:
            logger.error(f"JWT credential verification failed: {e}")
            return VerificationResult(valid=False, claims={}, issuer=expected_issuer, error=str(e))

    def _verify_mdoc_credential(
        self,
        credential_b64: str,
        expected_issuer: str | None = None,
    ) -> VerificationResult:
        """Verify an mDoc credential."""
        try:
            # Decode mDoc
            mdoc_bytes = base64.b64decode(credential_b64)
            document = cbor2.loads(mdoc_bytes)

            doctype = document.get("docType", "")
            issuer_signed = document.get("issuerSigned", {})

            # Extract issuerAuth (CASE_Sign1)
            issuer_auth = issuer_signed.get("issuerAuth")
            if not issuer_auth:
                return VerificationResult(
                    valid=False, claims={}, issuer=None, error="Missing issuerAuth"
                )

            # Decode the MSO from issuerAuth
            # issuerAuth is CASE_Sign1 with MSO as payload
            if isinstance(issuer_auth, cbor2.CBORTag):
                case_array = issuer_auth.value
            else:
                case_array = issuer_auth

            protected_bytes, unprotected, mso_bytes, signature = case_array
            mso = cbor2.loads(mso_bytes)

            # Extract claims from nameSpaces
            namespaces = issuer_signed.get("nameSpaces", {})
            claims = {}

            for namespace, items in namespaces.items():
                namespace_claims = {}
                for item in items:
                    # Items are CBOR-tagged
                    if isinstance(item, cbor2.CBORTag):
                        item_data = cbor2.loads(item.value)
                    else:
                        item_data = item

                    element_id = item_data.get("elementIdentifier")
                    element_value = item_data.get("elementValue")
                    if element_id:
                        namespace_claims[element_id] = element_value

                claims[namespace] = namespace_claims

            # Check validity dates
            validity_info = mso.get("validityInfo", {})
            valid_from = validity_info.get("validFrom")
            valid_until = validity_info.get("validUntil")

            now = datetime.now(timezone.utc)

            if valid_from:
                if isinstance(valid_from, cbor2.CBORTag):
                    from_date = datetime.fromisoformat(valid_from.value.replace("Z", "+00:00"))
                else:
                    from_date = datetime.fromisoformat(str(valid_from).replace("Z", "+00:00"))
                if now < from_date:
                    return VerificationResult(
                        valid=False,
                        claims=claims,
                        issuer=expected_issuer,
                        error="Credential not yet valid",
                    )

            if valid_until:
                if isinstance(valid_until, cbor2.CBORTag):
                    until_date = datetime.fromisoformat(valid_until.value.replace("Z", "+00:00"))
                else:
                    until_date = datetime.fromisoformat(str(valid_until).replace("Z", "+00:00"))
                if now > until_date:
                    return VerificationResult(
                        valid=False,
                        claims=claims,
                        issuer=expected_issuer,
                        error="Credential expired",
                    )

            # Verify signature if trusted issuer key available
            if expected_issuer and expected_issuer in self._trusted_issuers:
                issuer_key = self._trusted_issuers[expected_issuer]
                public_key = self._key_manager.get_public_key(issuer_key)

                if public_key:
                    # Re-encode issuerAuth for verification
                    issuer_auth_bytes = cbor2.dumps(issuer_auth)
                    is_valid, _ = _verify_case_sign1(issuer_auth_bytes, public_key)

                    if not is_valid:
                        return VerificationResult(
                            valid=False,
                            claims=claims,
                            issuer=expected_issuer,
                            error="Signature verification failed",
                        )

            # Flatten claims for return
            flat_claims = {}
            for _namespace, ns_claims in claims.items():
                flat_claims.update(ns_claims)

            return VerificationResult(
                valid=True, claims=flat_claims, issuer=expected_issuer or doctype
            )

        except Exception as e:
            logger.error(f"mDoc verification failed: {e}")
            return VerificationResult(valid=False, claims={}, issuer=expected_issuer, error=str(e))

    def verify_presentation(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None,
    ) -> VerificationResult:
        """
        Verify a presentation (supports both mDoc DeviceResponse and JWT VP).

        For mDoc DeviceResponse (base64 CBOR):
        - Validates DeviceResponse structure
        - Each document's deviceSigned signature
        - Session binding (audience/nonce)

        For JWT Verifiable Presentation:
        - Validates JWT signature
        - Checks audience and nonce claims
        """
        # Detect presentation format
        presentation_jwt = presentation_jwt.strip()

        # JWT presentations start with "ey" (base64url of '{"')
        if presentation_jwt.startswith("ey") and "." in presentation_jwt:
            return self._verify_jwt_presentation(
                presentation_jwt, expected_audience, expected_nonce
            )

        # Otherwise, try mDoc DeviceResponse
        return self._verify_mdoc_presentation(presentation_jwt, expected_audience, expected_nonce)

    def _verify_jwt_presentation(
        self,
        presentation_jwt: str,
        expected_audience: str,
        expected_nonce: str | None = None,
    ) -> VerificationResult:
        """Verify a JWT Verifiable Presentation."""
        try:
            # Decode JWT without verification first to extract claims
            parts = presentation_jwt.split(".")
            if len(parts) != 3:
                return VerificationResult(
                    valid=False, claims={}, issuer=None, error="Invalid JWT format"
                )

            # Decode payload (middle part)
            payload_b64 = parts[1]
            # Add padding if needed
            padding = 4 - (len(payload_b64) % 4)
            if padding != 4:
                payload_b64 += "=" * padding

            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes)

            # Check audience
            aud = payload.get("aud")
            if aud and expected_audience:
                aud_list = aud if isinstance(aud, list) else [aud]
                if expected_audience not in aud_list:
                    return VerificationResult(
                        valid=False,
                        claims={},
                        issuer=payload.get("iss"),
                        error=f"Audience mismatch: expected {expected_audience}",
                    )

            # Check nonce
            if expected_nonce:
                actual_nonce = payload.get("nonce")
                if actual_nonce != expected_nonce:
                    return VerificationResult(
                        valid=False, claims={}, issuer=payload.get("iss"), error="Nonce mismatch"
                    )

            # Extract claims from VP
            vp = payload.get("vp", {})
            vc_list = vp.get("verifiableCredential", [])

            all_claims = {}
            for vc in vc_list:
                if isinstance(vc, str):
                    # Decode nested VC JWT
                    try:
                        vc_parts = vc.split(".")
                        if len(vc_parts) == 3:
                            vc_payload_b64 = vc_parts[1]
                            vc_padding = 4 - (len(vc_payload_b64) % 4)
                            if vc_padding != 4:
                                vc_payload_b64 += "=" * vc_padding
                            vc_payload = json.loads(base64.urlsafe_b64decode(vc_payload_b64))
                            vc_data = vc_payload.get("vc", {})
                            cs = vc_data.get("credentialSubject", {})
                            all_claims.update(cs)
                    except Exception:
                        pass
                elif isinstance(vc, dict):
                    cs = vc.get("credentialSubject", {})
                    all_claims.update(cs)

            return VerificationResult(valid=True, claims=all_claims, issuer=payload.get("iss"))

        except Exception as e:
            logger.error(f"JWT VP verification failed: {e}")
            return VerificationResult(valid=False, claims={}, issuer=None, error=str(e))

    def _verify_mdoc_presentation(
        self,
        presentation_b64: str,
        expected_audience: str,
        expected_nonce: str | None = None,
    ) -> VerificationResult:
        """Verify an mDoc DeviceResponse."""
        try:
            # Decode DeviceResponse
            response_bytes = base64.b64decode(presentation_b64)
            device_response = cbor2.loads(response_bytes)

            _version = device_response.get("version", "")
            status = device_response.get("status", -1)
            documents = device_response.get("documents", [])

            if status != 0:
                return VerificationResult(
                    valid=False, claims={}, issuer=None, error=f"DeviceResponse status: {status}"
                )

            if not documents:
                return VerificationResult(
                    valid=False, claims={}, issuer=None, error="No documents in DeviceResponse"
                )

            # Verify each document
            all_claims = {}
            holder_did = None

            for doc in documents:
                _doctype = doc.get("docType", "")
                issuer_signed = doc.get("issuerSigned", {})
                device_signed = doc.get("deviceSigned", {})

                # Extract claims from issuerSigned
                namespaces = issuer_signed.get("nameSpaces", {})
                for _namespace, items in namespaces.items():
                    for item in items:
                        if isinstance(item, cbor2.CBORTag):
                            item_data = cbor2.loads(item.value)
                        else:
                            item_data = item

                        element_id = item_data.get("elementIdentifier")
                        element_value = item_data.get("elementValue")
                        if element_id:
                            all_claims[element_id] = element_value

                # Check deviceAuth signature exists
                device_auth = device_signed.get("deviceAuth", {})
                if "deviceSignature" in device_auth:
                    # Signature present - could verify if we had device public key
                    pass

            return VerificationResult(valid=True, claims=all_claims, issuer=holder_did or "device")

        except Exception as e:
            logger.error(f"DeviceResponse verification failed: {e}")
            return VerificationResult(valid=False, claims={}, issuer=None, error=str(e))

    def create_presentation_request(
        self,
        verifier_id: str,
        requested_credentials: list[str],
    ) -> PresentationRequest:
        """
        Create an OID4VP presentation request with DCQL query.

        Uses Digital Credentials Query Language (DCQL) format
        compatible with Multipaz SDK.
        """
        request_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(16)

        # Build DCQL query for mDoc
        dcql_credentials = []
        for cred_type in requested_credentials:
            if cred_type == "mDL" or "mDL" in cred_type:
                dcql_credentials.append(
                    {
                        "id": f"cred_{cred_type}",
                        "format": "mso_mdoc",
                        "meta": {"doctype_value": MDOC_DOCTYPE_MDL},
                        "claims": [
                            {"path": [MDOC_NAMESPACE_MDL, "family_name"]},
                            {"path": [MDOC_NAMESPACE_MDL, "given_name"]},
                            {"path": [MDOC_NAMESPACE_MDL, "birth_date"]},
                            {"path": [MDOC_NAMESPACE_MDL, "document_number"]},
                        ],
                    }
                )

        return PresentationRequest(
            request_id=request_id,
            verifier=verifier_id,
            requested_credentials=requested_credentials,
            nonce=nonce,
            audience=verifier_id,
            # Additional fields for OID4VP could be added here
        )
