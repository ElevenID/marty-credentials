use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Error module (only for python - has tracing dependencies)
#[cfg(feature = "python")]
mod error;

// Status list module (only for python - has PyO3 dependencies)
#[cfg(feature = "python")]
mod status_list;

// mDoc issuance and presentation module (only for python)
#[cfg(feature = "python")]
pub mod mdoc;

// SD-JWT module (only for python - has PyO3 and sd-jwt-rs dependencies)
#[cfg(feature = "python")]
mod sd_jwt;

// WASM module (only compiled with wasm feature)
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "python")]
pub use error::{init_tracing, MartyError, MartyResult};

// Re-export marty-verification types for Rust consumers (only when python feature enabled)
#[cfg(feature = "python")]
pub use marty_verification::{
    AuthStatus, ChainStatus, CscaRegistry, EmrtdVerificationResult, HashStatus, IacaRegistry,
    Jurisdiction, MdlVerificationResult, SignatureStatus, TrustAnchor, TrustPurpose, TrustRegistry,
};

/// High-level OID4VCI credential types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(flatten)]
    pub claims: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredentialData {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: HashMap<String, serde_json::Value>,
}

// =============================================================================
// Python bindings (only compiled with python feature)
// =============================================================================

#[cfg(feature = "python")]
mod python_bindings {
    use super::*;
    use pyo3::prelude::*;
    use ssi::crypto::{AlgorithmInstance, SecretKey};
    use ssi::jwk::{Params, JWK};

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    pub fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
        Ok((a + b).to_string())
    }

    /// Returns the version of the SSI library being used.
    #[pyfunction]
    pub fn get_ssi_version() -> PyResult<String> {
        Ok("0.12.0".to_string())
    }

    /// Checks if isomdl is linked.
    #[pyfunction]
    pub fn check_isomdl() -> PyResult<String> {
        let _ = isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry::default();
        Ok("isomdl is linked".to_string())
    }

    /// Generates a new Ed25519 key and returns (did, jwk_json)
    #[pyfunction]
    pub fn generate_did_key() -> PyResult<(String, String)> {
        let jwk = JWK::generate_ed25519()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

        let pk_bytes = if let Params::OKP(params) = &jwk.params {
            &params.public_key.0
        } else {
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Invalid key type",
            ));
        };

        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend(pk_bytes);

        let did = format!("did:key:z{}", bs58::encode(multicodec).into_string());
        let jwk_str = serde_json::to_string(&jwk)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        Ok((did, jwk_str))
    }

    /// Generates a new P-256 key and returns (did, jwk_json) - preferred for OID4VCI
    #[pyfunction]
    pub fn generate_p256_key() -> PyResult<(String, String)> {
        let jwk = JWK::generate_p256();
        let jwk_str = serde_json::to_string(&jwk)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(jwk_str.as_bytes());
        let did = format!("did:jwk:{}", encoded);
        Ok((did, jwk_str))
    }

    /// Generates a new P-384 key and returns (did, jwk_json) - for ES384
    #[pyfunction]
    pub fn generate_p384_key() -> PyResult<(String, String)> {
        let jwk = JWK::generate_p384();
        let jwk_str = serde_json::to_string(&jwk)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(jwk_str.as_bytes());
        let did = format!("did:jwk:{}", encoded);
        Ok((did, jwk_str))
    }

    /// Generates a new RSA key and returns (did, jwk_json)
    /// key_size: RSA key size in bits (2048, 3072, or 4096). Default is 2048 (fastest).
    /// use_pss: If true, marks the key for RSA-PSS (PS256/384/512). If false, PKCS#1 v1.5 (RS256/384/512).
    #[pyfunction]
    #[pyo3(signature = (key_size=2048, use_pss=false))]
    pub fn generate_rsa_key(key_size: Option<u32>, use_pss: Option<bool>) -> PyResult<(String, String)> {
        use ssi::jwk::{Algorithm, RSAParams};
        use rsa::{RsaPrivateKey, traits::PublicKeyParts, traits::PrivateKeyParts};
        use rand::rngs::OsRng;

        let bits = key_size.unwrap_or(2048);
        if bits != 2048 && bits != 3072 && bits != 4096 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "key_size must be 2048, 3072, or 4096",
            ));
        }

        let private_key = RsaPrivateKey::new(&mut OsRng, bits as usize)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("RSA key generation failed: {}", e)))?;

        // Convert to JWK format (SSI 0.12 uses descriptive field names)
        let n = private_key.n().to_bytes_be();
        let e = private_key.e().to_bytes_be();
        let d = private_key.d().to_bytes_be();
        let primes = private_key.primes();
        let p = primes.first().map(|p| p.to_bytes_be()).unwrap_or_default();
        let q = primes.get(1).map(|q| q.to_bytes_be()).unwrap_or_default();

        let rsa_params = RSAParams {
            modulus: Some(ssi::jwk::Base64urlUInt(n)),
            exponent: Some(ssi::jwk::Base64urlUInt(e)),
            private_exponent: Some(ssi::jwk::Base64urlUInt(d)),
            first_prime_factor: Some(ssi::jwk::Base64urlUInt(p)),
            second_prime_factor: Some(ssi::jwk::Base64urlUInt(q)),
            first_prime_factor_crt_exponent: None,
            second_prime_factor_crt_exponent: None,
            first_crt_coefficient: None,
            other_primes_info: None,
        };

        let alg = if use_pss.unwrap_or(false) {
            match bits {
                2048 => Algorithm::PS256,
                3072 => Algorithm::PS384,
                4096 => Algorithm::PS512,
                _ => Algorithm::PS256,
            }
        } else {
            match bits {
                2048 => Algorithm::RS256,
                3072 => Algorithm::RS384,
                4096 => Algorithm::RS512,
                _ => Algorithm::RS256,
            }
        };

        let jwk = JWK {
            params: ssi::jwk::Params::RSA(rsa_params),
            public_key_use: None,
            key_operations: None,
            algorithm: Some(alg),
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };

        let jwk_str = serde_json::to_string(&jwk)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(jwk_str.as_bytes());
        let did = format!("did:jwk:{}", encoded);
        Ok((did, jwk_str))
    }

    /// Extract SecretKey from JWK for signing
    fn jwk_to_secret_key(jwk: &JWK) -> Result<SecretKey, String> {
        match &jwk.params {
            Params::OKP(params) => {
                if let Some(d) = &params.private_key {
                    SecretKey::new_ed25519(&d.0)
                        .map_err(|e| format!("Invalid Ed25519 key: {:?}", e))
                } else {
                    Err("Missing private key (d) in OKP JWK".to_string())
                }
            }
            Params::EC(params) => {
                if let Some(d) = &params.ecc_private_key {
                    match params.curve.as_deref() {
                        Some("P-256") => SecretKey::new_p256(&d.0)
                            .map_err(|e| format!("Invalid P-256 key: {:?}", e)),
                        Some("secp256k1") => SecretKey::new_secp256k1(&d.0)
                            .map_err(|e| format!("Invalid secp256k1 key: {:?}", e)),
                        curve => Err(format!(
                            "Unsupported curve: {:?}. Supported: P-256, secp256k1",
                            curve
                        )),
                    }
                } else {
                    Err("Missing private key (d) in EC JWK".to_string())
                }
            }
            _ => Err("Unsupported key type".to_string()),
        }
    }

    /// Get algorithm instance based on JWK type
    fn get_algorithm_for_jwk(jwk: &JWK) -> Result<(AlgorithmInstance, &'static str), String> {
        match &jwk.params {
            Params::OKP(_) => Ok((AlgorithmInstance::EdDSA, "EdDSA")),
            Params::EC(ec) => match ec.curve.as_deref() {
                Some("P-256") => Ok((AlgorithmInstance::ES256, "ES256")),
                Some("secp256k1") => Ok((AlgorithmInstance::ES256K, "ES256K")),
                curve => Err(format!(
                    "Unsupported curve: {:?}. Supported: P-256, secp256k1",
                    curve
                )),
            },
            _ => Err("Unsupported key type".to_string()),
        }
    }

    /// Sign a message using the JWK
    fn sign_message(jwk: &JWK, message: &[u8]) -> Result<String, String> {
        let secret_key = jwk_to_secret_key(jwk)?;
        let (alg_instance, _) = get_algorithm_for_jwk(jwk)?;

        let signature = secret_key
            .sign(alg_instance, message)
            .map_err(|e| format!("Signing failed: {:?}", e))?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature))
    }

    /// Creates a verifiable credential and signs it as a JWT
    #[pyfunction]
    #[pyo3(signature = (issuer_did, issuer_jwk_json, subject_id, credential_type, claims_json, expiration_seconds=None))]
    pub fn create_verifiable_credential(
        issuer_did: String,
        issuer_jwk_json: String,
        subject_id: Option<String>,
        credential_type: String,
        claims_json: String,
        expiration_seconds: Option<i64>,
    ) -> PyResult<(String, String)> {
        use chrono::{Duration, Utc};

        let jwk: JWK = serde_json::from_str(&issuer_jwk_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid JWK: {}", e))
        })?;

        let claims: HashMap<String, serde_json::Value> = serde_json::from_str(&claims_json)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid claims JSON: {}",
                    e
                ))
            })?;

        let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        let now = Utc::now();
        let issuance_date = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let expiration_date = expiration_seconds.map(|secs| {
            (now + Duration::seconds(secs))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
        });

        let vc_data = VerifiableCredentialData {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://www.w3.org/2018/credentials/examples/v1".to_string(),
            ],
            id: credential_id.clone(),
            types: vec!["VerifiableCredential".to_string(), credential_type],
            issuer: issuer_did.clone(),
            issuance_date,
            expiration_date,
            credential_subject: CredentialSubject {
                id: subject_id,
                claims,
            },
        };

        let mut payload = serde_json::json!({
            "iss": issuer_did,
            "iat": now.timestamp(),
            "vc": vc_data,
        });

        if let Some(exp_secs) = expiration_seconds {
            payload["exp"] = serde_json::json!(now.timestamp() + exp_secs);
        }

        let (_, alg_str) = get_algorithm_for_jwk(&jwk)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        let header = serde_json::json!({ "alg": alg_str, "typ": "JWT" });

        let header_str = serde_json::to_string(&header).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize header: {}",
                e
            ))
        })?;
        let payload_str = serde_json::to_string(&payload).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize payload: {}",
                e
            ))
        })?;

        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_str.as_bytes());
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_str.as_bytes());

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = sign_message(&jwk, message.as_bytes())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        let jwt = format!("{}.{}", message, signature);
        Ok((jwt, credential_id))
    }

    /// Creates an OID4VCI credential offer
    #[pyfunction]
    #[pyo3(signature = (issuer_url, credential_types, pre_authorized_code=None, user_pin_required=false))]
    pub fn create_credential_offer(
        issuer_url: String,
        credential_types: Vec<String>,
        pre_authorized_code: Option<String>,
        user_pin_required: bool,
    ) -> PyResult<String> {
        let mut grants = HashMap::new();

        if let Some(code) = pre_authorized_code {
            let mut pre_auth_grant = HashMap::new();
            pre_auth_grant.insert("pre-authorized_code".to_string(), serde_json::json!(code));
            pre_auth_grant.insert(
                "user_pin_required".to_string(),
                serde_json::json!(user_pin_required),
            );
            grants.insert(
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                serde_json::json!(pre_auth_grant),
            );
        } else {
            grants.insert(
                "authorization_code".to_string(),
                serde_json::json!({
                    "issuer_state": uuid::Uuid::new_v4().to_string()
                }),
            );
        }

        let offer = CredentialOffer {
            credential_issuer: issuer_url,
            credential_configuration_ids: credential_types,
            grants,
        };

        serde_json::to_string(&offer)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    /// Generates a credential offer URI for QR code display
    #[pyfunction]
    pub fn generate_offer_uri(
        issuer_url: String,
        offer_id: String,
        format: String,
    ) -> PyResult<String> {
        match format.as_str() {
            "microsoft" => Ok(format!(
                "openid-vc://?request_uri={}/issuance-requests/{}",
                issuer_url, offer_id
            )),
            _ => Ok(format!(
                "openid-credential-offer://?credential_offer_uri={}/offers/{}",
                issuer_url, offer_id
            )),
        }
    }

    /// Creates a verifiable presentation from credentials
    #[pyfunction]
    #[pyo3(signature = (holder_did, holder_jwk_json, credential_jwts, audience, nonce=None))]
    pub fn create_presentation(
        holder_did: String,
        holder_jwk_json: String,
        credential_jwts: Vec<String>,
        audience: String,
        nonce: Option<String>,
    ) -> PyResult<String> {
        use chrono::Utc;

        let jwk: JWK = serde_json::from_str(&holder_jwk_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid JWK: {}", e))
        })?;

        let now = Utc::now();
        let vp = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "holder": holder_did,
            "verifiableCredential": credential_jwts,
        });

        let mut payload = serde_json::json!({
            "iss": holder_did,
            "aud": audience,
            "iat": now.timestamp(),
            "exp": now.timestamp() + 300,
            "vp": vp,
        });

        if let Some(n) = nonce {
            payload["nonce"] = serde_json::json!(n);
        }

        let (_, alg_str) = get_algorithm_for_jwk(&jwk)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;
        let header = serde_json::json!({ "alg": alg_str, "typ": "JWT" });

        let header_str = serde_json::to_string(&header).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize header: {}",
                e
            ))
        })?;
        let payload_str = serde_json::to_string(&payload).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize payload: {}",
                e
            ))
        })?;

        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_str.as_bytes());
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_str.as_bytes());

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = sign_message(&jwk, message.as_bytes())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        Ok(format!("{}.{}", message, signature))
    }

    /// Verifies a JWT structure and claims
    #[pyfunction]
    #[pyo3(signature = (jwt, expected_issuer=None, expected_audience=None))]
    pub fn verify_jwt(
        jwt: String,
        expected_issuer: Option<String>,
        expected_audience: Option<String>,
    ) -> PyResult<(bool, String, String)> {
        use chrono::Utc;

        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Ok((false, "{}".to_string(), "Invalid JWT format".to_string()));
        }

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid base64 in payload")
            })?;

        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid JSON in payload")
        })?;

        let payload_json = serde_json::to_string(&payload).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize payload: {}",
                e
            ))
        })?;

        if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
            if Utc::now().timestamp() > exp {
                return Ok((false, payload_json, "JWT has expired".to_string()));
            }
        }

        if let Some(expected) = expected_issuer {
            if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
                if iss != expected {
                    return Ok((
                        false,
                        payload_json,
                        format!("Issuer mismatch: expected {}, got {}", expected, iss),
                    ));
                }
            } else {
                return Ok((false, payload_json, "Missing issuer claim".to_string()));
            }
        }

        if let Some(expected) = expected_audience {
            if let Some(aud) = payload.get("aud").and_then(|v| v.as_str()) {
                if aud != expected {
                    return Ok((
                        false,
                        payload_json,
                        format!("Audience mismatch: expected {}, got {}", expected, aud),
                    ));
                }
            } else {
                return Ok((false, payload_json, "Missing audience claim".to_string()));
            }
        }

        Ok((true, payload_json, "".to_string()))
    }

    /// Generates issuer metadata for OID4VCI discovery
    #[pyfunction]
    pub fn generate_issuer_metadata(
        issuer_url: String,
        issuer_name: String,
        credential_types_json: String,
    ) -> PyResult<String> {
        let credential_types: Vec<serde_json::Value> = serde_json::from_str(&credential_types_json)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid JSON: {}", e))
            })?;

        let mut credential_configurations = serde_json::Map::new();

        for cred_type in credential_types {
            let type_id = cred_type
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            let type_name = cred_type
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(type_id);
            let format = cred_type
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("jwt_vc_json");

            credential_configurations.insert(type_id.to_string(), serde_json::json!({
            "format": format,
            "scope": type_id,
            "cryptographic_binding_methods_supported": ["did:key", "did:jwk"],
            "credential_signing_alg_values_supported": ["ES256", "EdDSA"],
            "proof_types_supported": { "jwt": { "proof_signing_alg_values_supported": ["ES256", "EdDSA"] } },
            "credential_definition": { "type": ["VerifiableCredential", type_name] },
            "display": [{ "name": type_name, "locale": "en-US" }]
        }));
        }

        let metadata = serde_json::json!({
            "credential_issuer": issuer_url,
            "credential_endpoint": format!("{}/credential", issuer_url),
            "token_endpoint": format!("{}/token", issuer_url),
            "authorization_endpoint": format!("{}/authorize", issuer_url),
            "credential_configurations_supported": credential_configurations,
            "display": [{ "name": issuer_name, "locale": "en-US" }]
        });

        serde_json::to_string(&metadata)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    // SD-JWT support is planned but requires proper integration with jsonwebtoken EncodingKey
    // For now, use standard JWT signing through create_verifiable_credential
    // TODO: Implement create_sd_jwt when proper JWK to EncodingKey conversion is available

    #[pymodule]
    pub fn _marty_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
        // Initialize tracing for structured logging
        crate::init_tracing();

        m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
        m.add_function(wrap_pyfunction!(get_ssi_version, m)?)?;
        m.add_function(wrap_pyfunction!(check_isomdl, m)?)?;
        m.add_function(wrap_pyfunction!(generate_did_key, m)?)?;
        m.add_function(wrap_pyfunction!(generate_p256_key, m)?)?;
        m.add_function(wrap_pyfunction!(generate_p384_key, m)?)?;
        m.add_function(wrap_pyfunction!(generate_rsa_key, m)?)?;
        m.add_function(wrap_pyfunction!(create_verifiable_credential, m)?)?;
        m.add_function(wrap_pyfunction!(create_credential_offer, m)?)?;
        m.add_function(wrap_pyfunction!(generate_offer_uri, m)?)?;
        m.add_function(wrap_pyfunction!(create_presentation, m)?)?;
        m.add_function(wrap_pyfunction!(verify_jwt, m)?)?;
        m.add_function(wrap_pyfunction!(generate_issuer_metadata, m)?)?;

        // Status list classes and functions for credential revocation
        crate::status_list::register_status_list_module(m)?;

        // mDoc classes and functions for ISO 18013-5 mobile driver's license
        crate::mdoc::register_mdoc_module(m)?;

        // SD-JWT classes and functions for Selective Disclosure JWT
        crate::sd_jwt::register_sd_jwt_module(m)?;

        // Note: marty-verification functions are now available in the separate
        // marty-verification-py package. Install both packages to access all functionality.

        Ok(())
    }
} // End of python_bindings module

// Re-export Python module when python feature is enabled
#[cfg(feature = "python")]
pub use python_bindings::_marty_rs;
