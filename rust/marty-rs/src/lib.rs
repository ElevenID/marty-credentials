#[cfg(feature = "python")]
use base64::Engine;

// Error module (only for python - has tracing dependencies)
#[cfg(feature = "python")]
mod error;

// Status list module (only for python - has PyO3 dependencies)
#[cfg(feature = "python")]
mod status_list;

// mDoc issuance and presentation module (only for python)
#[cfg(feature = "python")]
pub mod mdoc;

// eMRTD (electronic Machine Readable Travel Document) issuance module
pub mod emrtd;

// SD-JWT module (only for python - has PyO3 and sd-jwt-rs dependencies)
#[cfg(feature = "python")]
mod sd_jwt;

// OID4VCI/OID4VP protocol engine bindings (only for python)
#[cfg(feature = "python")]
mod oid4vci;

// BBS+ signature bindings (only for python)
#[cfg(feature = "python")]
mod bbs;

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

// =============================================================================
// Python bindings (only compiled with python feature)
// =============================================================================

#[cfg(feature = "python")]
mod python_bindings {
    use super::*;
    use pyo3::prelude::*;
    use ssi_crypto::{AlgorithmInstance, SecretKey};
    use ssi_jwk::{Params, JWK};

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
    pub fn generate_rsa_key(
        key_size: Option<u32>,
        use_pss: Option<bool>,
    ) -> PyResult<(String, String)> {
        use rsa::{
            rand_core::OsRng, traits::PrivateKeyParts, traits::PublicKeyParts, RsaPrivateKey,
        };
        use ssi_jwk::{Algorithm, RSAParams};

        let bits = key_size.unwrap_or(2048);
        if bits != 2048 && bits != 3072 && bits != 4096 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "key_size must be 2048, 3072, or 4096",
            ));
        }

        let private_key = RsaPrivateKey::new(&mut OsRng, bits as usize).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "RSA key generation failed: {}",
                e
            ))
        })?;

        // Convert to JWK format (SSI 0.12 uses descriptive field names)
        let n = private_key.n().to_bytes_be();
        let e = private_key.e().to_bytes_be();
        let d = private_key.d().to_bytes_be();
        let primes = private_key.primes();
        let p = primes.first().map(|p| p.to_bytes_be()).unwrap_or_default();
        let q = primes.get(1).map(|q| q.to_bytes_be()).unwrap_or_default();

        let rsa_params = RSAParams {
            modulus: Some(ssi_jwk::Base64urlUInt(n)),
            exponent: Some(ssi_jwk::Base64urlUInt(e)),
            private_exponent: Some(ssi_jwk::Base64urlUInt(d)),
            first_prime_factor: Some(ssi_jwk::Base64urlUInt(p)),
            second_prime_factor: Some(ssi_jwk::Base64urlUInt(q)),
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
            params: ssi_jwk::Params::RSA(rsa_params),
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
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)?;
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
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)?;

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

    fn verify_compact_jws(jwt: &str, decoding_key: &jsonwebtoken::DecodingKey) -> PyResult<String> {
        let header = jsonwebtoken::decode_header(jwt).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid JWT header: {e}"))
        })?;
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let token = jsonwebtoken::decode::<serde_json::Value>(jwt, decoding_key, &validation)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "JWT signature verification failed: {e}"
                ))
            })?;
        serde_json::to_string(&token.claims).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize verified JWT claims: {e}"
            ))
        })
    }

    /// Verify a compact JWS with a public JWK and return authenticated claims.
    #[pyfunction]
    pub fn verify_jws_with_jwk(jwt: &str, public_jwk_json: &str) -> PyResult<String> {
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_str(public_jwk_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid public JWK: {e}"))
        })?;
        let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Unsupported public JWK: {e}"))
        })?;
        verify_compact_jws(jwt, &key)
    }

    /// Verify a compact JWS with a PEM public key and return authenticated claims.
    #[pyfunction]
    pub fn verify_jws_with_pem(jwt: &str, public_key_pem: &str) -> PyResult<String> {
        let header = jsonwebtoken::decode_header(jwt).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid JWT header: {e}"))
        })?;
        let key = match header.alg {
            jsonwebtoken::Algorithm::ES256 | jsonwebtoken::Algorithm::ES384 => {
                jsonwebtoken::DecodingKey::from_ec_pem(public_key_pem.as_bytes())
            }
            jsonwebtoken::Algorithm::RS256
            | jsonwebtoken::Algorithm::RS384
            | jsonwebtoken::Algorithm::RS512
            | jsonwebtoken::Algorithm::PS256
            | jsonwebtoken::Algorithm::PS384
            | jsonwebtoken::Algorithm::PS512 => {
                jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            }
            jsonwebtoken::Algorithm::EdDSA => {
                jsonwebtoken::DecodingKey::from_ed_pem(public_key_pem.as_bytes())
            }
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Unsupported JWT signing algorithm",
                ));
            }
        }
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid public key: {e}"))
        })?;
        verify_compact_jws(jwt, &key)
    }

    /// Convert a P-256 public JWK to SubjectPublicKeyInfo PEM.
    #[pyfunction]
    pub fn p256_public_jwk_to_pem(public_jwk_json: &str) -> PyResult<String> {
        use p256::pkcs8::EncodePublicKey;

        let jwk: serde_json::Value = serde_json::from_str(public_jwk_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid public JWK: {e}"))
        })?;
        if jwk.get("kty").and_then(|value| value.as_str()) != Some("EC")
            || jwk.get("crv").and_then(|value| value.as_str()) != Some("P-256")
        {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Expected an EC P-256 public JWK",
            ));
        }

        let decode_coordinate = |name: &str| -> PyResult<Vec<u8>> {
            let encoded = jwk
                .get(name)
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                        "Public JWK is missing {name}"
                    ))
                })?;
            let coordinate = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                        "Invalid public JWK {name}: {e}"
                    ))
                })?;
            if coordinate.len() != 32 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Public JWK {name} must be 32 bytes"
                )));
            }
            Ok(coordinate)
        };

        let x = decode_coordinate("x")?;
        let y = decode_coordinate("y")?;
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let public_key = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid P-256 public point: {e}"
            ))
        })?;
        public_key
            .to_public_key_pem(Default::default())
            .map(|pem| pem.to_string())
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to encode public key: {e}"
                ))
            })
    }

    /// Verify a VCDM Data Integrity credential with DID material resolved by Python.
    #[pyfunction]
    pub fn verify_w3c_vc_signature(
        credential_json: &str,
        public_key_jwk_json: &str,
    ) -> PyResult<String> {
        let credential: serde_json::Value = serde_json::from_str(credential_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid credential JSON: {e}"))
        })?;
        let public_jwk: serde_json::Value =
            serde_json::from_str(public_key_jwk_json).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid public JWK: {e}"))
            })?;
        let issuer = credential
            .get("issuer")
            .and_then(|value| {
                value
                    .as_str()
                    .or_else(|| value.get("id").and_then(|id| id.as_str()))
            })
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("Credential is missing an issuer")
            })?
            .to_owned();
        let verification_method = credential
            .get("proof")
            .and_then(|proof| proof.get("verificationMethod"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Credential proof is missing verificationMethod",
                )
            })?
            .to_owned();
        let request = serde_json::json!({
            "document": credential,
            "resolved_verification_methods": [{
                "id": verification_method,
                "controller": issuer,
                "public_jwk": public_jwk,
            }],
        });
        Ok(marty_verification::vcdm::verify_vcdm_data_integrity_json(
            &request.to_string(),
        ))
    }

    /// Prepare a VCDM v2 EdDSA Data Integrity credential for issuer-DID signing.
    #[pyfunction]
    pub fn prepare_vcdm_data_integrity_credential(request_json: &str) -> PyResult<String> {
        marty_verification::vcdm::prepare_vcdm_data_integrity_credential_json(request_json)
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    }

    /// Complete and independently verify a remotely signed Data Integrity credential.
    #[pyfunction]
    pub fn complete_vcdm_data_integrity_credential(request_json: &str) -> PyResult<String> {
        marty_verification::vcdm::complete_vcdm_data_integrity_credential_json(request_json)
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    }

    #[pymodule]
    pub fn _marty_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
        // Initialize tracing for structured logging
        crate::init_tracing();

        // Register the authoritative marty-core protocol, verification, and
        // provider-integration surface before adding credential-specific APIs.
        // This keeps the one published `_marty_rs` wheel capability-complete.
        marty_core_bindings::register_marty_bindings(m)?;

        m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
        m.add_function(wrap_pyfunction!(get_ssi_version, m)?)?;
        m.add_function(wrap_pyfunction!(check_isomdl, m)?)?;
        m.add_function(wrap_pyfunction!(generate_did_key, m)?)?;
        m.add_function(wrap_pyfunction!(generate_p256_key, m)?)?;
        m.add_function(wrap_pyfunction!(generate_p384_key, m)?)?;
        m.add_function(wrap_pyfunction!(generate_rsa_key, m)?)?;
        m.add_function(wrap_pyfunction!(create_presentation, m)?)?;
        m.add_function(wrap_pyfunction!(verify_jwt, m)?)?;
        m.add_function(wrap_pyfunction!(verify_jws_with_jwk, m)?)?;
        m.add_function(wrap_pyfunction!(verify_jws_with_pem, m)?)?;
        m.add_function(wrap_pyfunction!(p256_public_jwk_to_pem, m)?)?;
        m.add_function(wrap_pyfunction!(verify_w3c_vc_signature, m)?)?;
        m.add_function(wrap_pyfunction!(prepare_vcdm_data_integrity_credential, m)?)?;
        m.add_function(wrap_pyfunction!(
            complete_vcdm_data_integrity_credential,
            m
        )?)?;

        // Status list classes and functions for credential revocation
        crate::status_list::register_status_list_module(m)?;

        // mDoc classes and functions for ISO 18013-5 mobile driver's license
        crate::mdoc::register_mdoc_module(m)?;

        // eMRTD classes and functions for ICAO 9303 passport issuance
        crate::emrtd::register_emrtd_module(m)?;

        // SD-JWT classes and functions for Selective Disclosure JWT
        crate::sd_jwt::register_sd_jwt_module(m)?;

        // OID4VCI/OID4VP protocol engine (from marty-oid4vci)
        crate::oid4vci::register_oid4vci_module(m)?;

        // BBS+ signatures (from marty-crypto)
        crate::bbs::register_bbs_module(m)?;

        // Note: marty-verification functions are now available in the separate
        // marty-verification-py package. Install both packages to access all functionality.

        Ok(())
    }
} // End of python_bindings module

// Re-export Python module when python feature is enabled
#[cfg(feature = "python")]
pub use python_bindings::_marty_rs;
