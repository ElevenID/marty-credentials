// SD-JWT (Selective Disclosure JWT) implementation using sd-jwt-rs crate
//
// This module provides Python bindings for creating and verifying
// Selective Disclosure JWTs according to the SD-JWT specification.

use jsonwebtoken::{DecodingKey, EncodingKey, Header};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
use sd_jwt_rs::{SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat, SDJWTVerifier};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

/// Builder for creating SD-JWT credentials with selective disclosure
#[pyclass]
pub struct SdJwtBuilder {
    issuer_claim: String,
    subject: Option<String>,
    claims: HashMap<String, Value>,
    disclosable_claim_paths: Vec<String>,
    expiration_seconds: Option<i64>,
}

#[pymethods]
impl SdJwtBuilder {
    #[new]
    pub fn new(issuer: String) -> Self {
        Self {
            issuer_claim: issuer,
            subject: None,
            claims: HashMap::new(),
            disclosable_claim_paths: Vec::new(),
            expiration_seconds: None,
        }
    }

    /// Set the subject (credential holder ID)
    pub fn set_subject(&mut self, subject: String) {
        self.subject = Some(subject);
    }

    /// Add a claim (non-disclosable, always visible)
    pub fn add_claim(&mut self, name: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let json_value = python_to_json(value)?;
        self.claims.insert(name, json_value);
        Ok(())
    }

    /// Add a selectively disclosable claim (top-level)
    pub fn add_disclosable_claim(
        &mut self,
        name: String,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let json_value = python_to_json(value)?;
        self.claims.insert(name.clone(), json_value);
        // Store JSONPath for the claim
        self.disclosable_claim_paths.push(format!("$.{}", name));
        Ok(())
    }

    /// Set expiration time in seconds from now
    pub fn set_expiration(&mut self, seconds: i64) {
        self.expiration_seconds = Some(seconds);
    }

    /// Build the SD-JWT and sign it with a PEM-encoded private key
    /// Supports EC (P-256/P-384) and RSA keys
    #[pyo3(signature = (private_key_pem, algorithm=None))]
    pub fn build(&self, private_key_pem: String, algorithm: Option<String>) -> PyResult<String> {
        let now = chrono::Utc::now();
        let alg = algorithm.unwrap_or_else(|| "ES256".to_string());

        // Build the user claims
        let mut user_claims = Map::new();
        user_claims.insert("iss".to_string(), json!(self.issuer_claim));
        user_claims.insert("iat".to_string(), json!(now.timestamp()));

        if let Some(ref sub) = self.subject {
            user_claims.insert("sub".to_string(), json!(sub));
        }

        if let Some(exp_secs) = self.expiration_seconds {
            user_claims.insert("exp".to_string(), json!(now.timestamp() + exp_secs));
        }

        // Add all claims to the payload
        for (key, value) in &self.claims {
            user_claims.insert(key.clone(), value.clone());
        }

        // Create the encoding key from PEM
        let encoding_key = create_encoding_key(&private_key_pem, &alg)?;

        // Create SD-JWT issuer
        let mut issuer = SDJWTIssuer::new(encoding_key, Some(alg));

        // Determine SD strategy
        let sd_strategy = if self.disclosable_claim_paths.is_empty() {
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims
        } else {
            // Convert paths to &str for the API
            let paths: Vec<&str> = self
                .disclosable_claim_paths
                .iter()
                .map(|s| s.as_str())
                .collect();
            ClaimsForSelectiveDisclosureStrategy::Custom(paths)
        };

        // Issue the SD-JWT
        let sd_jwt = issuer
            .issue_sd_jwt(
                Value::Object(user_claims),
                sd_strategy,
                None, // No holder key binding
                false, // No decoy claims
                SDJWTSerializationFormat::Compact,
            )
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to issue SD-JWT: {}",
                    e
                ))
            })?;

        Ok(sd_jwt)
    }
}

/// SD-JWT presentation creator (holder side)
#[pyclass]
pub struct SdJwtPresentation {
    sd_jwt: String,
    claims_to_disclose: Map<String, Value>,
}

#[pymethods]
impl SdJwtPresentation {
    #[new]
    pub fn new(sd_jwt: String) -> Self {
        Self {
            sd_jwt,
            claims_to_disclose: Map::new(),
        }
    }

    /// Add a claim to disclose in the presentation (marks claim value as true)
    pub fn disclose_claim(&mut self, claim_name: String) {
        self.claims_to_disclose
            .insert(claim_name, Value::Bool(true));
    }

    /// Create the presentation with selected disclosures
    #[pyo3(signature = (holder_key_pem=None, nonce=None, audience=None, algorithm=None))]
    pub fn create_presentation(
        &mut self,
        holder_key_pem: Option<String>,
        nonce: Option<String>,
        audience: Option<String>,
        algorithm: Option<String>,
    ) -> PyResult<String> {
        let mut holder =
            SDJWTHolder::new(self.sd_jwt.clone(), SDJWTSerializationFormat::Compact).map_err(
                |e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "Failed to parse SD-JWT: {}",
                        e
                    ))
                },
            )?;

        // Create presentation
        let presentation = match (holder_key_pem, nonce, audience) {
            (Some(key_pem), Some(n), Some(aud)) => {
                let alg = algorithm.unwrap_or_else(|| "ES256".to_string());
                let encoding_key = create_encoding_key(&key_pem, &alg)?;

                holder.create_presentation(
                    self.claims_to_disclose.clone(),
                    Some(n),
                    Some(aud),
                    Some(encoding_key),
                    Some(alg),
                )
            }
            (None, None, None) => holder.create_presentation(
                self.claims_to_disclose.clone(),
                None,
                None,
                None,
                None,
            ),
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Either provide all of (holder_key_pem, nonce, audience) or none",
                ));
            }
        }
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create presentation: {}",
                e
            ))
        })?;

        Ok(presentation)
    }
}

/// SD-JWT verifier
#[pyclass]
pub struct SdJwtVerifier {
    public_key_pem: String,
    algorithm: String,
}

#[pymethods]
impl SdJwtVerifier {
    #[new]
    #[pyo3(signature = (public_key_pem, algorithm=None))]
    pub fn new(public_key_pem: String, algorithm: Option<String>) -> Self {
        Self {
            public_key_pem,
            algorithm: algorithm.unwrap_or_else(|| "ES256".to_string()),
        }
    }

    /// Verify an SD-JWT presentation and return disclosed claims
    #[pyo3(signature = (presentation, expected_nonce=None, expected_audience=None))]
    pub fn verify(
        &self,
        presentation: String,
        expected_nonce: Option<String>,
        expected_audience: Option<String>,
    ) -> PyResult<String> {
        let public_key_pem = self.public_key_pem.clone();
        let alg = self.algorithm.clone();

        // Create the key resolver callback
        let cb_get_issuer_key: Box<dyn Fn(&str, &Header) -> DecodingKey> =
            Box::new(move |_issuer: &str, _header: &Header| {
                create_decoding_key(&public_key_pem, &alg)
                    .expect("Failed to create decoding key")
            });

        let verifier = SDJWTVerifier::new(
            presentation,
            cb_get_issuer_key,
            expected_audience,
            expected_nonce,
            SDJWTSerializationFormat::Compact,
        )
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Verification failed: {}", e))
        })?;

        // Return claims as JSON string
        serde_json::to_string(&verifier.verified_claims).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize claims: {}",
                e
            ))
        })
    }
}

// Helper functions

/// Convert Python value to JSON
fn python_to_json(py_value: &Bound<'_, PyAny>) -> PyResult<Value> {
    if let Ok(s) = py_value.extract::<String>() {
        Ok(json!(s))
    } else if let Ok(i) = py_value.extract::<i64>() {
        Ok(json!(i))
    } else if let Ok(f) = py_value.extract::<f64>() {
        Ok(json!(f))
    } else if let Ok(b) = py_value.extract::<bool>() {
        Ok(json!(b))
    } else if py_value.is_none() {
        Ok(Value::Null)
    } else if let Ok(dict) = py_value.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (key, value) in dict.iter() {
            let key_str: String = key.extract()?;
            let json_value = python_to_json(&value)?;
            map.insert(key_str, json_value);
        }
        Ok(Value::Object(map))
    } else if let Ok(list) = py_value.extract::<Vec<Bound<'_, PyAny>>>() {
        let arr: Result<Vec<Value>, _> = list.iter().map(|v| python_to_json(v)).collect();
        Ok(Value::Array(arr?))
    } else {
        // Try extracting as string representation
        if let Ok(repr) = py_value.str() {
            Ok(json!(repr.to_string()))
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Unsupported type for JSON conversion",
            ))
        }
    }
}

/// Create encoding key from PEM based on algorithm
fn create_encoding_key(pem: &str, algorithm: &str) -> PyResult<EncodingKey> {
    match algorithm {
        "ES256" | "ES384" => EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid EC private key PEM: {}",
                e
            ))
        }),
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid RSA private key PEM: {}",
                    e
                ))
            })
        }
        "EdDSA" => EncodingKey::from_ed_pem(pem.as_bytes()).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid EdDSA private key PEM: {}",
                e
            ))
        }),
        _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Unsupported algorithm: {}. Supported: ES256, ES384, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA",
            algorithm
        ))),
    }
}

/// Create decoding key from PEM based on algorithm
fn create_decoding_key(pem: &str, algorithm: &str) -> PyResult<DecodingKey> {
    match algorithm {
        "ES256" | "ES384" => DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid EC public key PEM: {}",
                e
            ))
        }),
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid RSA public key PEM: {}",
                    e
                ))
            })
        }
        "EdDSA" => DecodingKey::from_ed_pem(pem.as_bytes()).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid EdDSA public key PEM: {}",
                e
            ))
        }),
        _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Unsupported algorithm: {}",
            algorithm
        ))),
    }
}

// Python module functions

/// Create an SD-JWT with selective disclosure
#[pyfunction]
#[pyo3(signature = (issuer, subject_id, claims, disclosable_claims, private_key_pem, algorithm=None, expiration_seconds=None))]
pub fn create_sd_jwt(
    issuer: String,
    subject_id: Option<String>,
    claims: &Bound<'_, PyDict>,
    disclosable_claims: Vec<String>,
    private_key_pem: String,
    algorithm: Option<String>,
    expiration_seconds: Option<i64>,
) -> PyResult<String> {
    let mut builder = SdJwtBuilder::new(issuer);

    if let Some(sub) = subject_id {
        builder.set_subject(sub);
    }

    if let Some(exp) = expiration_seconds {
        builder.set_expiration(exp);
    }

    // Add claims
    for (key, value) in claims.iter() {
        let key_str: String = key.extract()?;
        if disclosable_claims.contains(&key_str) {
            builder.add_disclosable_claim(key_str, &value)?;
        } else {
            builder.add_claim(key_str, &value)?;
        }
    }

    builder.build(private_key_pem, algorithm)
}

/// Verify an SD-JWT presentation
#[pyfunction]
#[pyo3(signature = (presentation, public_key_pem, algorithm=None, expected_nonce=None, expected_audience=None))]
pub fn verify_sd_jwt(
    presentation: String,
    public_key_pem: String,
    algorithm: Option<String>,
    expected_nonce: Option<String>,
    expected_audience: Option<String>,
) -> PyResult<String> {
    let verifier = SdJwtVerifier::new(public_key_pem, algorithm);
    verifier.verify(presentation, expected_nonce, expected_audience)
}

/// Register SD-JWT functions and classes with Python module
pub(crate) fn register_sd_jwt_module(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    parent.add_class::<SdJwtBuilder>()?;
    parent.add_class::<SdJwtPresentation>()?;
    parent.add_class::<SdJwtVerifier>()?;
    parent.add_function(wrap_pyfunction!(create_sd_jwt, parent)?)?;
    parent.add_function(wrap_pyfunction!(verify_sd_jwt, parent)?)?;
    Ok(())
}
