// SD-JWT (Selective Disclosure JWT) implementation using sd-jwt-rs crate
//
// This module provides Python bindings for verifying Selective Disclosure
// JWTs according to the SD-JWT specification.

// sd-jwt-rs owns this type boundary and remains pinned to jsonwebtoken 10.
// The workspace-facing jsonwebtoken dependency can move independently.
use jsonwebtoken_legacy::{DecodingKey, Header};
use pyo3::prelude::*;
use sd_jwt_rs::{SDJWTSerializationFormat, SDJWTVerifier};

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
        #[allow(clippy::type_complexity)]
        let cb_get_issuer_key: Box<dyn Fn(&str, &Header) -> DecodingKey> =
            Box::new(move |_issuer: &str, _header: &Header| {
                create_decoding_key(&public_key_pem, &alg).expect("Failed to create decoding key")
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
    parent.add_class::<SdJwtVerifier>()?;
    parent.add_function(wrap_pyfunction!(verify_sd_jwt, parent)?)?;
    Ok(())
}
