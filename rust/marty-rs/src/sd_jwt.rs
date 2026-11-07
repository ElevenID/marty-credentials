// SD-JWT (Selective Disclosure JWT) implementation using sd-jwt-rs crate
//
// This module provides Python bindings for verifying Selective Disclosure
// JWTs according to the SD-JWT specification.

// Share Core's verification-only JOSE backend and SD-JWT revision.
use jsonwebtoken::DecodingKey;
use pyo3::prelude::*;
use sd_jwt_rs::{
    SDJWTKeyRequest, SDJWTKeyWithAlg, SDJWTSerializationFormat, SDJWTSignaturePolicy,
    SDJWTSignatureRole, SDJWTSignatureVerifier, SDJWTSignatureVerifierBuiltin, SDJWTVerifier,
};

// Preserve the legacy holder algorithm policy independently of the configured
// issuer algorithm. The holder key must still come from issuer-authenticated cnf.
const HOLDER_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ES256", "ES384", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
];

struct PemSignatureVerifier(SDJWTSignatureVerifierBuiltin);

impl SDJWTSignatureVerifier for PemSignatureVerifier {
    fn allowed_algs(&self, role: SDJWTSignatureRole) -> sd_jwt_rs::error::Result<Vec<String>> {
        self.0.allowed_algs(role)
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        request: &SDJWTKeyRequest,
    ) -> sd_jwt_rs::error::Result<()> {
        // The former resolver API required a string issuer. Keep that credential
        // boundary when adopting the fork's more general provider API.
        if request.role == SDJWTSignatureRole::IssuerJwt && request.iss.is_none() {
            return Err(sd_jwt_rs::error::Error::KeyNotFound(
                "Issuer JWT must contain a string iss claim".into(),
            ));
        }
        self.0.verify(message, signature, request)
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

    /// Verify an SD-JWT under the configured public key and issuer algorithm.
    ///
    /// The caller must establish that the PEM key is authoritative for the
    /// claimed issuer. This compatibility API does not resolve issuer trust.
    #[pyo3(signature = (presentation, expected_nonce=None, expected_audience=None))]
    pub fn verify(
        &self,
        presentation: String,
        expected_nonce: Option<String>,
        expected_audience: Option<String>,
    ) -> PyResult<String> {
        let key = create_decoding_key(&self.public_key_pem, &self.algorithm)?;

        let signature_verifier = SDJWTSignatureVerifierBuiltin::new(
            &[self.algorithm.as_str()],
            Some(HOLDER_SIGNATURE_ALGORITHMS),
        )
        .with_issuer_verifying_key(SDJWTKeyWithAlg::new(key, &self.algorithm))
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid issuer signature policy: {}",
                e
            ))
        })?;

        let verifier = SDJWTVerifier::new_with_signature_verifier(
            Box::new(PemSignatureVerifier(signature_verifier)),
            presentation,
            expected_audience,
            expected_nonce,
            SDJWTSerializationFormat::Compact,
            SDJWTSignaturePolicy::All,
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
