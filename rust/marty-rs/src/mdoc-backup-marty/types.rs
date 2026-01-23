//! mDoc/mDL type definitions for Python bindings.
//!
//! Provides PyO3-compatible wrapper types around isomdl types
//! for mDoc credential issuance and presentation.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Key algorithm for mDoc signing.
#[pyclass]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MdocKeyAlgorithm {
    /// ECDSA with P-256 curve (ES256)
    ES256,
    /// ECDSA with P-384 curve (ES384)
    ES384,
    /// ECDSA with P-521 curve (ES512)
    ES512,
    /// EdDSA with Ed25519
    EdDSA,
}

#[pymethods]
impl MdocKeyAlgorithm {
    #[staticmethod]
    pub fn es256() -> Self {
        Self::ES256
    }

    #[staticmethod]
    pub fn es384() -> Self {
        Self::ES384
    }

    #[staticmethod]
    pub fn eddsa() -> Self {
        Self::EdDSA
    }
}

/// Validity period for an mDoc credential.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdocValidityInfo {
    /// When the credential was signed (Unix timestamp)
    #[pyo3(get, set)]
    pub signed: i64,
    /// When the credential becomes valid (Unix timestamp)
    #[pyo3(get, set)]
    pub valid_from: i64,
    /// When the credential expires (Unix timestamp)
    #[pyo3(get, set)]
    pub valid_until: i64,
    /// Expected update time (optional, Unix timestamp)
    #[pyo3(get, set)]
    pub expected_update: Option<i64>,
}

#[pymethods]
impl MdocValidityInfo {
    #[new]
    #[pyo3(signature = (valid_from, valid_until, signed=None, expected_update=None))]
    pub fn new(
        valid_from: i64,
        valid_until: i64,
        signed: Option<i64>,
        expected_update: Option<i64>,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            signed: signed.unwrap_or(now),
            valid_from,
            valid_until,
            expected_update,
        }
    }

    /// Create validity info for a credential valid for N days from now.
    #[staticmethod]
    pub fn days_from_now(days: i64) -> Self {
        let now = chrono::Utc::now().timestamp();
        let valid_until = now + (days * 24 * 60 * 60);
        Self {
            signed: now,
            valid_from: now,
            valid_until,
            expected_update: None,
        }
    }

    /// Create validity info for a credential valid for N years from now.
    #[staticmethod]
    pub fn years_from_now(years: i64) -> Self {
        Self::days_from_now(years * 365)
    }
}

/// Device (holder) key information for mDoc binding.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdocDeviceKeyInfo {
    /// COSE key in JSON format
    #[pyo3(get, set)]
    pub cose_key_json: String,
    /// Optional key authorizations
    #[pyo3(get, set)]
    pub key_authorizations: Option<String>,
}

#[pymethods]
impl MdocDeviceKeyInfo {
    #[new]
    #[pyo3(signature = (cose_key_json, key_authorizations=None))]
    pub fn new(cose_key_json: String, key_authorizations: Option<String>) -> Self {
        Self {
            cose_key_json,
            key_authorizations,
        }
    }

    /// Create from a JWK JSON string (converts to COSE key internally).
    #[staticmethod]
    pub fn from_jwk(jwk_json: &str) -> PyResult<Self> {
        // For now, store as-is - conversion happens in Rust issuance
        Ok(Self {
            cose_key_json: jwk_json.to_string(),
            key_authorizations: None,
        })
    }
}

/// Request for mDoc credential issuance.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdocIssuanceRequest {
    /// Document type (e.g., "org.iso.18013.5.1.mDL")
    #[pyo3(get, set)]
    pub doc_type: String,
    /// Namespaced claims as JSON
    /// Format: {"org.iso.18013.5.1": {"family_name": "Doe", "given_name": "John"}}
    #[pyo3(get, set)]
    pub namespaces_json: String,
    /// Device (holder) public key
    #[pyo3(get, set)]
    pub device_key: MdocDeviceKeyInfo,
    /// Validity period
    #[pyo3(get, set)]
    pub validity: MdocValidityInfo,
}

#[pymethods]
impl MdocIssuanceRequest {
    #[new]
    pub fn new(
        doc_type: String,
        namespaces_json: String,
        device_key: MdocDeviceKeyInfo,
        validity: MdocValidityInfo,
    ) -> Self {
        Self {
            doc_type,
            namespaces_json,
            device_key,
            validity,
        }
    }

    /// Create an mDL issuance request with common fields.
    #[staticmethod]
    #[pyo3(signature = (family_name, given_name, birth_date, device_key, validity, portrait_base64=None, age_over_21=None))]
    pub fn mdl(
        family_name: String,
        given_name: String,
        birth_date: String,
        device_key: MdocDeviceKeyInfo,
        validity: MdocValidityInfo,
        portrait_base64: Option<String>,
        age_over_21: Option<bool>,
    ) -> PyResult<Self> {
        let mut claims = serde_json::Map::new();
        claims.insert("family_name".to_string(), serde_json::json!(family_name));
        claims.insert("given_name".to_string(), serde_json::json!(given_name));
        claims.insert("birth_date".to_string(), serde_json::json!(birth_date));

        if let Some(portrait) = portrait_base64 {
            claims.insert("portrait".to_string(), serde_json::json!(portrait));
        }
        if let Some(age) = age_over_21 {
            claims.insert("age_over_21".to_string(), serde_json::json!(age));
        }

        let namespaces = serde_json::json!({
            "org.iso.18013.5.1": claims
        });

        Ok(Self {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces_json: serde_json::to_string(&namespaces).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("JSON error: {}", e))
            })?,
            device_key,
            validity,
        })
    }
}

/// Issued mDoc credential.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdocCredential {
    /// Document type
    #[pyo3(get)]
    pub doc_type: String,
    /// CBOR-encoded mDoc bytes (base64)
    #[pyo3(get)]
    pub cbor_base64: String,
    /// Credential ID (UUID)
    #[pyo3(get)]
    pub credential_id: String,
    /// Issue timestamp (Unix)
    #[pyo3(get)]
    pub issued_at: i64,
    /// Expiry timestamp (Unix)
    #[pyo3(get)]
    pub valid_until: i64,
}

#[pymethods]
impl MdocCredential {
    /// Get the raw CBOR bytes.
    pub fn cbor_bytes(&self) -> PyResult<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.cbor_base64)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Base64 error: {}", e)))
    }
}

/// Prepared mDoc for remote/HSM signing.
#[pyclass]
#[derive(Debug, Clone)]
pub struct PreparedMdoc {
    /// Signature payload to be signed (base64)
    #[pyo3(get)]
    pub signature_payload_base64: String,
    /// Internal state for completion (opaque, base64-encoded)
    #[pyo3(get)]
    pub prepared_state_base64: String,
    /// Document type
    #[pyo3(get)]
    pub doc_type: String,
}

#[pymethods]
impl PreparedMdoc {
    /// Get the raw signature payload bytes.
    pub fn signature_payload(&self) -> PyResult<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.signature_payload_base64)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Base64 error: {}", e)))
    }
}

/// Selective disclosure request for presentation.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdocDisclosureRequest {
    /// Requested fields per namespace
    /// Format: {"org.iso.18013.5.1": ["family_name", "age_over_21"]}
    #[pyo3(get, set)]
    pub requested_fields_json: String,
    /// Whether to include intent-to-retain flag
    #[pyo3(get, set)]
    pub intent_to_retain: bool,
}

#[pymethods]
impl MdocDisclosureRequest {
    #[new]
    #[pyo3(signature = (requested_fields_json, intent_to_retain=false))]
    pub fn new(requested_fields_json: String, intent_to_retain: bool) -> Self {
        Self {
            requested_fields_json,
            intent_to_retain,
        }
    }

    /// Create a request for age verification only.
    #[staticmethod]
    pub fn age_verification() -> Self {
        let fields = serde_json::json!({
            "org.iso.18013.5.1": ["age_over_21", "age_over_18"]
        });
        Self {
            requested_fields_json: serde_json::to_string(&fields).unwrap(),
            intent_to_retain: false,
        }
    }

    /// Create a request for full identity.
    #[staticmethod]
    pub fn full_identity() -> Self {
        let fields = serde_json::json!({
            "org.iso.18013.5.1": [
                "family_name",
                "given_name",
                "birth_date",
                "portrait",
                "document_number",
                "issue_date",
                "expiry_date",
                "issuing_country",
                "issuing_authority"
            ]
        });
        Self {
            requested_fields_json: serde_json::to_string(&fields).unwrap(),
            intent_to_retain: false,
        }
    }
}

/// mDL namespace constants.
pub struct MdlNamespace;

impl MdlNamespace {
    pub const ISO_18013_5_1: &'static str = "org.iso.18013.5.1";
    pub const AAMVA: &'static str = "org.iso.18013.5.1.aamva";
}

/// mDL document type constant.
pub const MDL_DOC_TYPE: &'static str = "org.iso.18013.5.1.mDL";

/// Register mDoc types with Python module.
pub fn register_mdoc_types(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MdocKeyAlgorithm>()?;
    m.add_class::<MdocValidityInfo>()?;
    m.add_class::<MdocDeviceKeyInfo>()?;
    m.add_class::<MdocIssuanceRequest>()?;
    m.add_class::<MdocCredential>()?;
    m.add_class::<PreparedMdoc>()?;
    m.add_class::<MdocDisclosureRequest>()?;
    m.add("MDL_DOC_TYPE", MDL_DOC_TYPE)?;
    m.add("MDL_NAMESPACE", MdlNamespace::ISO_18013_5_1)?;
    Ok(())
}
