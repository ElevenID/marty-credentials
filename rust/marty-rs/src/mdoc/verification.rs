// Python bindings for mDoc verification using marty-verification

use marty_python_adapters::json_to_python;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Wrapper for marty_verification::mdoc::DeviceResponse
#[pyclass(skip_from_py_object)]
pub struct DeviceResponse {
    inner: marty_verification::mdoc::DeviceResponse,
}

#[pymethods]
impl DeviceResponse {
    /// Parse a DeviceResponse from CBOR bytes
    #[staticmethod]
    pub fn from_cbor(cbor_bytes: Vec<u8>) -> PyResult<Self> {
        let response =
            marty_verification::mdoc::parse_device_response(&cbor_bytes).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to parse DeviceResponse: {}",
                    e
                ))
            })?;

        Ok(Self { inner: response })
    }

    /// Get all document types in this response
    pub fn document_types(&self) -> PyResult<Vec<String>> {
        Ok(self
            .inner
            .documents
            .iter()
            .map(|d| d.doc_type.clone())
            .collect())
    }

    /// Get all fields from the mDL namespace as a dictionary
    pub fn get_mdl_fields(&self, py: Python) -> PyResult<Py<PyAny>> {
        let fields = self.inner.get_mdl_fields().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to extract fields: {}",
                e
            ))
        })?;

        let result = PyDict::new(py);
        for (key, value) in fields {
            let py_value = json_to_python(py, &value)?;
            result.set_item(key, py_value)?;
        }
        Ok(result.into())
    }

    /// Get a specific element from the mDL namespace
    pub fn get_mdl_element(&self, element_id: &str, py: Python) -> PyResult<Option<Py<PyAny>>> {
        match self.inner.get_mdl_element(element_id) {
            Some(value) => Ok(Some(json_to_python(py, &value)?)),
            None => Ok(None),
        }
    }

    /// Check if age_over_21 is true
    pub fn is_age_over_21(&self) -> PyResult<Option<bool>> {
        Ok(self.inner.is_age_over_21())
    }

    /// Get the document holder's family name
    pub fn get_family_name(&self) -> PyResult<Option<String>> {
        Ok(self.inner.get_family_name())
    }

    /// Get the document holder's given name
    pub fn get_given_name(&self) -> PyResult<Option<String>> {
        Ok(self.inner.get_given_name())
    }

    /// Get all namespaces and their items
    pub fn get_all_namespaces(&self, py: Python) -> PyResult<Py<PyAny>> {
        let result = PyDict::new(py);

        for doc in &self.inner.documents {
            for (ns_name, items) in &doc.namespaces {
                let ns_dict = PyDict::new(py);
                for item in items {
                    let py_value = json_to_python(py, &item.element_value)?;
                    ns_dict.set_item(&item.element_identifier, py_value)?;
                }
                result.set_item(ns_name, ns_dict)?;
            }
        }

        Ok(result.into())
    }
}

/// Parse a DeviceResponse from CBOR bytes (convenience function)
#[pyfunction]
pub fn parse_device_response(cbor_bytes: Vec<u8>) -> PyResult<DeviceResponse> {
    DeviceResponse::from_cbor(cbor_bytes)
}

/// Verify an mDoc and return the extracted fields
#[pyfunction]
pub fn verify_mdoc_cbor(cbor_bytes: Vec<u8>, py: Python) -> PyResult<Py<PyAny>> {
    let response = marty_verification::mdoc::parse_device_response(&cbor_bytes).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to parse: {}", e))
    })?;

    let fields = response.get_mdl_fields().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to extract fields: {}",
            e
        ))
    })?;

    let result = PyDict::new(py);
    for (key, value) in fields {
        let py_value = json_to_python(py, &value)?;
        result.set_item(key, py_value)?;
    }
    Ok(result.into())
}

/// Result of mDoc signature verification
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct MdocVerificationResult {
    #[pyo3(get)]
    pub signature_valid: bool,
    #[pyo3(get)]
    pub issuer_verified: bool,
    #[pyo3(get)]
    pub document_types: Vec<String>,
    #[pyo3(get)]
    pub document_evidence: Vec<MdocDocumentVerificationEvidence>,
    #[pyo3(get)]
    pub error: Option<String>,
}

/// Signature-authenticated evidence for one mdoc document.
#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdocDocumentVerificationEvidence {
    #[pyo3(get)]
    pub document_type: String,
    #[pyo3(get)]
    pub signature_algorithm: String,
    #[pyo3(get)]
    pub digest_algorithm: String,
    #[pyo3(get)]
    pub signed_at: String,
    #[pyo3(get)]
    pub valid_from: String,
    #[pyo3(get)]
    pub valid_until: String,
    #[pyo3(get)]
    pub issuer_certificate_sha256: String,
    #[pyo3(get)]
    pub validity_checked: bool,
    #[pyo3(get)]
    pub valid_at_verification_time: bool,
    /// Revocation is not checked by this offline binding.
    #[pyo3(get)]
    pub revocation_checked: bool,
    /// No non-revocation result is invented when no CRL/status authority ran.
    #[pyo3(get)]
    pub not_revoked: Option<bool>,
}

impl From<marty_verification::mdoc::MdocDocumentVerificationEvidence>
    for MdocDocumentVerificationEvidence
{
    fn from(value: marty_verification::mdoc::MdocDocumentVerificationEvidence) -> Self {
        Self {
            document_type: value.document_type,
            signature_algorithm: value.signature_algorithm,
            digest_algorithm: value.digest_algorithm,
            signed_at: value.signed_at,
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            issuer_certificate_sha256: value.issuer_certificate_sha256,
            validity_checked: value.validity_checked,
            valid_at_verification_time: value.valid_at_verification_time,
            revocation_checked: value.revocation_checked,
            not_revoked: value.not_revoked,
        }
    }
}

/// Result of issuer-only mdoc authentication for stored credentials.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct MdocIssuerVerificationResult {
    #[pyo3(get)]
    pub signature_valid: bool,
    #[pyo3(get)]
    pub issuer_trusted: bool,
    #[pyo3(get)]
    pub document_types: Vec<String>,
    #[pyo3(get)]
    pub document_evidence: Vec<MdocDocumentVerificationEvidence>,
    #[pyo3(get)]
    pub revocation_checked: bool,
    #[pyo3(get)]
    pub not_revoked: Option<bool>,
    #[pyo3(get)]
    pub error: Option<String>,
}

impl From<marty_verification::mdoc::MdocIssuerVerificationResult> for MdocIssuerVerificationResult {
    fn from(value: marty_verification::mdoc::MdocIssuerVerificationResult) -> Self {
        Self {
            signature_valid: value.signature_valid,
            issuer_trusted: value.issuer_trusted,
            document_types: value.document_types,
            document_evidence: value
                .document_evidence
                .into_iter()
                .map(Into::into)
                .collect(),
            revocation_checked: value.revocation_checked,
            not_revoked: value.not_revoked,
            error: value.error,
        }
    }
}

#[pymethods]
impl MdocIssuerVerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "MdocIssuerVerificationResult(signature_valid={}, issuer_trusted={}, document_types={:?})",
            self.signature_valid, self.issuer_trusted, self.document_types
        )
    }
}

/// Authenticate stored mdoc issuer signatures against verifier-owned trust.
///
/// This binding delegates to the pinned Core implementation. Interactive
/// holder authentication remains the separate `verify_mdoc_presentation`
/// operation and requires a verifier-owned session transcript.
#[pyfunction(signature = (
    mdoc_bytes,
    trusted_root_certs_pem,
    pinned_issuer_certs_pem = None
))]
pub fn verify_mdoc_issuer(
    mdoc_bytes: Vec<u8>,
    trusted_root_certs_pem: Vec<String>,
    pinned_issuer_certs_pem: Option<Vec<String>>,
) -> MdocIssuerVerificationResult {
    marty_verification::mdoc::verify_mdoc_issuer(
        &mdoc_bytes,
        &trusted_root_certs_pem,
        pinned_issuer_certs_pem.as_deref().unwrap_or_default(),
    )
    .into()
}

#[pymethods]
impl MdocVerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "MdocVerificationResult(signature_valid={}, issuer_verified={}, document_types={:?})",
            self.signature_valid, self.issuer_verified, self.document_types
        )
    }
}

/// Verify issuer and holder authentication for an OpenID4VP mdoc presentation.
///
/// `session_transcript_cbor` must be constructed from verifier-owned request
/// state. It is not accepted from the wallet. Issuer signing is a separate
/// operation selected by issuer profile and DID; this verifier never receives
/// a KMS key coordinate.
#[pyfunction]
pub fn verify_mdoc_presentation(
    mdoc_bytes: Vec<u8>,
    session_transcript_cbor: Vec<u8>,
    trusted_root_certs_pem: Vec<String>,
    pinned_issuer_certs_pem: Vec<String>,
) -> PyResult<MdocPresentationVerificationResult> {
    let result = marty_verification::mdoc::verify_mdoc_presentation(
        &mdoc_bytes,
        &session_transcript_cbor,
        &trusted_root_certs_pem,
        &pinned_issuer_certs_pem,
    );
    Ok(MdocPresentationVerificationResult {
        issuer_signature_valid: result.issuer_signature_valid,
        issuer_trusted: result.issuer_trusted,
        device_authentication_valid: result.device_authentication_valid,
        document_types: result.document_types,
        document_evidence: result
            .document_evidence
            .into_iter()
            .map(Into::into)
            .collect(),
        revocation_checked: result.revocation_checked,
        not_revoked: result.not_revoked,
        error: result.error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_presentation_fails_without_panicking() {
        let result = verify_mdoc_presentation(
            vec![0xff],
            vec![0x83, 0xf6, 0xf6, 0x82, 0x71],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

        assert!(!result.issuer_signature_valid);
        assert!(!result.issuer_trusted);
        assert!(!result.device_authentication_valid);
        assert!(result.document_evidence.is_empty());
        assert!(!result.revocation_checked);
        assert_eq!(result.not_revoked, None);
        assert!(result.error.is_some());
    }

    #[test]
    fn compatibility_signature_and_issuer_bindings_preserve_core_failures() {
        for bytes in [vec![], vec![0xff], vec![0xa0]] {
            let expected = marty_verification::mdoc::verify_mdoc_issuer(&bytes, &[], &[]);
            let signature = verify_mdoc_signature(bytes.clone(), vec![]).unwrap();
            let issuer = verify_mdoc_issuer(bytes, vec![], None);
            assert_eq!(signature.signature_valid, expected.signature_valid);
            assert_eq!(signature.issuer_verified, expected.issuer_trusted);
            assert_eq!(signature.document_types, expected.document_types);
            assert_eq!(signature.error, expected.error);
            assert_eq!(issuer.error, expected.error);
            assert!(!signature.signature_valid);
            assert!(signature.document_evidence.is_empty());
            assert!(!issuer.revocation_checked);
            assert_eq!(issuer.not_revoked, None);
        }
    }

    // Unmodified public-only vector from Core440's mdoc authentication suite.
    #[test]
    fn signed_presentation_preserves_issuer_trust_and_holder_binding() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/mdoc_presentation_signed_public.json"
        ))
        .unwrap();
        let response = STANDARD
            .decode(fixture["response_b64"].as_str().unwrap())
            .unwrap();
        let transcript = STANDARD
            .decode(fixture["transcript_b64"].as_str().unwrap())
            .unwrap();
        let certificate = fixture["certificate_pem"].as_str().unwrap().to_owned();
        let result = verify_mdoc_presentation(
            response.clone(),
            transcript.clone(),
            vec![],
            vec![certificate.clone()],
        )
        .unwrap();
        assert!(result.issuer_signature_valid);
        assert!(result.issuer_trusted);
        assert!(result.device_authentication_valid);
        assert_eq!(result.document_evidence.len(), 1);
        assert!(result.error.is_none());
        let untrusted =
            verify_mdoc_presentation(response.clone(), transcript, vec![], vec![]).unwrap();
        assert!(!untrusted.issuer_trusted);
        let changed =
            verify_mdoc_presentation(response, vec![0x80], vec![], vec![certificate]).unwrap();
        assert!(!changed.device_authentication_valid);
        assert!(!changed.revocation_checked);
        assert_eq!(changed.not_revoked, None);
    }

    #[test]
    fn evidence_projection_preserves_validity_and_revocation_fields() {
        let expected = marty_verification::mdoc::MdocDocumentVerificationEvidence {
            document_type: "org.iso.18013.5.1.mDL".into(),
            signature_algorithm: "ES256".into(),
            digest_algorithm: "SHA-256".into(),
            signed_at: "signed".into(),
            valid_from: "from".into(),
            valid_until: "until".into(),
            issuer_certificate_sha256: "digest".into(),
            validity_checked: true,
            valid_at_verification_time: false,
            revocation_checked: true,
            not_revoked: Some(false),
        };
        let actual: MdocDocumentVerificationEvidence = expected.clone().into();
        assert_eq!(actual.document_type, expected.document_type);
        assert_eq!(actual.signature_algorithm, expected.signature_algorithm);
        assert_eq!(actual.digest_algorithm, expected.digest_algorithm);
        assert_eq!(actual.signed_at, expected.signed_at);
        assert_eq!(actual.valid_from, expected.valid_from);
        assert_eq!(actual.valid_until, expected.valid_until);
        assert_eq!(
            actual.issuer_certificate_sha256,
            expected.issuer_certificate_sha256
        );
        assert_eq!(actual.validity_checked, expected.validity_checked);
        assert_eq!(
            actual.valid_at_verification_time,
            expected.valid_at_verification_time
        );
        assert_eq!(actual.revocation_checked, expected.revocation_checked);
        assert_eq!(actual.not_revoked, expected.not_revoked);
    }
}

/// Result of complete mdoc presentation authentication.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct MdocPresentationVerificationResult {
    /// The issuer COSE signature is valid for every returned document.
    #[pyo3(get)]
    pub issuer_signature_valid: bool,
    /// Every issuer certificate chain terminates at a configured trust anchor.
    #[pyo3(get)]
    pub issuer_trusted: bool,
    /// Every holder DeviceAuthentication signature matches verifier request state.
    #[pyo3(get)]
    pub device_authentication_valid: bool,
    #[pyo3(get)]
    pub document_types: Vec<String>,
    #[pyo3(get)]
    pub document_evidence: Vec<MdocDocumentVerificationEvidence>,
    /// This binding does not perform CRL or status-authority retrieval.
    #[pyo3(get)]
    pub revocation_checked: bool,
    #[pyo3(get)]
    pub not_revoked: Option<bool>,
    #[pyo3(get)]
    pub error: Option<String>,
}

#[pymethods]
impl MdocPresentationVerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "MdocPresentationVerificationResult(issuer_signature_valid={}, \
             issuer_trusted={}, device_authentication_valid={}, document_types={:?})",
            self.issuer_signature_valid,
            self.issuer_trusted,
            self.device_authentication_valid,
            self.document_types
        )
    }
}

/// Verify an mDoc's signature using isomdl
///
/// This function verifies the COSE_Sign1 signature on the MobileSecurityObject (MSO)
/// within the mDoc DeviceResponse.
///
/// # Arguments
///
/// * `mdoc_bytes` - The CBOR-encoded DeviceResponse bytes
/// * `trusted_issuer_certs_pem` - List of trusted issuer certificates in PEM format
///
/// # Returns
///
/// MdocVerificationResult with verification details
#[pyfunction]
pub fn verify_mdoc_signature(
    mdoc_bytes: Vec<u8>,
    trusted_issuer_certs_pem: Vec<String>,
) -> PyResult<MdocVerificationResult> {
    let result =
        marty_verification::mdoc::verify_mdoc_issuer(&mdoc_bytes, &trusted_issuer_certs_pem, &[]);
    Ok(MdocVerificationResult {
        signature_valid: result.signature_valid,
        issuer_verified: result.issuer_trusted,
        document_types: result.document_types,
        document_evidence: result
            .document_evidence
            .into_iter()
            .map(Into::into)
            .collect(),
        error: result.error,
    })
}
