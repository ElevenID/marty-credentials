// Python bindings for mDoc verification using marty-verification

use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::IntoPyObjectExt;

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

/// Convert serde_json::Value to Python object
fn json_to_python(py: Python, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    use serde_json::Value;

    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_py_any(py)?),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py_any(py)?)
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_py_any(py)?)
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py_any(py)?)
            } else {
                Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Invalid number",
                ))
            }
        }
        Value::String(s) => Ok(s.into_py_any(py)?),
        Value::Array(arr) => {
            let py_list = pyo3::types::PyList::empty(py);
            for item in arr {
                py_list.append(json_to_python(py, item)?)?;
            }
            Ok(py_list.into())
        }
        Value::Object(obj) => {
            let py_dict = PyDict::new(py);
            for (k, v) in obj {
                py_dict.set_item(k, json_to_python(py, v)?)?;
            }
            Ok(py_dict.into())
        }
    }
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
    pub error: Option<String>,
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
    trusted_issuer_certs_pem: Vec<String>,
) -> PyResult<MdocPresentationVerificationResult> {
    let issuer = verify_mdoc_signature(mdoc_bytes.clone(), trusted_issuer_certs_pem)?;
    let mut errors = issuer.error.into_iter().collect::<Vec<_>>();
    let (device_authentication_valid, device_document_types) =
        match marty_verification::verify_device_authentication(
            &mdoc_bytes,
            &session_transcript_cbor,
        ) {
            Ok(result) => (result.verified, result.document_types),
            Err(error) => {
                errors.push(format!("Holder device authentication failed: {error}"));
                (false, Vec::new())
            }
        };
    let document_types = if issuer.document_types.is_empty() {
        device_document_types
    } else {
        issuer.document_types
    };

    Ok(MdocPresentationVerificationResult {
        issuer_signature_valid: issuer.signature_valid,
        issuer_trusted: issuer.issuer_verified,
        device_authentication_valid,
        document_types,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_presentation_fails_without_panicking() {
        let result =
            verify_mdoc_presentation(vec![0xff], vec![0x83, 0xf6, 0xf6, 0x82, 0x71], Vec::new())
                .unwrap();

        assert!(!result.issuer_signature_valid);
        assert!(!result.issuer_trusted);
        assert!(!result.device_authentication_valid);
        assert!(result.error.is_some());
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
    // Parse DeviceResponse
    let response = match marty_verification::mdoc::parse_device_response(&mdoc_bytes) {
        Ok(r) => r,
        Err(e) => {
            return Ok(MdocVerificationResult {
                signature_valid: false,
                issuer_verified: false,
                document_types: vec![],
                error: Some(format!("Failed to parse mDoc: {}", e)),
            });
        }
    };

    // Get document types
    let document_types: Vec<String> = response
        .documents
        .iter()
        .map(|d| d.doc_type.clone())
        .collect();

    let mut chain_validator = marty_verification::verification::ChainValidator::new();
    let mut trust_configuration_valid = !trusted_issuer_certs_pem.is_empty();
    let mut errors = Vec::new();
    if trusted_issuer_certs_pem.is_empty() {
        errors.push("No trusted issuer certificates were configured".to_string());
    }
    for trusted_cert in &trusted_issuer_certs_pem {
        if let Err(error) = chain_validator.add_trust_anchor_pem(trusted_cert) {
            trust_configuration_valid = false;
            errors.push(format!("Invalid trusted issuer certificate: {error}"));
        }
    }

    // Verify each document's MSO signature
    let mut all_signatures_valid = true;
    let mut issuer_verified = trust_configuration_valid;

    for doc in &response.documents {
        // Get issuer certificate from the document's cert chain
        if doc.issuer_cert_chain.is_empty() {
            all_signatures_valid = false;
            issuer_verified = false;
            errors.push(format!(
                "No issuer certificate in cert chain for {}",
                doc.doc_type
            ));
            continue;
        }

        let issuer_cert_der = &doc.issuer_cert_chain[0];

        // Get MSO from document
        let mso = match &doc.mso {
            Some(m) => m,
            None => {
                all_signatures_valid = false;
                issuer_verified = false;
                errors.push(format!(
                    "No Mobile Security Object in document {}",
                    doc.doc_type
                ));
                continue;
            }
        };

        // Verify MSO signature
        match marty_verification::mdoc::verify_mso_signature(mso, issuer_cert_der) {
            Ok(_) => {
                // Signature is valid, now check if issuer is trusted
                if trust_configuration_valid {
                    match chain_validator.validate_chain_der(&doc.issuer_cert_chain) {
                        Ok(validation) if validation.valid => {}
                        Ok(validation) => {
                            issuer_verified = false;
                            errors.push(format!(
                                "Issuer certificate chain validation failed for {}: {}",
                                doc.doc_type,
                                validation.errors.join("; ")
                            ));
                        }
                        Err(error) => {
                            issuer_verified = false;
                            errors.push(format!(
                                "Issuer certificate chain validation failed for {}: {error}",
                                doc.doc_type
                            ));
                        }
                    }
                } else {
                    // No trusted certs configured — issuer trust CANNOT be established.
                    // Signature may be valid but we cannot confirm the issuer is
                    // in the trust list. Mark explicitly as unverified.
                    issuer_verified = false;
                    tracing::warn!(
                        "mDOC issuer trust check skipped: no trusted certificates configured. \
                         Issuer cert chain present but cannot be validated against a trust anchor."
                    );
                }
            }
            Err(e) => {
                all_signatures_valid = false;
                issuer_verified = false;
                errors.push(format!(
                    "Signature verification failed for {}: {}",
                    doc.doc_type, e
                ));
            }
        }
    }

    Ok(MdocVerificationResult {
        signature_valid: all_signatures_valid,
        issuer_verified,
        document_types,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    })
}
