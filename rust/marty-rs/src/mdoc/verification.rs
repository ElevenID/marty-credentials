// Python bindings for mDoc verification using marty-verification

use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::IntoPyObjectExt;

use coset_isomdl::{cbor::value::Value as CoseValue, iana, Label, RegisteredLabelWithPrivate};
use isomdl::definitions::device_response::{DeviceResponse as IsoDeviceResponse, Status};
use isomdl::definitions::helpers::Tag24;
use isomdl::definitions::x509::x5chain::{X5Chain, X5CHAIN_COSE_HEADER_LABEL};
use isomdl::definitions::{DigestAlgorithm, Mso};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

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
    let issuer = verify_mdoc_signature_with_policy(
        mdoc_bytes.clone(),
        trusted_root_certs_pem,
        pinned_issuer_certs_pem,
    )?;
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
        document_evidence: issuer.document_evidence,
        revocation_checked: false,
        not_revoked: None,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use isomdl::definitions::device_key::cose_key::EC2Y;
    use isomdl::definitions::{DeviceKeyInfo, ValidityInfo};
    use p256::ecdsa::SigningKey;
    use std::collections::BTreeMap;
    use time::Duration;

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

    fn mso_with_validity(valid_from: OffsetDateTime, valid_until: OffsetDateTime) -> Mso {
        let signing_key = SigningKey::from_slice(&[7_u8; 32]).unwrap();
        let point = signing_key.verifying_key().to_sec1_bytes();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        Mso {
            version: "1.0".to_string(),
            digest_algorithm: DigestAlgorithm::SHA256,
            value_digests: BTreeMap::new(),
            device_key_info: DeviceKeyInfo {
                device_key: isomdl::definitions::device_key::CoseKey::EC2 {
                    crv: isomdl::definitions::device_key::EC2Curve::P256,
                    x: point[1..33].to_vec(),
                    y: EC2Y::Value(point[33..65].to_vec()),
                },
                key_authorizations: None,
                key_info: None,
            },
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: ValidityInfo {
                signed: valid_from - Duration::minutes(1),
                valid_from,
                valid_until,
                expected_update: None,
            },
        }
    }

    #[test]
    fn authenticated_mso_evidence_is_typed_and_does_not_invent_revocation() {
        let now = OffsetDateTime::parse("2026-08-09T12:00:00Z", &Rfc3339).unwrap();
        let mso = mso_with_validity(now - Duration::hours(1), now + Duration::hours(1));

        let evidence = validated_mso_evidence(
            &mso,
            "org.iso.18013.5.1.mDL",
            "ES256",
            b"issuer-certificate",
            now,
        )
        .unwrap();

        assert_eq!(evidence.document_type, "org.iso.18013.5.1.mDL");
        assert_eq!(evidence.signature_algorithm, "ES256");
        assert_eq!(evidence.digest_algorithm, "SHA-256");
        assert_eq!(evidence.valid_from, "2026-08-09T11:00:00Z");
        assert_eq!(evidence.valid_until, "2026-08-09T13:00:00Z");
        assert_eq!(evidence.issuer_certificate_sha256.len(), 64);
        assert!(evidence
            .issuer_certificate_sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));
        assert!(evidence.validity_checked);
        assert!(evidence.valid_at_verification_time);
        assert!(!evidence.revocation_checked);
        assert_eq!(evidence.not_revoked, None);
    }

    #[test]
    fn authenticated_mso_evidence_rejects_type_and_validity_failures() {
        let now = OffsetDateTime::parse("2026-08-09T12:00:00Z", &Rfc3339).unwrap();
        let valid = mso_with_validity(now - Duration::hours(1), now + Duration::hours(1));
        assert!(validated_mso_evidence(&valid, "wrong.type", "ES256", b"cert", now).is_err());

        let future = mso_with_validity(now + Duration::seconds(1), now + Duration::hours(1));
        assert!(
            validated_mso_evidence(&future, "org.iso.18013.5.1.mDL", "ES256", b"cert", now,)
                .unwrap_err()
                .contains("not yet valid")
        );

        let expired = mso_with_validity(now - Duration::hours(1), now - Duration::seconds(1));
        assert!(
            validated_mso_evidence(&expired, "org.iso.18013.5.1.mDL", "ES256", b"cert", now,)
                .unwrap_err()
                .contains("expired")
        );

        let contradictory = mso_with_validity(now + Duration::hours(1), now - Duration::hours(1));
        assert!(validated_mso_evidence(
            &contradictory,
            "org.iso.18013.5.1.mDL",
            "ES256",
            b"cert",
            now,
        )
        .unwrap_err()
        .contains("contradictory"));
    }

    #[test]
    fn direct_issuer_pin_parser_requires_a_certificate_block() {
        let certificate = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            b"public-certificate",
        )
        .unwrap();
        assert_eq!(
            certificate_pem_to_der(&certificate).unwrap(),
            b"public-certificate"
        );

        let private_key =
            pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, b"private")
                .unwrap();
        assert!(certificate_pem_to_der(&private_key).is_err());
        assert!(certificate_pem_to_der("not pem").is_err());
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
    verify_mdoc_signature_with_policy(mdoc_bytes, trusted_issuer_certs_pem, Vec::new())
}

fn verify_mdoc_signature_with_policy(
    mdoc_bytes: Vec<u8>,
    trusted_root_certs_pem: Vec<String>,
    pinned_issuer_certs_pem: Vec<String>,
) -> PyResult<MdocVerificationResult> {
    // Parse the complete ISO DeviceResponse. The compatibility parser used
    // here previously extracts disclosed claims but intentionally does not
    // retain issuerAuth, the MSO, or the x5chain and therefore cannot
    // authenticate an issuer.
    let response: IsoDeviceResponse = match isomdl::cbor::from_slice(&mdoc_bytes) {
        Ok(r) => r,
        Err(e) => {
            return Ok(MdocVerificationResult {
                signature_valid: false,
                issuer_verified: false,
                document_types: vec![],
                document_evidence: vec![],
                error: Some(format!("Failed to parse mDoc DeviceResponse: {e}")),
            });
        }
    };
    if response.version != IsoDeviceResponse::VERSION || !matches!(response.status, Status::OK) {
        return Ok(MdocVerificationResult {
            signature_valid: false,
            issuer_verified: false,
            document_types: vec![],
            document_evidence: vec![],
            error: Some("mDoc DeviceResponse version or status is invalid".to_string()),
        });
    }
    let Some(documents) = response.documents.as_ref() else {
        return Ok(MdocVerificationResult {
            signature_valid: false,
            issuer_verified: false,
            document_types: vec![],
            document_evidence: vec![],
            error: Some("mDoc DeviceResponse contains no documents".to_string()),
        });
    };

    // Get document types
    let document_types: Vec<String> = documents
        .iter()
        .map(|document| document.doc_type.clone())
        .collect();

    let mut chain_validator = marty_verification::verification::ChainValidator::new();
    let mut trust_configuration_valid =
        !trusted_root_certs_pem.is_empty() || !pinned_issuer_certs_pem.is_empty();
    let mut errors = Vec::new();
    if !trust_configuration_valid {
        errors.push("No trusted issuer certificates were configured".to_string());
    }
    for trusted_cert in &trusted_root_certs_pem {
        if let Err(error) = chain_validator.add_trust_anchor_pem(trusted_cert) {
            trust_configuration_valid = false;
            errors.push(format!("Invalid trusted root certificate: {error}"));
        }
    }
    let mut pinned_issuer_certs_der = Vec::with_capacity(pinned_issuer_certs_pem.len());
    for pinned_cert in &pinned_issuer_certs_pem {
        match certificate_pem_to_der(pinned_cert) {
            Ok(certificate) => pinned_issuer_certs_der.push(certificate),
            Err(error) => {
                trust_configuration_valid = false;
                errors.push(format!("Invalid pinned issuer certificate: {error}"));
            }
        }
    }

    // Verify issuerAuth directly from the ISO document. Issuance/signing remains
    // behind the issuer profile and its DID verification method; verification
    // consumes only the public COSE signature and certificate chain.
    let mut all_signatures_valid = true;
    let mut issuer_verified = trust_configuration_valid;
    let mut document_evidence = Vec::with_capacity(documents.len());
    let validation_time = OffsetDateTime::now_utc();

    for document in documents.iter() {
        let issuer_auth = &document.issuer_signed.issuer_auth;
        let x5chain_value = issuer_auth
            .protected
            .header
            .rest
            .iter()
            .chain(issuer_auth.unprotected.rest.iter())
            .find_map(|(label, value)| {
                (label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL)).then_some(value)
            });

        let Some(x5chain_value) = x5chain_value else {
            all_signatures_valid = false;
            issuer_verified = false;
            errors.push(format!(
                "No issuer certificate chain in issuerAuth for {}",
                document.doc_type
            ));
            continue;
        };

        let certificate_chain = match certificate_chain_der(x5chain_value) {
            Ok(chain) => chain,
            Err(error) => {
                all_signatures_valid = false;
                issuer_verified = false;
                errors.push(format!(
                    "Invalid issuer certificate chain for {}: {error}",
                    document.doc_type
                ));
                continue;
            }
        };

        let x5chain = match X5Chain::from_cbor(x5chain_value.clone()) {
            Ok(chain) => chain,
            Err(error) => {
                all_signatures_valid = false;
                issuer_verified = false;
                errors.push(format!(
                    "Invalid issuer x5chain for {}: {error}",
                    document.doc_type
                ));
                continue;
            }
        };

        if let Err(error) =
            marty_verification::verification::mdl::validate_document_signer_certificate_der(
                &certificate_chain[0],
            )
        {
            all_signatures_valid = false;
            issuer_verified = false;
            errors.push(format!(
                "Invalid document-signer certificate profile for {}: {error}",
                document.doc_type
            ));
            continue;
        }

        if let Err(error) = marty_verification::verification::mdl::verify_issuer_signature(
            &x5chain,
            &document.issuer_signed,
        ) {
            all_signatures_valid = false;
            issuer_verified = false;
            errors.push(format!(
                "Signature verification failed for {}: {error}",
                document.doc_type
            ));
            continue;
        }

        if trust_configuration_valid {
            let directly_pinned = pinned_issuer_certs_der
                .iter()
                .any(|pinned| pinned == &certificate_chain[0]);
            let (chain_trusted, chain_error) = if trusted_root_certs_pem.is_empty() {
                (false, None)
            } else {
                match chain_validator.validate_chain_der(&certificate_chain) {
                    Ok(validation) if validation.valid => (true, None),
                    Ok(validation) => (false, Some(validation.errors.join("; "))),
                    Err(error) => (false, Some(error.to_string())),
                }
            };
            if !directly_pinned && !chain_trusted {
                issuer_verified = false;
                errors.push(format!(
                    "Issuer certificate for {} is neither directly pinned nor rooted in a trusted anchor{}",
                    document.doc_type,
                    chain_error
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                ));
            }
        } else {
            // No trusted certs configured — issuer trust CANNOT be established.
            // Signature may be valid but we cannot confirm the issuer is
            // in the trust list. Mark explicitly as unverified.
            issuer_verified = false;
            tracing::warn!(
                "mDOC issuer trust check skipped: no valid trusted certificates configured. \
                 Issuer cert chain present but cannot be validated against a trust anchor."
            );
        }

        match authenticated_document_evidence(document, &certificate_chain[0], validation_time) {
            Ok(evidence) => document_evidence.push(evidence),
            Err(error) => {
                all_signatures_valid = false;
                issuer_verified = false;
                errors.push(format!(
                    "Authenticated MSO evidence is invalid for {}: {error}",
                    document.doc_type
                ));
            }
        }
    }

    Ok(MdocVerificationResult {
        signature_valid: all_signatures_valid,
        issuer_verified,
        document_types,
        document_evidence,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    })
}

fn certificate_chain_der(value: &CoseValue) -> Result<Vec<Vec<u8>>, &'static str> {
    match value {
        CoseValue::Bytes(certificate) if !certificate.is_empty() => Ok(vec![certificate.clone()]),
        CoseValue::Array(certificates) if !certificates.is_empty() => certificates
            .iter()
            .map(|certificate| match certificate {
                CoseValue::Bytes(bytes) if !bytes.is_empty() => Ok(bytes.clone()),
                _ => Err("x5chain entries must be non-empty byte strings"),
            })
            .collect(),
        _ => Err("x5chain must be a byte string or non-empty array"),
    }
}

fn certificate_pem_to_der(value: &str) -> Result<Vec<u8>, String> {
    let (label, certificate) = pem_rfc7468::decode_vec(value.as_bytes())
        .map_err(|error| format!("PEM decode failed: {error}"))?;
    if label != "CERTIFICATE" || certificate.is_empty() {
        return Err("PEM must contain one non-empty CERTIFICATE block".to_string());
    }
    Ok(certificate)
}

fn authenticated_document_evidence(
    document: &isomdl::definitions::device_response::Document,
    issuer_certificate_der: &[u8],
    validation_time: OffsetDateTime,
) -> Result<MdocDocumentVerificationEvidence, String> {
    let algorithm = match document
        .issuer_signed
        .issuer_auth
        .protected
        .header
        .alg
        .as_ref()
    {
        Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256)) => "ES256",
        Some(_) => return Err("unsupported issuer signature algorithm".to_string()),
        None => return Err("issuer signature algorithm is not protected".to_string()),
    };
    let mso_bytes = document
        .issuer_signed
        .issuer_auth
        .payload
        .as_ref()
        .ok_or_else(|| "issuerAuth payload is detached".to_string())?;
    let mso = isomdl::cbor::from_slice::<Tag24<Mso>>(mso_bytes)
        .map_err(|error| format!("unable to parse MSO: {error}"))?
        .into_inner();
    validated_mso_evidence(
        &mso,
        &document.doc_type,
        algorithm,
        issuer_certificate_der,
        validation_time,
    )
}

fn validated_mso_evidence(
    mso: &Mso,
    authenticated_document_type: &str,
    signature_algorithm: &str,
    issuer_certificate_der: &[u8],
    validation_time: OffsetDateTime,
) -> Result<MdocDocumentVerificationEvidence, String> {
    if mso.version != "1.0" {
        return Err(format!("unsupported MSO version {}", mso.version));
    }
    if mso.doc_type != authenticated_document_type {
        return Err("MSO document type does not match the authenticated document".to_string());
    }
    if mso.validity_info.valid_from > mso.validity_info.valid_until {
        return Err("MSO validity window is contradictory".to_string());
    }
    if validation_time < mso.validity_info.valid_from {
        return Err("MSO is not yet valid".to_string());
    }
    if validation_time > mso.validity_info.valid_until {
        return Err("MSO is expired".to_string());
    }

    let digest_algorithm = match mso.digest_algorithm {
        DigestAlgorithm::SHA256 => "SHA-256",
        DigestAlgorithm::SHA384 => "SHA-384",
        DigestAlgorithm::SHA512 => "SHA-512",
    };
    let format_time = |value: OffsetDateTime| {
        value
            .format(&Rfc3339)
            .map_err(|error| format!("unable to format MSO validity timestamp: {error}"))
    };

    Ok(MdocDocumentVerificationEvidence {
        document_type: authenticated_document_type.to_string(),
        signature_algorithm: signature_algorithm.to_string(),
        digest_algorithm: digest_algorithm.to_string(),
        signed_at: format_time(mso.validity_info.signed)?,
        valid_from: format_time(mso.validity_info.valid_from)?,
        valid_until: format_time(mso.validity_info.valid_until)?,
        issuer_certificate_sha256: Sha256::digest(issuer_certificate_der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        validity_checked: true,
        valid_at_verification_time: true,
        revocation_checked: false,
        not_revoked: None,
    })
}

#[cfg(test)]
mod certificate_chain_tests {
    use super::*;

    #[test]
    fn certificate_chain_accepts_single_der_certificate() {
        assert_eq!(
            certificate_chain_der(&CoseValue::Bytes(vec![1, 2, 3])),
            Ok(vec![vec![1, 2, 3]])
        );
    }

    #[test]
    fn certificate_chain_accepts_der_certificate_array() {
        assert_eq!(
            certificate_chain_der(&CoseValue::Array(vec![
                CoseValue::Bytes(vec![1]),
                CoseValue::Bytes(vec![2]),
            ])),
            Ok(vec![vec![1], vec![2]])
        );
    }

    #[test]
    fn certificate_chain_rejects_empty_or_non_binary_values() {
        assert!(certificate_chain_der(&CoseValue::Bytes(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![CoseValue::Null])).is_err());
    }
}
