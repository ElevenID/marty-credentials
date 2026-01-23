// Signed mDoc document types

use super::helpers::{create_issuer_auth, der_to_cose_signature};
use ciborium::Value as CborValue;
use isomdl::definitions::issuer_signed::IssuerSignedItem;
use pyo3::prelude::*;
use std::collections::BTreeMap;

/// Signed mDoc document
#[pyclass]
pub struct MdocSignedDocument {
    pub(crate) doc_type: String,
    pub(crate) cbor_bytes: Vec<u8>,
}

#[pymethods]
impl MdocSignedDocument {
    /// Convert to CBOR bytes (DeviceResponse format)
    pub fn to_cbor(&self) -> PyResult<Vec<u8>> {
        Ok(self.cbor_bytes.clone())
    }

    /// Get the docType
    pub fn get_doc_type(&self) -> PyResult<String> {
        Ok(self.doc_type.clone())
    }

    /// Get base64url-encoded CBOR
    pub fn to_base64url(&self) -> PyResult<String> {
        use base64::Engine;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.cbor_bytes))
    }
}

/// Unsigned mDoc prepared for HSM signing
#[pyclass]
pub struct MdocPreparedForHsm {
    pub(crate) tbs_data: Vec<u8>,
    pub(crate) doc_type: String,
    pub(crate) namespaces: BTreeMap<String, BTreeMap<String, CborValue>>,
    pub(crate) issuer_signed_items: BTreeMap<String, Vec<IssuerSignedItem>>,
}

#[pymethods]
impl MdocPreparedForHsm {
    /// Get the data that needs to be signed by HSM (MSO bytes)
    pub fn get_tbs_data(&self) -> PyResult<Vec<u8>> {
        Ok(self.tbs_data.clone())
    }

    /// Complete the mDoc with signature from HSM
    /// signature_der: DER-encoded ECDSA signature from HSM
    /// Returns complete mDoc as CBOR DeviceResponse
    pub fn complete_with_signature(&self, signature_der: Vec<u8>) -> PyResult<MdocSignedDocument> {
        // Convert DER signature to COSE format
        let cose_signature = der_to_cose_signature(&signature_der)?;

        // Create IssuerAuth (COSE_Sign1 structure)
        let issuer_auth = create_issuer_auth(&self.tbs_data, &cose_signature)?;

        // Build DeviceResponse structure
        let device_response = build_device_response(
            &self.doc_type,
            &self.issuer_signed_items,
            &issuer_auth,
        )?;

        // Encode to CBOR
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&device_response, &mut cbor_bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "CBOR encoding failed: {}",
                e
            ))
        })?;

        Ok(MdocSignedDocument {
            doc_type: self.doc_type.clone(),
            cbor_bytes,
        })
    }
}

/// Build DeviceResponse CBOR structure
fn build_device_response(
    doc_type: &str,
    issuer_signed_items: &BTreeMap<String, Vec<IssuerSignedItem>>,
    issuer_auth: &[u8],
) -> PyResult<CborValue> {
    // Build nameSpaces
    let mut name_spaces = Vec::new();
    for (ns_name, items) in issuer_signed_items {
        let mut ns_items = Vec::new();
        for item in items {
            // Each IssuerSignedItem is Tag24-wrapped
            let mut item_bytes = Vec::new();
            ciborium::ser::into_writer(item, &mut item_bytes).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to encode item: {}",
                    e
                ))
            })?;
            ns_items.push(CborValue::Tag(24, Box::new(CborValue::Bytes(item_bytes))));
        }
        name_spaces.push((
            CborValue::Text(ns_name.clone()),
            CborValue::Array(ns_items),
        ));
    }

    // Build IssuerSigned
    let issuer_signed = CborValue::Map(vec![
        (
            CborValue::Text("nameSpaces".to_string()),
            CborValue::Map(name_spaces),
        ),
        (
            CborValue::Text("issuerAuth".to_string()),
            CborValue::Bytes(issuer_auth.to_vec()),
        ),
    ]);

    // Build Document
    let document = CborValue::Map(vec![
        (
            CborValue::Text("docType".to_string()),
            CborValue::Text(doc_type.to_string()),
        ),
        (
            CborValue::Text("issuerSigned".to_string()),
            issuer_signed,
        ),
    ]);

    // Build DeviceResponse
    let device_response = CborValue::Map(vec![
        (
            CborValue::Text("version".to_string()),
            CborValue::Text("1.0".to_string()),
        ),
        (
            CborValue::Text("documents".to_string()),
            CborValue::Array(vec![document]),
        ),
        (
            CborValue::Text("status".to_string()),
            CborValue::Integer(0.into()),
        ),
    ]);

    Ok(device_response)
}
