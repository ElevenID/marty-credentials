// Signed mDoc document types

use super::helpers::{create_issuer_auth, der_to_cose_signature};
use ciborium::Value as CborValue;
use isomdl::definitions::issuer_signed::{IssuerSigned, IssuerSignedItem};
use isomdl::definitions::device_response::Status;
use isomdl::definitions::{DeviceResponse, Document};
use isomdl::definitions::helpers::{NonEmptyMap, NonEmptyVec, Tag24, ByteStr};
use isomdl::cose::MaybeTagged;
use pyo3::prelude::*;
use ssi::claims::cose::CoseSign1;
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
        let cbor_bytes = build_device_response(
            &self.doc_type,
            &self.issuer_signed_items,
            &issuer_auth,
        )?;

        Ok(MdocSignedDocument {
            doc_type: self.doc_type.clone(),
            cbor_bytes,
        })
    }
}

/// Build DeviceResponse for testing (wraps Document with minimal deviceSigned)
/// For production, issued credentials should be bare Documents.
/// This creates a test DeviceResponse to allow immediate verification in tests.
fn build_device_response(
    doc_type: &str,
    issuer_signed_items: &BTreeMap<String, Vec<IssuerSignedItem>>,
    issuer_auth: &[u8],
) -> PyResult<Vec<u8>> {
    // Parse issuer_auth as CBOR value (keep it as-is for issuer_auth field)
    let issuer_auth_cbor: CborValue = ciborium::from_reader(&issuer_auth[..]).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to parse issuer_auth: {}",
            e
        ))
    })?;

    // Build namespaces map with Tag24-wrapped items using isomdl types
    let mut namespaces = BTreeMap::new();
    for (ns_name, items) in issuer_signed_items {
        let tagged_items: Result<Vec<Tag24<IssuerSignedItem>>, _> = items
            .iter()
            .map(|item| Tag24::new(item.clone()))
            .collect();
        
        let tagged_items = tagged_items.map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Failed to create Tag24: {}", e))
        })?;
        
        let items_vec = NonEmptyVec::try_from(tagged_items).map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Namespace must have at least one item")
        })?;
        
        namespaces.insert(ns_name.clone(), items_vec);
    }
    
    let namespaces_map = NonEmptyMap::try_from(namespaces).map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>("Must have at least one namespace")
    })?;

    // Serialize IssuerSigned with proper Tag24 wrapping by the library
    let issuer_signed_cbor = CborValue::Map(vec![
        (CborValue::Text("nameSpaces".to_string()), {
            // Let isomdl serialize the NonEmptyMap with proper Tag24 wrapping
            let mut ns_bytes = Vec::new();
            ciborium::ser::into_writer(&namespaces_map, &mut ns_bytes).unwrap();
            ciborium::from_reader(&ns_bytes[..]).unwrap()
        }),
        (CborValue::Text("issuerAuth".to_string()), issuer_auth_cbor),
    ]);

    // Build Document with minimal deviceSigned for testing
    // Real presentations add deviceAuth with holder's signature
    // For testing, create minimal valid deviceAuth (empty COSE_Sign1)
    let empty_device_namespaces = {
        let empty_map = BTreeMap::<String, Vec<u8>>::new();
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&empty_map, &mut bytes).unwrap();
        bytes
    };
    
    // Create minimal COSE_Sign1 structure [protected, unprotected, payload, signature]
    // Tag 18 is COSE_Sign1 per RFC 8152
    let empty_cose_sign1 = CborValue::Tag(18, Box::new(CborValue::Array(vec![
        CborValue::Bytes(vec![]), // empty protected headers
        CborValue::Map(vec![]),  // empty unprotected headers
        CborValue::Null,  // no payload for device auth
        CborValue::Bytes(vec![]), // empty signature (for testing)
    ])));
    
    let document_cbor = CborValue::Map(vec![
        (CborValue::Text("docType".to_string()), CborValue::Text(doc_type.to_string())),
        (CborValue::Text("issuerSigned".to_string()), issuer_signed_cbor),
        (CborValue::Text("deviceSigned".to_string()), CborValue::Map(vec![
            (CborValue::Text("nameSpaces".to_string()), 
             CborValue::Tag(24, Box::new(CborValue::Bytes(empty_device_namespaces)))),
            (CborValue::Text("deviceAuth".to_string()), CborValue::Map(vec![
                (CborValue::Text("deviceSignature".to_string()), empty_cose_sign1),
            ])),
        ])),
    ]);

    // Wrap in DeviceResponse for test compatibility
    let device_response_cbor = CborValue::Map(vec![
        (CborValue::Text("version".to_string()), CborValue::Text("1.0".to_string())),
        (CborValue::Text("documents".to_string()), CborValue::Array(vec![document_cbor])),
        (CborValue::Text("status".to_string()), CborValue::Integer(0.into())),
    ]);

    // Serialize DeviceResponse to CBOR bytes
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&device_response_cbor, &mut cbor_bytes).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to serialize DeviceResponse: {}",
            e
        ))
    })?;

    Ok(cbor_bytes)
}
