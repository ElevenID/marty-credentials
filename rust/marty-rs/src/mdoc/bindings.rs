// Python function bindings for mDoc operations

use super::builder::MdocBuilder;
use super::document::MdocPreparedForHsm;
use super::helpers::sign_with_der_key;
use super::types::create_issuer_signed_items;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Create an mDoc credential (full signing in Rust)
#[pyfunction]
#[pyo3(signature = (doc_type, namespaces, validity, signing_key_der, device_key_der=None, digest_algorithm=None))]
pub fn create_mdoc(
    doc_type: String,
    namespaces: &Bound<'_, PyDict>,
    validity: &Bound<'_, PyDict>,
    signing_key_der: Vec<u8>,
    device_key_der: Option<Vec<u8>>,
    digest_algorithm: Option<String>,
) -> PyResult<Vec<u8>> {
    let mut builder = MdocBuilder::new(doc_type, digest_algorithm);

    // Parse validity info
    let signed: String = validity
        .get_item("signed")?
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'signed' in validity")
        })?
        .extract()?;
    let valid_from: String = validity
        .get_item("valid_from")?
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'valid_from' in validity")
        })?
        .extract()?;
    let valid_until: String = validity
        .get_item("valid_until")?
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'valid_until' in validity")
        })?
        .extract()?;

    builder.set_validity(signed, valid_from, valid_until)?;

    // Add all namespaces
    for (ns_name, claims) in namespaces.iter() {
        let ns_str: String = ns_name.extract()?;
        let claims_dict = claims.downcast::<PyDict>()?;
        builder.add_namespace(ns_str, claims_dict)?;
    }

    // Set device key if provided
    if let Some(dk) = device_key_der {
        builder.set_device_key(dk)?;
    }

    // Build MSO (to-be-signed data)
    let tbs_data = builder.build_issuer_signed()?;

    // Sign with provided key
    let signature = sign_with_der_key(&signing_key_der, &tbs_data)?;

    // Create complete document
    let issuer_signed_items = create_issuer_signed_items(&builder.namespaces)?;
    let prepared = MdocPreparedForHsm {
        tbs_data,
        doc_type: builder.doc_type.clone(),
        namespaces: builder.namespaces.clone(),
        issuer_signed_items,
    };

    let signed_doc = prepared.complete_with_signature(signature)?;
    signed_doc.to_cbor()
}

/// Prepare mDoc for HSM signing (split-signing workflow)
#[pyfunction]
#[pyo3(signature = (doc_type, namespaces, validity, device_key_der=None, digest_algorithm=None))]
pub fn prepare_mdoc_for_hsm(
    doc_type: String,
    namespaces: &Bound<'_, PyDict>,
    validity: &Bound<'_, PyDict>,
    device_key_der: Option<Vec<u8>>,
    digest_algorithm: Option<String>,
) -> PyResult<MdocPreparedForHsm> {
    let mut builder = MdocBuilder::new(doc_type.clone(), digest_algorithm);

    // Parse validity info
    let signed: String = validity
        .get_item("signed")?
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'signed' in validity")
        })?
        .extract()?;
    let valid_from: String = validity
        .get_item("valid_from")?
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'valid_from' in validity")
        })?
        .extract()?;
    let valid_until: String = validity
        .get_item("valid_until")?
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Missing 'valid_until' in validity")
        })?
        .extract()?;

    builder.set_validity(signed, valid_from, valid_until)?;

    // Add all namespaces
    for (ns_name, claims) in namespaces.iter() {
        let ns_str: String = ns_name.extract()?;
        let claims_dict = claims.downcast::<PyDict>()?;
        builder.add_namespace(ns_str, claims_dict)?;
    }

    // Set device key if provided
    if let Some(dk) = device_key_der {
        builder.set_device_key(dk)?;
    }

    // Build to get TBS data
    let tbs_data = builder.build_issuer_signed()?;
    let issuer_signed_items = create_issuer_signed_items(&builder.namespaces)?;

    Ok(MdocPreparedForHsm {
        tbs_data,
        doc_type,
        namespaces: builder.namespaces.clone(),
        issuer_signed_items,
    })
}

/// Complete mDoc with external signature
#[pyfunction]
pub fn complete_mdoc_with_signature(
    prepared: &MdocPreparedForHsm,
    signature: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let signed_doc = prepared.complete_with_signature(signature)?;
    signed_doc.to_cbor()
}
