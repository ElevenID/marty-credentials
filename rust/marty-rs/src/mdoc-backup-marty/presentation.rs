//! mDoc presentation (selective disclosure).
//!
//! Provides functions for creating DeviceResponse presentations
//! with selective disclosure of claims.
//!
//! Note: The isomdl library uses a stateful SessionManager approach for device
//! presentations. This module provides a simpler API for basic use cases.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::types::{MdocCredential, MdocDisclosureRequest};

/// Create a DeviceResponse with selective disclosure.
///
/// This is a simplified presentation API. For full session-based presentations
/// (with reader authentication, session transcript binding, etc.), use the
/// `SessionManager` API directly via Rust.
///
/// # Arguments
/// * `credential` - The mDoc credential to present
/// * `disclosure_request` - Which claims to disclose
/// * `device_key_pem` - PEM-encoded device private key for device auth
///
/// # Returns
/// * Base64-encoded DeviceResponse CBOR
#[pyfunction]
#[pyo3(signature = (credential, disclosure_request, device_key_pem))]
pub fn create_device_response(
    credential: &MdocCredential,
    disclosure_request: &MdocDisclosureRequest,
    device_key_pem: &str,
) -> PyResult<String> {
    use base64::Engine;
    use p256::pkcs8::DecodePrivateKey;

    // Decode credential CBOR
    let credential_bytes = base64::engine::general_purpose::STANDARD
        .decode(&credential.cbor_base64)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Base64 decode error: {}", e)))?;

    // Parse the mDoc
    let mdoc: isomdl::issuance::Mdoc = ciborium::from_reader(&credential_bytes[..])
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("mDoc parse error: {}", e)))?;

    // Parse device signing key (for validation, not yet used in signing)
    let _device_key = p256::ecdsa::SigningKey::from_pkcs8_pem(device_key_pem)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Key parse error: {}", e)))?;

    // Parse requested fields from JSON
    let requested_fields: BTreeMap<String, Vec<String>> =
        serde_json::from_str(&disclosure_request.requested_fields_json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Requested fields JSON error: {}", e)))?;

    // Build DeviceResponse by filtering the mDoc's namespaces
    let filtered_namespaces = filter_namespaces(&mdoc, &requested_fields)?;

    // Build the DeviceResponse structure
    let device_response = DeviceResponseSimple {
        version: "1.0".to_string(),
        documents: if filtered_namespaces.is_empty() {
            None
        } else {
            Some(vec![DocumentSimple {
                doc_type: mdoc.doc_type.clone(),
                issuer_signed: IssuerSignedSimple {
                    namespaces: Some(filtered_namespaces),
                    issuer_auth: mdoc.issuer_auth.clone(),
                },
                device_signed: None, // No device signature in simple mode
                errors: None,
            }])
        },
        document_errors: None,
        status: 0, // OK
    };

    // Serialize to CBOR
    let mut response_bytes = Vec::new();
    ciborium::into_writer(&device_response, &mut response_bytes)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("CBOR error: {}", e)))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&response_bytes))
}

/// Filter namespaces to only include requested claims.
fn filter_namespaces(
    mdoc: &isomdl::issuance::Mdoc,
    requested_fields: &BTreeMap<String, Vec<String>>,
) -> PyResult<BTreeMap<String, Vec<ciborium::Value>>> {
    let mut filtered = BTreeMap::new();

    for (ns_name, requested_claims) in requested_fields {
        if let Some(issuer_signed_items) = mdoc.namespaces.get(ns_name) {
            // Convert and filter items
            let items: Vec<ciborium::Value> = issuer_signed_items
                .iter()
                .filter_map(|item_bytes| {
                    // Deserialize the Tag24<IssuerSignedItem>
                    let inner_bytes = &item_bytes.inner_bytes;
                    
                    // Parse to check element_identifier
                    if let Ok(item) = ciborium::from_reader::<isomdl::definitions::IssuerSignedItem, _>(&inner_bytes[..]) {
                        if requested_claims.contains(&item.element_identifier) {
                            // Return the original tagged bytes
                            let mut tagged_bytes = Vec::new();
                            if ciborium::into_writer(item_bytes, &mut tagged_bytes).is_ok() {
                                if let Ok(value) = ciborium::from_reader::<ciborium::Value, _>(&tagged_bytes[..]) {
                                    return Some(value);
                                }
                            }
                        }
                    }
                    None
                })
                .collect();

            if !items.is_empty() {
                filtered.insert(ns_name.clone(), items);
            }
        }
    }

    Ok(filtered)
}

// Simplified response types for serialization
use coset::CoseSign1;
use isomdl::cose::MaybeTagged;

#[derive(Serialize, Deserialize, Clone)]
struct DeviceResponseSimple {
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    documents: Option<Vec<DocumentSimple>>,
    #[serde(rename = "documentErrors", skip_serializing_if = "Option::is_none")]
    document_errors: Option<ciborium::Value>,
    status: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DocumentSimple {
    doc_type: String,
    issuer_signed: IssuerSignedSimple,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_signed: Option<ciborium::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<ciborium::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct IssuerSignedSimple {
    #[serde(skip_serializing_if = "Option::is_none")]
    namespaces: Option<BTreeMap<String, Vec<ciborium::Value>>>,
    issuer_auth: MaybeTagged<CoseSign1>,
}

/// Register presentation functions with Python module.
pub fn register_presentation_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_device_response, m)?)?;
    Ok(())
}
