// MdocBuilder - construct mDoc credentials step by step

use super::helpers::create_mobile_security_object;
use super::types::{create_issuer_signed_items, python_to_cbor_value, ValidityInfo};
use chrono::{DateTime, Utc};
use ciborium::Value as CborValue;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::BTreeMap;

/// Builder for creating mDoc credentials
#[pyclass]
pub struct MdocBuilder {
    pub(crate) doc_type: String,
    pub(crate) namespaces: BTreeMap<String, BTreeMap<String, CborValue>>,
    pub(crate) validity_info: Option<ValidityInfo>,
    pub(crate) device_key: Option<Vec<u8>>,
    pub(crate) digest_algorithm: String,
}

#[pymethods]
impl MdocBuilder {
    #[new]
    #[pyo3(signature = (doc_type, digest_algorithm=None))]
    pub fn new(doc_type: String, digest_algorithm: Option<String>) -> Self {
        Self {
            doc_type,
            namespaces: BTreeMap::new(),
            validity_info: None,
            device_key: None,
            digest_algorithm: digest_algorithm.unwrap_or_else(|| "SHA-256".to_string()),
        }
    }

    /// Add a namespace with claims
    pub fn add_namespace(&mut self, namespace: String, claims: &Bound<'_, PyDict>) -> PyResult<()> {
        let mut namespace_claims = BTreeMap::new();

        for (key, value) in claims.iter() {
            let key_str: String = key.extract()?;
            let cbor_value = python_to_cbor_value(&value)?;
            namespace_claims.insert(key_str, cbor_value);
        }

        self.namespaces.insert(namespace, namespace_claims);
        Ok(())
    }

    /// Set validity period
    pub fn set_validity(
        &mut self,
        signed: String,
        valid_from: String,
        valid_until: String,
    ) -> PyResult<()> {
        let signed_dt = DateTime::parse_from_rfc3339(&signed)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid signed date: {}",
                    e
                ))
            })?
            .with_timezone(&Utc);

        let valid_from_dt = DateTime::parse_from_rfc3339(&valid_from)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid valid_from date: {}",
                    e
                ))
            })?
            .with_timezone(&Utc);

        let valid_until_dt = DateTime::parse_from_rfc3339(&valid_until)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid valid_until date: {}",
                    e
                ))
            })?
            .with_timezone(&Utc);

        self.validity_info = Some(ValidityInfo {
            signed: signed_dt,
            valid_from: valid_from_dt,
            valid_until: valid_until_dt,
        });

        Ok(())
    }

    /// Set device public key (for device key binding)
    pub fn set_device_key(&mut self, device_key_der: Vec<u8>) -> PyResult<()> {
        self.device_key = Some(device_key_der);
        Ok(())
    }

    /// Build IssuerSigned structure (ready for signing)
    /// Returns CBOR-encoded MSO bytes that need to be signed
    pub fn build_issuer_signed(&self) -> PyResult<Vec<u8>> {
        // Validate required fields
        if self.namespaces.is_empty() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "At least one namespace is required",
            ));
        }

        if self.validity_info.is_none() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Validity info is required",
            ));
        }

        // Create IssuerSignedItems
        let issuer_signed_items = create_issuer_signed_items(&self.namespaces)?;

        // Create MSO (Mobile Security Object)
        let validity = self.validity_info.as_ref().unwrap();
        let mso = create_mobile_security_object(
            &self.doc_type,
            &issuer_signed_items,
            &self.digest_algorithm,
            &validity.signed,
            &validity.valid_from,
            &validity.valid_until,
            self.device_key.as_ref(),
        )?;

        // Encode MSO as CBOR
        let mut mso_bytes = Vec::new();
        ciborium::ser::into_writer(&mso, &mut mso_bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "CBOR encoding failed: {}",
                e
            ))
        })?;

        Ok(mso_bytes)
    }

    /// Get the to-be-signed data for HSM signing
    pub fn get_tbs_data(&self) -> PyResult<Vec<u8>> {
        self.build_issuer_signed()
    }
}
