// Core types for mDoc module

use chrono::{DateTime, Utc};
use ciborium::Value as CborValue;
use isomdl::definitions::helpers::ByteStr;
use isomdl::definitions::issuer_signed::IssuerSignedItem;
use isomdl::definitions::DigestId;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::BTreeMap;

/// Internal validity info structure
#[derive(Clone)]
pub struct ValidityInfo {
    pub signed: DateTime<Utc>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// Convert Python value to CBOR value
pub fn python_to_cbor_value(py_value: &Bound<'_, PyAny>) -> PyResult<CborValue> {
    if let Ok(s) = py_value.extract::<String>() {
        Ok(CborValue::Text(s))
    } else if let Ok(i) = py_value.extract::<i64>() {
        Ok(CborValue::Integer(i.into()))
    } else if let Ok(f) = py_value.extract::<f64>() {
        Ok(CborValue::Float(f))
    } else if let Ok(b) = py_value.extract::<bool>() {
        Ok(CborValue::Bool(b))
    } else if py_value.is_none() {
        Ok(CborValue::Null)
    } else if let Ok(bytes) = py_value.extract::<Vec<u8>>() {
        Ok(CborValue::Bytes(bytes))
    } else if let Ok(dict) = py_value.cast::<PyDict>() {
        let mut map = Vec::new();
        for (key, value) in dict.iter() {
            let key_cbor = python_to_cbor_value(&key)?;
            let value_cbor = python_to_cbor_value(&value)?;
            map.push((key_cbor, value_cbor));
        }
        Ok(CborValue::Map(map))
    } else {
        // Try as string representation
        if let Ok(repr) = py_value.str() {
            Ok(CborValue::Text(repr.to_string()))
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Unsupported type for CBOR conversion",
            ))
        }
    }
}

/// Create IssuerSignedItems from namespaces
pub fn create_issuer_signed_items(
    namespaces: &BTreeMap<String, BTreeMap<String, CborValue>>,
) -> PyResult<BTreeMap<String, Vec<IssuerSignedItem>>> {
    let mut result = BTreeMap::new();

    for (ns_name, claims) in namespaces {
        let mut items = Vec::new();

        for (idx, (claim_name, claim_value)) in claims.iter().enumerate() {
            // Generate random salt for each claim
            let mut random = [0u8; 16];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut random);

            let item = IssuerSignedItem {
                digest_id: DigestId::new(idx as i32),
                random: ByteStr::from(random.to_vec()),
                element_identifier: claim_name.clone(),
                element_value: claim_value.clone(),
            };

            items.push(item);
        }

        result.insert(ns_name.clone(), items);
    }

    Ok(result)
}
