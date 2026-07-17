// Helper functions for mDoc operations

use chrono::{DateTime, Utc};
use ciborium::Value as CborValue;
use isomdl::definitions::device_key::cose_key::{CoseKey, EC2Curve};
use isomdl::definitions::helpers::ByteStr;
use isomdl::definitions::issuer_signed::IssuerSignedItem;
use isomdl::definitions::{DeviceKeyInfo, DigestAlgorithm, Mso, ValidityInfo};
use p256::pkcs8::DecodePrivateKey;
use pyo3::prelude::*;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Convert chrono DateTime to time OffsetDateTime
fn datetime_to_offset(dt: &DateTime<Utc>) -> PyResult<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(dt.timestamp()).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid timestamp: {}", e))
    })
}

/// Create Mobile Security Object (MSO)
pub fn create_mobile_security_object(
    doc_type: &str,
    namespaces: &BTreeMap<String, Vec<IssuerSignedItem>>,
    digest_algorithm: &str,
    signed: &DateTime<Utc>,
    valid_from: &DateTime<Utc>,
    valid_until: &DateTime<Utc>,
    device_key: Option<&Vec<u8>>,
) -> PyResult<Mso> {
    // Compute value digests for each namespace
    let mut value_digests = BTreeMap::new();

    for (ns_name, items) in namespaces {
        let mut ns_digests = BTreeMap::new();

        for item in items {
            // Serialize the IssuerSignedItem to CBOR
            let mut item_bytes = Vec::new();
            ciborium::ser::into_writer(item, &mut item_bytes).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "CBOR encoding failed: {}",
                    e
                ))
            })?;

            // Compute digest
            let digest = compute_digest(digest_algorithm, &item_bytes)?;
            ns_digests.insert(item.digest_id, ByteStr::from(digest));
        }

        value_digests.insert(ns_name.clone(), ns_digests);
    }

    // Create ValidityInfo
    let validity_info = ValidityInfo {
        signed: datetime_to_offset(signed)?,
        valid_from: datetime_to_offset(valid_from)?,
        valid_until: datetime_to_offset(valid_until)?,
        expected_update: None,
    };

    // Parse device key if provided
    let device_key_info = if let Some(key_bytes) = device_key {
        // Parse CBOR-encoded COSE_Key
        let cose_key: CoseKey = ciborium::de::from_reader(&key_bytes[..]).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Failed to parse device key CBOR: {}. Expected COSE_Key structure.",
                e
            ))
        })?;

        // Validate that it's an EC2 key with P-256 curve
        if let CoseKey::EC2 { crv, .. } = &cose_key {
            if *crv != EC2Curve::P256 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Only P-256 curve supported, got: {:?}",
                    crv
                )));
            }
        } else {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Device key must be EC2 type",
            ));
        }

        DeviceKeyInfo {
            device_key: cose_key,
            key_authorizations: None,
            key_info: None,
        }
    } else {
        // If no device key provided, error - device key is required for mDoc
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Device key is required for mDoc creation",
        ));
    };

    // Parse digest algorithm enum
    let digest_alg = match digest_algorithm {
        "SHA-256" => DigestAlgorithm::SHA256,
        "SHA-384" => DigestAlgorithm::SHA384,
        "SHA-512" => DigestAlgorithm::SHA512,
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Unsupported digest algorithm: {}",
                digest_algorithm
            )))
        }
    };

    Ok(Mso {
        version: "1.0".to_string(),
        digest_algorithm: digest_alg,
        value_digests,
        device_key_info,
        doc_type: doc_type.to_string(),
        validity_info,
    })
}

/// Compute digest using specified algorithm
pub fn compute_digest(algorithm: &str, data: &[u8]) -> PyResult<Vec<u8>> {
    match algorithm {
        "SHA-256" => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "SHA-384" => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "SHA-512" => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Unsupported digest algorithm: {}",
            algorithm
        ))),
    }
}

/// Create COSE_Sign1 IssuerAuth structure
pub fn create_issuer_auth(mso_bytes: &[u8], signature: &[u8]) -> PyResult<Vec<u8>> {
    // COSE_Sign1 structure: [protected headers, unprotected headers, payload, signature]
    // Tag 18 is COSE_Sign1

    // Protected header: { 1: -7 } (alg: ES256)
    let protected_map = CborValue::Map(vec![(
        CborValue::Integer(1.into()),
        CborValue::Integer((-7).into()),
    )]);

    let mut protected_bytes = Vec::new();
    ciborium::ser::into_writer(&protected_map, &mut protected_bytes).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to encode protected header: {}",
            e
        ))
    })?;

    let cose_sign1 = CborValue::Tag(
        18,
        Box::new(CborValue::Array(vec![
            CborValue::Bytes(protected_bytes),    // protected
            CborValue::Map(vec![]),               // unprotected (empty)
            CborValue::Bytes(mso_bytes.to_vec()), // payload
            CborValue::Bytes(signature.to_vec()), // signature
        ])),
    );

    let mut result = Vec::new();
    ciborium::ser::into_writer(&cose_sign1, &mut result).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("COSE encoding failed: {}", e))
    })?;

    Ok(result)
}

/// Convert DER signature to COSE format (raw R||S)
pub fn der_to_cose_signature(der_sig: &[u8]) -> PyResult<Vec<u8>> {
    // DER signature format: 0x30 [length] 0x02 [r-length] [r] 0x02 [s-length] [s]
    // COSE format: [r][s] (raw concatenation, 32 bytes each for P-256)

    if der_sig.len() < 8 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Invalid DER signature: too short",
        ));
    }

    let mut pos = 0;

    // Check SEQUENCE tag
    if der_sig[pos] != 0x30 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Invalid DER signature: missing SEQUENCE tag",
        ));
    }
    pos += 1;

    // Skip length byte(s)
    if der_sig[pos] & 0x80 != 0 {
        // Long form length
        let len_bytes = (der_sig[pos] & 0x7f) as usize;
        pos += 1 + len_bytes;
    } else {
        pos += 1;
    }

    // Parse R
    if der_sig[pos] != 0x02 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Invalid DER signature: missing INTEGER tag for R",
        ));
    }
    pos += 1;
    let r_len = der_sig[pos] as usize;
    pos += 1;
    let r = &der_sig[pos..pos + r_len];
    pos += r_len;

    // Parse S
    if der_sig[pos] != 0x02 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Invalid DER signature: missing INTEGER tag for S",
        ));
    }
    pos += 1;
    let s_len = der_sig[pos] as usize;
    pos += 1;
    let s = &der_sig[pos..pos + s_len];

    // Remove leading zero bytes (DER padding for positive integers)
    let r_trimmed = if r.len() > 32 && r[0] == 0 {
        &r[1..]
    } else {
        r
    };
    let s_trimmed = if s.len() > 32 && s[0] == 0 {
        &s[1..]
    } else {
        s
    };

    // Concatenate R and S (pad to 32 bytes if needed)
    let mut result = vec![0u8; 64];
    let r_start = 32 - r_trimmed.len().min(32);
    let s_start = 64 - s_trimmed.len().min(32);
    result[r_start..32].copy_from_slice(&r_trimmed[..r_trimmed.len().min(32)]);
    result[s_start..64].copy_from_slice(&s_trimmed[..s_trimmed.len().min(32)]);

    Ok(result)
}

/// Sign data with DER-encoded private key (P-256)
pub fn sign_with_der_key(key_der: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    // Try PKCS#8 format first
    if let Ok(signing_key) = SigningKey::from_pkcs8_der(key_der) {
        let signature: Signature = signing_key.sign(data);
        return Ok(signature.to_der().to_bytes().to_vec());
    }

    // Try SEC1 format
    if let Ok(signing_key) = SigningKey::from_slice(key_der) {
        let signature: Signature = signing_key.sign(data);
        return Ok(signature.to_der().to_bytes().to_vec());
    }

    Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
        "Invalid private key format: expected PKCS#8 or SEC1 DER",
    ))
}
