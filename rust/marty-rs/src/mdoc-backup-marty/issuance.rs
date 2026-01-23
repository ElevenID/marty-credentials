//! mDoc credential issuance.
//!
//! Provides functions for creating and signing mDoc/mDL credentials
//! using the isomdl library.

use coset::iana::Algorithm;
use p256::pkcs8::DecodePrivateKey;
use pyo3::prelude::*;
use std::collections::BTreeMap;

use super::types::{
    MdocCredential, MdocDeviceKeyInfo, MdocIssuanceRequest, MdocKeyAlgorithm,
    PreparedMdoc,
};

/// Create an mDoc credential with a local signing key.
///
/// # Arguments
/// * `request` - Issuance request with doc_type, claims, device key, validity
/// * `issuer_cert_pem` - PEM-encoded issuer certificate chain
/// * `issuer_key_pem` - PEM-encoded issuer private key
/// * `algorithm` - Signing algorithm (ES256, ES384, EdDSA)
///
/// # Returns
/// * `MdocCredential` with CBOR-encoded mDoc
#[pyfunction]
#[pyo3(signature = (request, issuer_cert_pem, issuer_key_pem, algorithm=None))]
pub fn create_mdoc_credential(
    request: &MdocIssuanceRequest,
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
    algorithm: Option<MdocKeyAlgorithm>,
) -> PyResult<MdocCredential> {
    use base64::Engine;
    use isomdl::definitions::{DigestAlgorithm, ValidityInfo};
    use isomdl::issuance::Mdoc;
    use p256::ecdsa::SigningKey;
    use time::OffsetDateTime;

    let alg = algorithm.unwrap_or(MdocKeyAlgorithm::ES256);

    // Parse namespaces from JSON
    let namespaces = parse_namespaces_json(&request.namespaces_json)?;

    // Parse validity info
    let validity_info = ValidityInfo {
        signed: OffsetDateTime::from_unix_timestamp(request.validity.signed)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid timestamp: {}", e)))?,
        valid_from: OffsetDateTime::from_unix_timestamp(request.validity.valid_from)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid timestamp: {}", e)))?,
        valid_until: OffsetDateTime::from_unix_timestamp(request.validity.valid_until)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid timestamp: {}", e)))?,
        expected_update: request
            .validity
            .expected_update
            .map(|ts| OffsetDateTime::from_unix_timestamp(ts))
            .transpose()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid timestamp: {}", e)))?,
    };

    // Parse device key
    let device_key_info = parse_device_key_info(&request.device_key)?;

    // Parse issuer certificate chain
    let x5chain = isomdl::definitions::x509::x5chain::X5Chain::builder()
        .with_pem_certificate(issuer_cert_pem.as_bytes())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid certificate: {}", e)))?
        .build()
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("X5Chain error: {}", e)))?;

    // Parse issuer signing key
    let signing_key: SigningKey = SigningKey::from_pkcs8_pem(issuer_key_pem)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Key parse error: {}", e)))?;

    // Build and issue the mDoc
    let mdoc = match alg {
        MdocKeyAlgorithm::ES256 => {
            Mdoc::builder()
                .doc_type(request.doc_type.clone())
                .namespaces(namespaces)
                .validity_info(validity_info.clone())
                .digest_algorithm(DigestAlgorithm::SHA256)
                .device_key_info(device_key_info)
                .issue::<SigningKey, p256::ecdsa::Signature>(x5chain, signing_key)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Issuance error: {}", e)))?
        }
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Only ES256 is currently supported for mDoc issuance",
            ));
        }
    };

    // Serialize to CBOR
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&mdoc, &mut cbor_bytes)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("CBOR error: {}", e)))?;

    let credential_id = uuid::Uuid::new_v4().to_string();

    Ok(MdocCredential {
        doc_type: request.doc_type.clone(),
        cbor_base64: base64::engine::general_purpose::STANDARD.encode(&cbor_bytes),
        credential_id,
        issued_at: request.validity.signed,
        valid_until: request.validity.valid_until,
    })
}

/// Prepare an mDoc for remote/HSM signing.
///
/// Returns the signature payload that needs to be signed externally,
/// along with prepared state to complete the issuance.
///
/// # Arguments
/// * `request` - Issuance request
/// * `algorithm` - Signing algorithm
///
/// # Returns
/// * `PreparedMdoc` with signature payload and prepared state
#[pyfunction]
#[pyo3(signature = (request, algorithm=None))]
pub fn prepare_mdoc_for_signing(
    request: &MdocIssuanceRequest,
    algorithm: Option<MdocKeyAlgorithm>,
) -> PyResult<PreparedMdoc> {
    use base64::Engine;
    use isomdl::definitions::{DigestAlgorithm, ValidityInfo};
    use isomdl::issuance::Mdoc;
    use time::OffsetDateTime;

    let alg = algorithm.unwrap_or(MdocKeyAlgorithm::ES256);

    // Parse namespaces from JSON
    let namespaces = parse_namespaces_json(&request.namespaces_json)?;

    // Parse validity info
    let validity_info = ValidityInfo {
        signed: OffsetDateTime::from_unix_timestamp(request.validity.signed)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid timestamp: {}", e)))?,
        valid_from: OffsetDateTime::from_unix_timestamp(request.validity.valid_from)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid timestamp: {}", e)))?,
        valid_until: OffsetDateTime::from_unix_timestamp(request.validity.valid_until)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid timestamp: {}", e)))?,
        expected_update: request
            .validity
            .expected_update
            .map(|ts| OffsetDateTime::from_unix_timestamp(ts))
            .transpose()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid timestamp: {}", e)))?,
    };

    // Parse device key
    let device_key_info = parse_device_key_info(&request.device_key)?;

    // Determine signature algorithm
    let sig_alg = match alg {
        MdocKeyAlgorithm::ES256 => Algorithm::ES256,
        MdocKeyAlgorithm::ES384 => Algorithm::ES384,
        MdocKeyAlgorithm::ES512 => Algorithm::ES512,
        MdocKeyAlgorithm::EdDSA => Algorithm::EdDSA,
    };

    // Prepare the mDoc (doesn't require signing key yet)
    let prepared = Mdoc::prepare(
        request.doc_type.clone(),
        namespaces,
        validity_info,
        DigestAlgorithm::SHA256,
        device_key_info,
        sig_alg,
        true, // enable decoy digests
    )
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Prepare error: {}", e)))?;

    // Get signature payload
    let signature_payload = prepared.signature_payload().to_vec();

    // Serialize prepared state for later completion
    let mut prepared_state = Vec::new();
    ciborium::into_writer(&prepared, &mut prepared_state)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Serialize error: {}", e)))?;

    Ok(PreparedMdoc {
        signature_payload_base64: base64::engine::general_purpose::STANDARD.encode(&signature_payload),
        prepared_state_base64: base64::engine::general_purpose::STANDARD.encode(&prepared_state),
        doc_type: request.doc_type.clone(),
    })
}

/// Complete an mDoc with an externally-provided signature.
///
/// # Arguments
/// * `prepared` - PreparedMdoc from prepare_mdoc_for_signing()
/// * `signature_base64` - Base64-encoded signature from HSM
/// * `issuer_cert_pem` - PEM-encoded issuer certificate chain
///
/// # Returns
/// * `MdocCredential` with completed mDoc
#[pyfunction]
pub fn complete_mdoc_with_signature(
    prepared: &PreparedMdoc,
    signature_base64: &str,
    issuer_cert_pem: &str,
) -> PyResult<MdocCredential> {
    use base64::Engine;
    use isomdl::issuance::mdoc::PreparedMdoc as IsoPreparedMdoc;

    // Decode prepared state
    let prepared_state_bytes = base64::engine::general_purpose::STANDARD
        .decode(&prepared.prepared_state_base64)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Base64 error: {}", e)))?;

    let prepared_mdoc: IsoPreparedMdoc = ciborium::from_reader(&prepared_state_bytes[..])
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Deserialize error: {}", e)))?;

    // Decode signature
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Signature base64 error: {}", e)))?;

    // Parse issuer certificate chain
    let x5chain = isomdl::definitions::x509::x5chain::X5Chain::builder()
        .with_pem_certificate(issuer_cert_pem.as_bytes())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid certificate: {}", e)))?
        .build()
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("X5Chain error: {}", e)))?;

    // Complete the mDoc
    let mdoc = prepared_mdoc.complete(x5chain, signature);

    // Serialize to CBOR
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&mdoc, &mut cbor_bytes)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("CBOR error: {}", e)))?;

    let credential_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    Ok(MdocCredential {
        doc_type: prepared.doc_type.clone(),
        cbor_base64: base64::engine::general_purpose::STANDARD.encode(&cbor_bytes),
        credential_id,
        issued_at: now,
        valid_until: now + (365 * 24 * 60 * 60), // Default 1 year
    })
}

// ============================================================================
// Helper functions
// ============================================================================

/// Parse namespaces JSON to BTreeMap with ciborium values.
fn parse_namespaces_json(
    json: &str,
) -> PyResult<BTreeMap<String, BTreeMap<String, ciborium::Value>>> {
    let json_value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("JSON parse error: {}", e)))?;

    let mut result = BTreeMap::new();

    if let serde_json::Value::Object(namespaces) = json_value {
        for (ns_name, ns_claims) in namespaces {
            let mut claims = BTreeMap::new();
            if let serde_json::Value::Object(claim_map) = ns_claims {
                for (claim_name, claim_value) in claim_map {
                    let cbor_value = json_to_cbor(&claim_value)?;
                    claims.insert(claim_name, cbor_value);
                }
            }
            result.insert(ns_name, claims);
        }
    }

    Ok(result)
}

/// Convert JSON value to CBOR value.
fn json_to_cbor(value: &serde_json::Value) -> PyResult<ciborium::Value> {
    match value {
        serde_json::Value::Null => Ok(ciborium::Value::Null),
        serde_json::Value::Bool(b) => Ok(ciborium::Value::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(ciborium::Value::Integer(i.into()))
            } else if let Some(f) = n.as_f64() {
                Ok(ciborium::Value::Float(f))
            } else {
                Err(pyo3::exceptions::PyValueError::new_err("Invalid number"))
            }
        }
        serde_json::Value::String(s) => Ok(ciborium::Value::Text(s.clone())),
        serde_json::Value::Array(arr) => {
            let cbor_arr: Result<Vec<_>, _> = arr.iter().map(json_to_cbor).collect();
            Ok(ciborium::Value::Array(cbor_arr?))
        }
        serde_json::Value::Object(obj) => {
            let mut cbor_pairs = Vec::new();
            for (k, v) in obj {
                cbor_pairs.push((ciborium::Value::Text(k.clone()), json_to_cbor(v)?));
            }
            Ok(ciborium::Value::Map(cbor_pairs))
        }
    }
}

/// Parse device key info from wrapper type.
fn parse_device_key_info(
    device_key: &MdocDeviceKeyInfo,
) -> PyResult<isomdl::definitions::DeviceKeyInfo> {
    use isomdl::definitions::DeviceKeyInfo;

    // Parse the COSE key from JSON (JWK format)
    let jwk: serde_json::Value = serde_json::from_str(&device_key.cose_key_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Key JSON error: {}", e)))?;

    // Convert JWK to COSE key
    let cose_key = jwk_to_cose_key(&jwk)?;

    Ok(DeviceKeyInfo {
        device_key: cose_key,
        key_authorizations: None,
        key_info: None,
    })
}

/// Convert JWK to COSE key.
fn jwk_to_cose_key(jwk: &serde_json::Value) -> PyResult<isomdl::definitions::CoseKey> {
    use base64::Engine;
    use isomdl::definitions::CoseKey;

    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Missing kty in JWK"))?;

    match kty {
        "EC" => {
            let crv = jwk
                .get("crv")
                .and_then(|v| v.as_str())
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Missing crv in EC JWK"))?;

            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Missing x in EC JWK"))?;

            let y = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Missing y in EC JWK"))?;

            // Decode base64url
            let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("x decode error: {}", e)))?;
            let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("y decode error: {}", e)))?;

            // Create COSE key using ciborium CBOR map
            // COSE Key structure for EC2:
            // 1 (kty) = 2 (EC2)
            // -1 (crv) = curve identifier
            // -2 (x) = x coordinate
            // -3 (y) = y coordinate
            let cose_key_cbor = ciborium::Value::Map(vec![
                (ciborium::Value::Integer(1.into()), ciborium::Value::Integer(2.into())), // kty: EC2
                (
                    ciborium::Value::Integer((-1i64).into()),
                    match crv {
                        "P-256" => ciborium::Value::Integer(1.into()),
                        "P-384" => ciborium::Value::Integer(2.into()),
                        "P-521" => ciborium::Value::Integer(3.into()),
                        _ => return Err(pyo3::exceptions::PyValueError::new_err("Unsupported curve")),
                    },
                ), // crv
                (ciborium::Value::Integer((-2i64).into()), ciborium::Value::Bytes(x_bytes)), // x
                (ciborium::Value::Integer((-3i64).into()), ciborium::Value::Bytes(y_bytes)), // y
            ]);

            // Serialize and deserialize to get CoseKey
            let mut cose_bytes = Vec::new();
            ciborium::into_writer(&cose_key_cbor, &mut cose_bytes)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("CBOR error: {}", e)))?;

            let cose_key: CoseKey = ciborium::from_reader(&cose_bytes[..])
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("CoseKey parse error: {}", e)))?;

            Ok(cose_key)
        }
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unsupported key type: {}",
            kty
        ))),
    }
}

/// Register issuance functions with Python module.
pub fn register_issuance_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_mdoc_credential, m)?)?;
    m.add_function(wrap_pyfunction!(prepare_mdoc_for_signing, m)?)?;
    m.add_function(wrap_pyfunction!(complete_mdoc_with_signature, m)?)?;
    Ok(())
}
