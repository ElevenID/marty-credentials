//! PyO3 bindings for the `marty-oid4vci` protocol engine.
//!
//! Exposes the library-backed OID4VCI and OID4VP functionality to Python.
//! All credential issuance and verification goes through the structured
//! engine from `marty-oid4vci`.

use pyo3::prelude::*;
use std::collections::HashMap;

use marty_oid4vci::issuer::IssuanceEngine;
use marty_oid4vci::metadata;
use marty_oid4vci::types::{
    ClaimDefinition, CredentialFormat, CredentialTypeConfig, IssuerConfig, OfferConfig,
};
use marty_oid4vci::verifier::VerificationEngine;

// ── Credential Issuance ──────────────────────────────────────────────

/// Create an OID4VCI credential offer using the engine.
#[pyfunction]
#[pyo3(signature = (
    issuer_url,
    credential_types,
    pre_authorized_code = None,
    user_pin_required = false,
))]
pub fn create_credential_offer(
    issuer_url: String,
    credential_types: Vec<String>,
    pre_authorized_code: Option<String>,
    user_pin_required: bool,
) -> PyResult<String> {
    let config = IssuerConfig {
        credential_issuer_url: issuer_url.clone(),
        issuer_name: "".into(),
        credential_types: vec![],
        binding_methods: vec!["did:key".into(), "did:jwk".into()],
        proof_signing_alg_values: vec!["ES256".into(), "EdDSA".into()],
        ..IssuerConfig::stateless()
    };

    let engine = IssuanceEngine::new(config);

    let offer_config = OfferConfig {
        credential_configuration_ids: credential_types,
        pre_authorized_code,
        user_pin_required,
        issuer_state: None,
    };

    let offer = engine
        .create_offer(&offer_config)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    serde_json::to_string(&offer)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

// ── Offer URI ────────────────────────────────────────────────────────

/// Generate an OID4VCI offer URI.
#[pyfunction]
pub fn generate_offer_uri(
    issuer_url: String,
    offer_id: String,
    format: String,
) -> PyResult<String> {
    let uri = marty_oid4vci::issuer::generate_offer_uri(&issuer_url, &offer_id, &format);
    Ok(uri)
}

// ── Issuer Metadata ──────────────────────────────────────────────────

/// Generate OID4VCI issuer metadata using the engine.
///
/// `credential_types_json` is a JSON array of objects:
/// ```json
/// [
///   {
///     "id": "IdentityCredential",
///     "name": "Identity Credential",
///     "format": "jwt_vc_json",        // or "sd_jwt", "mso_mdoc", "zk_mdoc"
///     "formats": ["jwt_vc_json", "vc+sd-jwt"],  // optional: multiple formats
///     "doctype": "org.iso.18013.5.1.mDL",       // optional: for mDoc
///     "vct": "IdentityCredential",               // optional: for SD-JWT
///     "claims": {"name": {"mandatory": true}}    // optional: claim definitions
///   }
/// ]
/// ```
#[pyfunction]
pub fn generate_issuer_metadata(
    issuer_url: String,
    issuer_name: String,
    credential_types_json: String,
) -> PyResult<String> {
    let raw_types: Vec<serde_json::Value> =
        serde_json::from_str(&credential_types_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid credential types JSON: {}",
                e
            ))
        })?;

    let mut cred_types = Vec::new();
    for raw in &raw_types {
        let id = raw
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string();
        let name = raw
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string();

        // Parse formats: either "format" (single) or "formats" (array)
        let formats = if let Some(arr) = raw.get("formats").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(CredentialFormat::from_str_loose)
                .collect::<Vec<_>>()
        } else {
            let fmt_str = raw
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("jwt_vc_json");
            vec![CredentialFormat::from_str_loose(fmt_str).unwrap_or(CredentialFormat::JwtVcJson)]
        };

        // Parse claims
        let claims = if let Some(claims_obj) = raw.get("claims").and_then(|v| v.as_object()) {
            claims_obj
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        ClaimDefinition {
                            mandatory: v
                                .get("mandatory")
                                .and_then(|b| b.as_bool())
                                .unwrap_or(false),
                            value_type: v
                                .get("value_type")
                                .and_then(|s| s.as_str())
                                .map(String::from),
                            display: None,
                        },
                    )
                })
                .collect()
        } else {
            HashMap::new()
        };

        cred_types.push(CredentialTypeConfig {
            id,
            name,
            formats,
            vc_types: vec![],
            vct: raw.get("vct").and_then(|v| v.as_str()).map(String::from),
            doctype: raw
                .get("doctype")
                .and_then(|v| v.as_str())
                .map(String::from),
            claims,
            display: None,
        });
    }

    metadata::generate_issuer_metadata(&issuer_url, &issuer_name, &cred_types)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

// ── OID4VP Presentation ──────────────────────────────────────────────

/// Create a presentation definition for verifiable presentation requests.
///
/// Returns JSON string containing the presentation definition.
#[pyfunction]
#[pyo3(signature = (
    verifier_id,
    response_uri,
    requested_fields,
    credential_format = "mso_mdoc",
))]
pub fn create_presentation_definition(
    verifier_id: String,
    response_uri: String,
    requested_fields: Vec<String>,
    credential_format: &str,
) -> PyResult<String> {
    let engine = VerificationEngine::new(verifier_id, response_uri);

    let field_refs: Vec<&str> = requested_fields.iter().map(|s| s.as_str()).collect();

    // Build descriptor based on the format
    let descriptor = if credential_format == "zk_mdoc" {
        // For ZK format, build a ZK predicate descriptor for the first field
        // (production usage would be more granular)
        engine.mdl_descriptor("credential_request", &field_refs)
    } else {
        engine.mdl_descriptor("credential_request", &field_refs)
    };

    let pd = engine
        .create_presentation_definition("presentation_request", vec![descriptor])
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    serde_json::to_string(&pd)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Create a ZK age verification presentation definition.
///
/// Raises NotImplementedError because this binding does not include native ZK verification.
#[pyfunction]
pub fn create_zk_age_verification(verifier_id: String, response_uri: String) -> PyResult<String> {
    // This binding does not include the native ZK verifier capability. Core now
    // requires that capability to construct a verifiable, bound challenge.
    // Keep the Python entry point, but never advertise an unsupported request.
    let _ = (verifier_id, response_uri);
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        "ZK age verification requires a native ZK-enabled verifier build",
    ))
}

/// Verify presentation submission structure (format and descriptor matching).
///
/// `submission_json` and `definition_json` are the JSON-serialized
/// PresentationSubmission and PresentationDefinition respectively.
///
/// Returns JSON string with verification result.
#[pyfunction]
pub fn verify_presentation_structure(
    verifier_id: String,
    response_uri: String,
    definition_json: String,
    submission_json: String,
) -> PyResult<String> {
    let engine = VerificationEngine::new(verifier_id, response_uri);

    let definition: marty_oid4vci::verifier::PresentationDefinition =
        serde_json::from_str(&definition_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid presentation definition: {}",
                e
            ))
        })?;

    let submission: marty_oid4vci::verifier::PresentationSubmission =
        serde_json::from_str(&submission_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid presentation submission: {}",
                e
            ))
        })?;

    let result = engine.verify_presentation_structure(&definition, &submission);

    serde_json::to_string(&result)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Verify a JWT VP token cryptographically.
///
/// Validates nonce, audience, expiration, and JWT signature.
/// The holder's public key must be present in the JWT header (`jwk`)
/// or in the payload (`cnf.jwk`).
///
/// `verifier_id` is the verifier's DID (used to validate the `aud` claim).
/// `response_uri` is the verifier's response endpoint (used to construct the engine).
///
/// Returns JSON-encoded `VerificationResult`.
#[pyfunction]
pub fn verify_vp_token_jwt(
    verifier_id: String,
    response_uri: String,
    vp_token: String,
    expected_nonce: String,
) -> PyResult<String> {
    let engine = VerificationEngine::new(verifier_id, response_uri);
    let result = engine.verify_vp_token(&vp_token, &expected_nonce);
    serde_json::to_string(&result)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Register OID4VCI/OID4VP functions as a sub-module.
pub fn register_oid4vci_module(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    parent.add_function(pyo3::wrap_pyfunction!(create_credential_offer, parent)?)?;
    parent.add_function(pyo3::wrap_pyfunction!(generate_offer_uri, parent)?)?;
    parent.add_function(pyo3::wrap_pyfunction!(generate_issuer_metadata, parent)?)?;
    parent.add_function(pyo3::wrap_pyfunction!(
        create_presentation_definition,
        parent
    )?)?;
    parent.add_function(pyo3::wrap_pyfunction!(create_zk_age_verification, parent)?)?;
    parent.add_function(pyo3::wrap_pyfunction!(
        verify_presentation_structure,
        parent
    )?)?;
    parent.add_function(pyo3::wrap_pyfunction!(verify_vp_token_jwt, parent)?)?;
    Ok(())
}

#[cfg(test)]
mod issuance_tests {
    use super::*;

    #[test]
    fn unavailable_zk_capability_does_not_advertise_a_request() {
        Python::initialize();
        Python::attach(|py| {
            let error = create_zk_age_verification(
                "did:example:verifier".into(),
                "https://verifier.example/response".into(),
            )
            .unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyNotImplementedError>(py));
            assert!(error.to_string().contains("native ZK-enabled verifier"));
        });
    }
}
