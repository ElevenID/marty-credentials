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

fn credential_formats(raw: &serde_json::Value) -> PyResult<Vec<CredentialFormat>> {
    let parse = |value: &serde_json::Value| {
        value
            .as_str()
            .and_then(CredentialFormat::from_str_loose)
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "Credential formats must be supported format names",
                )
            })
    };

    if let Some(formats) = raw.get("formats") {
        let formats = formats
            .as_array()
            .filter(|values| !values.is_empty())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "Credential formats must be a non-empty array of format names",
                )
            })?;
        formats.iter().map(parse).collect()
    } else if let Some(format) = raw.get("format") {
        Ok(vec![parse(format)?])
    } else {
        // Preserve the documented default only when no format was supplied.
        Ok(vec![CredentialFormat::JwtVcJson])
    }
}

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
        if !raw.is_object() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Each credential type must be a JSON object",
            ));
        }
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

        let formats = credential_formats(raw)?;

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
/// This convenience binding supports mDL (`mso_mdoc`) requests. Other formats
/// are rejected instead of being silently replaced with an mDL request.
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
    if credential_format == "zk_mdoc" {
        return Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "ZK presentation requests require a native ZK-enabled verifier build",
        ));
    }
    if credential_format != "mso_mdoc" {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "This presentation-definition binding only supports mso_mdoc",
        ));
    }
    let engine = VerificationEngine::new(verifier_id, response_uri);

    let field_refs: Vec<&str> = requested_fields.iter().map(|s| s.as_str()).collect();

    let descriptor = engine.mdl_descriptor("credential_request", &field_refs);

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

    #[test]
    fn presentation_definition_preserves_the_requested_mdl_fields() {
        let definition: serde_json::Value = serde_json::from_str(
            &create_presentation_definition(
                "did:example:verifier".into(),
                "https://verifier.example/response".into(),
                vec!["age_over_18".into()],
                "mso_mdoc",
            )
            .unwrap(),
        )
        .unwrap();
        let descriptor = &definition["input_descriptors"][0];
        assert!(descriptor["format"]["mso_mdoc"].is_object());
        assert_eq!(
            descriptor["constraints"]["fields"][0]["path"][0],
            "$.org\\.iso\\.18013\\.5\\.1.age_over_18"
        );
    }

    #[test]
    fn presentation_definition_rejects_formats_it_cannot_construct() {
        Python::initialize();
        Python::attach(|py| {
            for format in ["zk_mdoc", "jwt_vc_json", "sd_jwt", "unknown", ""] {
                let error = create_presentation_definition(
                    "did:example:verifier".into(),
                    "https://verifier.example/response".into(),
                    vec!["age_over_18".into()],
                    format,
                )
                .unwrap_err();
                if format == "zk_mdoc" {
                    assert!(error.is_instance_of::<pyo3::exceptions::PyNotImplementedError>(py));
                } else {
                    assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(py));
                }
            }
        });
    }

    #[test]
    fn issuer_metadata_rejects_explicit_malformed_formats() {
        Python::initialize();
        Python::attach(|py| {
            for fields in [
                serde_json::json!(null),
                serde_json::json!(12),
                serde_json::json!("jwt_vc_json"),
                serde_json::json!([]),
                serde_json::json!({"format": "typo"}),
                serde_json::json!({"format": 12}),
                serde_json::json!({"format": null}),
                serde_json::json!({"formats": ["jwt_vc_json", "typo"]}),
                serde_json::json!({"formats": ["jwt_vc_json", 12]}),
                serde_json::json!({"formats": []}),
                serde_json::json!({"formats": "jwt_vc_json"}),
                serde_json::json!({"formats": null}),
            ] {
                let error = generate_issuer_metadata(
                    "https://issuer.example".into(),
                    "Example Issuer".into(),
                    serde_json::json!([fields]).to_string(),
                )
                .unwrap_err();
                assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(py));
            }
        });
    }

    #[test]
    fn issuer_metadata_keeps_the_default_and_supported_format_aliases() {
        let default: serde_json::Value = serde_json::from_str(
            &generate_issuer_metadata(
                "https://issuer.example".into(),
                "Example Issuer".into(),
                r#"[{"id":"example"}]"#.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            default["credential_configurations_supported"]["example"]["format"],
            "jwt_vc_json"
        );

        let aliases: serde_json::Value = serde_json::from_str(
            &generate_issuer_metadata(
                "https://issuer.example".into(),
                "Example Issuer".into(),
                r#"[{"id":"example","formats":["jwt_vc_json","sd_jwt"],"vct":"urn:example:credential"}]"#.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let configurations = aliases["credential_configurations_supported"]
            .as_object()
            .unwrap();
        assert!(configurations
            .values()
            .any(|entry| entry["format"] == "jwt_vc_json"));
        assert!(configurations
            .values()
            .any(|entry| entry["format"] == "dc+sd-jwt"));
    }
}
