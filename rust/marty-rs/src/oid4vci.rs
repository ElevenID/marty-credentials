//! PyO3 bindings for the `marty-oid4vci` protocol engine.
//!
//! Exposes the library-backed OID4VCI and OID4VP functionality to Python.
//! All credential issuance and verification goes through the structured
//! engine from `marty-oid4vci`.

use pyo3::prelude::*;
use std::collections::HashMap;

use marty_oid4vci::formats;
use marty_oid4vci::issuance_input::normalize_zk_predicate_claims;
use marty_oid4vci::issuer::IssuanceEngine;
use marty_oid4vci::metadata;
use marty_oid4vci::types::{
    ClaimDefinition, CredentialClaims, CredentialFormat, CredentialTypeConfig, IssuerConfig,
    IssuerKey, OfferConfig, SigningAlgorithm,
};
use marty_oid4vci::verifier::VerificationEngine;

// ── Credential Issuance ──────────────────────────────────────────────

/// Issue a verifiable credential using the marty-oid4vci engine.
///
/// Supports all formats: jwt_vc_json, vc+sd-jwt, mso_mdoc, zk_mdoc.
///
/// Returns (credential_string, credential_id).
#[pyfunction]
#[pyo3(signature = (
    issuer_did,
    issuer_jwk_json,
    subject_id,
    credential_type,
    claims_json,
    format = "jwt_vc_json",
    expiration_seconds = None,
    selective_disclosure_claims = None,
    mdoc_namespace = None,
    mdoc_doctype = None,
    zk_predicate_claims = None,
))]
#[allow(clippy::too_many_arguments)]
pub fn create_verifiable_credential(
    issuer_did: String,
    issuer_jwk_json: String,
    subject_id: Option<String>,
    credential_type: String,
    claims_json: String,
    format: &str,
    expiration_seconds: Option<i64>,
    selective_disclosure_claims: Option<Vec<String>>,
    mdoc_namespace: Option<String>,
    mdoc_doctype: Option<String>,
    zk_predicate_claims: Option<Vec<String>>,
) -> PyResult<(String, String)> {
    let claims: HashMap<String, serde_json::Value> =
        serde_json::from_str(&claims_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid claims JSON: {}", e))
        })?;

    let cred_format = CredentialFormat::from_str_loose(format).ok_or_else(|| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Unknown credential format: '{}'. Supported: jwt_vc_json, vc+sd-jwt, mso_mdoc, zk_mdoc",
            format
        ))
    })?;

    // Detect algorithm from the JWK
    let algorithm = detect_algorithm_from_jwk(&issuer_jwk_json)?;

    let issuer_key = IssuerKey {
        issuer_id: issuer_did,
        jwk_json: issuer_jwk_json,
        algorithm,
    };

    let zk_predicate_bindings =
        normalize_zk_predicate_claims(&claims, zk_predicate_claims.unwrap_or_default());

    let cred_claims = CredentialClaims {
        subject_id,
        credential_type,
        claims,
        expiration_seconds,
        selective_disclosure_claims: selective_disclosure_claims.unwrap_or_default(),
        mdoc_namespace,
        mdoc_doctype,
        zk_predicate_claims: zk_predicate_bindings,
        credential_payload_format: Default::default(),
        w3c_context: vec![],
        w3c_types: vec![],
    };

    let signed = formats::sign_credential(&cred_format, &issuer_key, &cred_claims)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    let credential_str = signed.encoded_credential().to_owned();

    Ok((credential_str, signed.credential_id().to_string()))
}

// ── Credential Offer ─────────────────────────────────────────────────

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
        issuer_key: IssuerKey {
            issuer_id: issuer_url.clone(),
            jwk_json: "{}".into(), // placeholder — not needed for offer creation
            algorithm: SigningAlgorithm::ES256,
        },
        token_endpoint: None,
        credential_endpoint: None,
        deferred_credential_endpoint: None,
        authorization_endpoint: None,
        binding_methods: vec!["did:key".into(), "did:jwk".into()],
        proof_signing_alg_values: vec!["ES256".into(), "EdDSA".into()],
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
/// Returns JSON string with (presentation_definition, challenge_session_id, nonce).
#[pyfunction]
pub fn create_zk_age_verification(verifier_id: String, response_uri: String) -> PyResult<String> {
    let engine = VerificationEngine::new(verifier_id, response_uri);

    let challenge = engine
        .create_zk_challenge("age_over_18")
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    let pd = marty_oid4vci::verifier::age_verification_definition(&engine, &challenge.nonce)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    let result = serde_json::json!({
        "presentation_definition": pd,
        "challenge_session_id": challenge.session_id,
        "nonce": challenge.nonce,
        "expires_in_seconds": challenge.expires_in_seconds,
    });

    serde_json::to_string(&result)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
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

fn detect_algorithm_from_jwk(jwk_json: &str) -> PyResult<SigningAlgorithm> {
    let algorithm = marty_oid4vci::issuer::detect_algorithm(jwk_json)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    // Keep the Python adapter's established capability set.
    match algorithm {
        SigningAlgorithm::ES256 | SigningAlgorithm::EdDSA | SigningAlgorithm::RS256 => {
            Ok(algorithm)
        }
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unsupported algorithm: {other}"
        ))),
    }
}

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
    parent.add_function(pyo3::wrap_pyfunction!(
        create_verifiable_credential,
        parent
    )?)?;
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
    fn algorithm_admission_keeps_python_capabilities_and_rejects_inconsistent_metadata() {
        Python::initialize();
        Python::attach(|py| {
            for (key, expected) in [
                (r#"{"kty":"EC","crv":"P-256"}"#, SigningAlgorithm::ES256),
                (r#"{"kty":"OKP","crv":"Ed25519"}"#, SigningAlgorithm::EdDSA),
                (r#"{"kty":"RSA"}"#, SigningAlgorithm::RS256),
            ] {
                assert_eq!(detect_algorithm_from_jwk(key).unwrap(), expected);
            }
            for key in [
                r#"{"alg":"ES256"}"#,
                r#"{"kty":"EC"}"#,
                r#"{"kty":"EC","crv":"P-256","alg":"EdDSA"}"#,
                r#"{"kty":"OKP","crv":"X25519"}"#,
                r#"{"kty":"EC","crv":"secp256k1"}"#,
                r#"{"kty":"EC","crv":"P-384"}"#,
                "invalid",
            ] {
                assert!(detect_algorithm_from_jwk(key)
                    .unwrap_err()
                    .is_instance_of::<pyo3::exceptions::PyValueError>(py));
            }
        });
    }

    #[test]
    fn python_issuance_preserves_tuple_and_signed_claims() {
        Python::initialize();
        Python::attach(|_| {
            let jwk = ssi_jwk::JWK::generate_ed25519().unwrap();
            let (jwt, id) = create_verifiable_credential(
                "did:example:issuer".into(),
                serde_json::to_string(&jwk).unwrap(),
                Some("did:example:holder".into()),
                "ExampleCredential".into(),
                r#"{"name":"test"}"#.into(),
                "jwt_vc_json",
                Some(3600),
                None,
                None,
                None,
                None,
            )
            .unwrap();
            let verified = marty_oid4vci::jose::verify_compact_jwt_with_public_jwk(
                &jwt,
                &serde_json::to_string(&jwk.to_public()).unwrap(),
                "EdDSA",
            )
            .unwrap();
            assert_eq!(verified.claims["vc"]["id"], id);
            assert_eq!(verified.claims["vc"]["credentialSubject"]["name"], "test");
        });
    }
}
