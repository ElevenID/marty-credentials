//! WASM bindings for marty-rs
//!
//! Exposes holder/issuer functionality for web wallet development.
//! Excludes heavy verification (CSCA/IACA chain validation) to keep bundle small.
//!
//! Build with: wasm-pack build --target web --features wasm --no-default-features

use base64::Engine;
use marty_verification::error::VerificationError;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

// Set up console error panic hook for better debugging
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(feature = "wasm")]
    console_error_panic_hook::set_once();
}

// Core's structured verification APIs intentionally box this large error.
#[allow(clippy::boxed_local)]
fn verification_error_to_js(err: Box<VerificationError>) -> JsValue {
    let report = err.to_structured();
    let payload = serde_json::json!({
        "code": report.code,
        "category": report.category,
        "severity": report.severity,
        "message": report.message,
        "source": report.source,
    });
    JsValue::from_str(&payload.to_string())
}

// =============================================================================
// Key Generation
// =============================================================================

/// Generate a P-256 key pair for OID4VCI
/// Returns JSON: { "did": "did:jwk:...", "jwk": {...}, "keyId": "..." }
#[wasm_bindgen]
pub fn generate_p256_key() -> Result<String, JsValue> {
    let material = marty_oid4vci::generate_p256_did_jwk_holder_key()
        .map_err(|e| JsValue::from_str(&format!("P-256 holder key generation failed: {e}")))?;
    let jwk: serde_json::Value = serde_json::from_str(&material.private_jwk)
        .map_err(|e| JsValue::from_str(&format!("Generated private JWK parse failed: {e}")))?;
    let key_id = format!(
        "key_{}",
        &uuid::Uuid::new_v4().to_string().replace("-", "")[..16]
    );

    let result = serde_json::json!({
        "did": material.kid,
        "jwk": jwk,
        "keyId": key_id
    });

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Generate an Ed25519 key pair
/// Returns JSON: { "did": "did:key:...", "jwk": {...}, "keyId": "..." }
#[wasm_bindgen]
pub fn generate_ed25519_key() -> Result<String, JsValue> {
    use ssi_jwk::{Params, JWK};

    let jwk = JWK::generate_ed25519()
        .map_err(|e| JsValue::from_str(&format!("Failed to generate key: {:?}", e)))?;

    let pk_bytes = if let Params::OKP(params) = &jwk.params {
        &params.public_key.0
    } else {
        return Err(JsValue::from_str("Invalid key type"));
    };

    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend(pk_bytes);
    let did = format!("did:key:z{}", bs58::encode(multicodec).into_string());
    let key_id = format!(
        "key_{}",
        &uuid::Uuid::new_v4().to_string().replace("-", "")[..16]
    );

    let result = serde_json::json!({
        "did": did,
        "jwk": jwk,
        "keyId": key_id
    });

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// =============================================================================
// Credential Issuance (Issuer Side)
// =============================================================================

/// Create a verifiable credential and sign it as a JWT
///
/// # Arguments
/// * `issuer_did` - DID of the issuer
/// * `issuer_jwk_json` - JWK of the issuer as JSON string
/// * `subject_id` - Optional DID of the subject
/// * `credential_type` - Type of credential (e.g., "TravelDocument")
/// * `claims_json` - Claims as JSON object string
/// * `expiration_seconds` - Optional expiration in seconds from now
///
/// # Returns
/// JSON: { "jwt": "...", "credentialId": "urn:uuid:..." }
#[wasm_bindgen]
pub fn create_verifiable_credential(
    issuer_did: &str,
    issuer_jwk_json: &str,
    subject_id: Option<String>,
    credential_type: &str,
    claims_json: &str,
    expiration_seconds: Option<i64>,
) -> Result<String, JsValue> {
    use chrono::Utc;
    use ssi_jwk::JWK;

    let jwk: JWK = serde_json::from_str(issuer_jwk_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JWK: {}", e)))?;

    let claims: HashMap<String, serde_json::Value> = serde_json::from_str(claims_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid claims JSON: {}", e)))?;

    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let now = Utc::now();
    let issuance_date = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let expires_at =
        marty_oid4vci::formats::jwt_vc::checked_jwt_vc_expiration(now, expiration_seconds)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let expiration_date = expires_at.map(|date| date.format("%Y-%m-%dT%H:%M:%SZ").to_string());

    let credential_subject = serde_json::json!({
        "id": subject_id,
        "claims": claims
    });

    let vc_data = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": credential_id,
        "type": ["VerifiableCredential", credential_type],
        "issuer": issuer_did,
        "issuanceDate": issuance_date,
        "expirationDate": expiration_date,
        "credentialSubject": credential_subject
    });

    let mut payload = serde_json::json!({
        "iss": issuer_did,
        "iat": now.timestamp(),
        "vc": vc_data
    });

    if let Some(expires_at) = expires_at {
        payload["exp"] = serde_json::json!(expires_at.timestamp());
    }

    let alg_str = get_algorithm_for_jwk_wasm(&jwk)?;
    let header = serde_json::json!({ "alg": alg_str, "typ": "JWT" });

    let jwt = sign_jwt(&jwk, &header, &payload)?;

    let result = serde_json::json!({
        "jwt": jwt,
        "credentialId": credential_id
    });

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

/// Create an OID4VCI credential offer
///
/// # Arguments
/// * `issuer_url` - Base URL of the credential issuer
/// * `credential_types` - JSON array of credential type IDs
/// * `pre_authorized_code` - Optional pre-authorized code for immediate issuance
/// * `user_pin_required` - Whether a PIN is required
///
/// # Returns
/// JSON credential offer object
#[wasm_bindgen]
pub fn create_credential_offer(
    issuer_url: &str,
    credential_types_json: &str,
    pre_authorized_code: Option<String>,
    user_pin_required: bool,
) -> Result<String, JsValue> {
    let credential_types: Vec<String> = serde_json::from_str(credential_types_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid credential types JSON: {}", e)))?;

    let mut grants = serde_json::Map::new();

    if let Some(code) = pre_authorized_code {
        let mut pre_auth_grant = serde_json::Map::new();
        pre_auth_grant.insert("pre-authorized_code".to_string(), serde_json::json!(code));
        pre_auth_grant.insert(
            "user_pin_required".to_string(),
            serde_json::json!(user_pin_required),
        );
        grants.insert(
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            serde_json::Value::Object(pre_auth_grant),
        );
    } else {
        grants.insert(
            "authorization_code".to_string(),
            serde_json::json!({
                "issuer_state": uuid::Uuid::new_v4().to_string()
            }),
        );
    }

    let offer = serde_json::json!({
        "credential_issuer": issuer_url,
        "credential_configuration_ids": credential_types,
        "grants": grants
    });

    serde_json::to_string(&offer)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize offer: {}", e)))
}

// =============================================================================
// Open Badges (OB2/OB3)
// =============================================================================

/// Issue an Open Badges v2 assertion (optionally signed).
///
/// # Arguments
/// * `request_json` - JSON payload with assertion + signing options
///
/// # Returns
/// JSON: { "issued": true, "version": "2.0", "credential": {...}, "warnings": [...] }
#[wasm_bindgen]
pub fn open_badge_ob2_issue(request_json: &str) -> Result<String, JsValue> {
    marty_verification::open_badges::issue_ob2_json(request_json).map_err(verification_error_to_js)
}

/// Verify an Open Badges v2 assertion.
///
/// # Arguments
/// * `request_json` - JSON payload with assertion + document_store
///
/// # Returns
/// JSON: { "valid": true|false, "version": "2.0", "errors": [...], "warnings": [...] }
#[wasm_bindgen]
pub fn open_badge_ob2_verify(request_json: &str) -> Result<String, JsValue> {
    marty_verification::open_badges::verify_ob2_json(request_json).map_err(verification_error_to_js)
}

/// Issue an Open Badges v3 credential with Data Integrity proof.
///
/// # Arguments
/// * `request_json` - JSON payload with credential + signing options
///
/// # Returns
/// JSON: { "issued": true, "version": "3.0", "credential": {...}, "warnings": [...] }
#[wasm_bindgen]
pub async fn open_badge_ob3_issue(request_json: &str) -> Result<String, JsValue> {
    marty_verification::open_badges::issue_ob3_json_async(request_json)
        .await
        .map_err(verification_error_to_js)
}

/// Verify an Open Badges v3 credential with Data Integrity proof.
///
/// # Arguments
/// * `request_json` - JSON payload with credential + document_store
///
/// # Returns
/// JSON: { "valid": true|false, "version": "3.0", "errors": [...], "warnings": [...] }
#[wasm_bindgen]
pub async fn open_badge_ob3_verify(request_json: &str) -> Result<String, JsValue> {
    marty_verification::open_badges::verify_ob3_json_async(request_json)
        .await
        .map_err(verification_error_to_js)
}

// =============================================================================
// DTC (Digital Travel Credential)
// =============================================================================

/// Normalize a DTC payload (JSON in/out).
///
/// # Arguments
/// * `request_json` - JSON payload describing the DTC record
///
/// # Returns
/// JSON: normalized DTC record
#[wasm_bindgen]
pub fn dtc_create(request_json: &str) -> Result<String, JsValue> {
    marty_verification::dtc::create_dtc_json(request_json).map_err(verification_error_to_js)
}

/// Sign a DTC payload (JSON in/out).
///
/// # Arguments
/// * `request_json` - JSON payload with DTC record + signing_key_pem
///
/// # Returns
/// JSON: signed DTC record
#[wasm_bindgen]
pub fn dtc_sign(request_json: &str) -> Result<String, JsValue> {
    marty_verification::dtc::sign_dtc_json(request_json).map_err(verification_error_to_js)
}

/// Verify a DTC payload (JSON in/out).
///
/// # Arguments
/// * `request_json` - JSON payload with DTC record + signer_public_key_pem
///
/// # Returns
/// JSON: verification result
#[wasm_bindgen]
pub fn dtc_verify(request_json: &str) -> Result<String, JsValue> {
    marty_verification::dtc::verify_dtc_json(request_json).map_err(verification_error_to_js)
}

/// Generate a credential offer URI for QR code display
///
/// # Arguments
/// * `issuer_url` - Base URL of the credential issuer
/// * `offer_id` - Unique identifier for this offer
/// * `format` - URI format: "oid4vci" (default) or "microsoft"
///
/// # Returns
/// URI string for QR code encoding
#[wasm_bindgen]
pub fn generate_offer_uri(issuer_url: &str, offer_id: &str, format: &str) -> String {
    marty_oid4vci::issuer::generate_offer_uri(issuer_url, offer_id, format)
}

// =============================================================================
// Presentation Creation (Holder Side)
// =============================================================================

/// Create a verifiable presentation from credentials
///
/// # Arguments
/// * `holder_did` - DID of the holder
/// * `holder_jwk_json` - JWK of the holder as JSON string
/// * `credential_jwts_json` - JSON array of credential JWTs
/// * `audience` - DID or URL of the verifier
/// * `nonce` - Optional nonce from the presentation request
///
/// # Returns
/// VP JWT string
#[wasm_bindgen]
pub fn create_presentation(
    holder_did: &str,
    holder_jwk_json: &str,
    credential_jwts_json: &str,
    audience: &str,
    nonce: Option<String>,
) -> Result<String, JsValue> {
    use chrono::Utc;
    use ssi_jwk::JWK;

    let jwk: JWK = serde_json::from_str(holder_jwk_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JWK: {}", e)))?;

    let credential_jwts: Vec<String> = serde_json::from_str(credential_jwts_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid credential JWTs JSON: {}", e)))?;

    let now = Utc::now();
    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "holder": holder_did,
        "verifiableCredential": credential_jwts
    });

    let mut payload = serde_json::json!({
        "iss": holder_did,
        "aud": audience,
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300, // 5 minute validity
        "vp": vp
    });

    if let Some(n) = nonce {
        payload["nonce"] = serde_json::json!(n);
    }

    let alg_str = get_algorithm_for_jwk_wasm(&jwk)?;
    let header = serde_json::json!({ "alg": alg_str, "typ": "JWT" });

    sign_jwt(&jwk, &header, &payload)
}

/// Create an OID4VP authorization response
///
/// # Arguments
/// * `vp_token` - The VP JWT
/// * `presentation_submission_json` - Presentation submission descriptor
/// * `state` - State from the authorization request
///
/// # Returns
/// JSON authorization response
#[wasm_bindgen]
pub fn create_authorization_response(
    vp_token: &str,
    presentation_submission_json: &str,
    state: Option<String>,
) -> Result<String, JsValue> {
    let presentation_submission: serde_json::Value =
        serde_json::from_str(presentation_submission_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid presentation submission: {}", e)))?;

    let mut response = serde_json::json!({
        "vp_token": vp_token,
        "presentation_submission": presentation_submission
    });

    if let Some(s) = state {
        response["state"] = serde_json::json!(s);
    }

    serde_json::to_string(&response)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize response: {}", e)))
}

// =============================================================================
// JWT Verification (Basic - no chain validation)
// =============================================================================

/// Verify a JWT structure and claims (does NOT verify cryptographic signature)
///
/// # Arguments
/// * `jwt` - The JWT string to verify
/// * `expected_issuer` - Optional expected issuer
/// * `expected_audience` - Optional expected audience
///
/// # Returns
/// JSON: { "valid": bool, "payload": {...}, "error": "..." }
#[wasm_bindgen]
pub fn verify_jwt_claims(
    jwt: &str,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
) -> Result<String, JsValue> {
    use chrono::Utc;

    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Ok(serde_json::json!({
            "valid": false,
            "payload": {},
            "error": "Invalid JWT format"
        })
        .to_string());
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| JsValue::from_str("Invalid base64 in payload"))?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| JsValue::from_str("Invalid JSON in payload"))?;

    // Check expiration
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        if Utc::now().timestamp() > exp {
            return Ok(serde_json::json!({
                "valid": false,
                "payload": payload,
                "error": "JWT has expired"
            })
            .to_string());
        }
    }

    // Check issuer
    if let Some(expected) = expected_issuer {
        if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
            if iss != expected {
                return Ok(serde_json::json!({
                    "valid": false,
                    "payload": payload,
                    "error": format!("Issuer mismatch: expected {}, got {}", expected, iss)
                })
                .to_string());
            }
        } else {
            return Ok(serde_json::json!({
                "valid": false,
                "payload": payload,
                "error": "Missing issuer claim"
            })
            .to_string());
        }
    }

    // Check audience
    if let Some(expected) = expected_audience {
        if let Some(aud) = payload.get("aud").and_then(|v| v.as_str()) {
            if aud != expected {
                return Ok(serde_json::json!({
                    "valid": false,
                    "payload": payload,
                    "error": format!("Audience mismatch: expected {}, got {}", expected, aud)
                })
                .to_string());
            }
        } else {
            return Ok(serde_json::json!({
                "valid": false,
                "payload": payload,
                "error": "Missing audience claim"
            })
            .to_string());
        }
    }

    Ok(serde_json::json!({
        "valid": true,
        "payload": payload,
        "error": ""
    })
    .to_string())
}

/// Extract credential from a VP JWT
///
/// # Arguments
/// * `vp_jwt` - The VP JWT string
///
/// # Returns
/// JSON array of credential objects
#[wasm_bindgen]
pub fn extract_credentials_from_vp(vp_jwt: &str) -> Result<String, JsValue> {
    let parts: Vec<&str> = vp_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(JsValue::from_str("Invalid JWT format"));
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| JsValue::from_str("Invalid base64 in payload"))?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| JsValue::from_str("Invalid JSON in payload"))?;

    let credentials = payload
        .get("vp")
        .and_then(|vp| vp.get("verifiableCredential"))
        .cloned()
        .unwrap_or(serde_json::json!([]));

    serde_json::to_string(&credentials)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize credentials: {}", e)))
}

// =============================================================================
// Helper Functions
// =============================================================================

fn get_algorithm_for_jwk_wasm(jwk: &ssi_jwk::JWK) -> Result<&'static str, JsValue> {
    use marty_oid4vci::types::SigningAlgorithm;
    let json = serde_json::to_string(jwk)
        .map_err(|error| JsValue::from_str(&format!("Invalid JWK: {error}")))?;
    let algorithm = marty_oid4vci::issuer::detect_algorithm(&json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    // Preserve the browser adapter's existing signing capability set.
    match algorithm {
        SigningAlgorithm::EdDSA => Ok("EdDSA"),
        SigningAlgorithm::ES256 => Ok("ES256"),
        SigningAlgorithm::ES256K => Ok("ES256K"),
        other => Err(JsValue::from_str(&format!(
            "Unsupported algorithm: {other}"
        ))),
    }
}

fn sign_jwt(
    jwk: &ssi_jwk::JWK,
    header: &serde_json::Value,
    payload: &serde_json::Value,
) -> Result<String, JsValue> {
    marty_oid4vci::jose::sign_compact_jwt(jwk, header, payload)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

// =============================================================================
// Utility Exports for Testing
// =============================================================================

/// Get the version of marty-rs WASM module
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check if WASM module is initialized correctly
#[wasm_bindgen]
pub fn health_check() -> String {
    serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "features": ["key_generation", "credential_issuance", "presentation_creation", "jwt_verification"]
    }).to_string()
}

#[cfg(test)]
mod offer_uri_tests {
    #[test]
    fn wasm_wrapper_preserves_offer_wire_contract() {
        for (format, expected) in [
            ("microsoft", "openid-vc://?request_uri=https://issuer.example/base/issuance-requests/id"),
            ("oid4vci", "openid-credential-offer://?credential_offer_uri=https://issuer.example/base/offers/id"),
            ("unknown", "openid-credential-offer://?credential_offer_uri=https://issuer.example/base/offers/id"),
        ] {
            assert_eq!(super::generate_offer_uri("https://issuer.example/base", "id", format), expected);
        }
    }
}

#[cfg(test)]
mod issuance_tests {
    #[test]
    fn browser_issuance_keeps_legacy_envelope_and_valid_signature() {
        let jwk = ssi_jwk::JWK::generate_ed25519().unwrap();
        for expiration in [None, Some(3600)] {
            let result = super::create_verifiable_credential(
                "did:example:issuer",
                &serde_json::to_string(&jwk).unwrap(),
                None,
                "ExampleCredential",
                r#"{"name":"test"}"#,
                expiration,
            )
            .unwrap();
            let result: serde_json::Value = serde_json::from_str(&result).unwrap();
            let verified = marty_oid4vci::jose::verify_compact_jwt_with_public_jwk(
                result["jwt"].as_str().unwrap(),
                &serde_json::to_string(&jwk.to_public()).unwrap(),
                "EdDSA",
            )
            .unwrap();
            assert_eq!(verified.claims["vc"]["id"], result["credentialId"]);
            assert_eq!(
                verified.claims["vc"]["credentialSubject"]["claims"]["name"],
                "test"
            );
            assert!(verified.claims["vc"]["credentialSubject"]["id"].is_null());
            assert_eq!(
                verified.claims["vc"]["@context"][0],
                "https://www.w3.org/2018/credentials/v1"
            );
            if let Some(seconds) = expiration {
                assert_eq!(
                    verified.claims["exp"].as_i64().unwrap()
                        - verified.claims["iat"].as_i64().unwrap(),
                    seconds
                );
            } else {
                assert!(verified.claims.get("exp").is_none());
                assert!(verified.claims["vc"]["expirationDate"].is_null());
            }
        }
    }
}
