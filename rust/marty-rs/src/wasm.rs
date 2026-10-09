//! WASM bindings for marty-rs
//!
//! Exposes public protocol and verification functionality for web wallets.
//! Excludes heavy verification (CSCA/IACA chain validation) to keep bundle small.
//!
//! Build with: wasm-pack build --target web --features wasm --no-default-features

use marty_verification::error::VerificationError;
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
// Credential Issuance (Issuer Side)
// =============================================================================

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
        "features": ["credential_offers", "verification"]
    })
    .to_string()
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
