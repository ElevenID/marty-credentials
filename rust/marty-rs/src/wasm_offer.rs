//! Compatibility boundary for the existing WASM offer export.
//!
//! Core owns offer construction and authorization-state generation. This older
//! export retains its `user_pin_required` wire field; switching consumers to
//! Core's `tx_code` representation requires a separately versioned API change.

use marty_oid4vci::{issuer, types::GrantType};

pub(super) fn create_credential_offer(
    issuer_url: &str,
    credential_types_json: &str,
    pre_authorized_code: Option<&str>,
    user_pin_required: bool,
) -> Result<String, String> {
    let credential_types: Vec<String> = serde_json::from_str(credential_types_json)
        .map_err(|error| format!("Invalid credential types JSON: {error}"))?;
    let core_offer = issuer::create_credential_offer(
        issuer_url,
        &credential_types,
        pre_authorized_code,
        user_pin_required,
    )
    .map_err(|error| format!("Failed to create offer: {error}"))?;
    let mut offer: serde_json::Value = serde_json::from_str(&core_offer)
        .map_err(|error| format!("Invalid Core credential offer: {error}"))?;

    if pre_authorized_code.is_some() {
        let grant = offer
            .get_mut("grants")
            .and_then(|grants| grants.get_mut(GrantType::PreAuthorizedCode.as_str()))
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| {
                "Core credential offer is missing its pre-authorized grant".to_string()
            })?;
        grant.remove("tx_code");
        grant.insert("user_pin_required".into(), user_pin_required.into());
    }

    serde_json::to_string(&offer).map_err(|error| format!("Failed to serialize offer: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn pre_authorized_offers_preserve_the_existing_wasm_wire_contract() {
        for pin_required in [false, true] {
            for code in ["", "code with \"quotes\" and a newline\n"] {
                let offer = create_credential_offer(
                    "https://issuer.example/base",
                    r#"["EmployeeCard","StudentCard"]"#,
                    Some(code),
                    pin_required,
                )
                .unwrap();
                assert_eq!(
                    offer,
                    serde_json::json!({
                        "credential_issuer": "https://issuer.example/base",
                        "credential_configuration_ids": ["EmployeeCard", "StudentCard"],
                        "grants": {
                            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                                "pre-authorized_code": code,
                                "user_pin_required": pin_required,
                            }
                        }
                    })
                    .to_string()
                );
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn authorization_code_offers_keep_fresh_states_and_ignore_the_pin_flag() {
        let mut states = Vec::new();
        for pin_required in [false, true] {
            let offer = create_credential_offer("https://issuer.example", "[]", None, pin_required)
                .unwrap();
            let offer: serde_json::Value = serde_json::from_str(&offer).unwrap();
            let state = offer["grants"]["authorization_code"]["issuer_state"]
                .as_str()
                .unwrap();
            assert_eq!(uuid::Uuid::parse_str(state).unwrap().get_version_num(), 4);
            assert_eq!(
                offer,
                serde_json::json!({
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": [],
                    "grants": {"authorization_code": {"issuer_state": state}}
                })
            );
            states.push(state.to_string());
        }
        assert_ne!(states[0], states[1]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn malformed_credential_type_inputs_keep_the_existing_error_boundary() {
        for input in ["not json", "{}", "null", "[7]"] {
            let error =
                create_credential_offer("https://issuer.example", input, Some("code"), false)
                    .unwrap_err();
            assert!(
                error.starts_with("Invalid credential types JSON:"),
                "{error}"
            );
        }
    }
}
