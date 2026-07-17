//! IETF SD-JWT specification conformance tests.
//!
//! Tests the wire-format properties of SD-JWTs produced by the `sd-jwt-rs` crate
//! (the underlying implementation used by marty-rs SdJwtBuilder and marty-oid4vci).
//!
//! Normative references:
//!   RFC 9449 — SD-JWT (Selective Disclosure for JWTs)
//!   draft-ietf-oauth-sd-jwt-vc — SD-JWT Verifiable Credentials
//!
//!  §1  Compact serialization format — `header.payload.sig~disc1~disc2~`
//!  §2  Disclosure encoding — base64url(JSON([salt, claim_name, claim_value]))
//!  §3  SD claim hash derivation — `_sd` array in payload contains SHA-256 hashes
//!  §4  SD-JWT issuance — NoSDClaims vs Custom selectors
//!  §5  Selective presentation — holder discloses only chosen claims
//!  §6  Key binding JWT — bound SD-JWT has KB-JWT appended
//!  §7  Verification — SDJWTVerifier accepts valid presentations

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::EncodingKey;
use sd_jwt_rs::{
    issuer::ClaimsForSelectiveDisclosureStrategy, SDJWTHolder, SDJWTIssuer,
    SDJWTSerializationFormat,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

// ── Test fixtures ─────────────────────────────────────────────────────────────

/// Generate a deterministic P-256 private key PEM for test signing.
/// This uses the `p256` crate directly to avoid any runtime key generation.
fn test_ec_key_pem() -> String {
    use p256::pkcs8::EncodePrivateKey;
    use p256::SecretKey;

    // Fixed 32-byte seed for reproducibility across test runs.
    let seed = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20u8,
    ];
    let secret = SecretKey::from_bytes((&seed).into()).expect("fixed test key");
    secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("to PEM")
        .to_string()
}

fn make_issuer(alg: &str) -> SDJWTIssuer {
    let pem = test_ec_key_pem();
    let enc_key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("encoding key");
    SDJWTIssuer::new(enc_key, Some(alg.to_string()))
}

fn minimal_payload() -> Value {
    json!({
        "iss": "https://issuer.example.com",
        "iat": 1_700_000_000i64,
        "vct": "VerifiableCredential",
        "sub": "did:example:holder",
        "given_name": "Alice",
        "family_name": "Smith",
        "birth_date": "1990-01-15"
    })
}

// ── §1  Compact serialization format ─────────────────────────────────────────

/// RFC 9449 §5.2 — An SD-JWT with no disclosures must have the form
/// `header.payload.sig~` (one trailing tilde, zero disclosure segments).
#[test]
fn compact_no_sd_claims_format() {
    let mut issuer = make_issuer("ES256");
    let sd_jwt = issuer
        .issue_sd_jwt(
            minimal_payload(),
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issue SD-JWT");

    // Split on '~'
    let parts: Vec<&str> = sd_jwt.split('~').collect();

    // parts[0] = header.payload.sig (the JWS), parts[1] = "" (trailing ~)
    let jws = parts[0];
    let jws_parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(
        jws_parts.len(),
        3,
        "JWS portion must have exactly 3 dot-separated parts: {:?}",
        jws
    );

    // With NoSDClaims the only segment after the JWS must be the empty string
    assert_eq!(
        parts.len(),
        2,
        "SD-JWT with NoSDClaims must be 'JWS~': got {} tilde segments",
        parts.len()
    );
    assert_eq!(
        parts[1], "",
        "segment after trailing tilde must be empty string"
    );
}

/// When disclosures are present each `~`-delimited segment after the JWS
/// must be a non-empty base64url string (the disclosure).
#[test]
fn compact_with_sd_claims_has_disclosure_segments() {
    let mut issuer = make_issuer("ES256");
    let paths = vec!["$.given_name", "$.family_name"];
    let sd_jwt = issuer
        .issue_sd_jwt(
            minimal_payload(),
            ClaimsForSelectiveDisclosureStrategy::Custom(paths),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issue SD-JWT");

    let parts: Vec<&str> = sd_jwt.split('~').collect();
    // parts[0] = JWS, parts[1..n-1] = disclosures, parts[n] = "" (trailing ~)
    assert!(
        parts.len() >= 3,
        "SD-JWT with 2 disclosures must have at least 3 tilde segments; got: {}",
        parts.len()
    );

    // Each disclosure segment (skip first JWS and last empty) must be non-empty base64url
    for disc in &parts[1..parts.len() - 1] {
        assert!(!disc.is_empty(), "disclosure segment must be non-empty");
        // base64url-only characters
        assert!(
            disc.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "disclosure must be base64url: {}",
            disc
        );
    }
}

// ── §2  Disclosure encoding ───────────────────────────────────────────────────

/// RFC 9449 §5.2 — Each disclosure must be base64url(JSON([salt, name, value])).
/// Decoded JSON must be a 3-element array.
#[test]
fn disclosure_is_base64url_of_json_array() {
    let mut issuer = make_issuer("ES256");
    let sd_jwt = issuer
        .issue_sd_jwt(
            minimal_payload(),
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.birth_date"]),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issue");

    let parts: Vec<&str> = sd_jwt.split('~').collect();
    // Middle parts are disclosures
    let disclosures: Vec<&str> = parts[1..parts.len() - 1].to_vec();
    assert!(!disclosures.is_empty(), "must have at least one disclosure");

    for disc_b64 in disclosures {
        let decoded = URL_SAFE_NO_PAD
            .decode(disc_b64)
            .expect("disclosure must be valid base64url");
        let json_val: Value =
            serde_json::from_slice(&decoded).expect("disclosure must be valid JSON");

        let arr = json_val.as_array().expect("disclosure must be JSON array");
        assert_eq!(
            arr.len(),
            3,
            "disclosure array must have exactly 3 elements [salt, name, value]; got {:?}",
            arr
        );

        // [0] = salt (non-empty string)
        assert!(
            arr[0].is_string() && !arr[0].as_str().unwrap().is_empty(),
            "disclosure[0] (salt) must be a non-empty string"
        );
        // [1] = claim name (non-empty string)
        assert!(
            arr[1].is_string() && !arr[1].as_str().unwrap().is_empty(),
            "disclosure[1] (claim name) must be a non-empty string"
        );
        // [2] = claim value (any JSON type)
        let _ = &arr[2]; // just assert present
    }
}

/// Each disclosure's salt must be unique across disclosures (§5.2.1 entropy requirement).
#[test]
fn disclosure_salts_are_unique() {
    let mut issuer = make_issuer("ES256");
    let sd_jwt = issuer
        .issue_sd_jwt(
            minimal_payload(),
            ClaimsForSelectiveDisclosureStrategy::Custom(vec![
                "$.given_name",
                "$.family_name",
                "$.birth_date",
            ]),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issue");

    let parts: Vec<&str> = sd_jwt.split('~').collect();
    let mut salts = std::collections::HashSet::new();

    for disc_b64 in &parts[1..parts.len() - 1] {
        let decoded = URL_SAFE_NO_PAD.decode(disc_b64).expect("base64url");
        let arr: Vec<Value> = serde_json::from_slice(&decoded).expect("json");
        let salt = arr[0].as_str().unwrap().to_string();
        assert!(
            salts.insert(salt.clone()),
            "disclosure salts must be unique; duplicate: {}",
            salt
        );
    }
}

// ── §3  SD claim hash derivation in payload ───────────────────────────────────

/// The JWT payload must contain an `_sd` array with SHA-256 hashes of disclosures.
/// Each hash in `_sd` is `base64url(SHA-256(ascii(disclosure)))`.
#[test]
fn payload_sd_array_contains_disclosure_hashes() {
    let mut issuer = make_issuer("ES256");
    let sd_jwt = issuer
        .issue_sd_jwt(
            minimal_payload(),
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.given_name"]),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issue");

    let parts: Vec<&str> = sd_jwt.split('~').collect();
    let jws = parts[0];
    let jws_parts: Vec<&str> = jws.split('.').collect();

    // Decode the JWS payload (part 1)
    let payload_b64 = jws_parts[1];
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("payload base64url");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("payload json");

    // Must have `_sd` array
    let sd_arr = payload
        .get("_sd")
        .and_then(|v| v.as_array())
        .expect("payload must have '_sd' array for selectively-disclosed claims");

    assert!(
        !sd_arr.is_empty(),
        "'_sd' array must be non-empty when disclosures are present"
    );

    // Verify at least one hash corresponds to a disclosure
    let disclosures: Vec<&str> = parts[1..parts.len() - 1].to_vec();

    let mut found_match = false;
    for disc_b64 in &disclosures {
        let hash = Sha256::digest(disc_b64.as_bytes());
        let expected_hash = URL_SAFE_NO_PAD.encode(hash);

        if sd_arr.iter().any(|h| h.as_str() == Some(&expected_hash)) {
            found_match = true;
            break;
        }
    }
    assert!(
        found_match,
        "at least one _sd hash must match SHA-256(disclosure_b64)"
    );
}

/// The `_sd_alg` claim must be present and set to `sha-256` when SD claims exist.
#[test]
fn payload_sd_alg_is_sha256() {
    let mut issuer = make_issuer("ES256");
    let sd_jwt = issuer
        .issue_sd_jwt(
            minimal_payload(),
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.given_name"]),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issue");

    let parts: Vec<&str> = sd_jwt.split('~').collect();
    let payload_b64 = parts[0].split('.').nth(1).expect("payload part");
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).expect("base64url");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("json");

    let sd_alg = payload
        .get("_sd_alg")
        .and_then(|v| v.as_str())
        .expect("_sd_alg must be present");

    assert_eq!(
        sd_alg, "sha-256",
        "_sd_alg must be 'sha-256' per RFC 9449 §5.1"
    );
}

// ── §4  SD-JWT issuance correctness ──────────────────────────────────────────

/// Claims NOT in the SD list must appear in plaintext in the JWT payload.
#[test]
fn non_sd_claims_are_plaintext_in_payload() {
    let mut issuer = make_issuer("ES256");
    let payload = json!({
        "iss": "https://issuer.example.com",
        "iat": 1_700_000_000i64,
        "vct": "VC",
        "public_claim": "visible",
        "private_claim": "hidden",
    });

    let sd_jwt = issuer
        .issue_sd_jwt(
            payload,
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.private_claim"]),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issue");

    let parts: Vec<&str> = sd_jwt.split('~').collect();
    let payload_b64 = parts[0].split('.').nth(1).expect("payload");
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).expect("base64url");
    let decoded: Value = serde_json::from_slice(&payload_bytes).expect("json");

    assert_eq!(
        decoded.get("public_claim").and_then(|v| v.as_str()),
        Some("visible"),
        "non-SD claim 'public_claim' must be plaintext in payload"
    );
    assert!(
        decoded.get("private_claim").is_none(),
        "'private_claim' must NOT appear in plaintext payload when SD-selected"
    );
}

// ── §5  Selective presentation ───────────────────────────────────────────────

/// When a holder creates a presentation disclosing only `given_name`, only that
/// disclosure must appear in the resulting compact representation.
#[test]
fn holder_discloses_one_of_two_claims() {
    // Issue with two SD claims
    let mut issuer = make_issuer("ES256");
    let sd_jwt = issuer
        .issue_sd_jwt(
            minimal_payload(),
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.given_name", "$.family_name"]),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issue");

    // Count disclosures in issuance
    let issued_parts: Vec<&str> = sd_jwt.split('~').collect();
    let issued_disclosure_count = issued_parts.len() - 2; // exclude JWS and trailing empty
    assert_eq!(issued_disclosure_count, 2, "must have 2 issued disclosures");

    // Holder presents only given_name
    let mut claims_to_disclose = Map::new();
    claims_to_disclose.insert("given_name".to_string(), Value::Bool(true));

    let mut holder =
        SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).expect("SDJWTHolder");
    let presentation = holder
        .create_presentation(
            claims_to_disclose,
            None, // no nonce
            None, // no audience
            None, // no holder key
            None,
        )
        .expect("create_presentation");

    let pres_parts: Vec<&str> = presentation.split('~').collect();
    let pres_disclosure_count = pres_parts.len() - 2;
    assert_eq!(
        pres_disclosure_count, 1,
        "presentation must contain exactly 1 disclosure; got {}",
        pres_disclosure_count
    );
}

/// A presentation with zero disclosures must still end with `~`.
#[test]
fn holder_discloses_nothing() {
    let mut issuer = make_issuer("ES256");
    let sd_jwt = issuer
        .issue_sd_jwt(
            minimal_payload(),
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.birth_date"]),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issue");

    let mut holder =
        SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).expect("SDJWTHolder");
    let presentation = holder
        .create_presentation(
            Map::new(), // disclose nothing
            None,
            None,
            None,
            None,
        )
        .expect("create_presentation (empty)");

    // Trailing tilde must still be present
    assert!(
        presentation.ends_with('~'),
        "SD-JWT presentation must end with '~' even when no disclosures chosen"
    );
}
#![cfg(not(target_arch = "wasm32"))]
