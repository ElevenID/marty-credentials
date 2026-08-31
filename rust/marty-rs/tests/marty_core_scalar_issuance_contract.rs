#![cfg(not(target_arch = "wasm32"))]

//! First-party contract tests for the pinned `marty-core` scalar issuance boundary.

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use isomdl::definitions::{helpers::Tag24, CoseKey, EC2Curve, IssuerSigned, Mso, EC2Y};
use marty_oid4vci::{
    issuer::IssuanceEngine,
    types::{
        CredentialClaims, CredentialFormat, CredentialPayloadFormat, CredentialRequest,
        CredentialTypeConfig, IssuerConfig, IssuerKey, ProofsObject, SignedCredential,
        SigningAlgorithm,
    },
    Oid4vciError,
};
use p256::ecdsa::signature::Signer as _;
use serde_json::{json, Value};
use ssi_jwk::JWK;

const ISSUER_URL: &str = "https://issuer.example.test";
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

struct ProofFixture {
    compact: String,
    private_jwk: Value,
    public_jwk: Value,
}

fn issuance_engine() -> IssuanceEngine {
    let issuer_jwk = JWK::generate_p256();
    IssuanceEngine::new(IssuerConfig {
        credential_issuer_url: ISSUER_URL.into(),
        issuer_name: "Pinned core contract issuer".into(),
        credential_types: vec![CredentialTypeConfig {
            id: "EmployeeCredential".into(),
            name: "Employee credential".into(),
            formats: vec![CredentialFormat::SdJwt, CredentialFormat::MsoMdoc],
            vc_types: vec!["VerifiableCredential".into()],
            vct: Some("https://credentials.example.test/employee".into()),
            doctype: Some("org.iso.18013.5.1.mDL".into()),
            claims: HashMap::new(),
            display: None,
        }],
        issuer_key: IssuerKey {
            issuer_id: "did:example:contract-issuer".into(),
            jwk_json: serde_json::to_string(&issuer_jwk).unwrap(),
            algorithm: SigningAlgorithm::ES256,
        },
        token_endpoint: None,
        credential_endpoint: None,
        authorization_endpoint: None,
        deferred_credential_endpoint: None,
        binding_methods: vec!["jwk".into()],
        proof_signing_alg_values: vec!["ES256".into(), "EdDSA".into()],
    })
}

fn claims(payload_format: CredentialPayloadFormat) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some("did:example:employee-holder".into()),
        credential_type: "https://credentials.example.test/employee".into(),
        claims: HashMap::from([
            ("employee_id".into(), json!("employee-123")),
            ("department".into(), json!("engineering")),
        ]),
        expiration_seconds: Some(3_600),
        selective_disclosure_claims: vec!["department".into()],
        mdoc_namespace: Some("org.iso.18013.5.1".into()),
        mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
        zk_predicate_claims: vec![],
        credential_payload_format: payload_format,
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn request(format: &str, proof: Option<String>) -> CredentialRequest {
    CredentialRequest {
        format: Some(format.into()),
        credential_configuration_id: Some("EmployeeCredential".into()),
        credential_identifier: None,
        proofs: proof.map(|compact| ProofsObject {
            jwt: Some(vec![compact]),
        }),
        credential_definition: None,
        vct: None,
        doctype: None,
        claims: None,
    }
}

fn p256_proof(nonce: &str) -> ProofFixture {
    let holder = marty_oid4vci::generate_p256_did_jwk_holder_key().unwrap();
    let private_jwk: Value = serde_json::from_str(&holder.private_jwk).unwrap();
    let public_jwk: Value = serde_json::from_str(&holder.public_jwk).unwrap();
    let private_scalar = URL_SAFE_NO_PAD
        .decode(private_jwk["d"].as_str().unwrap())
        .unwrap();
    let signing_key = p256::ecdsa::SigningKey::from_slice(&private_scalar).unwrap();
    let header = json!({
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt",
        "jwk": public_jwk,
    });
    let payload = json!({
        "iss": holder.kid,
        "aud": ISSUER_URL,
        "iat": chrono::Utc::now().timestamp(),
        "nonce": nonce,
    });
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header}.{payload}");
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());

    ProofFixture {
        compact: format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
        private_jwk,
        public_jwk,
    }
}

fn scalar_credential(response: marty_oid4vci::types::CredentialResponse) -> String {
    response
        .credential
        .and_then(|credential| credential.as_str().map(str::to_owned))
        .expect("scalar issuance must return exactly one encoded credential")
}

fn decode_sd_jwt_payload(compact: &str) -> Value {
    let issuer_jwt = compact.split('~').next().unwrap();
    let payload = issuer_jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn assert_public_jwk(actual: &Value, expected: &Value) {
    assert_eq!(actual, expected, "credential must bind the exact proof key");
    let members = actual.as_object().expect("holder JWK must be an object");
    for private_member in PRIVATE_JWK_MEMBERS {
        assert!(
            !members.contains_key(*private_member),
            "credential leaked private JWK member {private_member}"
        );
    }
}

fn tamper_signature(compact: &str) -> String {
    let mut parts = compact.split('.');
    let header = parts.next().unwrap();
    let payload = parts.next().unwrap();
    let signature = parts.next().unwrap();
    assert!(parts.next().is_none());
    let mut signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
    signature[0] ^= 1;
    format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[test]
fn scalar_sd_jwt_uses_exact_proof_public_key_without_private_material() {
    let engine = issuance_engine();
    let nonce = uuid::Uuid::new_v4().to_string();
    let proof = p256_proof(&nonce);
    assert!(proof.private_jwk.get("d").is_some());

    let response = engine
        .issue_credential(
            &request("dc+sd-jwt", Some(proof.compact)),
            &claims(CredentialPayloadFormat::IetfSdJwt),
            &nonce,
            None,
        )
        .unwrap();
    let payload = decode_sd_jwt_payload(&scalar_credential(response));

    assert_public_jwk(&payload["cnf"]["jwk"], &proof.public_jwk);
}

#[test]
fn scalar_mdoc_uses_exact_proof_public_key_without_private_material() {
    let engine = issuance_engine();
    let nonce = uuid::Uuid::new_v4().to_string();
    let proof = p256_proof(&nonce);
    assert!(proof.private_jwk.get("d").is_some());
    let expected_x = URL_SAFE_NO_PAD
        .decode(proof.public_jwk["x"].as_str().unwrap())
        .unwrap();
    let expected_y = URL_SAFE_NO_PAD
        .decode(proof.public_jwk["y"].as_str().unwrap())
        .unwrap();

    let response = engine
        .issue_credential(
            &request("mso_mdoc", Some(proof.compact)),
            &claims(CredentialPayloadFormat::W3cVcdmV2SdJwt),
            &nonce,
            None,
        )
        .unwrap();
    let encoded = scalar_credential(response);
    let issuer_signed: IssuerSigned =
        isomdl::cbor::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
    let tagged_mso: Tag24<Mso> = isomdl::cbor::from_slice(
        issuer_signed
            .issuer_auth
            .payload
            .as_ref()
            .expect("issuerAuth must contain the mobile security object"),
    )
    .unwrap();

    let raw_mso: ciborium::Value = isomdl::cbor::from_slice(&tagged_mso.inner_bytes).unwrap();
    let ciborium::Value::Map(raw_mso) = raw_mso else {
        panic!("mobile security object must be a CBOR map")
    };
    let raw_device_key_info = raw_mso
        .iter()
        .find_map(|(key, value)| {
            (key == &ciborium::Value::Text("deviceKeyInfo".into())).then_some(value)
        })
        .expect("deviceKeyInfo must be present");
    let ciborium::Value::Map(raw_device_key_info) = raw_device_key_info else {
        panic!("deviceKeyInfo must be a CBOR map")
    };
    let raw_device_key = raw_device_key_info
        .iter()
        .find_map(|(key, value)| {
            (key == &ciborium::Value::Text("deviceKey".into())).then_some(value)
        })
        .expect("deviceKey must be present");
    let ciborium::Value::Map(raw_device_key) = raw_device_key else {
        panic!("deviceKey must be a COSE_Key map")
    };
    let mut labels = raw_device_key
        .iter()
        .map(|(label, _)| match label {
            ciborium::Value::Integer(label) => i128::from(*label),
            _ => panic!("COSE_Key labels must be integers"),
        })
        .collect::<Vec<_>>();
    labels.sort_unstable();
    assert_eq!(labels, [-3, -2, -1, 1], "device key must be public-only");

    assert_eq!(
        tagged_mso.into_inner().device_key_info.device_key,
        CoseKey::EC2 {
            crv: EC2Curve::P256,
            x: expected_x,
            y: EC2Y::Value(expected_y),
        },
        "mdoc must bind the exact public key that verified the proof"
    );
}

#[test]
fn missing_or_invalid_proof_cannot_yield_a_credential() {
    let engine = issuance_engine();
    for (format, payload_format) in [
        ("dc+sd-jwt", CredentialPayloadFormat::IetfSdJwt),
        ("mso_mdoc", CredentialPayloadFormat::W3cVcdmV2SdJwt),
    ] {
        let nonce = uuid::Uuid::new_v4().to_string();
        let proof = p256_proof(&nonce);

        let missing = engine
            .issue_credential(
                &request(format, None),
                &claims(payload_format.clone()),
                &nonce,
                None,
            )
            .unwrap_err();
        assert!(matches!(missing, Oid4vciError::ProofVerificationFailed(_)));

        let invalid = engine
            .issue_credential(
                &request(format, Some(tamper_signature(&proof.compact))),
                &claims(payload_format),
                &nonce,
                None,
            )
            .unwrap_err();
        assert!(matches!(invalid, Oid4vciError::ProofVerificationFailed(_)));
    }
}

#[test]
fn direct_non_proof_sd_jwt_remains_unbound() {
    let signed = issuance_engine()
        .issue_credential_in_format(
            &CredentialFormat::SdJwt,
            &claims(CredentialPayloadFormat::IetfSdJwt),
        )
        .unwrap();
    let SignedCredential::SdJwt { compact, .. } = signed else {
        panic!("direct SD-JWT issuance must return an SD-JWT")
    };

    assert!(decode_sd_jwt_payload(&compact).get("cnf").is_none());
}
