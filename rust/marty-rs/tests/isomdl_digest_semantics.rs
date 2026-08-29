use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use base64::Engine as _;
use ciborium::Value;
use coset_isomdl::iana::Algorithm;
use isomdl::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
use isomdl::definitions::{DeviceKeyInfo, DigestAlgorithm, ValidityInfo};
use isomdl::digest_executor::{
    DigestExecutionError, DigestExecutor, DigestJob, DigestResult, SerialDigestExecutor,
};
use isomdl::issuance::mdoc::{Mdoc, Namespaces, PreparedMdoc};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use time::OffsetDateTime;

const IDENTITY_NAMESPACE: &str = "org.example.identity";
const STATUS_NAMESPACE: &str = "org.example.status";

#[test]
fn public_prepare_scalar_route_commits_every_disclosed_item() {
    for (algorithm, name, digest_length) in digest_algorithms() {
        let prepared = prepare_fixture(algorithm, false);
        assert_prepared_semantics(&prepared, name, digest_length, false);
    }
}

#[test]
fn public_prepare_decoys_extend_digests_without_changing_disclosures() {
    for (algorithm, name, digest_length) in digest_algorithms() {
        let prepared = prepare_fixture(algorithm, true);
        assert_prepared_semantics(&prepared, name, digest_length, true);
    }
}

#[test]
fn selected_serial_executor_jobs_reconstruct_the_mso_digest_multiset() {
    for (algorithm, name, digest_length) in digest_algorithms() {
        let executor = RecordingSerialDigestExecutor::default();
        let (doc_type, namespaces, validity_info, device_key_info) = prepare_fixture_inputs();
        let prepared = Mdoc::prepare_with_digest_executor(
            doc_type,
            namespaces,
            validity_info,
            algorithm,
            device_key_info,
            Algorithm::ES256,
            true,
            &executor,
        )
        .unwrap();
        let jobs = executor.recorded_jobs();

        let prepared_value = decode_value(&encode_value(&prepared));
        let mso = text_entry(&prepared_value, "mso");
        let disclosed_item_count =
            issuer_signed_item_count(text_entry(&prepared_value, "namespaces"));
        let mut mso_digests = digest_multiset(text_entry(mso, "valueDigests"));

        assert!(
            jobs.len() > disclosed_item_count,
            "decoy-enabled preparation must submit both disclosure and decoy jobs"
        );
        assert_eq!(jobs.len(), mso_digests.len());
        assert!(jobs.iter().all(|job| job.algorithm == algorithm));

        let mut independently_computed = jobs
            .iter()
            .map(|job| digest(name, &job.input))
            .collect::<Vec<_>>();
        assert!(
            independently_computed
                .iter()
                .all(|digest| digest.len() == digest_length),
            "the independently selected hash must have the expected output length"
        );

        independently_computed.sort();
        mso_digests.sort();
        assert_eq!(independently_computed, mso_digests);
    }
}

#[derive(Default)]
struct RecordingSerialDigestExecutor {
    jobs: Mutex<Vec<DigestJob>>,
}

impl RecordingSerialDigestExecutor {
    fn recorded_jobs(&self) -> Vec<DigestJob> {
        self.jobs.lock().unwrap().clone()
    }
}

impl DigestExecutor for RecordingSerialDigestExecutor {
    fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
        self.jobs
            .lock()
            .map_err(|_| DigestExecutionError)?
            .extend_from_slice(jobs);
        SerialDigestExecutor.execute(jobs)
    }
}

fn digest_algorithms() -> [(DigestAlgorithm, &'static str, usize); 3] {
    [
        (DigestAlgorithm::SHA256, "SHA-256", 32),
        (DigestAlgorithm::SHA384, "SHA-384", 48),
        (DigestAlgorithm::SHA512, "SHA-512", 64),
    ]
}

fn prepare_fixture(digest_algorithm: DigestAlgorithm, enable_decoy_digests: bool) -> PreparedMdoc {
    let (doc_type, namespaces, validity_info, device_key_info) = prepare_fixture_inputs();

    Mdoc::prepare(
        doc_type,
        namespaces,
        validity_info,
        digest_algorithm,
        device_key_info,
        Algorithm::ES256,
        enable_decoy_digests,
    )
    .unwrap()
}

fn prepare_fixture_inputs() -> (String, Namespaces, ValidityInfo, DeviceKeyInfo) {
    let namespaces: Namespaces = BTreeMap::from([
        (
            IDENTITY_NAMESPACE.to_owned(),
            BTreeMap::from([
                ("family_name".to_owned(), Value::Text("Nguyen".to_owned())),
                ("given_name".to_owned(), Value::Text("Avery".to_owned())),
            ]),
        ),
        (
            STATUS_NAMESPACE.to_owned(),
            BTreeMap::from([
                ("age_over_18".to_owned(), Value::Bool(true)),
                ("portrait".to_owned(), Value::Bytes(vec![0xa5; 257])),
            ]),
        ),
    ]);
    let signed = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    let validity_info = ValidityInfo {
        signed,
        valid_from: signed,
        valid_until: OffsetDateTime::from_unix_timestamp(1_731_536_000).unwrap(),
        expected_update: None,
    };
    let decode_coordinate = |coordinate: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(coordinate)
            .unwrap()
    };
    let device_key_info = DeviceKeyInfo {
        device_key: CoseKey::EC2 {
            crv: EC2Curve::P256,
            x: decode_coordinate("axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"),
            y: EC2Y::Value(decode_coordinate(
                "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
            )),
        },
        key_authorizations: None,
        key_info: None,
    };

    (
        "org.example.identity.document".to_owned(),
        namespaces,
        validity_info,
        device_key_info,
    )
}

fn assert_prepared_semantics(
    prepared: &PreparedMdoc,
    expected_algorithm: &str,
    expected_digest_length: usize,
    expect_decoys: bool,
) {
    let prepared_value = decode_value(&encode_value(prepared));
    let mso = text_entry(&prepared_value, "mso");
    let namespaces = text_entry(&prepared_value, "namespaces");
    let value_digests = text_entry(mso, "valueDigests");

    assert_eq!(
        text_entry(mso, "digestAlgorithm"),
        &Value::Text(expected_algorithm.to_owned())
    );
    assert_eq!(map_len(namespaces), 2);
    assert_eq!(map_len(value_digests), 2);
    assert_eq!(
        text_map_keys(namespaces),
        [IDENTITY_NAMESPACE, STATUS_NAMESPACE]
    );
    assert_eq!(
        text_map_keys(value_digests),
        [IDENTITY_NAMESPACE, STATUS_NAMESPACE]
    );

    for namespace in [IDENTITY_NAMESPACE, STATUS_NAMESPACE] {
        let expected_claims = expected_claims(namespace);
        let items = text_entry(namespaces, namespace);
        let digests = digest_map(text_entry(value_digests, namespace));
        let Value::Array(items) = items else {
            panic!("issuer namespace must contain an item array");
        };
        assert_eq!(items.len(), expected_claims.len());

        let mut disclosed_ids = BTreeSet::new();
        let mut disclosed_identifiers = Vec::new();
        for item_bytes in items {
            let item = decoded_issuer_signed_item(item_bytes);
            let digest_id = unsigned_integer(text_entry(&item, "digestID"));
            let random = byte_string(text_entry(&item, "random"));
            let identifier = text_string(text_entry(&item, "elementIdentifier"));
            let element_value = text_entry(&item, "elementValue");

            assert!(disclosed_ids.insert(digest_id), "digest IDs must be unique");
            assert_eq!(random.len(), 16, "each disclosure keeps a 16-byte salt");
            disclosed_identifiers.push(identifier.to_owned());
            assert_eq!(
                Some(element_value),
                expected_claims.get(identifier),
                "each disclosure must retain its input value"
            );

            let expected = digest(expected_algorithm, &encode_value(item_bytes));
            assert_eq!(
                digests.get(&digest_id),
                Some(&expected),
                "the MSO must commit to the complete tag-24 IssuerSignedItemBytes"
            );
        }

        assert_eq!(
            disclosed_identifiers,
            expected_claims
                .keys()
                .map(|identifier| (*identifier).to_owned())
                .collect::<Vec<_>>()
        );
        assert!(
            digests
                .values()
                .all(|digest| digest.len() == expected_digest_length),
            "every real and decoy output must have the selected digest length"
        );

        let decoy_count = digests
            .keys()
            .filter(|digest_id| !disclosed_ids.contains(digest_id))
            .count();
        if expect_decoys {
            assert!(
                (5..=9).contains(&decoy_count),
                "each namespace must retain the 5-9 decoy distribution"
            );
            assert_eq!(digests.len(), items.len() + decoy_count);
        } else {
            assert_eq!(decoy_count, 0);
            assert_eq!(digests.len(), items.len());
        }
    }

    assert_signature_payload_contains_mso(prepared, mso);
}

fn expected_claims(namespace: &str) -> BTreeMap<&'static str, Value> {
    match namespace {
        IDENTITY_NAMESPACE => BTreeMap::from([
            ("family_name", Value::Text("Nguyen".to_owned())),
            ("given_name", Value::Text("Avery".to_owned())),
        ]),
        STATUS_NAMESPACE => BTreeMap::from([
            ("age_over_18", Value::Bool(true)),
            ("portrait", Value::Bytes(vec![0xa5; 257])),
        ]),
        _ => panic!("unexpected test namespace"),
    }
}

fn assert_signature_payload_contains_mso(prepared: &PreparedMdoc, mso: &Value) {
    let signature_structure = decode_value(prepared.signature_payload());
    let Value::Array(signature_structure) = signature_structure else {
        panic!("COSE signature payload must be an array");
    };
    let payload = byte_string(
        signature_structure
            .get(3)
            .expect("COSE signature payload must include the MSO payload"),
    );
    let expected_payload = encode_value(&Value::Tag(24, Box::new(Value::Bytes(encode_value(mso)))));
    assert_eq!(payload, expected_payload);
}

fn decoded_issuer_signed_item(item_bytes: &Value) -> Value {
    let Value::Tag(24, encoded_item) = item_bytes else {
        panic!("IssuerSignedItemBytes must use CBOR tag 24");
    };
    decode_value(byte_string(encoded_item))
}

fn digest_map(value: &Value) -> BTreeMap<u64, Vec<u8>> {
    let Value::Map(entries) = value else {
        panic!("valueDigests namespace must be a map");
    };
    entries
        .iter()
        .map(|(digest_id, digest)| (unsigned_integer(digest_id), byte_string(digest).to_vec()))
        .collect()
}

fn digest_multiset(value: &Value) -> Vec<Vec<u8>> {
    let Value::Map(namespaces) = value else {
        panic!("valueDigests must be a namespace map");
    };
    let mut digests = Vec::new();
    for (_, namespace_digests) in namespaces {
        let Value::Map(namespace_digests) = namespace_digests else {
            panic!("each valueDigests namespace must be a map");
        };
        digests.extend(
            namespace_digests
                .iter()
                .map(|(_, digest)| byte_string(digest).to_vec()),
        );
    }
    digests
}

fn issuer_signed_item_count(value: &Value) -> usize {
    let Value::Map(namespaces) = value else {
        panic!("issuer namespaces must be a map");
    };
    namespaces
        .iter()
        .map(|(_, items)| {
            let Value::Array(items) = items else {
                panic!("each issuer namespace must contain an item array");
            };
            items.len()
        })
        .sum()
}

fn digest(algorithm: &str, input: &[u8]) -> Vec<u8> {
    match algorithm {
        "SHA-256" => Sha256::digest(input).to_vec(),
        "SHA-384" => Sha384::digest(input).to_vec(),
        "SHA-512" => Sha512::digest(input).to_vec(),
        _ => panic!("unsupported test digest algorithm"),
    }
}

fn encode_value(value: &impl serde::Serialize) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).unwrap();
    encoded
}

fn decode_value(encoded: &[u8]) -> Value {
    ciborium::from_reader(encoded).unwrap()
}

fn text_entry<'a>(value: &'a Value, expected_key: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected a CBOR map while looking for {expected_key}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::Text(key) if key == expected_key => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing CBOR map key {expected_key}"))
}

fn map_len(value: &Value) -> usize {
    let Value::Map(entries) = value else {
        panic!("expected a CBOR map");
    };
    entries.len()
}

fn text_map_keys(value: &Value) -> Vec<&str> {
    let Value::Map(entries) = value else {
        panic!("expected a CBOR map");
    };
    entries.iter().map(|(key, _)| text_string(key)).collect()
}

fn unsigned_integer(value: &Value) -> u64 {
    let Value::Integer(integer) = value else {
        panic!("expected an unsigned CBOR integer");
    };
    u64::try_from(*integer).unwrap()
}

fn byte_string(value: &Value) -> &[u8] {
    let Value::Bytes(bytes) = value else {
        panic!("expected a CBOR byte string");
    };
    bytes
}

fn text_string(value: &Value) -> &str {
    let Value::Text(text) = value else {
        panic!("expected a CBOR text string");
    };
    text
}
