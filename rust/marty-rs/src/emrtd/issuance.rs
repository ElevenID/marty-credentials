//! eMRTD passport issuance: CSCA/DSC generation + SOD construction.
//!
//! Provides two entrypoints:
//!
//! - [`issue_emrtd_passport`] — production use; caller supplies an existing
//!   CSCA certificate and private key.
//! - [`issue_emrtd_passport_self_signed`] — testing / bootstrapping; generates
//!   a fresh CSCA and DSC internally.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use marty_verification::issuance::CscaAuthority;

use super::types::{EmrtdCredential, EmrtdIssuanceRequest};

// ============================================================================
// Public API
// ============================================================================

/// Issue an eMRTD credential using the supplied CSCA.
///
/// A fresh Document Signer Certificate (DSC) is generated, signed by the CSCA,
/// and used to sign the `LDSSecurityObject`.  Both certificates are P-256
/// ECDSA.
///
/// # Arguments
/// - `request`      — Issuance parameters and data group content.
/// - `csca_cert_der` — DER-encoded Country Signing CA certificate.
/// - `csca_key_pem`  — PKCS#8 PEM private key for the CSCA.
///
/// # Returns
/// [`EmrtdCredential`] ready to be sent to the verifier or stored.
pub fn issue_emrtd_passport(
    request: &EmrtdIssuanceRequest,
    csca_cert_der: &[u8],
    csca_key_pem: &str,
) -> Result<EmrtdCredential, Box<dyn std::error::Error + Send + Sync>> {
    let csca = CscaAuthority::from_pem(
        &request.country_code,
        csca_cert_der.to_vec(),
        csca_key_pem.to_owned(),
    );
    issue_with_authority(request, &csca)
}

/// Issue an eMRTD credential with a freshly generated, self-contained CSCA.
///
/// This is suitable for **testing and offline fixtures only**.  The generated
/// CSCA is single-use and not trusted by any external registry.
///
/// # Arguments
/// - `request` — Issuance parameters and data group content.
///
/// # Returns
/// [`EmrtdCredential`] (which includes the CSCA PEM for test registry setup).
pub fn issue_emrtd_passport_self_signed(
    request: &EmrtdIssuanceRequest,
) -> Result<EmrtdCredential, Box<dyn std::error::Error + Send + Sync>> {
    let csca = match request.csca_key_algorithm {
        Some(algorithm) => CscaAuthority::new_with_algorithm(
            &request.country_code,
            &request.organization,
            3650,
            algorithm,
        )?,
        None => CscaAuthority::new(&request.country_code, &request.organization, 3650)?,
    };
    issue_with_authority(request, &csca)
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Build the [`EmrtdCredential`] from resolved CSCA + DSC material.
fn issue_with_authority(
    request: &EmrtdIssuanceRequest,
    csca: &CscaAuthority,
) -> Result<EmrtdCredential, Box<dyn std::error::Error + Send + Sync>> {
    let dsc = csca.issue_dsc(&request.organization, 730)?;
    let mut personalizer = dsc.personalizer();
    for data_group in &request.data_groups {
        personalizer = personalizer.set_data_group(data_group.number, data_group.content.clone());
    }
    let passport = personalizer.build()?;
    let data_groups = passport
        .data_groups
        .into_iter()
        .map(|(number, content)| (format!("DG{number}"), BASE64.encode(content)))
        .collect();

    Ok(EmrtdCredential {
        sod_der_base64: BASE64.encode(passport.sod_der),
        country_code: request.country_code.clone(),
        data_groups,
        csca_cert_pem: csca.cert_pem()?,
        dsc_cert_pem: dsc.cert_pem()?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::emrtd::CscaKeyAlgorithm;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use der::Decode;
    use marty_crypto::cert_builder::create_csca_certificate;
    use marty_crypto::keygen::KeyType;
    use marty_verification::verification::emrtd::{verify_emrtd, HashStatus, SecurityObject};
    use marty_verification::CscaRegistry;
    use x509_cert::Certificate;

    use super::*;

    fn request() -> EmrtdIssuanceRequest {
        EmrtdIssuanceRequest::with_dg1(
            "TST",
            "Test Document Signer",
            b"P<TSTMUSTER<<ERIKA<<<<<<<<<<<<<<<<<<<<<<<<<<".to_vec(),
        )
    }

    fn assert_round_trip_and_tamper_rejection(
        request: &EmrtdIssuanceRequest,
        credential: &EmrtdCredential,
    ) {
        let (_, csca_der) = pem_rfc7468::decode_vec(credential.csca_cert_pem.as_bytes()).unwrap();
        let csca = Certificate::from_der(&csca_der).unwrap();
        let mut registry = CscaRegistry::new();
        registry.add_country_csca("TST", csca).unwrap();
        let sod_der = BASE64.decode(&credential.sod_der_base64).unwrap();
        let security_object =
            SecurityObject::from_sod_der(&sod_der, Some("TST".to_owned())).unwrap();
        let data_groups = request
            .data_groups
            .iter()
            .map(|data_group| (data_group.number, data_group.content.clone()))
            .collect::<HashMap<_, _>>();

        let verified = verify_emrtd(&security_object, &data_groups, &registry);
        assert!(verified.verified, "{:?}", verified.errors);

        let mut tampered = data_groups;
        tampered.insert(1, b"tampered".to_vec());
        let rejected = verify_emrtd(&security_object, &tampered, &registry);
        assert!(!rejected.verified);
        assert_eq!(rejected.dg_hash_status, HashStatus::Invalid);
    }

    #[test]
    fn self_signed_issuance_round_trips_through_the_canonical_verifier() {
        let request = request();
        let credential = issue_emrtd_passport_self_signed(&request).unwrap();

        assert_round_trip_and_tamper_rejection(&request, &credential);
    }

    #[test]
    fn self_signed_consumer_routes_every_supported_csca_algorithm() {
        for algorithm in CscaKeyAlgorithm::ALL {
            let mut request = request();
            request.csca_key_algorithm = Some(algorithm);
            let serialized = serde_json::to_value(&request).unwrap();
            assert_eq!(serialized["csca_key_algorithm"], algorithm.as_str());
            let decoded: EmrtdIssuanceRequest = serde_json::from_value(serialized).unwrap();
            assert_eq!(decoded.csca_key_algorithm, Some(algorithm));

            let credential = issue_emrtd_passport_self_signed(&decoded).unwrap();
            assert_round_trip_and_tamper_rejection(&decoded, &credential);
        }
    }

    #[test]
    fn omitted_csca_algorithm_preserves_the_existing_request_shape() {
        let serialized = serde_json::to_value(request()).unwrap();
        assert!(serialized.get("csca_key_algorithm").is_none());
    }

    #[test]
    fn imported_csca_issuance_round_trips_through_the_canonical_verifier() {
        let request = request();
        let (csca_cert_der, csca_key_pem) = create_csca_certificate(
            &request.country_code,
            "Imported Test CSCA",
            3650,
            KeyType::EcdsaP256,
        )
        .unwrap();
        let credential = issue_emrtd_passport(&request, &csca_cert_der, &csca_key_pem).unwrap();

        assert_round_trip_and_tamper_rejection(&request, &credential);
    }
}
