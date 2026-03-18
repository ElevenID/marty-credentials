//! eMRTD passport issuance: CSCA/DSC generation + SOD construction.
//!
//! Provides two entrypoints:
//!
//! - [`issue_emrtd_passport`] — production use; caller supplies an existing
//!   CSCA certificate and private key.
//! - [`issue_emrtd_passport_self_signed`] — testing / bootstrapping; generates
//!   a fresh CSCA and DSC internally.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use marty_crypto::cert_builder::{create_csca_certificate, create_dsc_certificate};
use marty_crypto::keygen::KeyType;
use marty_crypto::sod_builder::build_emrtd_sod_der;

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
    // Generate a DSC signed by the provided CSCA.
    let (dsc_cert_der, dsc_key_pem) = create_dsc_certificate(
        &request.country_code,
        &request.organization,
        csca_cert_der,
        csca_key_pem,
        730,
        KeyType::EcdsaP256,
    )?;

    build_credential(request, csca_cert_der, &dsc_cert_der, &dsc_key_pem)
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
    // Generate a fresh CSCA.
    let (csca_cert_der, csca_key_pem) = create_csca_certificate(
        &request.country_code,
        &request.organization,
        3650,
        KeyType::EcdsaP256,
    )?;

    issue_emrtd_passport(request, &csca_cert_der, &csca_key_pem)
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Build the [`EmrtdCredential`] from resolved CSCA + DSC material.
fn build_credential(
    request: &EmrtdIssuanceRequest,
    csca_cert_der: &[u8],
    dsc_cert_der: &[u8],
    dsc_key_pem: &str,
) -> Result<EmrtdCredential, Box<dyn std::error::Error + Send + Sync>> {
    // Convert data groups to the flat (number, bytes) slice the SOD builder wants.
    let dg_pairs: Vec<(u8, Vec<u8>)> = request
        .data_groups
        .iter()
        .map(|dg| (dg.number, dg.content.clone()))
        .collect();

    // Build the EF.SOD.
    let sod_der = build_emrtd_sod_der(&dg_pairs, dsc_cert_der, dsc_key_pem)?;

    // Base64-encode the SOD and each data group.
    let sod_der_base64 = BASE64.encode(&sod_der);

    let mut data_groups_b64 = std::collections::HashMap::new();
    for dg in &request.data_groups {
        let key = format!("DG{}", dg.number);
        data_groups_b64.insert(key, BASE64.encode(&dg.content));
    }

    // PEM-encode the certificates for inclusion in the credential.
    let csca_cert_pem = der_to_pem(csca_cert_der, "CERTIFICATE")?;
    let dsc_cert_pem = der_to_pem(dsc_cert_der, "CERTIFICATE")?;

    Ok(EmrtdCredential {
        sod_der_base64,
        country_code: request.country_code.clone(),
        data_groups: data_groups_b64,
        csca_cert_pem,
        dsc_cert_pem,
    })
}

/// DER → PEM helper using `pem_rfc7468`.
fn der_to_pem(
    der: &[u8],
    label: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, der)
        .map_err(|e| format!("PEM encode error: {e}").into())
}
