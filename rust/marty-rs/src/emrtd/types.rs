//! Types for eMRTD (electronic Machine Readable Travel Document) issuance.
//!
//! Per ICAO 9303 Part 10 (LDS and PKI Maintenance).

use serde::{Deserialize, Serialize};

// ============================================================================
// Data group representation
// ============================================================================

/// A single data group, identified by its ICAO number (1–20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmrtdDataGroup {
    /// ICAO data group number (1 = MRZ, 2 = Portrait, etc.)
    pub number: u8,
    /// Raw data group bytes (the full EF.DG content).
    pub content: Vec<u8>,
}

// ============================================================================
// Issuance request
// ============================================================================

/// Request to issue an eMRTD credential.
///
/// The caller is responsible for encoding data group content correctly
/// (e.g., DG1 = ICAO tag-length-value MRZ object, DG2 = JPEG portrait
/// wrapped in an LDS binary data object).  For testing, bare `MRZ_LINE1 +
/// MRZ_LINE2` bytes are sufficient as DG1 content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmrtdIssuanceRequest {
    /// ISO 3166-1 alpha-3 country code (e.g. `"DEU"`, `"USA"`).
    pub country_code: String,
    /// Organisation name for the Document Signer Certificate subject.
    pub organization: String,
    /// Data groups to include in the Security Object and credential.
    pub data_groups: Vec<EmrtdDataGroup>,
}

impl EmrtdIssuanceRequest {
    /// Convenience constructor: build a request with a single DG1 (MRZ data).
    pub fn with_dg1(country_code: impl Into<String>, org: impl Into<String>, dg1: Vec<u8>) -> Self {
        Self {
            country_code: country_code.into(),
            organization: org.into(),
            data_groups: vec![EmrtdDataGroup { number: 1, content: dg1 }],
        }
    }
}

// ============================================================================
// Issued credential
// ============================================================================

/// An issued eMRTD credential, ready for transmission or storage.
///
/// All binary fields are base64-encoded (standard alphabet, with padding) so
/// the struct serialises cleanly to JSON and matches the wire format expected
/// by `marty_verifier::verify_emrtd_offline`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmrtdCredential {
    /// Base64-encoded DER `ContentInfo` (CMS `SignedData` / EF.SOD).
    pub sod_der_base64: String,
    /// Country code propagated from the issuance request.
    pub country_code: String,
    /// Base64-encoded data groups, keyed by `"DG1"`, `"DG2"`, etc.
    pub data_groups: std::collections::HashMap<String, String>,
    /// PEM-encoded Country Signing CA certificate.
    pub csca_cert_pem: String,
    /// PEM-encoded Document Signer Certificate (embedded in SOD).
    pub dsc_cert_pem: String,
}
