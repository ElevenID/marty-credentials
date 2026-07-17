//! PyO3 Python bindings for the eMRTD issuance module.
//!
//! Exposed functions (all available in the `_marty_rs` Python module):
//!
//! - `issue_emrtd_passport(request_json, csca_cert_pem, csca_key_pem) -> str`
//! - `issue_emrtd_passport_self_signed(request_json) -> str`

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use super::issuance::{
    issue_emrtd_passport as issue, issue_emrtd_passport_self_signed as issue_self_signed,
};
use super::types::EmrtdIssuanceRequest;

/// Issue an eMRTD credential using an existing CSCA.
///
/// Returns a JSON-encoded `EmrtdCredential`.
///
/// # Arguments (Python)
/// - `request_json`  — JSON string of `EmrtdIssuanceRequest`
/// - `csca_cert_pem` — PEM-encoded CSCA certificate
/// - `csca_key_pem`  — PEM-encoded PKCS#8 private key for the CSCA
#[pyfunction]
pub fn issue_emrtd_passport(
    request_json: &str,
    csca_cert_pem: &str,
    csca_key_pem: &str,
) -> PyResult<String> {
    let request: EmrtdIssuanceRequest = serde_json::from_str(request_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid request JSON: {e}")))?;

    // Decode PEM certificate to DER.
    let csca_cert_der = pem_to_der(csca_cert_pem)
        .map_err(|e| PyValueError::new_err(format!("CSCA cert PEM decode: {e}")))?;

    let credential = issue(&request, &csca_cert_der, csca_key_pem)
        .map_err(|e| PyValueError::new_err(format!("Issue passport: {e}")))?;

    serde_json::to_string(&credential)
        .map_err(|e| PyValueError::new_err(format!("Credential JSON encode: {e}")))
}

/// Issue an eMRTD credential with a freshly generated self-signed CSCA.
///
/// Intended for testing and fixture generation only.  Returns a
/// JSON-encoded `EmrtdCredential` which includes the CSCA PEM so the caller
/// can register it with a trust store.
///
/// # Arguments (Python)
/// - `request_json` — JSON string of `EmrtdIssuanceRequest`
#[pyfunction]
pub fn issue_emrtd_passport_self_signed(request_json: &str) -> PyResult<String> {
    let request: EmrtdIssuanceRequest = serde_json::from_str(request_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid request JSON: {e}")))?;

    let credential = issue_self_signed(&request)
        .map_err(|e| PyValueError::new_err(format!("Issue self-signed passport: {e}")))?;

    serde_json::to_string(&credential)
        .map_err(|e| PyValueError::new_err(format!("Credential JSON encode: {e}")))
}

// ============================================================================
// Helpers
// ============================================================================

fn pem_to_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let (_, der) =
        pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|e| format!("PEM decode error: {e}"))?;
    Ok(der)
}
