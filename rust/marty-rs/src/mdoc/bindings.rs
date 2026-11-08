//! Transport-only Python bindings over Core's remote mdoc preparation.

use super::prepared::MdocPreparedForHsm;
use marty_crypto::strict_json::parse_unique_json;
use marty_oid4vci::remote_credential::{prepare_remote_mdoc, RemoteMdocRequest};
use pyo3::prelude::*;

/// Prepare one ES256 mdoc using public issuer/holder metadata only.
///
/// Core owns the complete COSE Sig_structure and salted issuer items. The
/// issuer's remote signer must sign exactly `prepared.get_tbs_data()` and return
/// a raw IEEE P1363 signature. No private key is accepted or retained here.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    issuer_id,
    verification_method_id,
    issuer_public_jwk_json,
    doc_type,
    namespace,
    claims_json,
    expiration_seconds=None,
    credential_id=None,
    holder_jwk_json=None,
))]
pub fn prepare_mdoc_for_hsm(
    issuer_id: &str,
    verification_method_id: &str,
    issuer_public_jwk_json: &str,
    doc_type: &str,
    namespace: &str,
    claims_json: &str,
    expiration_seconds: Option<i64>,
    credential_id: Option<&str>,
    holder_jwk_json: Option<&str>,
) -> PyResult<MdocPreparedForHsm> {
    let claims = parse_unique_json(claims_json.as_bytes())
        .and_then(serde_json::from_value)
        .map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid claims JSON: {error}"))
        })?;
    let holder_jwk = holder_jwk_json
        .map(|json| parse_unique_json(json.as_bytes()))
        .transpose()
        .map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid holder JWK JSON: {error}"))
        })?;
    let prepared = prepare_remote_mdoc(RemoteMdocRequest {
        issuer_id: issuer_id.to_owned(),
        verification_method_id: verification_method_id.to_owned(),
        algorithm: "ES256".into(),
        issuer_public_jwk: issuer_public_jwk_json.to_owned(),
        credential_type: doc_type.to_owned(),
        namespace: namespace.to_owned(),
        claims,
        expiration_seconds,
        credential_id: credential_id.map(str::to_owned),
        holder_jwk,
    })
    .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    Ok(MdocPreparedForHsm::new(prepared))
}

/// Complete the same prepared mdoc with the remote signer's raw ES256 signature.
/// Returns canonical IssuerSigned CBOR, not a fabricated holder presentation.
#[pyfunction]
pub fn complete_mdoc_with_signature(
    prepared: &mut MdocPreparedForHsm,
    signature: Vec<u8>,
) -> PyResult<Vec<u8>> {
    prepared.complete_with_signature(signature)
}
