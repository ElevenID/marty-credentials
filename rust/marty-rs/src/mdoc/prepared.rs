//! An opaque Core preparation retained across the external signing operation.

use base64::Engine as _;
use marty_oid4vci::formats::mdoc::{assemble_mdoc, PreparedMdoc};
use marty_oid4vci::types::SignedCredential;
use pyo3::prelude::*;

#[pyclass]
pub struct MdocPreparedForHsm {
    inner: Option<PreparedMdoc>,
}

impl MdocPreparedForHsm {
    pub(super) fn new(prepared: PreparedMdoc) -> Self {
        Self {
            inner: Some(prepared),
        }
    }

    fn prepared(&self) -> PyResult<&PreparedMdoc> {
        self.inner.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("mDoc preparation has already been completed")
        })
    }
}

#[pymethods]
impl MdocPreparedForHsm {
    /// The complete COSE Sign1 Sig_structure to pass unchanged to the HSM.
    pub fn get_tbs_data(&self) -> PyResult<Vec<u8>> {
        Ok(self.prepared()?.signing_payload().to_vec())
    }

    /// The identifier Core reserved during preparation.
    pub fn get_credential_id(&self) -> PyResult<String> {
        Ok(self.prepared()?.credential_id().to_owned())
    }

    /// Complete once, using a raw ES256 (r || s) signature from external custody.
    /// Invalid signatures leave the prepared state available for a corrected retry.
    pub fn complete_with_signature(&mut self, signature: Vec<u8>) -> PyResult<Vec<u8>> {
        self.prepared()?
            .validate_signature(&signature)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        let prepared = self.inner.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("mDoc preparation has already been completed")
        })?;
        let signed = assemble_mdoc(prepared, &signature)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        let SignedCredential::MsoMdoc {
            issuer_signed_b64, ..
        } = signed
        else {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Core returned an unexpected credential format",
            ));
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(issuer_signed_b64)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }
}
