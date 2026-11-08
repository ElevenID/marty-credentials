//! Python transport adapters over Core-owned mdoc preparation and verification.

mod bindings;
mod prepared;
mod verification;

pub use prepared::MdocPreparedForHsm;
pub use verification::{
    DeviceResponse, MdocDocumentVerificationEvidence, MdocIssuerVerificationResult,
    MdocPresentationVerificationResult, MdocVerificationResult,
};

use pyo3::prelude::*;

/// Register mDoc functions and classes with Python module
pub(crate) fn register_mdoc_module(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    // Issuance
    parent.add_class::<MdocPreparedForHsm>()?;
    parent.add_function(wrap_pyfunction!(bindings::prepare_mdoc_for_hsm, parent)?)?;
    parent.add_function(wrap_pyfunction!(
        bindings::complete_mdoc_with_signature,
        parent
    )?)?;

    // Verification
    parent.add_class::<DeviceResponse>()?;
    parent.add_class::<MdocVerificationResult>()?;
    parent.add_class::<MdocIssuerVerificationResult>()?;
    parent.add_class::<MdocPresentationVerificationResult>()?;
    parent.add_class::<MdocDocumentVerificationEvidence>()?;
    parent.add_function(wrap_pyfunction!(
        verification::parse_device_response,
        parent
    )?)?;
    parent.add_function(wrap_pyfunction!(verification::verify_mdoc_cbor, parent)?)?;
    parent.add_function(wrap_pyfunction!(
        verification::verify_mdoc_signature,
        parent
    )?)?;
    parent.add_function(wrap_pyfunction!(verification::verify_mdoc_issuer, parent)?)?;
    parent.add_function(wrap_pyfunction!(
        verification::verify_mdoc_presentation,
        parent
    )?)?;

    Ok(())
}
