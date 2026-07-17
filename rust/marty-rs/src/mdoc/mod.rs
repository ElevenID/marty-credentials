// mDoc (ISO 18013-5) issuance implementation using isomdl crate
//
// This module provides Python bindings for creating mobile driver's licenses
// and other mDoc credentials according to ISO 18013-5 standard.
//
// Module structure:
// - types: Core data structures (ValidityInfo, etc.)
// - builder: MdocBuilder for constructing credentials
// - document: MdocSignedDocument and MdocPreparedForHsm
// - helpers: Utility functions for CBOR, signing, etc.
// - bindings: Python function bindings
// - verification: mDoc verification and parsing

mod bindings;
mod builder;
mod document;
mod helpers;
mod types;
mod verification;

pub use builder::MdocBuilder;
pub use document::{MdocPreparedForHsm, MdocSignedDocument};
pub use verification::{DeviceResponse, MdocVerificationResult};

use pyo3::prelude::*;

/// Register mDoc functions and classes with Python module
pub(crate) fn register_mdoc_module(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    // Issuance
    parent.add_class::<MdocBuilder>()?;
    parent.add_class::<MdocSignedDocument>()?;
    parent.add_class::<MdocPreparedForHsm>()?;
    parent.add_function(wrap_pyfunction!(bindings::create_mdoc, parent)?)?;
    parent.add_function(wrap_pyfunction!(bindings::prepare_mdoc_for_hsm, parent)?)?;
    parent.add_function(wrap_pyfunction!(
        bindings::complete_mdoc_with_signature,
        parent
    )?)?;

    // Verification
    parent.add_class::<DeviceResponse>()?;
    parent.add_class::<MdocVerificationResult>()?;
    parent.add_function(wrap_pyfunction!(
        verification::parse_device_response,
        parent
    )?)?;
    parent.add_function(wrap_pyfunction!(verification::verify_mdoc_cbor, parent)?)?;
    parent.add_function(wrap_pyfunction!(
        verification::verify_mdoc_signature,
        parent
    )?)?;

    Ok(())
}
