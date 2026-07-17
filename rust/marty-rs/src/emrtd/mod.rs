//! eMRTD issuance module — ICAO 9303-compliant passport credential issuance.
//!
//! ## Structure
//!
//! | Sub-module    | Purpose                                             |
//! |---------------|-----------------------------------------------------|
//! | [`types`]     | `EmrtdIssuanceRequest`, `EmrtdCredential`, etc.     |
//! | [`builder`]   | Fluent `EmrtdPassportBuilder` for requests          |
//! | [`issuance`]  | `issue_emrtd_passport`, `issue_emrtd_passport_self_signed` |
//! | [`bindings`]  | PyO3 `#[pyfunction]` wrappers                       |

pub mod builder;
pub mod issuance;
pub mod types;

#[cfg(feature = "python")]
pub mod bindings;

pub use builder::EmrtdPassportBuilder;
pub use issuance::{issue_emrtd_passport, issue_emrtd_passport_self_signed};
pub use types::{EmrtdCredential, EmrtdDataGroup, EmrtdIssuanceRequest};

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Register all eMRTD classes and functions onto the parent Python module.
#[cfg(feature = "python")]
pub(crate) fn register_emrtd_module(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    // Issuance functions
    parent.add_function(wrap_pyfunction!(bindings::issue_emrtd_passport, parent)?)?;
    parent.add_function(wrap_pyfunction!(
        bindings::issue_emrtd_passport_self_signed,
        parent
    )?)?;

    Ok(())
}
