//! mDoc (Mobile Document) credential module.
//!
//! Provides comprehensive mDoc/mDL issuance and presentation functionality
//! with support for both local signing and remote/HSM signing workflows.
//!
//! ## Modules
//!
//! - [`types`]: PyO3-compatible wrapper types for mDoc operations
//! - [`issuance`]: Credential issuance and signing functions
//! - [`presentation`]: Selective disclosure and DeviceResponse creation
//!
//! ## Features
//!
//! - **Full mDoc/mDL Issuance**: Create ISO 18013-5 compliant mobile documents
//! - **HSM/Remote Signing**: Prepare-then-sign workflow for external key management
//! - **Selective Disclosure**: Create DeviceResponse with chosen claims
//! - **Python Bindings**: All types and functions exposed via PyO3
//!
//! ## Example Usage
//!
//! ### Local Signing
//! ```python
//! from marty_rs import (
//!     MdocIssuanceRequest,
//!     MdocValidityInfo,
//!     MdocDeviceKeyInfo,
//!     create_mdoc_credential,
//! )
//!
//! # Create issuance request
//! request = MdocIssuanceRequest.mdl({
//!     "org.iso.18013.5.1": {
//!         "family_name": "Doe",
//!         "given_name": "John",
//!         "birth_date": "1990-01-15",
//!     }
//! })
//!
//! # Set validity and device key
//! request.validity = MdocValidityInfo.years_from_now(5)
//! request.device_key = MdocDeviceKeyInfo.from_jwk(holder_jwk)
//!
//! # Issue the credential
//! credential = create_mdoc_credential(
//!     request,
//!     issuer_cert_pem,
//!     issuer_key_pem,
//! )
//! ```
//!
//! ### HSM/Remote Signing
//! ```python
//! from marty_rs import prepare_mdoc_for_signing, complete_mdoc_with_signature
//!
//! # Prepare for signing (no key needed)
//! prepared = prepare_mdoc_for_signing(request)
//!
//! # Send signature payload to HSM
//! signature = hsm_client.sign(prepared.signature_payload_base64)
//!
//! # Complete with signature
//! credential = complete_mdoc_with_signature(
//!     prepared,
//!     signature,
//!     issuer_cert_pem,
//! )
//! ```

pub mod issuance;
pub mod presentation;
pub mod types;

pub use issuance::*;
pub use presentation::*;
pub use types::*;

use pyo3::prelude::*;

/// Register all mDoc types and functions with Python module.
pub fn register_mdoc_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register types
    types::register_mdoc_types(m)?;

    // Register issuance functions
    issuance::register_issuance_functions(m)?;

    // Register presentation functions
    presentation::register_presentation_functions(m)?;

    Ok(())
}
