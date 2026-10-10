// Error module (only for python - has tracing dependencies)
#[cfg(feature = "python")]
mod error;

// Status list module (only for python - has PyO3 dependencies)
#[cfg(feature = "python")]
mod status_list;

// Thin local parity binding over the exact pinned Core decision builder.
#[cfg(feature = "python")]
mod canonical_verification;

// mDoc issuance and presentation module (only for python)
#[cfg(feature = "python")]
pub mod mdoc;

// SD-JWT module (only for python - has PyO3 and sd-jwt-rs dependencies)
#[cfg(feature = "python")]
mod sd_jwt;

// OID4VCI/OID4VP protocol engine bindings (only for python)
#[cfg(feature = "python")]
mod oid4vci;

// BBS+ signature bindings (only for python)
#[cfg(feature = "python")]
mod bbs;

// WASM module (only compiled with wasm feature)
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "python")]
pub use error::{init_tracing, MartyError, MartyResult};

// Re-export marty-verification types for Rust consumers (only when python feature enabled)
#[cfg(feature = "python")]
pub use marty_verification::{
    AuthStatus, ChainStatus, CscaRegistry, EmrtdVerificationResult, HashStatus, IacaRegistry,
    Jurisdiction, MdlVerificationResult, SignatureStatus, TrustAnchor, TrustPurpose, TrustRegistry,
};

// =============================================================================
// Python bindings (only compiled with python feature)
// =============================================================================

#[cfg(feature = "python")]
mod python_bindings {
    use pyo3::prelude::*;

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    pub fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
        Ok((a + b).to_string())
    }

    /// Returns the version of the SSI library being used.
    #[pyfunction]
    pub fn get_ssi_version() -> PyResult<String> {
        Ok("0.12.0".to_string())
    }

    /// Checks if isomdl is linked.
    #[pyfunction]
    pub fn check_isomdl() -> PyResult<String> {
        let _ = isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry::default();
        Ok("isomdl is linked".to_string())
    }

    /// Prepare a VCDM v2 EdDSA Data Integrity credential for issuer-DID signing.
    #[pyfunction]
    pub fn prepare_vcdm_data_integrity_credential(request_json: &str) -> PyResult<String> {
        marty_verification::vcdm::prepare_vcdm_data_integrity_credential_json(request_json)
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    }

    /// Complete and independently verify a remotely signed Data Integrity credential.
    #[pyfunction]
    pub fn complete_vcdm_data_integrity_credential(request_json: &str) -> PyResult<String> {
        marty_verification::vcdm::complete_vcdm_data_integrity_credential_json(request_json)
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    }

    /// Verify a compact W3C VCDM v2 VC-JWT with public issuer material.
    ///
    /// Keep this compatibility binding as a thin adapter over the pinned Core
    /// implementation so Python consumers cannot diverge from the canonical
    /// Rust verification decision or expose unauthenticated claims.
    #[pyfunction]
    pub fn verify_vcdm_jwt(request_json: &str) -> String {
        marty_verification::vcdm::verify_vcdm_jwt_json(request_json)
    }

    /// Select issuer-bound disclosures for an unbound SD-JWT presentation.
    ///
    /// Nonce or audience binding requires a holder-key-aware OID4VP flow and
    /// therefore fails closed at this retained compatibility boundary.
    #[pyfunction]
    #[pyo3(signature = (sd_jwt_compact, disclosed_fields, nonce=None, audience=None))]
    pub fn sd_jwt_create_presentation(
        sd_jwt_compact: &str,
        disclosed_fields: Vec<String>,
        nonce: Option<&str>,
        audience: Option<&str>,
    ) -> PyResult<String> {
        if nonce.is_some() || audience.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "SD-JWT nonce or audience binding requires a holder-key-aware OID4VP flow",
            ));
        }
        marty_oid4vci::formats::sd_jwt::create_sd_jwt_presentation(
            sd_jwt_compact,
            &disclosed_fields,
        )
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pymodule]
    pub fn _marty_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
        // Initialize tracing for structured logging
        crate::init_tracing();

        m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
        m.add_function(wrap_pyfunction!(get_ssi_version, m)?)?;
        m.add_function(wrap_pyfunction!(check_isomdl, m)?)?;
        m.add_function(wrap_pyfunction!(prepare_vcdm_data_integrity_credential, m)?)?;
        m.add_function(wrap_pyfunction!(
            complete_vcdm_data_integrity_credential,
            m
        )?)?;
        m.add_function(wrap_pyfunction!(verify_vcdm_jwt, m)?)?;
        m.add_function(wrap_pyfunction!(sd_jwt_create_presentation, m)?)?;
        crate::canonical_verification::register(m)?;

        // Status list classes and functions for credential revocation
        crate::status_list::register_status_list_module(m)?;

        // mDoc classes and functions for ISO 18013-5 mobile driver's license
        crate::mdoc::register_mdoc_module(m)?;

        // SD-JWT classes and functions for Selective Disclosure JWT
        crate::sd_jwt::register_sd_jwt_module(m)?;

        // OID4VCI/OID4VP protocol engine (from marty-oid4vci)
        crate::oid4vci::register_oid4vci_module(m)?;

        // BBS+ signatures (from marty-crypto)
        crate::bbs::register_bbs_module(m)?;

        // Note: marty-verification functions are now available in the separate
        // marty-verification-py package. Install both packages to access all functionality.

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn production_module_excludes_private_key_operations() {
            Python::initialize();
            Python::attach(|py| {
                let module = PyModule::new(py, "_marty_rs").unwrap();
                _marty_rs(&module).unwrap();

                for private_operation in [
                    "generate_did_key",
                    "generate_p256_key",
                    "generate_p256_jwk",
                    "generate_p384_key",
                    "generate_rsa_key",
                    "create_presentation",
                    "create_verifiable_credential",
                    "create_mdoc",
                    "SdJwtBuilder",
                    "SdJwtPresentation",
                    "create_sd_jwt",
                    "generate_bls12381_key",
                    "bbs_sign",
                    "issue_emrtd_passport",
                    "issue_emrtd_passport_self_signed",
                ] {
                    assert!(
                        !module.hasattr(private_operation).unwrap(),
                        "{private_operation}"
                    );
                }

                for public_operation in [
                    "prepare_mdoc_for_hsm",
                    "complete_mdoc_with_signature",
                    "SdJwtVerifier",
                    "verify_sd_jwt",
                    "bbs_verify",
                ] {
                    assert!(
                        module.hasattr(public_operation).unwrap(),
                        "{public_operation}"
                    );
                }
            });
        }
    }
} // End of python_bindings module

// Re-export Python module when python feature is enabled
#[cfg(feature = "python")]
pub use python_bindings::_marty_rs;
