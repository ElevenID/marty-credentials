//! Unified error types for the Marty Rust library.
//!
//! This module provides structured error types with hierarchical error codes
//! that map to the same error taxonomy used in the Python API layer.
//!
//! # Error Codes
//!
//! Error codes follow a hierarchical format: `CATEGORY.SPECIFIC_ERROR`
//!
//! - `CRED.*` - Credential operations
//! - `KEY.*` - Key management
//! - `STATUS.*` - Status list operations
//! - `VAL.*` - Validation errors
//! - `CRYPTO.*` - Cryptographic operations
//!
//! # Debugging
//!
//! Set `RUST_BACKTRACE=1` to capture backtraces with errors.
//! The `debug_report()` method provides full diagnostic information including
//! backtraces and span traces.
//!
//! # Example
//!
//! ```rust
//! use _marty_rs::{MartyError, MartyResult};
//!
//! fn sign_credential(data: &[u8]) -> MartyResult<Vec<u8>> {
//!     // ... operation that might fail
//!     Err(MartyError::key_not_found("did:key:abc123"))
//! }
//! ```

#[cfg(feature = "python")]
use pyo3::exceptions::{PyIndexError, PyKeyError, PyRuntimeError, PyTypeError, PyValueError};
#[cfg(feature = "python")]
use pyo3::PyErr;
use std::fmt;
use thiserror::Error;
#[cfg(feature = "python")]
use tracing::{error, warn};
#[cfg(feature = "python")]
use tracing_error::SpanTrace;

/// Wrapper around std::backtrace::Backtrace to avoid thiserror's unstable feature detection.
#[derive(Debug)]
pub struct CapturedBacktrace(std::backtrace::Backtrace);

impl CapturedBacktrace {
    /// Capture a backtrace at the current location.
    pub fn capture() -> Self {
        Self(std::backtrace::Backtrace::capture())
    }

    /// Get the status of this backtrace.
    pub fn status(&self) -> std::backtrace::BacktraceStatus {
        self.0.status()
    }
}

impl fmt::Display for CapturedBacktrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Result type alias for Marty operations.
/// Use this when you want error type inference with MartyError.
pub type MartyResult<T> = std::result::Result<T, MartyError>;

/// Unified error type for all Marty Rust operations.
///
/// Each variant maps to a hierarchical error code and includes
/// relevant context for debugging. Errors automatically capture
/// backtraces (when RUST_BACKTRACE=1) and span traces.
#[derive(Error, Debug)]
pub enum MartyError {
    // =========================================================================
    // Credential Errors (CRED.*)
    // =========================================================================
    /// Failed to issue a credential.
    #[error("CRED.ISSUANCE_FAILED: Failed to issue credential: {reason}")]
    CredentialIssuanceFailed {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Failed to verify a credential.
    #[error("CRED.VERIFICATION_FAILED: Credential verification failed: {reason}")]
    CredentialVerificationFailed {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Credential has been revoked.
    #[error("CRED.REVOKED: Credential has been revoked: {credential_id}")]
    CredentialRevoked {
        credential_id: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Credential has expired.
    #[error("CRED.EXPIRED: Credential has expired: {credential_id}")]
    CredentialExpired {
        credential_id: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Invalid credential format.
    #[error("CRED.INVALID_FORMAT: Invalid credential format: {reason}")]
    CredentialInvalidFormat {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Credential serialization/deserialization error.
    #[error("CRED.SERIALIZATION_ERROR: Credential serialization error: {reason}")]
    CredentialSerializationError {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // Key Management Errors (KEY.*)
    // =========================================================================
    /// Key not found.
    #[error("KEY.NOT_FOUND: Key not found: {key_id}")]
    KeyNotFound {
        key_id: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Key generation failed.
    #[error("KEY.GENERATION_FAILED: Key generation failed: {reason}")]
    KeyGenerationFailed {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Invalid key format.
    #[error("KEY.INVALID_FORMAT: Invalid key format: {reason}")]
    KeyInvalidFormat {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Unsupported key algorithm.
    #[error("KEY.UNSUPPORTED_ALGORITHM: Unsupported key algorithm: {algorithm}")]
    KeyUnsupportedAlgorithm {
        algorithm: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Key import failed.
    #[error("KEY.IMPORT_FAILED: Key import failed: {reason}")]
    KeyImportFailed {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // Status List Errors (STATUS.*)
    // =========================================================================
    /// Status list index out of bounds.
    #[error("STATUS.INDEX_OUT_OF_BOUNDS: Index {index} out of range [0, {size})")]
    StatusIndexOutOfBounds {
        index: usize,
        size: usize,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Invalid status list format.
    #[error("STATUS.INVALID_FORMAT: Invalid status list format: {reason}")]
    StatusInvalidFormat {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Status list compression error.
    #[error("STATUS.COMPRESSION_ERROR: Status list compression error: {reason}")]
    StatusCompressionError {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Status list encoding error.
    #[error("STATUS.ENCODING_ERROR: Status list encoding error: {reason}")]
    StatusEncodingError {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // Validation Errors (VAL.*)
    // =========================================================================
    /// Required field is missing.
    #[error("VAL.REQUIRED_FIELD: Required field missing: {field}")]
    ValidationRequiredField {
        field: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Invalid field format.
    #[error("VAL.INVALID_FORMAT: Invalid format for field '{field}': {reason}")]
    ValidationInvalidFormat {
        field: String,
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Value out of allowed range.
    #[error("VAL.OUT_OF_RANGE: Value out of range for '{field}': {reason}")]
    ValidationOutOfRange {
        field: String,
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// General validation error.
    #[error("VAL.CONSTRAINT_VIOLATED: Validation constraint violated: {reason}")]
    ValidationConstraintViolated {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // Cryptographic Errors (CRYPTO.*)
    // =========================================================================
    /// Signature creation failed.
    #[error("CRYPTO.SIGNATURE_FAILED: Signature creation failed: {reason}")]
    CryptoSignatureFailed {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Signature verification failed.
    #[error("CRYPTO.VERIFICATION_FAILED: Signature verification failed: {reason}")]
    CryptoVerificationFailed {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Encryption failed.
    #[error("CRYPTO.ENCRYPTION_FAILED: Encryption failed: {reason}")]
    CryptoEncryptionFailed {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Decryption failed.
    #[error("CRYPTO.DECRYPTION_FAILED: Decryption failed: {reason}")]
    CryptoDecryptionFailed {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Hash computation failed.
    #[error("CRYPTO.HASH_FAILED: Hash computation failed: {reason}")]
    CryptoHashFailed {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // DID Errors (DID.*)
    // =========================================================================
    /// DID resolution failed.
    #[error("DID.RESOLUTION_FAILED: DID resolution failed for '{did}': {reason}")]
    DidResolutionFailed {
        did: String,
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Invalid DID format.
    #[error("DID.INVALID_FORMAT: Invalid DID format: {did}")]
    DidInvalidFormat {
        did: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Unsupported DID method.
    #[error("DID.UNSUPPORTED_METHOD: Unsupported DID method: {method}")]
    DidUnsupportedMethod {
        method: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // Internal Errors (SRV.*)
    // =========================================================================
    /// Internal error with context.
    #[error("SRV.INTERNAL_ERROR: Internal error: {reason}")]
    InternalError {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// External dependency error.
    #[error("SRV.EXTERNAL_SERVICE: External service error: {service}: {reason}")]
    ExternalServiceError {
        service: String,
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// I/O error.
    #[error("SRV.IO_ERROR: I/O error: {reason}")]
    IoError {
        reason: String,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },
}

impl MartyError {
    /// Get the hierarchical error code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            // Credential errors
            MartyError::CredentialIssuanceFailed { .. } => "CRED.ISSUANCE_FAILED",
            MartyError::CredentialVerificationFailed { .. } => "CRED.VERIFICATION_FAILED",
            MartyError::CredentialRevoked { .. } => "CRED.REVOKED",
            MartyError::CredentialExpired { .. } => "CRED.EXPIRED",
            MartyError::CredentialInvalidFormat { .. } => "CRED.INVALID_FORMAT",
            MartyError::CredentialSerializationError { .. } => "CRED.SERIALIZATION_ERROR",

            // Key errors
            MartyError::KeyNotFound { .. } => "KEY.NOT_FOUND",
            MartyError::KeyGenerationFailed { .. } => "KEY.GENERATION_FAILED",
            MartyError::KeyInvalidFormat { .. } => "KEY.INVALID_FORMAT",
            MartyError::KeyUnsupportedAlgorithm { .. } => "KEY.UNSUPPORTED_ALGORITHM",
            MartyError::KeyImportFailed { .. } => "KEY.IMPORT_FAILED",

            // Status list errors
            MartyError::StatusIndexOutOfBounds { .. } => "STATUS.INDEX_OUT_OF_BOUNDS",
            MartyError::StatusInvalidFormat { .. } => "STATUS.INVALID_FORMAT",
            MartyError::StatusCompressionError { .. } => "STATUS.COMPRESSION_ERROR",
            MartyError::StatusEncodingError { .. } => "STATUS.ENCODING_ERROR",

            // Validation errors
            MartyError::ValidationRequiredField { .. } => "VAL.REQUIRED_FIELD",
            MartyError::ValidationInvalidFormat { .. } => "VAL.INVALID_FORMAT",
            MartyError::ValidationOutOfRange { .. } => "VAL.OUT_OF_RANGE",
            MartyError::ValidationConstraintViolated { .. } => "VAL.CONSTRAINT_VIOLATED",

            // Crypto errors
            MartyError::CryptoSignatureFailed { .. } => "CRYPTO.SIGNATURE_FAILED",
            MartyError::CryptoVerificationFailed { .. } => "CRYPTO.VERIFICATION_FAILED",
            MartyError::CryptoEncryptionFailed { .. } => "CRYPTO.ENCRYPTION_FAILED",
            MartyError::CryptoDecryptionFailed { .. } => "CRYPTO.DECRYPTION_FAILED",
            MartyError::CryptoHashFailed { .. } => "CRYPTO.HASH_FAILED",

            // DID errors
            MartyError::DidResolutionFailed { .. } => "DID.RESOLUTION_FAILED",
            MartyError::DidInvalidFormat { .. } => "DID.INVALID_FORMAT",
            MartyError::DidUnsupportedMethod { .. } => "DID.UNSUPPORTED_METHOD",

            // Internal errors
            MartyError::InternalError { .. } => "SRV.INTERNAL_ERROR",
            MartyError::ExternalServiceError { .. } => "SRV.EXTERNAL_SERVICE",
            MartyError::IoError { .. } => "SRV.IO_ERROR",
        }
    }

    /// Check if this error is recoverable (client should retry).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            MartyError::ExternalServiceError { .. }
                | MartyError::IoError { .. }
                | MartyError::DidResolutionFailed { .. }
        )
    }

    /// Get a user-friendly message for this error.
    pub fn user_message(&self) -> &'static str {
        match self {
            // Credential errors
            MartyError::CredentialIssuanceFailed { .. } => {
                "Failed to create the credential. Please try again."
            }
            MartyError::CredentialVerificationFailed { .. } => {
                "The credential could not be verified."
            }
            MartyError::CredentialRevoked { .. } => "This credential has been revoked.",
            MartyError::CredentialExpired { .. } => "This credential has expired.",
            MartyError::CredentialInvalidFormat { .. } => "The credential format is invalid.",
            MartyError::CredentialSerializationError { .. } => {
                "Failed to process the credential data."
            }

            // Key errors
            MartyError::KeyNotFound { .. } => "The required cryptographic key was not found.",
            MartyError::KeyGenerationFailed { .. } => "Failed to generate a new key.",
            MartyError::KeyInvalidFormat { .. } => "The key format is invalid.",
            MartyError::KeyUnsupportedAlgorithm { .. } => "The key algorithm is not supported.",
            MartyError::KeyImportFailed { .. } => "Failed to import the key.",

            // Status list errors
            MartyError::StatusIndexOutOfBounds { .. } => "The status index is out of range.",
            MartyError::StatusInvalidFormat { .. } => "The status list format is invalid.",
            MartyError::StatusCompressionError { .. } => "Failed to process the status list data.",
            MartyError::StatusEncodingError { .. } => "Failed to encode the status list.",

            // Validation errors
            MartyError::ValidationRequiredField { .. } => "A required field is missing.",
            MartyError::ValidationInvalidFormat { .. } => "The input format is invalid.",
            MartyError::ValidationOutOfRange { .. } => "The value is outside the allowed range.",
            MartyError::ValidationConstraintViolated { .. } => {
                "The input does not meet the requirements."
            }

            // Crypto errors
            MartyError::CryptoSignatureFailed { .. } => "Failed to create a digital signature.",
            MartyError::CryptoVerificationFailed { .. } => "Signature verification failed.",
            MartyError::CryptoEncryptionFailed { .. } => "Failed to encrypt the data.",
            MartyError::CryptoDecryptionFailed { .. } => "Failed to decrypt the data.",
            MartyError::CryptoHashFailed { .. } => "Failed to compute the hash.",

            // DID errors
            MartyError::DidResolutionFailed { .. } => {
                "Failed to resolve the decentralized identifier."
            }
            MartyError::DidInvalidFormat { .. } => {
                "The decentralized identifier format is invalid."
            }
            MartyError::DidUnsupportedMethod { .. } => "The DID method is not supported.",

            // Internal errors
            MartyError::InternalError { .. } => "An unexpected error occurred. Please try again.",
            MartyError::ExternalServiceError { .. } => {
                "A dependent service is temporarily unavailable."
            }
            MartyError::IoError { .. } => "An I/O error occurred. Please try again.",
        }
    }

    /// Log this error with appropriate level and context.
    pub fn log(&self) {
        let code = self.code();
        let message = self.to_string();

        // Use different log levels based on error severity
        if code.starts_with("VAL.") {
            // Validation errors are expected, log at info/debug
            warn!(error_code = code, %message, "Validation error");
        } else if code.starts_with("SRV.") || code.starts_with("CRYPTO.") {
            // Internal and crypto errors are serious
            error!(error_code = code, %message, "Internal error");
        } else {
            // Other errors at warning level
            warn!(error_code = code, %message, "Operation error");
        }
    }

    /// Borrow both diagnostics from the same error variant.
    fn diagnostics(&self) -> (&CapturedBacktrace, &SpanTrace) {
        match self {
            MartyError::CredentialIssuanceFailed { bt, span_trace, .. }
            | MartyError::CredentialVerificationFailed { bt, span_trace, .. }
            | MartyError::CredentialRevoked { bt, span_trace, .. }
            | MartyError::CredentialExpired { bt, span_trace, .. }
            | MartyError::CredentialInvalidFormat { bt, span_trace, .. }
            | MartyError::CredentialSerializationError { bt, span_trace, .. }
            | MartyError::KeyNotFound { bt, span_trace, .. }
            | MartyError::KeyGenerationFailed { bt, span_trace, .. }
            | MartyError::KeyInvalidFormat { bt, span_trace, .. }
            | MartyError::KeyUnsupportedAlgorithm { bt, span_trace, .. }
            | MartyError::KeyImportFailed { bt, span_trace, .. }
            | MartyError::StatusIndexOutOfBounds { bt, span_trace, .. }
            | MartyError::StatusInvalidFormat { bt, span_trace, .. }
            | MartyError::StatusCompressionError { bt, span_trace, .. }
            | MartyError::StatusEncodingError { bt, span_trace, .. }
            | MartyError::ValidationRequiredField { bt, span_trace, .. }
            | MartyError::ValidationInvalidFormat { bt, span_trace, .. }
            | MartyError::ValidationOutOfRange { bt, span_trace, .. }
            | MartyError::ValidationConstraintViolated { bt, span_trace, .. }
            | MartyError::CryptoSignatureFailed { bt, span_trace, .. }
            | MartyError::CryptoVerificationFailed { bt, span_trace, .. }
            | MartyError::CryptoEncryptionFailed { bt, span_trace, .. }
            | MartyError::CryptoDecryptionFailed { bt, span_trace, .. }
            | MartyError::CryptoHashFailed { bt, span_trace, .. }
            | MartyError::DidResolutionFailed { bt, span_trace, .. }
            | MartyError::DidInvalidFormat { bt, span_trace, .. }
            | MartyError::DidUnsupportedMethod { bt, span_trace, .. }
            | MartyError::InternalError { bt, span_trace, .. }
            | MartyError::ExternalServiceError { bt, span_trace, .. }
            | MartyError::IoError { bt, span_trace, .. } => (bt, span_trace),
        }
    }

    /// Get the backtrace for this error (if captured).
    pub fn backtrace(&self) -> &CapturedBacktrace {
        self.diagnostics().0
    }

    /// Get the span trace for this error (if captured).
    pub fn span_trace(&self) -> &SpanTrace {
        self.diagnostics().1
    }

    /// Get a full debug report including backtrace and span trace.
    ///
    /// This is useful for developer debugging - it includes the full backtrace
    /// (when RUST_BACKTRACE=1 or RUST_BACKTRACE=full) and span trace context.
    pub fn debug_report(&self) -> String {
        let mut report = format!("Error: {}\n", self);
        report.push_str(&format!("Code: {}\n", self.code()));

        // Include span trace
        let span_trace = self.span_trace();
        if span_trace.status() == tracing_error::SpanTraceStatus::CAPTURED {
            report.push_str("\nSpan trace:\n");
            report.push_str(&format!("{}", span_trace));
        }

        // Include backtrace if captured
        let backtrace = self.backtrace();
        if backtrace.status() == std::backtrace::BacktraceStatus::Captured {
            report.push_str("\nBacktrace:\n");
            report.push_str(&format!("{}", backtrace));
        }

        report
    }

    // =========================================================================
    // Builder Functions
    // =========================================================================

    fn with_diagnostics(build: impl FnOnce(CapturedBacktrace, SpanTrace) -> Self) -> Self {
        build(CapturedBacktrace::capture(), SpanTrace::capture())
    }

    /// Create a credential issuance failed error.
    pub fn credential_issuance_failed(reason: impl Into<String>) -> Self {
        MartyError::with_diagnostics(|bt, span_trace| Self::CredentialIssuanceFailed {
            reason: reason.into(),
            bt,
            span_trace,
        })
    }

    /// Create a credential serialization error.
    pub fn serialization_error(reason: impl Into<String>) -> Self {
        MartyError::with_diagnostics(|bt, span_trace| Self::CredentialSerializationError {
            reason: reason.into(),
            bt,
            span_trace,
        })
    }

    /// Create a key not found error.
    pub fn key_not_found(key_id: impl Into<String>) -> Self {
        MartyError::with_diagnostics(|bt, span_trace| Self::KeyNotFound {
            key_id: key_id.into(),
            bt,
            span_trace,
        })
    }

    /// Create an internal error.
    pub fn internal(reason: impl Into<String>) -> Self {
        MartyError::with_diagnostics(|bt, span_trace| Self::InternalError {
            reason: reason.into(),
            bt,
            span_trace,
        })
    }

    /// Create a validation required field error.
    pub fn required_field(field: impl Into<String>) -> Self {
        MartyError::with_diagnostics(|bt, span_trace| Self::ValidationRequiredField {
            field: field.into(),
            bt,
            span_trace,
        })
    }

    /// Create a validation invalid format error.
    pub fn invalid_format(field: impl Into<String>, reason: impl Into<String>) -> Self {
        MartyError::with_diagnostics(|bt, span_trace| Self::ValidationInvalidFormat {
            field: field.into(),
            reason: reason.into(),
            bt,
            span_trace,
        })
    }

    /// Create a crypto signature failed error.
    pub fn signature_failed(reason: impl Into<String>) -> Self {
        MartyError::with_diagnostics(|bt, span_trace| Self::CryptoSignatureFailed {
            reason: reason.into(),
            bt,
            span_trace,
        })
    }
}

// =============================================================================
// PyO3 Conversions (only compiled with python feature)
// =============================================================================

#[cfg(feature = "python")]
impl From<MartyError> for PyErr {
    fn from(err: MartyError) -> PyErr {
        // Log the error before converting
        err.log();

        let code = err.code();

        // Build message with span trace for debugging
        let mut message = format!("[{}] {}", code, err);

        // Include span trace for debugging if captured
        let span_trace = err.span_trace();
        if span_trace.status() == tracing_error::SpanTraceStatus::CAPTURED {
            message.push_str("\n\nSpan trace:\n");
            message.push_str(&format!("{}", span_trace));
        }

        // Map to appropriate Python exception type
        match &err {
            // Index errors
            MartyError::StatusIndexOutOfBounds { .. } => PyIndexError::new_err(message),

            // Key/lookup errors
            MartyError::KeyNotFound { .. } => PyKeyError::new_err(message),

            // Validation errors -> ValueError
            MartyError::ValidationRequiredField { .. }
            | MartyError::ValidationInvalidFormat { .. }
            | MartyError::ValidationOutOfRange { .. }
            | MartyError::ValidationConstraintViolated { .. }
            | MartyError::CredentialInvalidFormat { .. }
            | MartyError::KeyInvalidFormat { .. }
            | MartyError::StatusInvalidFormat { .. }
            | MartyError::DidInvalidFormat { .. } => PyValueError::new_err(message),

            // Type errors
            MartyError::KeyUnsupportedAlgorithm { .. }
            | MartyError::DidUnsupportedMethod { .. } => PyTypeError::new_err(message),

            // Everything else -> RuntimeError
            _ => PyRuntimeError::new_err(message),
        }
    }
}

// =============================================================================
// Conversions from external errors
// =============================================================================

impl From<std::io::Error> for MartyError {
    fn from(err: std::io::Error) -> Self {
        MartyError::with_diagnostics(|bt, span_trace| MartyError::IoError {
            reason: err.to_string(),
            bt,
            span_trace,
        })
    }
}

impl From<serde_json::Error> for MartyError {
    fn from(err: serde_json::Error) -> Self {
        Self::serialization_error(err.to_string())
    }
}

impl From<base64::DecodeError> for MartyError {
    fn from(err: base64::DecodeError) -> Self {
        Self::invalid_format("base64", err.to_string())
    }
}

// =============================================================================
// Tracing initialization
// =============================================================================

/// Initialize tracing for the Rust library.
///
/// This should be called once during library initialization to enable
/// structured logging and span trace capture. If not called, log output
/// will be silently dropped and span traces will not be captured.
///
/// # Example
///
/// ```rust
/// use _marty_rs::init_tracing;
/// init_tracing();
/// ```
pub fn init_tracing() {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // Only initialize if not already initialized
    let _ = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with(fmt::layer().json())
        .with(ErrorLayer::default()) // Enable SpanTrace capture
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builders_and_conversions_preserve_error_contracts() {
        let cases = [
            (
                MartyError::credential_issuance_failed("reason"),
                "CRED.ISSUANCE_FAILED",
                false,
            ),
            (
                MartyError::serialization_error("reason"),
                "CRED.SERIALIZATION_ERROR",
                false,
            ),
            (MartyError::key_not_found("reason"), "KEY.NOT_FOUND", false),
            (MartyError::internal("reason"), "SRV.INTERNAL_ERROR", false),
            (
                MartyError::required_field("reason"),
                "VAL.REQUIRED_FIELD",
                false,
            ),
            (
                MartyError::invalid_format("field", "reason"),
                "VAL.INVALID_FORMAT",
                false,
            ),
            (
                MartyError::signature_failed("reason"),
                "CRYPTO.SIGNATURE_FAILED",
                false,
            ),
            (
                MartyError::from(std::io::Error::other("reason")),
                "SRV.IO_ERROR",
                true,
            ),
        ];
        for (error, code, retryable) in cases {
            assert_eq!(error.code(), code);
            assert_eq!(error.is_retryable(), retryable);
            assert!(error.to_string().contains("reason"));
            assert!(!error.user_message().is_empty());
            assert!(error.debug_report().contains(&format!("Code: {code}")));
        }
        let json_error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let message = json_error.to_string();
        let error = MartyError::from(json_error);
        assert_eq!(error.code(), "CRED.SERIALIZATION_ERROR");
        assert!(error.to_string().contains(&message));
        let error = MartyError::from(base64::DecodeError::InvalidLength(1));
        assert_eq!(error.code(), "VAL.INVALID_FORMAT");
        assert!(error.to_string().contains("base64"));
    }

    #[test]
    fn diagnostic_accessors_borrow_the_original_public_fields() {
        let error = MartyError::internal("reason");
        let MartyError::InternalError { bt, span_trace, .. } = &error else {
            unreachable!()
        };
        assert!(std::ptr::eq(error.backtrace(), bt));
        assert!(std::ptr::eq(error.span_trace(), span_trace));
    }

    #[test]
    fn python_exception_types_and_codes_remain_stable() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cases = [
                (
                    MartyError::key_not_found("key"),
                    "KeyError",
                    "KEY.NOT_FOUND",
                ),
                (
                    MartyError::invalid_format("field", "reason"),
                    "ValueError",
                    "VAL.INVALID_FORMAT",
                ),
                (
                    MartyError::internal("reason"),
                    "RuntimeError",
                    "SRV.INTERNAL_ERROR",
                ),
            ];
            for (error, exception, code) in cases {
                let error: PyErr = error.into();
                use pyo3::types::{PyStringMethods, PyTypeMethods};
                assert_eq!(
                    error.get_type(py).name().unwrap().to_str().unwrap(),
                    exception
                );
                assert!(error.to_string().contains(&format!("[{code}]")));
            }
        });
    }

    #[test]
    fn test_error_codes() {
        let err = MartyError::key_not_found("test");
        assert_eq!(err.code(), "KEY.NOT_FOUND");
    }

    #[test]
    fn test_error_message() {
        let err = MartyError::StatusIndexOutOfBounds {
            index: 10,
            size: 5,
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        };
        assert!(err.to_string().contains("10"));
        assert!(err.to_string().contains("5"));
    }

    #[test]
    fn test_retryable() {
        let retryable = MartyError::ExternalServiceError {
            service: "test".to_string(),
            reason: "timeout".to_string(),
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        };
        assert!(retryable.is_retryable());

        let not_retryable = MartyError::required_field("name");
        assert!(!not_retryable.is_retryable());
    }

    #[test]
    fn test_builder_functions() {
        let err = MartyError::credential_issuance_failed("test failure");
        assert_eq!(err.code(), "CRED.ISSUANCE_FAILED");
        assert!(err.to_string().contains("test failure"));

        let err = MartyError::internal("internal issue");
        assert_eq!(err.code(), "SRV.INTERNAL_ERROR");

        let err = MartyError::serialization_error("JSON parse error");
        assert_eq!(err.code(), "CRED.SERIALIZATION_ERROR");
    }

    #[test]
    fn test_debug_report() {
        let err = MartyError::internal("test error");
        let report = err.debug_report();
        assert!(report.contains("Error:"));
        assert!(report.contains("Code: SRV.INTERNAL_ERROR"));
    }
}
