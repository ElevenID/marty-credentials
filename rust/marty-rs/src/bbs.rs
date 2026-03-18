// BBS+ signature Python bindings
//
// Exposes BBS+ key generation, signing, verification, and selective
// disclosure proof operations from marty-crypto to Python via PyO3.

use pyo3::prelude::*;

/// Generate a BLS12-381 key pair for BBS+ signatures.
///
/// Returns (secret_key_bytes, public_key_bytes) where public key is 96 bytes
/// (BLS12-381 G2 compressed point).
///
/// Args:
///     ciphersuite: "BBS_BLS12381_SHA256" or "BBS_BLS12381_SHAKE256" (default)
#[pyfunction]
#[pyo3(signature = (ciphersuite="BBS_BLS12381_SHAKE256"))]
pub fn generate_bls12381_key(ciphersuite: &str) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let cs = marty_crypto::bbs::BbsCiphersuite::from_algorithm_name(ciphersuite)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let kp = marty_crypto::bbs::BbsKeyPair::generate(cs)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    Ok((kp.secret_key().to_vec(), kp.public_key().to_vec()))
}

/// Sign multiple messages with BBS+.
///
/// Args:
///     secret_key: Secret key bytes
///     public_key: Public key bytes (96 bytes)
///     messages: List of byte strings to sign
///     header: Header bytes for domain separation
///     ciphersuite: "BBS_BLS12381_SHA256" or "BBS_BLS12381_SHAKE256"
///
/// Returns: Signature bytes (80 bytes)
#[pyfunction]
#[pyo3(signature = (secret_key, public_key, messages, header, ciphersuite="BBS_BLS12381_SHAKE256"))]
pub fn bbs_sign(
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    messages: Vec<Vec<u8>>,
    header: Vec<u8>,
    ciphersuite: &str,
) -> PyResult<Vec<u8>> {
    let cs = marty_crypto::bbs::BbsCiphersuite::from_algorithm_name(ciphersuite)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    marty_crypto::bbs::bbs_sign(&secret_key, &public_key, &messages, &header, cs)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Verify a BBS+ signature over multiple messages.
///
/// Args:
///     public_key: Public key bytes (96 bytes)
///     messages: List of all signed messages
///     header: Header bytes used during signing
///     signature: Signature bytes (80 bytes)
///     ciphersuite: "BBS_BLS12381_SHA256" or "BBS_BLS12381_SHAKE256"
///
/// Returns: True if valid
/// Raises: RuntimeError if verification fails
#[pyfunction]
#[pyo3(signature = (public_key, messages, header, signature, ciphersuite="BBS_BLS12381_SHAKE256"))]
pub fn bbs_verify(
    public_key: Vec<u8>,
    messages: Vec<Vec<u8>>,
    header: Vec<u8>,
    signature: Vec<u8>,
    ciphersuite: &str,
) -> PyResult<bool> {
    let cs = marty_crypto::bbs::BbsCiphersuite::from_algorithm_name(ciphersuite)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    marty_crypto::bbs::bbs_verify(&public_key, &messages, &header, &signature, cs)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    Ok(true)
}

/// Create a selective disclosure proof from a BBS+ signature.
///
/// The holder uses this to reveal only selected messages to a verifier
/// while proving possession of a valid signature over all messages.
///
/// Args:
///     public_key: Issuer's public key bytes
///     signature: Original BBS+ signature
///     messages: All signed messages (in original order)
///     disclosed_indices: List of 0-based indices of messages to reveal
///     header: Header bytes used during signing
///     presentation_header: Fresh nonce from verifier for replay protection
///     ciphersuite: "BBS_BLS12381_SHA256" or "BBS_BLS12381_SHAKE256"
///
/// Returns: Proof bytes (variable length)
#[pyfunction]
#[pyo3(signature = (public_key, signature, messages, disclosed_indices, header, presentation_header, ciphersuite="BBS_BLS12381_SHAKE256"))]
pub fn bbs_create_proof(
    public_key: Vec<u8>,
    signature: Vec<u8>,
    messages: Vec<Vec<u8>>,
    disclosed_indices: Vec<usize>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    ciphersuite: &str,
) -> PyResult<Vec<u8>> {
    let cs = marty_crypto::bbs::BbsCiphersuite::from_algorithm_name(ciphersuite)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    marty_crypto::bbs::bbs_create_proof(
        &public_key,
        &signature,
        &messages,
        &disclosed_indices,
        &header,
        &presentation_header,
        cs,
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Verify a BBS+ selective disclosure proof.
///
/// The verifier uses this to confirm that disclosed messages are authentic
/// without seeing the hidden messages or the original signature.
///
/// Args:
///     public_key: Issuer's public key bytes
///     proof: Proof bytes from bbs_create_proof
///     disclosed_indices: List of 0-based indices of disclosed messages
///     disclosed_messages: List of disclosed message bytes (same order as indices)
///     header: Header bytes used during signing
///     presentation_header: Same nonce used in proof creation
///     ciphersuite: "BBS_BLS12381_SHA256" or "BBS_BLS12381_SHAKE256"
///
/// Returns: True if valid
/// Raises: RuntimeError if verification fails
#[pyfunction]
#[pyo3(signature = (public_key, proof, disclosed_indices, disclosed_messages, header, presentation_header, ciphersuite="BBS_BLS12381_SHAKE256"))]
pub fn bbs_verify_proof(
    public_key: Vec<u8>,
    proof: Vec<u8>,
    disclosed_indices: Vec<usize>,
    disclosed_messages: Vec<Vec<u8>>,
    header: Vec<u8>,
    presentation_header: Vec<u8>,
    ciphersuite: &str,
) -> PyResult<bool> {
    let cs = marty_crypto::bbs::BbsCiphersuite::from_algorithm_name(ciphersuite)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let pk = marty_crypto::bbs::BbsVerifyingKey::from_bytes(&public_key, cs)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    pk.verify_proof(
        &proof,
        &disclosed_messages,
        &disclosed_indices,
        &header,
        &presentation_header,
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    Ok(true)
}

/// Register BBS+ functions into the Python module.
pub fn register_bbs_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_bls12381_key, m)?)?;
    m.add_function(wrap_pyfunction!(bbs_sign, m)?)?;
    m.add_function(wrap_pyfunction!(bbs_verify, m)?)?;
    m.add_function(wrap_pyfunction!(bbs_create_proof, m)?)?;
    m.add_function(wrap_pyfunction!(bbs_verify_proof, m)?)?;
    Ok(())
}
