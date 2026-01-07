//! Status List implementations for credential revocation.
//!
//! This module provides Rust implementations for:
//! - IETF Token Status List (for mDoc/CWT credentials)
//! - W3C Bitstring Status List v1.0 (for SD-JWT VC credentials)
//!
//! Both implementations are exposed to Python via PyO3 bindings.

use base64::Engine;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use pyo3::prelude::*;
use std::io::{Read, Write};

/// Token Status List implementation per IETF draft-ietf-oauth-status-list-14.
///
/// This format uses 1-8 bits per status entry, supporting values 0-255.
/// The list is compressed using DEFLATE and can be embedded in JWT/CWT.
///
/// Status values:
/// - 0: VALID
/// - 1: INVALID (revoked)
/// - 2-255: Application-specific
#[pyclass]
pub struct TokenStatusList {
    /// Bits per status entry (1, 2, 4, or 8)
    bits: u8,
    /// Raw status data
    data: Vec<u8>,
    /// Number of entries in the list
    size: usize,
}

#[pymethods]
impl TokenStatusList {
    /// Create a new Token Status List.
    ///
    /// # Arguments
    /// * `size` - Number of entries in the list
    /// * `bits` - Bits per status (1, 2, 4, or 8)
    ///
    /// # Returns
    /// A new TokenStatusList with all entries set to 0 (valid)
    #[new]
    #[pyo3(signature = (size, bits=8))]
    pub fn new(size: usize, bits: u8) -> PyResult<Self> {
        if ![1, 2, 4, 8].contains(&bits) {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "bits must be 1, 2, 4, or 8",
            ));
        }

        // Calculate byte size based on bits per entry
        let entries_per_byte = 8 / bits as usize;
        let byte_size = (size + entries_per_byte - 1) / entries_per_byte;

        Ok(Self {
            bits,
            data: vec![0u8; byte_size],
            size,
        })
    }

    /// Get the status at a specific index.
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    ///
    /// # Returns
    /// Status value (0-255 depending on bits)
    pub fn get(&self, index: usize) -> PyResult<u8> {
        if index >= self.size {
            return Err(PyErr::new::<pyo3::exceptions::PyIndexError, _>(format!(
                "Index {} out of range [0, {})",
                index, self.size
            )));
        }

        let entries_per_byte = 8 / self.bits as usize;
        let byte_index = index / entries_per_byte;
        let bit_offset = (index % entries_per_byte) * self.bits as usize;
        let mask = (1u8 << self.bits) - 1;

        let value = (self.data[byte_index] >> (8 - self.bits as usize - bit_offset)) & mask;
        Ok(value)
    }

    /// Set the status at a specific index.
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    /// * `status` - Status value to set
    pub fn set(&mut self, index: usize, status: u8) -> PyResult<()> {
        if index >= self.size {
            return Err(PyErr::new::<pyo3::exceptions::PyIndexError, _>(format!(
                "Index {} out of range [0, {})",
                index, self.size
            )));
        }

        let max_value = (1u16 << self.bits) - 1;
        if status as u16 > max_value {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Status {} out of range [0, {}] for {}-bit status",
                status, max_value, self.bits
            )));
        }

        let entries_per_byte = 8 / self.bits as usize;
        let byte_index = index / entries_per_byte;
        let bit_offset = (index % entries_per_byte) * self.bits as usize;
        let mask = (1u8 << self.bits) - 1;

        // Clear existing bits
        self.data[byte_index] &= !(mask << (8 - self.bits as usize - bit_offset));
        // Set new bits
        self.data[byte_index] |= status << (8 - self.bits as usize - bit_offset);

        Ok(())
    }

    /// Check if a credential is revoked (status != 0).
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    ///
    /// # Returns
    /// True if revoked (status != 0)
    pub fn is_revoked(&self, index: usize) -> PyResult<bool> {
        let status = self.get(index)?;
        Ok(status != 0)
    }

    /// Revoke a credential (set status to 1).
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    pub fn revoke(&mut self, index: usize) -> PyResult<()> {
        self.set(index, 1)
    }

    /// Reinstate a credential (set status to 0).
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    pub fn reinstate(&mut self, index: usize) -> PyResult<()> {
        self.set(index, 0)
    }

    /// Get the number of entries in the list.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Check if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Get the bits per status entry.
    pub fn bits_per_status(&self) -> u8 {
        self.bits
    }

    /// Compress the status list using DEFLATE.
    ///
    /// # Returns
    /// Compressed bytes
    pub fn compress(&self) -> PyResult<Vec<u8>> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&self.data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    /// Encode as base64url string (for JWT embedding).
    ///
    /// # Returns
    /// Base64url encoded compressed data
    pub fn to_base64url(&self) -> PyResult<String> {
        let compressed = self.compress()?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed))
    }

    /// Create from compressed data.
    ///
    /// # Arguments
    /// * `data` - DEFLATE compressed status list data
    /// * `size` - Number of entries
    /// * `bits` - Bits per status
    #[staticmethod]
    #[pyo3(signature = (data, size, bits=8))]
    pub fn from_compressed(data: Vec<u8>, size: usize, bits: u8) -> PyResult<Self> {
        let mut decoder = DeflateDecoder::new(&data[..]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

        Ok(Self {
            bits,
            data: decompressed,
            size,
        })
    }

    /// Create from base64url encoded string.
    ///
    /// # Arguments
    /// * `encoded` - Base64url encoded compressed data
    /// * `size` - Number of entries
    /// * `bits` - Bits per status
    #[staticmethod]
    #[pyo3(signature = (encoded, size, bits=8))]
    pub fn from_base64url(encoded: &str, size: usize, bits: u8) -> PyResult<Self> {
        let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Self::from_compressed(compressed, size, bits)
    }

    /// Get raw data bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// Bitstring Status List implementation per W3C Bitstring Status List v1.0.
///
/// This format uses 1 bit per status entry (revoked/not revoked).
/// The list is compressed using GZIP and base64url encoded.
///
/// Status values:
/// - 0 (false): Not revoked
/// - 1 (true): Revoked
#[pyclass]
pub struct BitstringStatusList {
    /// Raw bitstring data
    data: Vec<u8>,
    /// Number of entries (bits) in the list
    size: usize,
}

#[pymethods]
impl BitstringStatusList {
    /// Create a new Bitstring Status List.
    ///
    /// # Arguments
    /// * `size` - Number of entries (bits) in the list
    ///
    /// # Returns
    /// A new BitstringStatusList with all entries set to 0 (not revoked)
    #[new]
    pub fn new(size: usize) -> Self {
        let byte_size = (size + 7) / 8;
        Self {
            data: vec![0u8; byte_size],
            size,
        }
    }

    /// Get the status at a specific index.
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    ///
    /// # Returns
    /// True if revoked, False if not revoked
    pub fn get(&self, index: usize) -> PyResult<bool> {
        if index >= self.size {
            return Err(PyErr::new::<pyo3::exceptions::PyIndexError, _>(format!(
                "Index {} out of range [0, {})",
                index, self.size
            )));
        }

        let byte_index = index / 8;
        let bit_index = 7 - (index % 8); // MSB first per W3C spec
        let value = (self.data[byte_index] >> bit_index) & 1;
        Ok(value == 1)
    }

    /// Set the status at a specific index.
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    /// * `revoked` - True to revoke, False to reinstate
    pub fn set(&mut self, index: usize, revoked: bool) -> PyResult<()> {
        if index >= self.size {
            return Err(PyErr::new::<pyo3::exceptions::PyIndexError, _>(format!(
                "Index {} out of range [0, {})",
                index, self.size
            )));
        }

        let byte_index = index / 8;
        let bit_index = 7 - (index % 8); // MSB first per W3C spec

        if revoked {
            self.data[byte_index] |= 1 << bit_index;
        } else {
            self.data[byte_index] &= !(1 << bit_index);
        }

        Ok(())
    }

    /// Check if a credential is revoked.
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    ///
    /// # Returns
    /// True if revoked
    pub fn is_revoked(&self, index: usize) -> PyResult<bool> {
        self.get(index)
    }

    /// Revoke a credential.
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    pub fn revoke(&mut self, index: usize) -> PyResult<()> {
        self.set(index, true)
    }

    /// Reinstate a credential.
    ///
    /// # Arguments
    /// * `index` - Index in the status list
    pub fn reinstate(&mut self, index: usize) -> PyResult<()> {
        self.set(index, false)
    }

    /// Get the number of entries in the list.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Check if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Compress the status list using GZIP.
    ///
    /// # Returns
    /// Compressed bytes
    pub fn compress(&self) -> PyResult<Vec<u8>> {
        use flate2::write::GzEncoder;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&self.data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    /// Encode as base64url string (for VC embedding).
    ///
    /// Per W3C spec: GZIP compress, then base64url encode.
    ///
    /// # Returns
    /// Base64url encoded compressed data
    pub fn to_base64url(&self) -> PyResult<String> {
        let compressed = self.compress()?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed))
    }

    /// Create from compressed data.
    ///
    /// # Arguments
    /// * `data` - GZIP compressed status list data
    /// * `size` - Number of entries (bits)
    #[staticmethod]
    pub fn from_compressed(data: Vec<u8>, size: usize) -> PyResult<Self> {
        use flate2::read::GzDecoder;
        let mut decoder = GzDecoder::new(&data[..]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

        Ok(Self {
            data: decompressed,
            size,
        })
    }

    /// Create from base64url encoded string.
    ///
    /// # Arguments
    /// * `encoded` - Base64url encoded GZIP compressed data
    /// * `size` - Number of entries (bits)
    #[staticmethod]
    pub fn from_base64url(encoded: &str, size: usize) -> PyResult<Self> {
        let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Self::from_compressed(compressed, size)
    }

    /// Get raw data bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Count the number of revoked credentials.
    pub fn count_revoked(&self) -> usize {
        let mut count = 0;
        for i in 0..self.size {
            if let Ok(true) = self.get(i) {
                count += 1;
            }
        }
        count
    }
}

/// Create a status list token claim for JWT/CWT embedding.
///
/// Per IETF draft-ietf-oauth-status-list-14.
///
/// # Arguments
/// * `status_list` - The TokenStatusList to encode
///
/// # Returns
/// JSON string for the status_list claim
#[pyfunction]
pub fn create_status_list_claim(status_list: &TokenStatusList) -> PyResult<String> {
    let encoded = status_list.to_base64url()?;
    let claim = serde_json::json!({
        "bits": status_list.bits_per_status(),
        "lst": encoded
    });
    serde_json::to_string(&claim)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Create a BitstringStatusListCredential subject for VC embedding.
///
/// Per W3C Bitstring Status List v1.0.
///
/// # Arguments
/// * `status_list` - The BitstringStatusList to encode
/// * `id` - Status list credential subject ID
/// * `status_purpose` - Purpose (e.g., "revocation", "suspension")
///
/// # Returns
/// JSON string for the credentialSubject
#[pyfunction]
#[pyo3(signature = (status_list, id, status_purpose="revocation"))]
pub fn create_bitstring_credential_subject(
    status_list: &BitstringStatusList,
    id: &str,
    status_purpose: &str,
) -> PyResult<String> {
    let encoded = status_list.to_base64url()?;
    let subject = serde_json::json!({
        "id": id,
        "type": "BitstringStatusList",
        "statusPurpose": status_purpose,
        "encodedList": encoded
    });
    serde_json::to_string(&subject)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

/// Register status list module with parent.
pub fn register_status_list_module(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let status_list_module = PyModule::new_bound(parent.py(), "status_list")?;

    status_list_module.add_class::<TokenStatusList>()?;
    status_list_module.add_class::<BitstringStatusList>()?;
    status_list_module.add_function(wrap_pyfunction!(
        create_status_list_claim,
        &status_list_module
    )?)?;
    status_list_module.add_function(wrap_pyfunction!(
        create_bitstring_credential_subject,
        &status_list_module
    )?)?;

    parent.add_submodule(&status_list_module)?;

    // Re-export on the parent module for backwards compatibility.
    parent.add_class::<TokenStatusList>()?;
    parent.add_class::<BitstringStatusList>()?;
    parent.add_function(wrap_pyfunction!(create_status_list_claim, parent)?)?;
    parent.add_function(wrap_pyfunction!(
        create_bitstring_credential_subject,
        parent
    )?)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_status_list_basic() {
        let mut tsl = TokenStatusList::new(100, 8).unwrap();
        assert_eq!(tsl.get(0).unwrap(), 0);
        assert!(!tsl.is_revoked(0).unwrap());

        tsl.revoke(0).unwrap();
        assert_eq!(tsl.get(0).unwrap(), 1);
        assert!(tsl.is_revoked(0).unwrap());

        tsl.reinstate(0).unwrap();
        assert_eq!(tsl.get(0).unwrap(), 0);
        assert!(!tsl.is_revoked(0).unwrap());
    }

    #[test]
    fn test_token_status_list_2bit() {
        let mut tsl = TokenStatusList::new(100, 2).unwrap();
        tsl.set(0, 0).unwrap();
        tsl.set(1, 1).unwrap();
        tsl.set(2, 2).unwrap();
        tsl.set(3, 3).unwrap();

        assert_eq!(tsl.get(0).unwrap(), 0);
        assert_eq!(tsl.get(1).unwrap(), 1);
        assert_eq!(tsl.get(2).unwrap(), 2);
        assert_eq!(tsl.get(3).unwrap(), 3);
    }

    #[test]
    fn test_bitstring_status_list_basic() {
        let mut bsl = BitstringStatusList::new(1000);
        assert!(!bsl.is_revoked(0).unwrap());
        assert!(!bsl.is_revoked(999).unwrap());

        bsl.revoke(500).unwrap();
        assert!(bsl.is_revoked(500).unwrap());
        assert_eq!(bsl.count_revoked(), 1);

        bsl.reinstate(500).unwrap();
        assert!(!bsl.is_revoked(500).unwrap());
        assert_eq!(bsl.count_revoked(), 0);
    }

    #[test]
    fn test_compression_roundtrip() {
        let mut tsl = TokenStatusList::new(1000, 8).unwrap();
        tsl.revoke(100).unwrap();
        tsl.revoke(200).unwrap();

        let encoded = tsl.to_base64url().unwrap();
        let restored = TokenStatusList::from_base64url(&encoded, 1000, 8).unwrap();

        assert!(restored.is_revoked(100).unwrap());
        assert!(restored.is_revoked(200).unwrap());
        assert!(!restored.is_revoked(300).unwrap());
    }

    #[test]
    fn test_bitstring_compression_roundtrip() {
        let mut bsl = BitstringStatusList::new(1000);
        bsl.revoke(100).unwrap();
        bsl.revoke(200).unwrap();

        let encoded = bsl.to_base64url().unwrap();
        let restored = BitstringStatusList::from_base64url(&encoded, 1000).unwrap();

        assert!(restored.is_revoked(100).unwrap());
        assert!(restored.is_revoked(200).unwrap());
        assert!(!restored.is_revoked(300).unwrap());
    }
}
