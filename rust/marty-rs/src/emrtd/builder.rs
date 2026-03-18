//! Fluent builder for constructing [`EmrtdIssuanceRequest`]s.

use super::types::{EmrtdDataGroup, EmrtdIssuanceRequest};

/// Fluent builder for an [`EmrtdIssuanceRequest`].
///
/// # Example
///
/// ```rust,ignore
/// let request = EmrtdPassportBuilder::new("DEU", "Bundesdruckerei")
///     .add_dg1(mrz_bytes)
///     .add_dg2(portrait_jpeg)
///     .build();
/// ```
pub struct EmrtdPassportBuilder {
    country_code: String,
    organization: String,
    data_groups: Vec<EmrtdDataGroup>,
}

impl EmrtdPassportBuilder {
    /// Start building for the given country and issuing organization.
    pub fn new(country_code: impl Into<String>, organization: impl Into<String>) -> Self {
        Self {
            country_code: country_code.into(),
            organization: organization.into(),
            data_groups: Vec::new(),
        }
    }

    /// Set DG1 (MRZ data).
    ///
    /// The `content` should be the raw EF.DG1 bytes.  For testing, passing
    /// the two 44-character MRZ lines concatenated as UTF-8 is sufficient;
    /// no ICAO TLV wrapping is required for the SOD hash to be correct.
    pub fn add_dg1(mut self, content: Vec<u8>) -> Self {
        self.data_groups.retain(|dg| dg.number != 1);
        self.data_groups.push(EmrtdDataGroup { number: 1, content });
        self
    }

    /// Set DG2 (portrait / facial image).
    pub fn add_dg2(mut self, content: Vec<u8>) -> Self {
        self.data_groups.retain(|dg| dg.number != 2);
        self.data_groups.push(EmrtdDataGroup { number: 2, content });
        self
    }

    /// Add an arbitrary data group.  Replaces any existing DG with the same
    /// number.
    pub fn add_data_group(mut self, number: u8, content: Vec<u8>) -> Self {
        self.data_groups.retain(|dg| dg.number != number);
        self.data_groups.push(EmrtdDataGroup { number, content });
        self
    }

    /// Finalise and return the [`EmrtdIssuanceRequest`].
    pub fn build(self) -> EmrtdIssuanceRequest {
        EmrtdIssuanceRequest {
            country_code: self.country_code,
            organization: self.organization,
            data_groups: self.data_groups,
        }
    }
}
