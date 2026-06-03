//! Typed error variants for the host-local encrypted-profile envelope v2.
//!
//! The Bucket B B.1 plan requires a typed error taxonomy in place of the
//! existing stringly-typed `anyhow` messages. PR6 introduces the enum
//! crate-internally; PR7 wires it into the writer/reader cutover and surfaces
//! it through the public decrypt path.

use core::fmt;

use crate::argon2_params::ParamsError;

/// Errors surfaced by the host-local encrypted-profile envelope (v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// Envelope shorter than the minimum v2 header (39 bytes). Produced when
    /// a caller hands a truncated or corrupt file to the reader.
    Truncated { actual: usize, minimum: usize },

    /// Envelope reports a `version` byte the reader does not implement.
    UnsupportedVersion(u8),

    /// Envelope reports a `kdf_id` the reader does not implement.
    UnsupportedKdf(u8),

    /// Argon2id parameters fell outside the configured floor/ceiling.
    UnsupportedParams {
        m_cost: u32,
        t_cost: u32,
        p_cost: u8,
    },

    /// `EncryptedProfileRecord` metadata failed the AAD pre-conditions.
    ///
    /// Today this fires when any of `record_id`, `kind`, or `source`
    /// contains an interior NUL (`0x00`).
    InvalidMetadata { reason: &'static str },
}

impl StateError {
    /// Static marker for an `record_id` interior-NUL rejection.
    pub const RECORD_ID_INTERIOR_NUL: &'static str = "record_id contains interior NUL";
    /// Static marker for a `kind` interior-NUL rejection.
    pub const KIND_INTERIOR_NUL: &'static str = "kind contains interior NUL";
    /// Static marker for a `source` interior-NUL rejection.
    pub const SOURCE_INTERIOR_NUL: &'static str = "source contains interior NUL";
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Truncated { actual, minimum } => write!(
                f,
                "encrypted profile envelope truncated: {actual} bytes, minimum {minimum}"
            ),
            StateError::UnsupportedVersion(v) => {
                write!(f, "unsupported encrypted profile envelope version {v}")
            }
            StateError::UnsupportedKdf(id) => {
                write!(f, "unsupported encrypted profile kdf_id {id}")
            }
            StateError::UnsupportedParams {
                m_cost,
                t_cost,
                p_cost,
            } => write!(
                f,
                "unsupported argon2 params: m_cost={m_cost}, t_cost={t_cost}, p_cost={p_cost}"
            ),
            StateError::InvalidMetadata { reason } => {
                write!(f, "invalid encrypted profile metadata: {reason}")
            }
        }
    }
}

impl std::error::Error for StateError {}

impl From<ParamsError> for StateError {
    fn from(err: ParamsError) -> Self {
        match err {
            ParamsError::BelowFloor {
                m_cost,
                t_cost,
                p_cost,
            } => StateError::UnsupportedParams {
                m_cost,
                t_cost,
                p_cost,
            },
            ParamsError::AboveCeiling { m_cost } => StateError::UnsupportedParams {
                m_cost,
                t_cost: 0,
                p_cost: 0,
            },
        }
    }
}
