use thiserror::Error;

#[derive(Debug, Error)]
pub enum FrostUtilsError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("codec error: {0}")]
    Codec(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("wrong package mode: {0}")]
    WrongPackageMode(String),
    #[error("passphrase required")]
    PassphraseRequired,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    // ----- Bucket B B.2 portable-package envelope v2 typed errors -----
    /// Envelope reports a `version` byte the reader does not implement.
    #[error("unsupported portable package envelope version {0}")]
    UnsupportedVersion(u8),
    /// Envelope reports a `kdf` marker the reader does not implement.
    #[error("unsupported portable package kdf {0:?}")]
    UnsupportedKdf(String),
    /// Envelope reports an `aead` marker the reader does not implement.
    #[error("unsupported portable package aead {0:?}")]
    UnsupportedAead(String),
    /// Argon2id parameters fell outside the configured floor/ceiling.
    #[error("unsupported argon2 params: m_cost={m_cost}, t_cost={t_cost}, p_cost={p_cost}")]
    UnsupportedParams {
        m_cost: u32,
        t_cost: u32,
        p_cost: u8,
    },
    /// AAD pre-conditions failed (e.g. interior NUL in `outer_id`).
    #[error("invalid portable package metadata: {0}")]
    InvalidMetadata(&'static str),
}

pub type FrostUtilsResult<T> = Result<T, FrostUtilsError>;
