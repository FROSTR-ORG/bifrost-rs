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
}

pub type FrostUtilsResult<T> = Result<T, FrostUtilsError>;
