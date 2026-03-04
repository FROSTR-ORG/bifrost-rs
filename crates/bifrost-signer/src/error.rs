use thiserror::Error;

pub type Result<T> = std::result::Result<T, SignerError>;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid sender binding: {0}")]
    InvalidSenderBinding(String),
    #[error("replay request detected: {0}")]
    ReplayDetected(String),
    #[error("state corrupted: {0}")]
    StateCorrupted(String),
    #[error("unknown peer: {0}")]
    UnknownPeer(String),
    #[error("nonce unavailable")]
    NonceUnavailable,
    #[error("decrypt failed: {0}")]
    DecryptFailed(String),
}
