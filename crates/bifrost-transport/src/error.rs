use thiserror::Error;

pub type TransportResult<T> = Result<T, TransportError>;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport is not connected")]
    NotConnected,
    #[error("timeout")]
    Timeout,
    #[error("peer not found")]
    PeerNotFound,
    #[error("codec error: {0}")]
    Codec(String),
    #[error("transport backend error: {0}")]
    Backend(String),
}
