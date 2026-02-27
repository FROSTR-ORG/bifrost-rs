use thiserror::Error;

pub type NodeResult<T> = Result<T, NodeError>;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("core error: {0}")]
    Core(String),
    #[error("peer not found")]
    PeerNotFound,
    #[error("insufficient peers for threshold operation")]
    InsufficientPeers,
    #[error("nonce unavailable for required peer")]
    NonceUnavailable,
    #[error("invalid group configuration")]
    InvalidGroup,
    #[error("node is not ready")]
    NotReady,
    #[error("operation not implemented yet: {0}")]
    NotImplemented(&'static str),
    #[error("invalid response")]
    InvalidResponse,
    #[error("invalid sign session: {0}")]
    InvalidSignSession(&'static str),
}
