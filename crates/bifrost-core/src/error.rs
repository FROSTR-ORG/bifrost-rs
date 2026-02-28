use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid hex string")]
    InvalidHex,
    #[error("invalid scalar")]
    InvalidScalar,
    #[error("invalid pubkey bytes")]
    InvalidPubkey,
    #[error("threshold must be greater than zero")]
    InvalidThreshold,
    #[error("member list is empty")]
    EmptyMembers,
    #[error("session must include at least one member")]
    EmptySessionMembers,
    #[error("session members contain duplicates")]
    DuplicateSessionMember,
    #[error("session must include at least one hash")]
    EmptySessionHashes,
    #[error("batch item count mismatch")]
    BatchItemCountMismatch,
    #[error("batch signing is not supported in this implementation")]
    UnsupportedBatchSigning,
    #[error("session gid mismatch")]
    SessionGroupIdMismatch,
    #[error("session sid mismatch")]
    SessionIdMismatch,
    #[error("session hash mismatch")]
    SessionHashMismatch,
    #[error("missing member in group")]
    MissingMember,
    #[error("session missing nonces")]
    MissingNonces,
    #[error("signing nonce code not found for peer")]
    NonceNotFound,
    #[error("signing nonce code already claimed/consumed")]
    NonceAlreadyClaimed,
    #[error("hash index out of range")]
    HashIndexOutOfRange,
    #[error("duplicate hash index")]
    HashIndexDuplicate,
    #[error("missing hash index contribution")]
    MissingHashIndexContribution,
    #[error("frost error: {0}")]
    Frost(String),
}
