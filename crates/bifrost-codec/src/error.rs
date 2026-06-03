use thiserror::Error;

pub type CodecResult<T> = Result<T, CodecError>;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("json encode/decode error: {0}")]
    Json(String),
    #[error("hex decode error")]
    Hex,
    #[error("invalid byte length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid payload shape: {0}")]
    InvalidPayload(&'static str),
    #[error("bridge envelope exceeds maximum size")]
    EnvelopeTooLarge,
    #[error("field `{field}` exceeds maximum size of {limit} bytes")]
    FieldTooLarge { field: &'static str, limit: usize },
}

impl From<serde_json::Error> for CodecError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value.to_string())
    }
}
