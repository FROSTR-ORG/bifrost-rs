use crate::error::{CodecError, CodecResult};

pub fn encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn decode<const N: usize>(value: &str) -> CodecResult<[u8; N]> {
    let bytes = hex::decode(value).map_err(|_| CodecError::Hex)?;
    if bytes.len() != N {
        return Err(CodecError::InvalidLength {
            expected: N,
            actual: bytes.len(),
        });
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode_vec(value: &str) -> CodecResult<Vec<u8>> {
    hex::decode(value).map_err(|_| CodecError::Hex)
}
