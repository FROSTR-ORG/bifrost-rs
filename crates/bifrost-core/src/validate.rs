use crate::error::{CoreError, CoreResult};

pub fn decode_hex32(value: &str) -> CoreResult<[u8; 32]> {
    decode_fixed_hex::<32>(value)
}

pub fn decode_hex33(value: &str) -> CoreResult<[u8; 33]> {
    decode_fixed_hex::<33>(value)
}

pub fn decode_sig64(value: &str) -> CoreResult<[u8; 64]> {
    decode_fixed_hex::<64>(value)
}

pub fn decode_fixed_hex<const N: usize>(value: &str) -> CoreResult<[u8; N]> {
    let raw = hex::decode(value).map_err(|_| CoreError::InvalidHex)?;
    if raw.len() != N {
        return Err(CoreError::InvalidHex);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub fn encode_hex<const N: usize>(value: &[u8; N]) -> String {
    hex::encode(value)
}

pub fn validate_pubkey33(value: &[u8]) -> CoreResult<()> {
    if value.len() != 33 {
        return Err(CoreError::InvalidPubkey);
    }
    Ok(())
}

pub fn validate_signature64(value: &[u8]) -> CoreResult<()> {
    if value.len() != 64 {
        return Err(CoreError::InvalidScalar);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_helpers_enforce_size() {
        let hex32 = hex::encode([1u8; 32]);
        assert!(decode_hex32(&hex32).is_ok());
        assert!(decode_hex33(&hex32).is_err());
    }
}
