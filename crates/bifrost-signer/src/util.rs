#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use bifrost_core::types::{Bytes32, GroupPackage, MemberPackage};
use rand_core::{OsRng, RngCore};

use crate::{Result, SignerError};

pub(crate) fn now_unix_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        return (js_sys::Date::now() / 1000.0).floor() as u64;
    }

    #[cfg(not(target_arch = "wasm32"))]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn parse_request_id_components(request_id: &str) -> Option<(u64, u16, u64, u64)> {
    let mut parts = request_id.split('-');
    let ts = parts.next()?.parse::<u64>().ok()?;
    let idx = parts.next()?.parse::<u16>().ok()?;
    let boot = parts.next()?.parse::<u64>().ok()?;
    let seq = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((ts, idx, boot, seq))
}

pub(crate) fn decode_member_index(members: &[MemberPackage], peer: &str) -> Result<u16> {
    if peer != peer.to_ascii_lowercase() {
        return Err(SignerError::InvalidConfig(
            "peer pubkey must be lowercase hex".to_string(),
        ));
    }
    let expected = hex::decode(peer)
        .map_err(|_| SignerError::InvalidConfig("invalid peer pubkey encoding".to_string()))?;
    if expected.len() != 32 {
        return Err(SignerError::InvalidConfig(
            "peer pubkey must be 32-byte x-only".to_string(),
        ));
    }
    for member in members {
        if member.pubkey[1..] == expected[..] {
            return Ok(member.idx);
        }
    }
    Err(SignerError::UnknownPeer(peer.to_string()))
}

pub(crate) fn decode_member_pubkey(group: &GroupPackage, idx: u16) -> Result<String> {
    for member in &group.members {
        if member.idx == idx {
            return Ok(hex::encode(&member.pubkey[1..]));
        }
    }
    Err(SignerError::InvalidConfig(
        "share index not found in group members".to_string(),
    ))
}

pub(crate) fn decode_pubkey32(value: &str) -> Result<Bytes32> {
    if value != value.to_ascii_lowercase() {
        return Err(SignerError::InvalidRequest(
            "ecdh target key must be lowercase hex".to_string(),
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| SignerError::InvalidRequest("invalid ecdh target key encoding".to_string()))?;
    if bytes.len() != 32 {
        return Err(SignerError::InvalidRequest(
            "ecdh target key must be 32 bytes".to_string(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn decode_32(hex32: &str) -> Result<[u8; 32]> {
    if hex32 != hex32.to_ascii_lowercase() {
        return Err(SignerError::InvalidRequest(
            "pubkey must be lowercase hex".to_string(),
        ));
    }
    let raw = hex::decode(hex32)
        .map_err(|_| SignerError::InvalidRequest("invalid pubkey hex".to_string()))?;
    if raw.len() != 32 {
        return Err(SignerError::InvalidRequest(
            "expected 32-byte x-only pubkey".to_string(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub(crate) fn shuffle_strings(values: &mut [String]) {
    if values.len() < 2 {
        return;
    }
    for i in (1..values.len()).rev() {
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        let j = (u64::from_le_bytes(bytes) as usize) % (i + 1);
        values.swap(i, j);
    }
}

pub(crate) fn is_valid_pubkey32_hex(value: &str) -> bool {
    if value.len() != 64 {
        return false;
    }
    if value != value.to_ascii_lowercase() {
        return false;
    }
    hex::decode(value).is_ok_and(|bytes| bytes.len() == 32)
}

#[cfg(test)]
mod tests {
    use bifrost_core::types::MemberPackage;

    use super::{decode_member_index, decode_pubkey32, is_valid_pubkey32_hex, now_unix_secs};

    #[test]
    fn now_unix_secs_is_monotonic_non_decreasing() {
        let a = now_unix_secs();
        let b = now_unix_secs();
        assert!(b >= a);
    }

    #[test]
    fn decode_pubkey32_rejects_uppercase_identity_hex() {
        let uppercase = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(decode_pubkey32(uppercase).is_err());
    }

    #[test]
    fn decode_member_index_rejects_33_byte_identity_key() {
        let mut member_key = [0u8; 33];
        member_key[0] = 0x02;
        member_key[1..].copy_from_slice(&[7u8; 32]);
        let members = vec![MemberPackage {
            idx: 1,
            pubkey: member_key,
        }];
        let peer33 = hex::encode(member_key);
        assert!(decode_member_index(&members, &peer33).is_err());
    }

    #[test]
    fn is_valid_pubkey32_hex_rejects_uppercase() {
        let lowercase = "abababababababababababababababababababababababababababababababab";
        let uppercase = "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
        assert!(is_valid_pubkey32_hex(lowercase));
        assert!(!is_valid_pubkey32_hex(uppercase));
    }
}
