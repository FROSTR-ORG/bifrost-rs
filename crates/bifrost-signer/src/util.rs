#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use bifrost_core::types::{Bytes33, GroupPackage, MemberPackage};
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

pub(crate) fn parse_request_id_components(request_id: &str) -> Option<(u64, u16, u64)> {
    let mut parts = request_id.split('-');
    let ts = parts.next()?.parse::<u64>().ok()?;
    let idx = parts.next()?.parse::<u16>().ok()?;
    let seq = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((ts, idx, seq))
}

pub(crate) fn decode_member_index(members: &[MemberPackage], peer: &str) -> Result<u16> {
    let mut expected = [0u8; 33];
    let bytes = hex::decode(peer)
        .map_err(|_| SignerError::InvalidConfig("invalid peer pubkey encoding".to_string()))?;
    if bytes.len() != expected.len() {
        return Err(SignerError::InvalidConfig(
            "peer pubkey must be 33-byte compressed".to_string(),
        ));
    }
    expected.copy_from_slice(&bytes);
    for member in members {
        if member.pubkey == expected {
            return Ok(member.idx);
        }
    }
    Err(SignerError::UnknownPeer(peer.to_string()))
}

pub(crate) fn decode_member_pubkey(group: &GroupPackage, idx: u16) -> Result<String> {
    for member in &group.members {
        if member.idx == idx {
            return Ok(hex::encode(member.pubkey));
        }
    }
    Err(SignerError::InvalidConfig(
        "share index not found in group members".to_string(),
    ))
}

pub(crate) fn decode_pubkey33(value: &str) -> Result<Bytes33> {
    let bytes = hex::decode(value)
        .map_err(|_| SignerError::InvalidRequest("invalid ecdh target key encoding".to_string()))?;
    if bytes.len() != 33 {
        return Err(SignerError::InvalidRequest(
            "ecdh target key must be 33 bytes".to_string(),
        ));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn decode_33(hex33: &str) -> Result<[u8; 33]> {
    let raw = hex::decode(hex33)
        .map_err(|_| SignerError::InvalidRequest("invalid pubkey hex".to_string()))?;
    if raw.len() != 33 {
        return Err(SignerError::InvalidRequest(
            "expected 33-byte compressed pubkey".to_string(),
        ));
    }
    let mut out = [0u8; 33];
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

pub(crate) fn is_valid_compressed_pubkey_hex(value: &str) -> bool {
    if value.len() != 66 {
        return false;
    }
    if hex::decode(value).map_or(true, |bytes| bytes.len() != 33) {
        return false;
    }
    value.starts_with("02") || value.starts_with("03")
}

pub(crate) fn xonly_from_compressed(pubkey33: &str) -> Result<String> {
    if !is_valid_compressed_pubkey_hex(pubkey33) {
        return Err(SignerError::InvalidConfig(
            "peer public key must be compressed hex".to_string(),
        ));
    }
    Ok(pubkey33[2..].to_string())
}

#[cfg(test)]
mod tests {
    use super::now_unix_secs;

    #[test]
    fn now_unix_secs_is_monotonic_non_decreasing() {
        let a = now_unix_secs();
        let b = now_unix_secs();
        assert!(b >= a);
    }
}
