use bech32::{Bech32m, Hrp};
use bifrost_core::types::{Bytes32, SharePackage};

use crate::errors::{FrostUtilsError, FrostUtilsResult};
use crate::types::OnboardingPackage;

const PREFIX_ONBOARD: &str = "bfonboard";
const SHARE_INDEX_SIZE: usize = 4;
const SHARE_SECKEY_SIZE: usize = 32;
const PEER_PK_SIZE: usize = 32;
const RELAY_COUNT_SIZE: usize = 2;
const RELAY_LEN_SIZE: usize = 2;
const MAX_RELAY_LENGTH: usize = 512;
const MAX_RELAY_COUNT: usize = 100;
const MIN_RELAY_COUNT: usize = 1;
const MIN_DATA_SIZE: usize = SHARE_INDEX_SIZE + SHARE_SECKEY_SIZE + PEER_PK_SIZE + RELAY_COUNT_SIZE;

pub fn build_onboarding_package(
    share: SharePackage,
    peer_pk: Bytes32,
    relays: Vec<String>,
) -> FrostUtilsResult<OnboardingPackage> {
    validate_relays(&relays)?;
    Ok(OnboardingPackage {
        share,
        peer_pk,
        relays,
    })
}

pub fn encode_onboarding_package(pkg: &OnboardingPackage) -> FrostUtilsResult<String> {
    validate_relays(&pkg.relays)?;
    let bytes = serialize_onboarding_data(pkg)?;
    let hrp = Hrp::parse(PREFIX_ONBOARD).map_err(|e| FrostUtilsError::Codec(e.to_string()))?;
    bech32::encode::<Bech32m>(hrp, &bytes).map_err(|e| FrostUtilsError::Codec(e.to_string()))
}

pub fn decode_onboarding_package(value: &str) -> FrostUtilsResult<OnboardingPackage> {
    let (hrp, bytes) = bech32::decode(value).map_err(|e| FrostUtilsError::Codec(e.to_string()))?;
    if hrp.to_string() != PREFIX_ONBOARD {
        return Err(FrostUtilsError::WrongPackageMode(format!(
            "expected prefix {PREFIX_ONBOARD}, got {}",
            hrp
        )));
    }
    deserialize_onboarding_data(&bytes)
}

pub fn serialize_onboarding_data(pkg: &OnboardingPackage) -> FrostUtilsResult<Vec<u8>> {
    validate_relays(&pkg.relays)?;

    let mut out = Vec::with_capacity(
        MIN_DATA_SIZE
            + pkg
                .relays
                .iter()
                .map(|r| RELAY_LEN_SIZE + r.len())
                .sum::<usize>(),
    );

    out.extend_from_slice(&(pkg.share.idx as u32).to_be_bytes());
    out.extend_from_slice(&pkg.share.seckey);
    out.extend_from_slice(&pkg.peer_pk);

    out.extend_from_slice(&(pkg.relays.len() as u16).to_be_bytes());
    for relay in &pkg.relays {
        let bytes = relay.as_bytes();
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    Ok(out)
}

pub fn deserialize_onboarding_data(data: &[u8]) -> FrostUtilsResult<OnboardingPackage> {
    if data.len() < MIN_DATA_SIZE {
        return Err(FrostUtilsError::Codec("onboard data too short".to_string()));
    }

    let mut offset = 0usize;

    let idx = read_u32_be(data, &mut offset)?;
    if idx == 0 || idx > u16::MAX as u32 {
        return Err(FrostUtilsError::Codec("invalid share idx".to_string()));
    }

    let mut seckey = [0u8; SHARE_SECKEY_SIZE];
    seckey.copy_from_slice(read_exact(data, &mut offset, SHARE_SECKEY_SIZE)?);

    let mut peer_pk = [0u8; PEER_PK_SIZE];
    peer_pk.copy_from_slice(read_exact(data, &mut offset, PEER_PK_SIZE)?);

    let relay_count = read_u16_be(data, &mut offset)? as usize;
    if !(MIN_RELAY_COUNT..=MAX_RELAY_COUNT).contains(&relay_count) {
        return Err(FrostUtilsError::Codec(
            "relay count exceeds allowed bounds".to_string(),
        ));
    }

    let mut relays = Vec::with_capacity(relay_count);
    for _ in 0..relay_count {
        let relay_len = read_u16_be(data, &mut offset)? as usize;
        if relay_len > MAX_RELAY_LENGTH {
            return Err(FrostUtilsError::Codec(
                "relay URL length exceeds maximum allowed".to_string(),
            ));
        }
        let relay_bytes = read_exact(data, &mut offset, relay_len)?;
        let relay = std::str::from_utf8(relay_bytes)
            .map_err(|_| FrostUtilsError::Codec("relay URL is not valid UTF-8".to_string()))?
            .to_string();
        relays.push(relay);
    }

    if offset != data.len() {
        return Err(FrostUtilsError::Codec(
            "extra data after onboard package".to_string(),
        ));
    }

    validate_relays(&relays)?;

    Ok(OnboardingPackage {
        share: SharePackage {
            idx: idx as u16,
            seckey,
        },
        peer_pk,
        relays,
    })
}

fn validate_relays(relays: &[String]) -> FrostUtilsResult<()> {
    if !(MIN_RELAY_COUNT..=MAX_RELAY_COUNT).contains(&relays.len()) {
        return Err(FrostUtilsError::InvalidInput(
            "relay count must be in [1, 100]".to_string(),
        ));
    }

    for relay in relays {
        if relay.is_empty() || relay.len() > MAX_RELAY_LENGTH {
            return Err(FrostUtilsError::InvalidInput(
                "relay URL length out of bounds".to_string(),
            ));
        }
        if !(relay.starts_with("ws://") || relay.starts_with("wss://")) {
            return Err(FrostUtilsError::InvalidInput(
                "relay URL must start with ws:// or wss://".to_string(),
            ));
        }
    }

    Ok(())
}

fn read_exact<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> FrostUtilsResult<&'a [u8]> {
    if data.len().saturating_sub(*offset) < len {
        return Err(FrostUtilsError::Codec("unexpected end of data".to_string()));
    }
    let out = &data[*offset..*offset + len];
    *offset += len;
    Ok(out)
}

fn read_u16_be(data: &[u8], offset: &mut usize) -> FrostUtilsResult<u16> {
    let raw = read_exact(data, offset, 2)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u32_be(data: &[u8], offset: &mut usize) -> FrostUtilsResult<u32> {
    let raw = read_exact(data, offset, 4)?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_package() -> OnboardingPackage {
        build_onboarding_package(
            SharePackage {
                idx: 2,
                seckey: [7u8; 32],
            },
            [3u8; 32],
            vec!["ws://127.0.0.1:8194".to_string()],
        )
        .expect("build package")
    }

    #[test]
    fn onboarding_roundtrip_bech32() {
        let pkg = fixture_package();
        let encoded = encode_onboarding_package(&pkg).expect("encode");
        let decoded = decode_onboarding_package(&encoded).expect("decode");
        assert_eq!(decoded.share.idx, 2);
        assert_eq!(decoded.peer_pk, [3u8; 32]);
        assert_eq!(decoded.relays, vec!["ws://127.0.0.1:8194"]);
    }

    #[test]
    fn onboarding_prefix_mismatch_rejected() {
        let pkg = fixture_package();
        let encoded = encode_onboarding_package(&pkg).expect("encode");
        let wrong = encoded.replacen(PREFIX_ONBOARD, "wrongprefix", 1);
        assert!(decode_onboarding_package(&wrong).is_err());
    }

    #[test]
    fn onboarding_binary_layout_is_minimal() {
        let pkg = fixture_package();
        let raw = serialize_onboarding_data(&pkg).expect("serialize");
        let expected = SHARE_INDEX_SIZE
            + SHARE_SECKEY_SIZE
            + PEER_PK_SIZE
            + RELAY_COUNT_SIZE
            + RELAY_LEN_SIZE
            + "ws://127.0.0.1:8194".len();
        assert_eq!(raw.len(), expected);
    }
}
