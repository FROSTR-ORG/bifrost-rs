use argon2::{Algorithm, Argon2, Params, Version};
use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use bifrost_core::types::{Bytes32, SharePackage};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::errors::{FrostUtilsError, FrostUtilsResult};
use crate::types::{InviteToken, OnboardingPackage};

const PREFIX_ONBOARD: &str = "bfonboard";
const INVITE_TOKEN_VERSION: u8 = 1;
const ONBOARDING_FORMAT_VERSION: u8 = 3;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;
pub const MIN_ONBOARDING_PASSWORD_LEN: usize = 8;

const ARGON2_M_COST_KIB: u32 = 19 * 1024;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

const FORMAT_VERSION_SIZE: usize = 1;
const SHARE_INDEX_SIZE: usize = 2;
const SHARE_SECKEY_SIZE: usize = 32;
const PEER_PK_SIZE: usize = 32;
const CHALLENGE_SIZE: usize = 32;
const TIMESTAMP_SIZE: usize = 8;
const RELAY_COUNT_SIZE: usize = 2;
const RELAY_LEN_SIZE: usize = 2;
const MAX_RELAY_LENGTH: usize = 512;
const MAX_RELAY_COUNT: usize = 100;
const MIN_RELAY_COUNT: usize = 1;

const MIN_PAYLOAD_SIZE: usize = FORMAT_VERSION_SIZE
    + SHARE_INDEX_SIZE
    + SHARE_SECKEY_SIZE
    + PEER_PK_SIZE
    + CHALLENGE_SIZE
    + TIMESTAMP_SIZE
    + TIMESTAMP_SIZE
    + RELAY_COUNT_SIZE;

const MIN_ENVELOPE_SIZE: usize = FORMAT_VERSION_SIZE + SALT_SIZE + NONCE_SIZE + 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InviteTokenData {
    version: u8,
    callback_peer_pk: String,
    relays: Vec<String>,
    challenge: String,
    created_at: u64,
    expires_at: u64,
    label: Option<String>,
}

pub fn build_invite_token(
    callback_peer_pk: Bytes32,
    relays: Vec<String>,
    challenge: Bytes32,
    created_at: u64,
    expires_at: u64,
    label: Option<String>,
) -> FrostUtilsResult<InviteToken> {
    validate_relays(&relays)?;
    if expires_at <= created_at {
        return Err(FrostUtilsError::InvalidInput(
            "invite expiration must be after creation time".to_string(),
        ));
    }

    Ok(InviteToken {
        version: INVITE_TOKEN_VERSION,
        callback_peer_pk,
        relays,
        challenge,
        created_at,
        expires_at,
        label,
    })
}

pub fn encode_invite_token(token: &InviteToken) -> FrostUtilsResult<String> {
    validate_relays(&token.relays)?;
    serde_json::to_string(&InviteTokenData::from_token(token))
        .map_err(|e| FrostUtilsError::Codec(e.to_string()))
}

pub fn decode_invite_token(value: &str) -> FrostUtilsResult<InviteToken> {
    let data: InviteTokenData =
        serde_json::from_str(value).map_err(|e| FrostUtilsError::Codec(e.to_string()))?;
    data.into_token()
}

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
        challenge: None,
        created_at: None,
        expires_at: None,
    })
}

pub fn assemble_onboarding_package(
    token: &InviteToken,
    share: SharePackage,
) -> FrostUtilsResult<OnboardingPackage> {
    validate_relays(&token.relays)?;
    Ok(OnboardingPackage {
        share,
        peer_pk: token.callback_peer_pk,
        relays: token.relays.clone(),
        challenge: Some(token.challenge),
        created_at: Some(token.created_at),
        expires_at: Some(token.expires_at),
    })
}

pub fn encode_onboarding_package(
    pkg: &OnboardingPackage,
    password: &str,
) -> FrostUtilsResult<String> {
    validate_password(password)?;
    validate_relays(&pkg.relays)?;

    let challenge = pkg.challenge.ok_or_else(|| {
        FrostUtilsError::InvalidInput(
            "onboarding package requires invite challenge metadata".to_string(),
        )
    })?;
    let created_at = pkg.created_at.ok_or_else(|| {
        FrostUtilsError::InvalidInput(
            "onboarding package requires invite creation time".to_string(),
        )
    })?;
    let expires_at = pkg.expires_at.ok_or_else(|| {
        FrostUtilsError::InvalidInput(
            "onboarding package requires invite expiration time".to_string(),
        )
    })?;
    if expires_at <= created_at {
        return Err(FrostUtilsError::InvalidInput(
            "invite expiration must be after creation time".to_string(),
        ));
    }

    let payload = serialize_onboarding_payload(pkg, challenge, created_at, expires_at)?;

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = encrypt_payload(&payload, password, &salt, &nonce)?;
    let envelope = serialize_encrypted_envelope(&salt, &nonce, &ciphertext);
    encode_bech32(PREFIX_ONBOARD, &envelope)
}

pub fn decode_onboarding_package(value: &str, password: Option<&str>) -> FrostUtilsResult<OnboardingPackage> {
    let password = password.ok_or(FrostUtilsError::PassphraseRequired)?;
    validate_password(password)?;

    let bytes = decode_bech32(PREFIX_ONBOARD, value)?;
    let (salt, nonce, ciphertext) = deserialize_encrypted_envelope(&bytes)?;
    let plaintext = decrypt_payload(ciphertext, password, salt, nonce)?;
    deserialize_onboarding_payload(&plaintext)
}

fn serialize_onboarding_payload(
    pkg: &OnboardingPackage,
    challenge: Bytes32,
    created_at: u64,
    expires_at: u64,
) -> FrostUtilsResult<Vec<u8>> {
    let mut out = Vec::with_capacity(
        MIN_PAYLOAD_SIZE
            + pkg
                .relays
                .iter()
                .map(|relay| RELAY_LEN_SIZE + relay.len())
                .sum::<usize>(),
    );

    out.push(ONBOARDING_FORMAT_VERSION);
    out.extend_from_slice(&pkg.share.idx.to_be_bytes());
    out.extend_from_slice(&pkg.share.seckey);
    out.extend_from_slice(&pkg.peer_pk);
    out.extend_from_slice(&challenge);
    out.extend_from_slice(&created_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.extend_from_slice(&(pkg.relays.len() as u16).to_be_bytes());
    for relay in &pkg.relays {
        let bytes = relay.as_bytes();
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    Ok(out)
}

fn deserialize_onboarding_payload(data: &[u8]) -> FrostUtilsResult<OnboardingPackage> {
    if data.len() < MIN_PAYLOAD_SIZE {
        return Err(FrostUtilsError::Codec("onboard payload too short".to_string()));
    }

    let mut offset = 0usize;
    let version = read_u8(data, &mut offset)?;
    if version != ONBOARDING_FORMAT_VERSION {
        return Err(FrostUtilsError::UnsupportedFormat(format!(
            "unsupported onboarding package version {version}"
        )));
    }

    let idx = read_u16_be(data, &mut offset)?;
    if idx == 0 {
        return Err(FrostUtilsError::Codec("invalid share idx".to_string()));
    }

    let mut seckey = [0u8; SHARE_SECKEY_SIZE];
    seckey.copy_from_slice(read_exact(data, &mut offset, SHARE_SECKEY_SIZE)?);

    let mut peer_pk = [0u8; PEER_PK_SIZE];
    peer_pk.copy_from_slice(read_exact(data, &mut offset, PEER_PK_SIZE)?);

    let mut challenge = [0u8; CHALLENGE_SIZE];
    challenge.copy_from_slice(read_exact(data, &mut offset, CHALLENGE_SIZE)?);

    let created_at = read_u64_be(data, &mut offset)?;
    let expires_at = read_u64_be(data, &mut offset)?;
    if expires_at <= created_at {
        return Err(FrostUtilsError::Codec(
            "invite expiration must be after creation time".to_string(),
        ));
    }

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
            "extra data after onboarding package".to_string(),
        ));
    }

    validate_relays(&relays)?;

    Ok(OnboardingPackage {
        share: SharePackage { idx, seckey },
        peer_pk,
        relays,
        challenge: Some(challenge),
        created_at: Some(created_at),
        expires_at: Some(expires_at),
    })
}

fn serialize_encrypted_envelope(
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FORMAT_VERSION_SIZE + SALT_SIZE + NONCE_SIZE + ciphertext.len());
    out.push(ONBOARDING_FORMAT_VERSION);
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

fn deserialize_encrypted_envelope(
    data: &[u8],
) -> FrostUtilsResult<(&[u8; SALT_SIZE], &[u8; NONCE_SIZE], &[u8])> {
    if data.len() < MIN_ENVELOPE_SIZE {
        return Err(FrostUtilsError::Codec("onboarding envelope too short".to_string()));
    }

    let mut offset = 0usize;
    let version = read_u8(data, &mut offset)?;
    if version != ONBOARDING_FORMAT_VERSION {
        return Err(FrostUtilsError::UnsupportedFormat(format!(
            "unsupported onboarding envelope version {version}"
        )));
    }

    let salt = read_exact(data, &mut offset, SALT_SIZE)?
        .try_into()
        .map_err(|_| FrostUtilsError::Codec("invalid salt size".to_string()))?;
    let nonce = read_exact(data, &mut offset, NONCE_SIZE)?
        .try_into()
        .map_err(|_| FrostUtilsError::Codec("invalid nonce size".to_string()))?;
    let remaining = data.len().saturating_sub(offset);
    let ciphertext = read_exact(data, &mut offset, remaining)?;
    if ciphertext.is_empty() {
        return Err(FrostUtilsError::Codec(
            "onboarding ciphertext is empty".to_string(),
        ));
    }

    Ok((salt, nonce, ciphertext))
}

fn decode_bech32(expected_prefix: &str, value: &str) -> FrostUtilsResult<Vec<u8>> {
    let checked =
        CheckedHrpstring::new::<Bech32m>(value).map_err(|e| FrostUtilsError::Codec(e.to_string()))?;
    if checked.hrp().to_string() != expected_prefix {
        return Err(FrostUtilsError::WrongPackageMode(format!(
            "expected prefix {expected_prefix}, got {}",
            checked.hrp()
        )));
    }
    Ok(checked.byte_iter().collect())
}

fn encode_bech32(prefix: &str, bytes: &[u8]) -> FrostUtilsResult<String> {
    let hrp = Hrp::parse(prefix).map_err(|e| FrostUtilsError::Codec(e.to_string()))?;
    bech32::encode::<Bech32m>(hrp, bytes).map_err(|e| FrostUtilsError::Codec(e.to_string()))
}

fn validate_password(password: &str) -> FrostUtilsResult<()> {
    if password.len() < MIN_ONBOARDING_PASSWORD_LEN {
        return Err(FrostUtilsError::InvalidInput(format!(
            "password must be at least {MIN_ONBOARDING_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

fn encrypt_payload(
    plaintext: &[u8],
    password: &str,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> FrostUtilsResult<Vec<u8>> {
    let key = derive_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?;
    cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| FrostUtilsError::DecryptionFailed)
}

fn decrypt_payload(
    ciphertext: &[u8],
    password: &str,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> FrostUtilsResult<Vec<u8>> {
    let key = derive_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?;
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| FrostUtilsError::DecryptionFailed)
}

fn derive_key(password: &str, salt: &[u8; SALT_SIZE]) -> FrostUtilsResult<[u8; KEY_SIZE]> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
        .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?;
    Ok(key)
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

fn read_u8(data: &[u8], offset: &mut usize) -> FrostUtilsResult<u8> {
    Ok(read_exact(data, offset, 1)?[0])
}

fn read_u16_be(data: &[u8], offset: &mut usize) -> FrostUtilsResult<u16> {
    let raw = read_exact(data, offset, 2)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u64_be(data: &[u8], offset: &mut usize) -> FrostUtilsResult<u64> {
    let raw = read_exact(data, offset, 8)?;
    Ok(u64::from_be_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn decode_hex32(value: &str, label: &str) -> FrostUtilsResult<Bytes32> {
    decode_hex_fixed::<32>(value, label)
}

fn decode_hex_fixed<const N: usize>(value: &str, label: &str) -> FrostUtilsResult<[u8; N]> {
    let bytes = hex::decode(value)
        .map_err(|e| FrostUtilsError::Codec(format!("invalid {label} hex: {e}")))?;
    if bytes.len() != N {
        return Err(FrostUtilsError::Codec(format!(
            "{label} must be {N} bytes"
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

impl InviteTokenData {
    fn from_token(token: &InviteToken) -> Self {
        Self {
            version: token.version,
            callback_peer_pk: hex::encode(token.callback_peer_pk),
            relays: token.relays.clone(),
            challenge: hex::encode(token.challenge),
            created_at: token.created_at,
            expires_at: token.expires_at,
            label: token.label.clone(),
        }
    }

    fn into_token(self) -> FrostUtilsResult<InviteToken> {
        if self.version != INVITE_TOKEN_VERSION {
            return Err(FrostUtilsError::UnsupportedFormat(format!(
                "unsupported invite token version {}",
                self.version
            )));
        }

        build_invite_token(
            decode_hex32(&self.callback_peer_pk, "callback_peer_pk")?,
            self.relays,
            decode_hex32(&self.challenge, "challenge")?,
            self.created_at,
            self.expires_at,
            self.label,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery staple";

    fn fixture_token() -> InviteToken {
        build_invite_token(
            [3u8; 32],
            vec!["ws://127.0.0.1:8194".to_string()],
            [9u8; 32],
            1_700_000_000,
            1_700_000_600,
            Some("bob".to_string()),
        )
        .expect("build token")
    }

    fn fixture_package() -> OnboardingPackage {
        assemble_onboarding_package(
            &fixture_token(),
            SharePackage {
                idx: 2,
                seckey: [7u8; 32],
            },
        )
        .expect("assemble package")
    }

    #[test]
    fn invite_token_roundtrip_json() {
        let token = fixture_token();
        let encoded = encode_invite_token(&token).expect("encode");
        assert!(encoded.starts_with('{'));
        let decoded = decode_invite_token(&encoded).expect("decode");
        assert_eq!(decoded, token);
    }

    #[test]
    fn encrypted_onboarding_roundtrip_bech32() {
        let pkg = fixture_package();
        let encoded = encode_onboarding_package(&pkg, PASSWORD).expect("encode");
        assert!(encoded.starts_with("bfonboard1"));
        let decoded = decode_onboarding_package(&encoded, Some(PASSWORD)).expect("decode");
        assert_eq!(decoded, pkg);
    }

    #[test]
    fn onboarding_requires_password() {
        let pkg = fixture_package();
        let encoded = encode_onboarding_package(&pkg, PASSWORD).expect("encode");
        let err = decode_onboarding_package(&encoded, None).expect_err("must require password");
        assert!(matches!(err, FrostUtilsError::PassphraseRequired));
    }

    #[test]
    fn onboarding_rejects_wrong_password() {
        let pkg = fixture_package();
        let encoded = encode_onboarding_package(&pkg, PASSWORD).expect("encode");
        let err = decode_onboarding_package(&encoded, Some("wrong password"))
            .expect_err("must reject wrong password");
        assert!(matches!(err, FrostUtilsError::DecryptionFailed));
    }

    #[test]
    fn onboarding_rejects_short_password() {
        let pkg = fixture_package();
        let err = encode_onboarding_package(&pkg, "short").expect_err("must reject short password");
        assert!(matches!(err, FrostUtilsError::InvalidInput(_)));
    }

    #[test]
    fn onboarding_prefix_mismatch_rejected() {
        let pkg = fixture_package();
        let encoded = encode_onboarding_package(&pkg, PASSWORD).expect("encode");
        let wrong = encoded.replacen(PREFIX_ONBOARD, "wrongprefix", 1);
        assert!(decode_onboarding_package(&wrong, Some(PASSWORD)).is_err());
    }

    #[test]
    fn onboarding_rejects_legacy_plaintext_payloads() {
        let legacy = bech32::encode::<Bech32m>(
            Hrp::parse(PREFIX_ONBOARD).expect("hrp"),
            &[1u8; 72],
        )
        .expect("encode");
        let err = decode_onboarding_package(&legacy, Some(PASSWORD)).expect_err("must reject");
        assert!(matches!(
            err,
            FrostUtilsError::UnsupportedFormat(_) | FrostUtilsError::DecryptionFailed | FrostUtilsError::Codec(_)
        ));
    }
}
