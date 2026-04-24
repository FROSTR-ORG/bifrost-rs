use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bech32::primitives::checksum::Engine as ChecksumEngine;
use bech32::primitives::decode::UncheckedHrpstring;
use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};
use bech32::{Checksum, Fe32};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use nostr::{Event, EventBuilder, Keys, Kind, SecretKey, Timestamp};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::form_urlencoded::{Serializer, parse as parse_urlencoded};

use bifrost_codec::wire::GroupPackageWire;
use bifrost_core::types::{
    GroupPackage, MethodPolicyOverride, PeerPolicyOverride, PolicyOverrideValue,
};

use crate::argon2_params::{
    Argon2Params, PACKAGE_KDF_SALT_LEN, derive_package_encryption_key_v2,
};
use crate::errors::{FrostUtilsError, FrostUtilsResult};
use crate::package_aad::build_aad_package;

/// Portable bech32m package envelope version. Bumped 1→2 by Bucket B B.2;
/// v1 envelopes (old PBKDF2 + AES-GCM-24 scheme) are not readable.
pub const BF_PACKAGE_VERSION: u8 = 2;
/// Salt length in raw bytes used by the package envelope.
pub const BF_PACKAGE_SALT_BYTES: usize = 16;
/// XChaCha20Poly1305 nonce length in raw bytes (24-byte native nonce).
pub const BF_PACKAGE_XCHACHA_NONCE_BYTES: usize = 24;
pub const PROFILE_BACKUP_EVENT_KIND: u16 = 10_000;
pub const PROFILE_BACKUP_KEY_DOMAIN: &str = "frostr-profile-backup/v1";
pub const PROFILE_ID_DOMAIN: &str = "frostr:profile-id:v1";
pub const PREFIX_BFSHARE: &str = "bfshare";
pub const PREFIX_BFONBOARD: &str = "bfonboard";
pub const PREFIX_BFPROFILE: &str = "bfprofile";

const KDF_MARKER_ARGON2ID: &str = "argon2id";
const AEAD_MARKER_XCHACHA20POLY1305: &str = "xchacha20poly1305";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BfPolicyOverrideValue {
    #[default]
    Unset,
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BfMethodPolicyOverride {
    #[serde(default)]
    pub echo: BfPolicyOverrideValue,
    #[serde(default)]
    pub ping: BfPolicyOverrideValue,
    #[serde(default)]
    pub onboard: BfPolicyOverrideValue,
    #[serde(default)]
    pub sign: BfPolicyOverrideValue,
    #[serde(default)]
    pub ecdh: BfPolicyOverrideValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BfPeerPolicyOverride {
    #[serde(default)]
    pub request: BfMethodPolicyOverride,
    #[serde(default)]
    pub respond: BfMethodPolicyOverride,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BfManualPeerPolicyOverride {
    pub pubkey: String,
    pub policy: BfPeerPolicyOverride,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BfSharePayload {
    pub share_secret: String,
    pub relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BfOnboardPayload {
    pub share_secret: String,
    pub relays: Vec<String>,
    pub peer_pk: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BfProfileDevice {
    pub name: String,
    pub share_secret: String,
    #[serde(default)]
    pub manual_peer_policy_overrides: Vec<BfManualPeerPolicyOverride>,
    pub relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BfProfilePayload {
    pub profile_id: String,
    pub version: u8,
    pub device: BfProfileDevice,
    pub group_package: GroupPackageWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedProfileBackupDevice {
    pub name: String,
    pub share_public_key: String,
    #[serde(default)]
    pub manual_peer_policy_overrides: Vec<BfManualPeerPolicyOverride>,
    pub relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedProfileBackup {
    pub version: u8,
    pub device: EncryptedProfileBackupDevice,
    pub group_package: GroupPackageWire,
}

/// Portable bech32m package envelope (v2). Bucket B B.2 (2026-04-22) replaced
/// the v1 envelope (PBKDF2 + AES-GCM-24) with this layout. Reader rejects
/// any `version != 2` and any other `kdf` / `aead` marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProtectedPackageEnvelope {
    version: u8,
    kdf: String,
    kdf_m_cost: u32,
    kdf_t_cost: u32,
    kdf_p_cost: u8,
    aead: String,
    salt_hex: String,
    nonce_hex: String,
    ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePackagePair {
    pub profile_string: String,
    pub share_string: String,
}

pub fn encode_bfshare_package(
    payload: &BfSharePayload,
    password: &str,
) -> FrostUtilsResult<String> {
    let normalized = normalize_share_payload(payload)?;
    encrypt_plaintext_payload(
        PREFIX_BFSHARE,
        &build_compact_package_text_share(&normalized),
        password,
    )
}

pub fn decode_bfshare_package(
    package_text: &str,
    password: &str,
) -> FrostUtilsResult<BfSharePayload> {
    let plaintext = decrypt_plaintext_payload(PREFIX_BFSHARE, package_text, password)?;
    parse_compact_share_payload(&plaintext)
}

pub fn encode_bfonboard_package(
    payload: &BfOnboardPayload,
    password: &str,
) -> FrostUtilsResult<String> {
    let normalized = normalize_onboard_payload(payload)?;
    encrypt_plaintext_payload(
        PREFIX_BFONBOARD,
        &build_compact_package_text_onboard(&normalized),
        password,
    )
}

pub fn decode_bfonboard_package(
    package_text: &str,
    password: &str,
) -> FrostUtilsResult<BfOnboardPayload> {
    let plaintext = decrypt_plaintext_payload(PREFIX_BFONBOARD, package_text, password)?;
    parse_compact_onboard_payload(&plaintext)
}

pub fn encode_bfprofile_package(
    payload: &BfProfilePayload,
    password: &str,
) -> FrostUtilsResult<String> {
    let normalized = normalize_profile_payload(payload)?;
    let plaintext = serde_json::to_string(&normalized)
        .map_err(|e| FrostUtilsError::Codec(format!("serialize bfprofile payload: {e}")))?;
    encrypt_profile_payload_with_outer_id(
        PREFIX_BFPROFILE,
        &normalized.profile_id,
        &plaintext,
        password,
    )
}

pub fn decode_bfprofile_package(
    package_text: &str,
    password: &str,
) -> FrostUtilsResult<BfProfilePayload> {
    let (outer_profile_id, plaintext) =
        decrypt_profile_payload_with_outer_id(PREFIX_BFPROFILE, package_text, password)?;
    let payload: BfProfilePayload = serde_json::from_str(&plaintext)
        .map_err(|_| FrostUtilsError::InvalidInput("Invalid bfprofile payload.".to_string()))?;
    let normalized = normalize_profile_payload(&payload)?;
    if normalized.profile_id != outer_profile_id {
        return Err(FrostUtilsError::InvalidInput(
            "bfprofile outer profile id mismatch".to_string(),
        ));
    }
    Ok(normalized)
}

pub fn create_profile_package_pair(
    payload: &BfProfilePayload,
    password: &str,
) -> FrostUtilsResult<ProfilePackagePair> {
    let normalized = normalize_profile_payload(payload)?;
    Ok(ProfilePackagePair {
        profile_string: encode_bfprofile_package(&normalized, password)?,
        share_string: encode_bfshare_package(
            &BfSharePayload {
                share_secret: normalized.device.share_secret.clone(),
                relays: normalized.device.relays.clone(),
            },
            password,
        )?,
    })
}

pub fn create_encrypted_profile_backup(
    payload: &BfProfilePayload,
) -> FrostUtilsResult<EncryptedProfileBackup> {
    let normalized = normalize_profile_payload(payload)?;
    Ok(EncryptedProfileBackup {
        version: normalized.version,
        device: EncryptedProfileBackupDevice {
            name: normalized.device.name,
            share_public_key: derive_share_public_key_hex(&normalized.device.share_secret)?,
            manual_peer_policy_overrides: normalized.device.manual_peer_policy_overrides,
            relays: normalized.device.relays,
        },
        group_package: normalized.group_package,
    })
}

pub fn derive_profile_id_from_share_pubkey(share_pubkey_hex: &str) -> FrostUtilsResult<String> {
    let normalized = normalize_hex32(share_pubkey_hex, "share public key")?;
    let mut hasher = Sha256::new();
    hasher.update(PROFILE_ID_DOMAIN.as_bytes());
    hasher.update(hex::decode(normalized).expect("hex32"));
    Ok(hex::encode(hasher.finalize()))
}

pub fn derive_profile_id_from_share_secret(share_secret: &str) -> FrostUtilsResult<String> {
    let share_pubkey = derive_share_public_key_hex(share_secret)?;
    derive_profile_id_from_share_pubkey(&share_pubkey)
}

pub fn derive_profile_backup_conversation_key(share_secret: &str) -> FrostUtilsResult<[u8; 32]> {
    let share_secret = normalize_hex32(share_secret, "share secret")?;
    hmac_sha256(
        PROFILE_BACKUP_KEY_DOMAIN.as_bytes(),
        &hex::decode(&share_secret).expect("hex32"),
    )
}

pub fn encrypt_profile_backup_content(
    backup: &EncryptedProfileBackup,
    share_secret: &str,
) -> FrostUtilsResult<String> {
    let normalized = normalize_profile_backup(backup)?;
    let conversation_key = derive_profile_backup_conversation_key(share_secret)?;
    let plaintext = serde_json::to_string(&normalized)
        .map_err(|e| FrostUtilsError::Codec(format!("serialize backup payload: {e}")))?;
    encrypt_nip44_compatible_payload(&conversation_key, &plaintext)
}

pub fn decrypt_profile_backup_content(
    ciphertext: &str,
    share_secret: &str,
) -> FrostUtilsResult<EncryptedProfileBackup> {
    let conversation_key = derive_profile_backup_conversation_key(share_secret)?;
    let plaintext = decrypt_nip44_compatible_payload(&conversation_key, ciphertext)?;
    let backup: EncryptedProfileBackup = serde_json::from_str(&plaintext).map_err(|_| {
        FrostUtilsError::InvalidInput("Invalid encrypted profile backup.".to_string())
    })?;
    normalize_profile_backup(&backup)
}

pub fn build_profile_backup_event(
    share_secret: &str,
    backup: &EncryptedProfileBackup,
    created_at: Option<u64>,
) -> FrostUtilsResult<Event> {
    let share_secret = normalize_hex32(share_secret, "share secret")?;
    let secret = secret_key_from_hex(&share_secret)?;
    let keys = Keys::new(secret);
    let content = encrypt_profile_backup_content(backup, &share_secret)?;
    let mut builder = EventBuilder::new(Kind::Custom(PROFILE_BACKUP_EVENT_KIND), content);
    if let Some(created_at) = created_at {
        builder = builder.custom_created_at(Timestamp::from(created_at));
    }
    builder
        .sign_with_keys(&keys)
        .map_err(|e| FrostUtilsError::Crypto(format!("sign backup event: {e}")))
}

pub fn parse_profile_backup_event(
    event: &Event,
    share_secret: &str,
) -> FrostUtilsResult<EncryptedProfileBackup> {
    if event.kind != Kind::Custom(PROFILE_BACKUP_EVENT_KIND) {
        return Err(FrostUtilsError::WrongPackageMode(format!(
            "expected kind {PROFILE_BACKUP_EVENT_KIND}, got {}",
            event.kind.as_u16()
        )));
    }
    let share_secret = normalize_hex32(share_secret, "share secret")?;
    let expected_pubkey = Keys::new(secret_key_from_hex(&share_secret)?).public_key();
    if event.pubkey != expected_pubkey {
        return Err(FrostUtilsError::VerificationFailed(
            "backup event author does not match the provided share secret".to_string(),
        ));
    }
    let backup = decrypt_profile_backup_content(&event.content, &share_secret)?;
    let expected_share_pubkey = derive_share_public_key_hex(&share_secret)?;
    if backup.device.share_public_key != expected_share_pubkey {
        return Err(FrostUtilsError::VerificationFailed(
            "encrypted profile backup does not match the provided share".to_string(),
        ));
    }
    Ok(backup)
}

fn normalize_share_payload(payload: &BfSharePayload) -> FrostUtilsResult<BfSharePayload> {
    Ok(BfSharePayload {
        share_secret: normalize_hex32(&payload.share_secret, "share secret")?,
        relays: normalize_relays(&payload.relays)?,
    })
}

fn normalize_onboard_payload(payload: &BfOnboardPayload) -> FrostUtilsResult<BfOnboardPayload> {
    Ok(BfOnboardPayload {
        share_secret: normalize_hex32(&payload.share_secret, "share secret")?,
        relays: normalize_relays(&payload.relays)?,
        peer_pk: normalize_hex32(&payload.peer_pk, "peer public key")?,
    })
}

fn normalize_profile_payload(payload: &BfProfilePayload) -> FrostUtilsResult<BfProfilePayload> {
    let profile_id = normalize_hex32(&payload.profile_id, "profile id")?;
    let device_name = payload.device.name.trim();
    if device_name.is_empty() {
        return Err(FrostUtilsError::InvalidInput(
            "device name must be non-empty".to_string(),
        ));
    }
    let group = normalize_group_package(&payload.group_package)?;
    let manual_peer_policy_overrides = payload
        .device
        .manual_peer_policy_overrides
        .iter()
        .map(normalize_manual_peer_policy_override)
        .collect::<FrostUtilsResult<Vec<_>>>()?;
    let normalized = BfProfilePayload {
        profile_id,
        version: if payload.version == 0 {
            BF_PACKAGE_VERSION
        } else {
            payload.version
        },
        device: BfProfileDevice {
            name: device_name.to_string(),
            share_secret: normalize_hex32(&payload.device.share_secret, "share secret")?,
            manual_peer_policy_overrides,
            relays: normalize_relays(&payload.device.relays)?,
        },
        group_package: group,
    };
    let expected_profile_id = derive_profile_id_from_share_secret(&normalized.device.share_secret)?;
    if normalized.profile_id != expected_profile_id {
        return Err(FrostUtilsError::InvalidInput(
            "Invalid profile id.".to_string(),
        ));
    }
    Ok(normalized)
}

fn normalize_profile_backup(
    backup: &EncryptedProfileBackup,
) -> FrostUtilsResult<EncryptedProfileBackup> {
    let device_name = backup.device.name.trim();
    if device_name.is_empty() {
        return Err(FrostUtilsError::InvalidInput(
            "backup device name must be non-empty".to_string(),
        ));
    }
    let group_package = normalize_group_package(&backup.group_package)?;
    Ok(EncryptedProfileBackup {
        version: if backup.version == 0 {
            BF_PACKAGE_VERSION
        } else {
            backup.version
        },
        device: EncryptedProfileBackupDevice {
            name: device_name.to_string(),
            share_public_key: normalize_hex32(&backup.device.share_public_key, "share public key")?,
            manual_peer_policy_overrides: backup
                .device
                .manual_peer_policy_overrides
                .iter()
                .map(normalize_manual_peer_policy_override)
                .collect::<FrostUtilsResult<Vec<_>>>()?,
            relays: normalize_relays(&backup.device.relays)?,
        },
        group_package,
    })
}

fn normalize_manual_peer_policy_override(
    policy: &BfManualPeerPolicyOverride,
) -> FrostUtilsResult<BfManualPeerPolicyOverride> {
    Ok(BfManualPeerPolicyOverride {
        pubkey: normalize_hex32(&policy.pubkey, "peer policy pubkey")?,
        policy: normalize_peer_policy_override(&policy.policy),
    })
}

fn normalize_peer_policy_override(policy: &BfPeerPolicyOverride) -> BfPeerPolicyOverride {
    BfPeerPolicyOverride {
        request: normalize_method_policy_override(&policy.request),
        respond: normalize_method_policy_override(&policy.respond),
    }
}

fn normalize_method_policy_override(policy: &BfMethodPolicyOverride) -> BfMethodPolicyOverride {
    BfMethodPolicyOverride {
        echo: policy.echo,
        ping: policy.ping,
        onboard: policy.onboard,
        sign: policy.sign,
        ecdh: policy.ecdh,
    }
}

pub fn bf_policy_override_to_core(policy: &BfPeerPolicyOverride) -> PeerPolicyOverride {
    PeerPolicyOverride {
        request: bf_method_policy_override_to_core(&policy.request),
        respond: bf_method_policy_override_to_core(&policy.respond),
    }
}

pub fn bf_method_policy_override_to_core(policy: &BfMethodPolicyOverride) -> MethodPolicyOverride {
    MethodPolicyOverride {
        echo: bf_policy_override_value_to_core(policy.echo),
        ping: bf_policy_override_value_to_core(policy.ping),
        onboard: bf_policy_override_value_to_core(policy.onboard),
        sign: bf_policy_override_value_to_core(policy.sign),
        ecdh: bf_policy_override_value_to_core(policy.ecdh),
    }
}

pub fn bf_policy_override_value_to_core(value: BfPolicyOverrideValue) -> PolicyOverrideValue {
    match value {
        BfPolicyOverrideValue::Unset => PolicyOverrideValue::Unset,
        BfPolicyOverrideValue::Allow => PolicyOverrideValue::Allow,
        BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
    }
}

pub fn core_peer_policy_override_to_bf(policy: &PeerPolicyOverride) -> BfPeerPolicyOverride {
    BfPeerPolicyOverride {
        request: core_method_policy_override_to_bf(&policy.request),
        respond: core_method_policy_override_to_bf(&policy.respond),
    }
}

pub fn core_method_policy_override_to_bf(policy: &MethodPolicyOverride) -> BfMethodPolicyOverride {
    BfMethodPolicyOverride {
        echo: core_policy_override_value_to_bf(policy.echo),
        ping: core_policy_override_value_to_bf(policy.ping),
        onboard: core_policy_override_value_to_bf(policy.onboard),
        sign: core_policy_override_value_to_bf(policy.sign),
        ecdh: core_policy_override_value_to_bf(policy.ecdh),
    }
}

pub fn core_policy_override_value_to_bf(value: PolicyOverrideValue) -> BfPolicyOverrideValue {
    match value {
        PolicyOverrideValue::Unset => BfPolicyOverrideValue::Unset,
        PolicyOverrideValue::Allow => BfPolicyOverrideValue::Allow,
        PolicyOverrideValue::Deny => BfPolicyOverrideValue::Deny,
    }
}

fn normalize_group_package(group: &GroupPackageWire) -> FrostUtilsResult<GroupPackageWire> {
    let parsed: GroupPackage =
        group
            .clone()
            .try_into()
            .map_err(|e: bifrost_codec::CodecError| {
                FrostUtilsError::InvalidInput(format!("Invalid group package: {e}"))
            })?;
    Ok(GroupPackageWire::from(parsed))
}

fn normalize_relays(relays: &[String]) -> FrostUtilsResult<Vec<String>> {
    let normalized = relays
        .iter()
        .map(|relay| relay.trim().to_string())
        .filter(|relay| !relay.is_empty())
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return Err(FrostUtilsError::InvalidInput(
            "at least one relay is required".to_string(),
        ));
    }
    Ok(normalized)
}

fn normalize_hex32(value: &str, label: &str) -> FrostUtilsResult<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || normalized.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err(FrostUtilsError::InvalidInput(format!("Invalid {label}.")));
    }
    Ok(normalized)
}

fn build_compact_package_text_share(payload: &BfSharePayload) -> String {
    let mut serializer = Serializer::new(String::new());
    for relay in &payload.relays {
        serializer.append_pair("relay", relay);
    }
    format!("{}?{}", payload.share_secret, serializer.finish())
}

fn build_compact_package_text_onboard(payload: &BfOnboardPayload) -> String {
    let mut serializer = Serializer::new(String::new());
    for relay in &payload.relays {
        serializer.append_pair("relay", relay);
    }
    serializer.append_pair("peer_pk", &payload.peer_pk);
    format!("{}?{}", payload.share_secret, serializer.finish())
}

fn parse_compact_share_payload(plaintext: &str) -> FrostUtilsResult<BfSharePayload> {
    let (share_secret, query) = split_compact_package_text(plaintext)?;
    let mut relays = Vec::new();
    for (key, value) in parse_urlencoded(query.as_bytes()) {
        if key == "relay" {
            relays.push(value.into_owned());
        }
    }
    normalize_share_payload(&BfSharePayload {
        share_secret: share_secret.to_string(),
        relays,
    })
}

fn parse_compact_onboard_payload(plaintext: &str) -> FrostUtilsResult<BfOnboardPayload> {
    let (share_secret, query) = split_compact_package_text(plaintext)?;
    let mut relays = Vec::new();
    let mut peer_pk = None;
    for (key, value) in parse_urlencoded(query.as_bytes()) {
        match key.as_ref() {
            "relay" => relays.push(value.into_owned()),
            "peer_pk" => peer_pk = Some(value.into_owned()),
            _ => {}
        }
    }
    normalize_onboard_payload(&BfOnboardPayload {
        share_secret: share_secret.to_string(),
        relays,
        peer_pk: peer_pk.unwrap_or_default(),
    })
}

fn split_compact_package_text(plaintext: &str) -> FrostUtilsResult<(&str, &str)> {
    let trimmed = plaintext.trim();
    let Some((share_secret, query)) = trimmed.split_once('?') else {
        return Err(FrostUtilsError::InvalidInput(
            "compact package payload is missing query parameters".to_string(),
        ));
    };
    Ok((share_secret, query))
}

fn encrypt_plaintext_payload(
    prefix: &str,
    plaintext: &str,
    password: &str,
) -> FrostUtilsResult<String> {
    encrypt_plaintext_payload_with_params(prefix, plaintext, password, &Argon2Params::default())
}

fn encrypt_plaintext_payload_with_params(
    prefix: &str,
    plaintext: &str,
    password: &str,
    params: &Argon2Params,
) -> FrostUtilsResult<String> {
    let salt = random_salt();
    let nonce = random_nonce();
    let envelope = build_v2_envelope(prefix, password, plaintext, None, &salt, &nonce, params)?;
    encode_envelope(prefix, &envelope)
}

fn encrypt_profile_payload_with_outer_id(
    prefix: &str,
    profile_id: &str,
    plaintext: &str,
    password: &str,
) -> FrostUtilsResult<String> {
    encrypt_profile_payload_with_outer_id_and_params(
        prefix,
        profile_id,
        plaintext,
        password,
        &Argon2Params::default(),
    )
}

fn encrypt_profile_payload_with_outer_id_and_params(
    prefix: &str,
    profile_id: &str,
    plaintext: &str,
    password: &str,
    params: &Argon2Params,
) -> FrostUtilsResult<String> {
    let normalized_profile_id = normalize_hex32(profile_id, "profile id")?;
    let salt = random_salt();
    let nonce = random_nonce();
    let envelope = build_v2_envelope(
        prefix,
        password,
        plaintext,
        Some(&normalized_profile_id),
        &salt,
        &nonce,
        params,
    )?;
    encode_profile_envelope(prefix, &normalized_profile_id, &envelope)
}

fn build_v2_envelope(
    prefix: &str,
    password: &str,
    plaintext: &str,
    outer_id: Option<&str>,
    salt: &[u8; PACKAGE_KDF_SALT_LEN],
    nonce: &[u8; BF_PACKAGE_XCHACHA_NONCE_BYTES],
    params: &Argon2Params,
) -> FrostUtilsResult<ProtectedPackageEnvelope> {
    let aad = build_aad_package(BF_PACKAGE_VERSION, prefix, salt, outer_id)?;
    let key = derive_package_encryption_key_v2(password, salt, params)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| FrostUtilsError::DecryptionFailed)?;
    Ok(ProtectedPackageEnvelope {
        version: BF_PACKAGE_VERSION,
        kdf: KDF_MARKER_ARGON2ID.to_string(),
        kdf_m_cost: params.m_cost(),
        kdf_t_cost: params.t_cost(),
        kdf_p_cost: params.p_cost(),
        aead: AEAD_MARKER_XCHACHA20POLY1305.to_string(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
    })
}

fn decrypt_plaintext_payload(
    prefix: &str,
    package_text: &str,
    password: &str,
) -> FrostUtilsResult<String> {
    let envelope = decode_envelope(prefix, package_text)?;
    decrypt_v2_envelope(prefix, &envelope, password, None)
}

fn decrypt_profile_payload_with_outer_id(
    prefix: &str,
    package_text: &str,
    password: &str,
) -> FrostUtilsResult<(String, String)> {
    let (profile_id, envelope) = decode_profile_envelope(prefix, package_text)?;
    let plaintext = decrypt_v2_envelope(prefix, &envelope, password, Some(&profile_id))?;
    Ok((profile_id, plaintext))
}

fn decrypt_v2_envelope(
    prefix: &str,
    envelope: &ProtectedPackageEnvelope,
    password: &str,
    outer_id: Option<&str>,
) -> FrostUtilsResult<String> {
    if envelope.version != BF_PACKAGE_VERSION {
        return Err(FrostUtilsError::UnsupportedVersion(envelope.version));
    }
    if envelope.kdf != KDF_MARKER_ARGON2ID {
        return Err(FrostUtilsError::UnsupportedKdf(envelope.kdf.clone()));
    }
    if envelope.aead != AEAD_MARKER_XCHACHA20POLY1305 {
        return Err(FrostUtilsError::UnsupportedAead(envelope.aead.clone()));
    }
    let params = Argon2Params::new(envelope.kdf_m_cost, envelope.kdf_t_cost, envelope.kdf_p_cost)
        .map_err(FrostUtilsError::from)?;
    let salt_bytes = hex::decode(&envelope.salt_hex)
        .map_err(|e| FrostUtilsError::Codec(format!("decode {prefix} salt: {e}")))?;
    if salt_bytes.len() != PACKAGE_KDF_SALT_LEN {
        return Err(FrostUtilsError::Codec(format!(
            "{prefix} salt length {} != {}",
            salt_bytes.len(),
            PACKAGE_KDF_SALT_LEN
        )));
    }
    let mut salt = [0u8; PACKAGE_KDF_SALT_LEN];
    salt.copy_from_slice(&salt_bytes);

    let nonce_bytes = hex::decode(&envelope.nonce_hex)
        .map_err(|e| FrostUtilsError::Codec(format!("decode {prefix} nonce: {e}")))?;
    if nonce_bytes.len() != BF_PACKAGE_XCHACHA_NONCE_BYTES {
        return Err(FrostUtilsError::Codec(format!(
            "{prefix} nonce length {} != {}",
            nonce_bytes.len(),
            BF_PACKAGE_XCHACHA_NONCE_BYTES
        )));
    }

    let aad = build_aad_package(BF_PACKAGE_VERSION, prefix, &salt, outer_id)?;
    let key = derive_package_encryption_key_v2(password, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = URL_SAFE_NO_PAD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| FrostUtilsError::Codec(format!("Invalid {prefix} package.")))?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| FrostUtilsError::DecryptionFailed)?;
    String::from_utf8(plaintext)
        .map_err(|e| FrostUtilsError::Codec(format!("decode {prefix} plaintext: {e}")))
}

fn random_salt() -> [u8; PACKAGE_KDF_SALT_LEN] {
    let mut buf = [0u8; PACKAGE_KDF_SALT_LEN];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn random_nonce() -> [u8; BF_PACKAGE_XCHACHA_NONCE_BYTES] {
    let mut buf = [0u8; BF_PACKAGE_XCHACHA_NONCE_BYTES];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn encode_envelope(prefix: &str, envelope: &ProtectedPackageEnvelope) -> FrostUtilsResult<String> {
    let bytes = serde_json::to_vec(envelope)
        .map_err(|e| FrostUtilsError::Codec(format!("serialize package envelope: {e}")))?;
    let hrp = Hrp::parse(prefix).map_err(|e| FrostUtilsError::Codec(e.to_string()))?;
    let mut out = String::with_capacity(prefix.len() + 1 + bytes.len() * 2);
    out.extend(
        bytes
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .chars(),
    );
    Ok(out)
}

fn encode_profile_envelope(
    prefix: &str,
    profile_id: &str,
    envelope: &ProtectedPackageEnvelope,
) -> FrostUtilsResult<String> {
    let normalized_profile_id = normalize_hex32(profile_id, "profile id")?;
    let envelope_bytes = serde_json::to_vec(envelope)
        .map_err(|e| FrostUtilsError::Codec(format!("serialize package envelope: {e}")))?;
    let mut bytes = Vec::with_capacity(64 + envelope_bytes.len());
    bytes.extend_from_slice(normalized_profile_id.as_bytes());
    bytes.extend_from_slice(&envelope_bytes);
    let hrp = Hrp::parse(prefix).map_err(|e| FrostUtilsError::Codec(e.to_string()))?;
    let mut out = String::with_capacity(prefix.len() + 1 + bytes.len() * 2);
    out.extend(
        bytes
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .chars(),
    );
    Ok(out)
}

fn decode_envelope(prefix: &str, value: &str) -> FrostUtilsResult<ProtectedPackageEnvelope> {
    let unchecked = UncheckedHrpstring::new(value)
        .map_err(|_| FrostUtilsError::Codec(format!("Invalid {prefix} package.")))?;
    if unchecked.hrp().as_str() != prefix {
        return Err(FrostUtilsError::WrongPackageMode(format!(
            "Expected {prefix} package."
        )));
    }
    validate_checksum_unchecked::<Bech32m>(&unchecked)
        .map_err(|_| FrostUtilsError::Codec(format!("Invalid {prefix} package.")))?;
    let ascii = &unchecked.data_part_ascii()
        [..unchecked.data_part_ascii().len() - Bech32m::CHECKSUM_LENGTH];
    let bytes = ascii
        .iter()
        .map(|&b| Fe32::from_char_unchecked(b))
        .fes_to_bytes()
        .collect::<Vec<u8>>();
    serde_json::from_slice(&bytes)
        .map_err(|_| FrostUtilsError::Codec(format!("Invalid {prefix} package.")))
}

fn decode_profile_envelope(
    prefix: &str,
    value: &str,
) -> FrostUtilsResult<(String, ProtectedPackageEnvelope)> {
    let unchecked = UncheckedHrpstring::new(value)
        .map_err(|_| FrostUtilsError::Codec(format!("Invalid {prefix} package.")))?;
    if unchecked.hrp().as_str() != prefix {
        return Err(FrostUtilsError::WrongPackageMode(format!(
            "Expected {prefix} package."
        )));
    }
    validate_checksum_unchecked::<Bech32m>(&unchecked)
        .map_err(|_| FrostUtilsError::Codec(format!("Invalid {prefix} package.")))?;
    let ascii = &unchecked.data_part_ascii()
        [..unchecked.data_part_ascii().len() - Bech32m::CHECKSUM_LENGTH];
    let bytes = ascii
        .iter()
        .map(|&b| Fe32::from_char_unchecked(b))
        .fes_to_bytes()
        .collect::<Vec<u8>>();
    if bytes.len() <= 64 {
        return Err(FrostUtilsError::Codec(format!("Invalid {prefix} package.")));
    }
    let profile_id = std::str::from_utf8(&bytes[..64])
        .map_err(|_| FrostUtilsError::Codec(format!("Invalid {prefix} package.")))?;
    let normalized_profile_id = normalize_hex32(profile_id, "profile id")
        .map_err(|_| FrostUtilsError::Codec(format!("Invalid {prefix} package.")))?;
    let envelope: ProtectedPackageEnvelope = serde_json::from_slice(&bytes[64..])
        .map_err(|_| FrostUtilsError::Codec(format!("Invalid {prefix} package.")))?;
    Ok((normalized_profile_id, envelope))
}

fn validate_checksum_unchecked<Ck: bech32::Checksum>(
    unchecked: &UncheckedHrpstring<'_>,
) -> Result<(), ()> {
    if unchecked.data_part_ascii().len() < Ck::CHECKSUM_LENGTH {
        return Err(());
    }
    let mut checksum_engine = ChecksumEngine::<Ck>::new();
    checksum_engine.input_hrp(unchecked.hrp());
    for fe in unchecked
        .data_part_ascii()
        .iter()
        .map(|&b| Fe32::from_char_unchecked(b))
    {
        checksum_engine.input_fe(fe);
    }
    if checksum_engine.residue() != &Ck::TARGET_RESIDUE {
        return Err(());
    }
    Ok(())
}

fn derive_share_public_key_hex(share_secret: &str) -> FrostUtilsResult<String> {
    let secret = secret_key_from_hex(share_secret)?;
    Ok(Keys::new(secret)
        .public_key()
        .to_string()
        .to_ascii_lowercase())
}

fn secret_key_from_hex(hex32: &str) -> FrostUtilsResult<SecretKey> {
    let bytes = hex::decode(hex32)
        .map_err(|e| FrostUtilsError::InvalidInput(format!("invalid share secret: {e}")))?;
    SecretKey::from_slice(&bytes)
        .map_err(|e| FrostUtilsError::InvalidInput(format!("invalid share secret: {e}")))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> FrostUtilsResult<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| FrostUtilsError::Crypto(format!("HMAC init failed: {e}")))?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn encrypt_nip44_compatible_payload(
    conversation_key: &[u8; 32],
    plaintext: &str,
) -> FrostUtilsResult<String> {
    let mut nonce32 = [0u8; 32];
    OsRng.fill_bytes(&mut nonce32);
    bifrost_core::nip44::encrypt_under_conversation_key(conversation_key, &nonce32, plaintext)
        .map_err(cipher_error)
}

fn decrypt_nip44_compatible_payload(
    conversation_key: &[u8; 32],
    payload: &str,
) -> FrostUtilsResult<String> {
    bifrost_core::nip44::decrypt_under_conversation_key(conversation_key, payload)
        .map_err(cipher_error)
}

/// Map `bifrost_core::nip44::CipherError` onto the crate's native error
/// type. Cipher-level failures collapse to `DecryptionFailed` to keep the
/// pre-consolidation caller contract; structural / input errors surface
/// as `Crypto` / `InvalidInput` so the underlying diagnostic is not lost.
fn cipher_error(e: bifrost_core::nip44::CipherError) -> FrostUtilsError {
    use bifrost_core::nip44::CipherError;
    match e {
        CipherError::InvalidVersion
        | CipherError::PayloadTooShort
        | CipherError::MacMismatch
        | CipherError::BadUtf8 => FrostUtilsError::DecryptionFailed,
        CipherError::BadBase64(msg) => {
            FrostUtilsError::Codec(format!("invalid backup base64: {msg}"))
        }
        CipherError::BadLength(msg) => FrostUtilsError::InvalidInput(msg),
        CipherError::Crypto(msg) => FrostUtilsError::Crypto(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD_NO_PAD;

    fn sample_profile() -> BfProfilePayload {
        let device = BfProfileDevice {
            name: "Alice Laptop".to_string(),
            share_secret: "11".repeat(32),
            manual_peer_policy_overrides: vec![BfManualPeerPolicyOverride {
                pubkey: "22".repeat(32),
                policy: BfPeerPolicyOverride {
                    request: BfMethodPolicyOverride {
                        echo: BfPolicyOverrideValue::Unset,
                        ping: BfPolicyOverrideValue::Unset,
                        onboard: BfPolicyOverrideValue::Unset,
                        sign: BfPolicyOverrideValue::Allow,
                        ecdh: BfPolicyOverrideValue::Unset,
                    },
                    respond: BfMethodPolicyOverride {
                        echo: BfPolicyOverrideValue::Unset,
                        ping: BfPolicyOverrideValue::Unset,
                        onboard: BfPolicyOverrideValue::Unset,
                        sign: BfPolicyOverrideValue::Deny,
                        ecdh: BfPolicyOverrideValue::Unset,
                    },
                },
            }],
            relays: vec!["wss://relay.one".to_string(), "wss://relay.two".to_string()],
        };
        BfProfilePayload {
            profile_id: derive_profile_id_from_share_secret(&device.share_secret)
                .expect("profile id"),
            version: BF_PACKAGE_VERSION,
            device,
            group_package: GroupPackageWire {
                group_name: "Alpha".to_string(),
                group_pk: "33".repeat(32),
                threshold: 2,
                members: vec![
                    bifrost_codec::wire::MemberPackageWire {
                        idx: 1,
                        pubkey: format!("02{}", "44".repeat(32)),
                    },
                    bifrost_codec::wire::MemberPackageWire {
                        idx: 2,
                        pubkey: format!("03{}", "55".repeat(32)),
                    },
                    bifrost_codec::wire::MemberPackageWire {
                        idx: 3,
                        pubkey: format!("02{}", "66".repeat(32)),
                    },
                ],
            },
        }
    }

    #[test]
    fn bfshare_round_trip_preserves_relay_order() {
        let payload = BfSharePayload {
            share_secret: "11".repeat(32),
            relays: vec!["wss://relay.two".into(), "wss://relay.one".into()],
        };
        let encoded = encode_bfshare_package(&payload, "secret").expect("encode");
        let decoded = decode_bfshare_package(&encoded, "secret").expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn bfonboard_requires_peer_pk() {
        let err = normalize_onboard_payload(&BfOnboardPayload {
            share_secret: "11".repeat(32),
            relays: vec!["wss://relay.one".into()],
            peer_pk: String::new(),
        })
        .expect_err("missing peer pk must fail");
        assert!(err.to_string().contains("peer public key"));
    }

    #[test]
    fn bfprofile_round_trip() {
        let profile = sample_profile();
        let encoded = encode_bfprofile_package(&profile, "secret").expect("encode");
        let decoded = decode_bfprofile_package(&encoded, "secret").expect("decode");
        assert_eq!(decoded, profile);
    }

    #[test]
    fn create_profile_package_pair_uses_final_formats() {
        let pair = create_profile_package_pair(&sample_profile(), "secret").expect("pair");
        assert!(pair.profile_string.starts_with("bfprofile1"));
        assert!(pair.share_string.starts_with("bfshare1"));
    }

    #[test]
    fn bfprofile_rejects_mismatched_profile_id() {
        let mut profile = sample_profile();
        profile.profile_id = "aa".repeat(32);
        let err = encode_bfprofile_package(&profile, "secret")
            .expect_err("mismatched profile id must fail");
        assert!(err.to_string().contains("Invalid profile id"));
    }

    #[test]
    fn backup_encrypt_decrypt_round_trip() {
        let profile = sample_profile();
        let backup = create_encrypted_profile_backup(&profile).expect("backup");
        let ciphertext =
            encrypt_profile_backup_content(&backup, &profile.device.share_secret).expect("encrypt");
        let decrypted = decrypt_profile_backup_content(&ciphertext, &profile.device.share_secret)
            .expect("decrypt");
        assert_eq!(decrypted, backup);
    }

    #[test]
    fn odd_parity_member_pubkeys_survive_profile_and_backup_round_trips() {
        let profile = sample_profile();
        let expected_pubkeys = profile
            .group_package
            .members
            .iter()
            .map(|member| member.pubkey.clone())
            .collect::<Vec<_>>();
        assert!(
            expected_pubkeys
                .iter()
                .any(|pubkey| pubkey.starts_with("03")),
            "sample profile must include an odd-parity compressed member pubkey"
        );

        let encoded = encode_bfprofile_package(&profile, "secret").expect("encode");
        let decoded = decode_bfprofile_package(&encoded, "secret").expect("decode");
        let decoded_pubkeys = decoded
            .group_package
            .members
            .iter()
            .map(|member| member.pubkey.clone())
            .collect::<Vec<_>>();
        assert_eq!(decoded_pubkeys, expected_pubkeys);

        let backup = create_encrypted_profile_backup(&profile).expect("backup");
        let ciphertext =
            encrypt_profile_backup_content(&backup, &profile.device.share_secret).expect("encrypt");
        let decrypted = decrypt_profile_backup_content(&ciphertext, &profile.device.share_secret)
            .expect("decrypt");
        let backup_pubkeys = decrypted
            .group_package
            .members
            .iter()
            .map(|member| member.pubkey.clone())
            .collect::<Vec<_>>();
        assert_eq!(backup_pubkeys, expected_pubkeys);
    }

    #[test]
    fn build_and_parse_backup_event_round_trip() {
        let profile = sample_profile();
        let backup = create_encrypted_profile_backup(&profile).expect("backup");
        let event =
            build_profile_backup_event(&profile.device.share_secret, &backup, Some(1_700_000_000))
                .expect("build event");
        assert_eq!(event.kind, Kind::Custom(PROFILE_BACKUP_EVENT_KIND));
        let parsed =
            parse_profile_backup_event(&event, &profile.device.share_secret).expect("parse");
        assert_eq!(parsed, backup);
    }

    #[test]
    fn wrong_password_fails_decode() {
        let payload = BfSharePayload {
            share_secret: "11".repeat(32),
            relays: vec!["wss://relay.one".into()],
        };
        let encoded = encode_bfshare_package(&payload, "secret").expect("encode");
        let err = decode_bfshare_package(&encoded, "wrong").expect_err("wrong password must fail");
        matches!(err, FrostUtilsError::DecryptionFailed);
    }

    /// Flip a single bit in the MAC tag at four probed positions on a
    /// profile-backup payload and confirm `decrypt_nip44_compatible_payload`
    /// rejects every tampered variant. Guards the constant-time MAC compare.
    #[test]
    fn decrypt_nip44_compatible_payload_rejects_mac_mismatch_at_every_probed_position() {
        let conversation_key = [0xABu8; 32];
        let ciphertext = encrypt_nip44_compatible_payload(&conversation_key, "mac-probe-backup")
            .expect("encrypt");
        let bytes = STANDARD_NO_PAD
            .decode(ciphertext.as_bytes())
            .expect("decode payload");
        let mac_start = bytes.len() - 32;

        let probes: &[(usize, u8)] = &[(0, 0x80), (16, 0x01), (31, 0x40), (0, 0x01)];
        for &(offset, mask) in probes {
            let mut tampered = bytes.clone();
            tampered[mac_start + offset] ^= mask;
            let encoded = STANDARD_NO_PAD.encode(&tampered);
            let err = decrypt_nip44_compatible_payload(&conversation_key, &encoded).expect_err(
                &format!("mac flip at offset {offset:#x} mask {mask:#x} must fail"),
            );
            assert!(matches!(err, FrostUtilsError::DecryptionFailed));
        }
    }
}
