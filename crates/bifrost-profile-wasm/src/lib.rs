use bifrost_codec::wire::{GroupPackageWire, MemberPackageWire};
use bifrost_profile::{
    RelayProfile, derive_profile_id_for_share_secret, preview_from_profile_payload,
    validate_relay_profile,
};
use frostr_utils::{
    BF_PACKAGE_VERSION, BfManualPeerPolicyOverride, BfOnboardPayload, BfProfileDevice,
    BfProfilePayload, BfSharePayload, EncryptedProfileBackup, EncryptedProfileBackupDevice,
    PREFIX_BFONBOARD, PREFIX_BFPROFILE, PREFIX_BFSHARE, PROFILE_BACKUP_EVENT_KIND,
    PROFILE_BACKUP_KEY_DOMAIN, ProfilePackagePair,
    build_profile_backup_event as rust_build_profile_backup_event,
    create_encrypted_profile_backup as rust_create_encrypted_profile_backup,
    create_profile_package_pair as rust_create_profile_package_pair,
    decode_bfonboard_package as rust_decode_bfonboard_package,
    decode_bfprofile_package as rust_decode_bfprofile_package,
    decode_bfshare_package as rust_decode_bfshare_package,
    decrypt_profile_backup_content as rust_decrypt_profile_backup_content,
    derive_profile_backup_conversation_key as rust_derive_profile_backup_conversation_key,
    derive_profile_id_from_share_pubkey as rust_derive_profile_id_from_share_pubkey,
    encode_bfonboard_package as rust_encode_bfonboard_package,
    encode_bfprofile_package as rust_encode_bfprofile_package,
    encode_bfshare_package as rust_encode_bfshare_package,
    encrypt_profile_backup_content as rust_encrypt_profile_backup_content,
    parse_profile_backup_event as rust_parse_profile_backup_event,
};
use nostr::Event;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
type HostError = JsValue;
#[cfg(not(target_arch = "wasm32"))]
type HostError = String;

type HostResult<T> = std::result::Result<T, HostError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserGroupPackageMember {
    idx: u16,
    pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserGroupPackage {
    group_name: String,
    group_pk: String,
    threshold: u16,
    members: Vec<BrowserGroupPackageMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserSharePackagePayload {
    share_secret: String,
    relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserOnboardPackagePayload {
    share_secret: String,
    relays: Vec<String>,
    peer_pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserProfilePackageDevice {
    name: String,
    share_secret: String,
    #[serde(default)]
    manual_peer_policy_overrides: Vec<BfManualPeerPolicyOverride>,
    relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserProfilePackagePayload {
    profile_id: String,
    version: u8,
    device: BrowserProfilePackageDevice,
    group_package: BrowserGroupPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserEncryptedProfileBackupDevice {
    name: String,
    share_public_key: String,
    #[serde(default)]
    manual_peer_policy_overrides: Vec<BfManualPeerPolicyOverride>,
    relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserEncryptedProfileBackup {
    version: u8,
    device: BrowserEncryptedProfileBackupDevice,
    group_package: BrowserGroupPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserProfilePackagePair {
    profile_string: String,
    share_string: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserBfshareRecoveryPreview {
    profile_id: String,
    share: BrowserSharePackagePayload,
}

#[cfg(target_arch = "wasm32")]
fn to_host_error(message: impl Into<String>) -> HostError {
    JsValue::from_str(&message.into())
}

#[cfg(not(target_arch = "wasm32"))]
fn to_host_error(message: impl Into<String>) -> HostError {
    message.into()
}

fn parse_json<T: DeserializeOwned>(value: &str, label: &str) -> HostResult<T> {
    serde_json::from_str(value).map_err(|error| to_host_error(format!("parse {label}: {error}")))
}

fn to_json<T: Serialize>(value: &T, label: &str) -> HostResult<String> {
    serde_json::to_string(value)
        .map_err(|error| to_host_error(format!("serialize {label}: {error}")))
}

fn browser_group_from_wire(group: &GroupPackageWire) -> BrowserGroupPackage {
    BrowserGroupPackage {
        group_name: group.group_name.clone(),
        group_pk: group.group_pk.clone(),
        threshold: group.threshold,
        members: group
            .members
            .iter()
            .map(|member| BrowserGroupPackageMember {
                idx: member.idx,
                pubkey: member.pubkey.clone(),
            })
            .collect(),
    }
}

fn wire_group_from_browser(group: BrowserGroupPackage) -> GroupPackageWire {
    GroupPackageWire {
        group_name: group.group_name,
        group_pk: group.group_pk,
        threshold: group.threshold,
        members: group
            .members
            .into_iter()
            .map(|member| MemberPackageWire {
                idx: member.idx,
                pubkey: member.pubkey,
            })
            .collect(),
    }
}

fn browser_share_from_payload(payload: &BfSharePayload) -> BrowserSharePackagePayload {
    BrowserSharePackagePayload {
        share_secret: payload.share_secret.clone(),
        relays: payload.relays.clone(),
    }
}

fn payload_share_from_browser(payload: BrowserSharePackagePayload) -> BfSharePayload {
    BfSharePayload {
        share_secret: payload.share_secret,
        relays: payload.relays,
    }
}

fn browser_onboard_from_payload(payload: &BfOnboardPayload) -> BrowserOnboardPackagePayload {
    BrowserOnboardPackagePayload {
        share_secret: payload.share_secret.clone(),
        relays: payload.relays.clone(),
        peer_pubkey: payload.peer_pk.clone(),
    }
}

fn payload_onboard_from_browser(payload: BrowserOnboardPackagePayload) -> BfOnboardPayload {
    BfOnboardPayload {
        share_secret: payload.share_secret,
        relays: payload.relays,
        peer_pk: payload.peer_pubkey,
    }
}

fn browser_profile_from_payload(payload: &BfProfilePayload) -> BrowserProfilePackagePayload {
    BrowserProfilePackagePayload {
        profile_id: payload.profile_id.clone(),
        version: payload.version,
        device: BrowserProfilePackageDevice {
            name: payload.device.name.clone(),
            share_secret: payload.device.share_secret.clone(),
            manual_peer_policy_overrides: payload.device.manual_peer_policy_overrides.clone(),
            relays: payload.device.relays.clone(),
        },
        group_package: browser_group_from_wire(&payload.group_package),
    }
}

fn payload_profile_from_browser(payload: BrowserProfilePackagePayload) -> BfProfilePayload {
    BfProfilePayload {
        profile_id: payload.profile_id,
        version: payload.version,
        device: BfProfileDevice {
            name: payload.device.name,
            share_secret: payload.device.share_secret,
            manual_peer_policy_overrides: payload.device.manual_peer_policy_overrides,
            relays: payload.device.relays,
        },
        group_package: wire_group_from_browser(payload.group_package),
    }
}

fn browser_backup_from_payload(backup: &EncryptedProfileBackup) -> BrowserEncryptedProfileBackup {
    BrowserEncryptedProfileBackup {
        version: backup.version,
        device: BrowserEncryptedProfileBackupDevice {
            name: backup.device.name.clone(),
            share_public_key: backup.device.share_public_key.clone(),
            manual_peer_policy_overrides: backup.device.manual_peer_policy_overrides.clone(),
            relays: backup.device.relays.clone(),
        },
        group_package: browser_group_from_wire(&backup.group_package),
    }
}

fn payload_backup_from_browser(backup: BrowserEncryptedProfileBackup) -> EncryptedProfileBackup {
    EncryptedProfileBackup {
        version: backup.version,
        device: EncryptedProfileBackupDevice {
            name: backup.device.name,
            share_public_key: backup.device.share_public_key,
            manual_peer_policy_overrides: backup.device.manual_peer_policy_overrides,
            relays: backup.device.relays,
        },
        group_package: wire_group_from_browser(backup.group_package),
    }
}

fn browser_pair_from_payload(pair: &ProfilePackagePair) -> BrowserProfilePackagePair {
    BrowserProfilePackagePair {
        profile_string: pair.profile_string.clone(),
        share_string: pair.share_string.clone(),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn validate_relay_profile_json(profile_json: &str) -> HostResult<String> {
    let profile: RelayProfile = parse_json(profile_json, "relay profile")?;
    validate_relay_profile(&profile).map_err(|error| to_host_error(error.to_string()))?;
    to_json(&profile, "relay profile")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn bf_package_version() -> u8 {
    BF_PACKAGE_VERSION
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn bfshare_prefix() -> String {
    PREFIX_BFSHARE.to_string()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn bfonboard_prefix() -> String {
    PREFIX_BFONBOARD.to_string()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn bfprofile_prefix() -> String {
    PREFIX_BFPROFILE.to_string()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn profile_backup_event_kind() -> u16 {
    PROFILE_BACKUP_EVENT_KIND
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn profile_backup_key_domain() -> String {
    PROFILE_BACKUP_KEY_DOMAIN.to_string()
}

pub fn derive_profile_id_from_share_secret_export(share_secret: &str) -> HostResult<String> {
    derive_profile_id_for_share_secret(share_secret)
        .map_err(|error| to_host_error(error.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn derive_profile_id_from_share_secret(share_secret: &str) -> HostResult<String> {
    derive_profile_id_from_share_secret_export(share_secret)
}

pub fn derive_profile_id_from_share_pubkey_export(share_pubkey: &str) -> HostResult<String> {
    rust_derive_profile_id_from_share_pubkey(share_pubkey)
        .map_err(|error| to_host_error(error.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn derive_profile_id_from_share_pubkey(share_pubkey: &str) -> HostResult<String> {
    derive_profile_id_from_share_pubkey_export(share_pubkey)
}

pub fn encode_bfprofile_package_json(payload_json: &str, password: &str) -> HostResult<String> {
    let payload = payload_profile_from_browser(parse_json(payload_json, "bfprofile payload")?);
    rust_encode_bfprofile_package(&payload, password)
        .map_err(|error| to_host_error(error.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encode_bfprofile_package(payload_json: &str, password: &str) -> HostResult<String> {
    encode_bfprofile_package_json(payload_json, password)
}

pub fn decode_bfprofile_package_json(package_text: &str, password: &str) -> HostResult<String> {
    let payload = rust_decode_bfprofile_package(package_text, password)
        .map_err(|error| to_host_error(error.to_string()))?;
    to_json(&browser_profile_from_payload(&payload), "bfprofile payload")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decode_bfprofile_package(package_text: &str, password: &str) -> HostResult<String> {
    decode_bfprofile_package_json(package_text, password)
}

pub fn preview_bfprofile_package_json(
    package_text: &str,
    password: &str,
    label_override: Option<String>,
) -> HostResult<String> {
    let payload = rust_decode_bfprofile_package(package_text, password)
        .map_err(|error| to_host_error(error.to_string()))?;
    let preview = preview_from_profile_payload(&payload, label_override, "bfprofile")
        .map_err(|error| to_host_error(error.to_string()))?;
    to_json(&preview, "profile preview")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn preview_bfprofile_package(
    package_text: &str,
    password: &str,
    label_override: Option<String>,
) -> HostResult<String> {
    preview_bfprofile_package_json(package_text, password, label_override)
}

pub fn encode_bfshare_package_json(payload_json: &str, password: &str) -> HostResult<String> {
    let payload = payload_share_from_browser(parse_json(payload_json, "bfshare payload")?);
    rust_encode_bfshare_package(&payload, password)
        .map_err(|error| to_host_error(error.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encode_bfshare_package(payload_json: &str, password: &str) -> HostResult<String> {
    encode_bfshare_package_json(payload_json, password)
}

pub fn decode_bfshare_package_json(package_text: &str, password: &str) -> HostResult<String> {
    let payload = rust_decode_bfshare_package(package_text, password)
        .map_err(|error| to_host_error(error.to_string()))?;
    to_json(&browser_share_from_payload(&payload), "bfshare payload")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decode_bfshare_package(package_text: &str, password: &str) -> HostResult<String> {
    decode_bfshare_package_json(package_text, password)
}

pub fn encode_bfonboard_package_json(payload_json: &str, password: &str) -> HostResult<String> {
    let payload = payload_onboard_from_browser(parse_json(payload_json, "bfonboard payload")?);
    rust_encode_bfonboard_package(&payload, password)
        .map_err(|error| to_host_error(error.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encode_bfonboard_package(payload_json: &str, password: &str) -> HostResult<String> {
    encode_bfonboard_package_json(payload_json, password)
}

pub fn decode_bfonboard_package_json(package_text: &str, password: &str) -> HostResult<String> {
    let payload = rust_decode_bfonboard_package(package_text, password)
        .map_err(|error| to_host_error(error.to_string()))?;
    to_json(&browser_onboard_from_payload(&payload), "bfonboard payload")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decode_bfonboard_package(package_text: &str, password: &str) -> HostResult<String> {
    decode_bfonboard_package_json(package_text, password)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn preview_bfshare_recovery_json(package_text: &str, password: &str) -> HostResult<String> {
    let share = rust_decode_bfshare_package(package_text, password)
        .map_err(|error| to_host_error(error.to_string()))?;
    let preview = BrowserBfshareRecoveryPreview {
        profile_id: derive_profile_id_for_share_secret(&share.share_secret)
            .map_err(|error| to_host_error(error.to_string()))?,
        share: browser_share_from_payload(&share),
    };
    to_json(&preview, "bfshare recovery preview")
}

pub fn create_profile_package_pair_json(payload_json: &str, password: &str) -> HostResult<String> {
    let payload = payload_profile_from_browser(parse_json(payload_json, "bfprofile payload")?);
    let pair = rust_create_profile_package_pair(&payload, password)
        .map_err(|error| to_host_error(error.to_string()))?;
    to_json(&browser_pair_from_payload(&pair), "profile package pair")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn create_profile_package_pair(payload_json: &str, password: &str) -> HostResult<String> {
    create_profile_package_pair_json(payload_json, password)
}

pub fn create_encrypted_profile_backup_json(profile_json: &str) -> HostResult<String> {
    let profile = payload_profile_from_browser(parse_json(profile_json, "bfprofile payload")?);
    let backup = rust_create_encrypted_profile_backup(&profile)
        .map_err(|error| to_host_error(error.to_string()))?;
    to_json(&browser_backup_from_payload(&backup), "encrypted profile backup")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn create_encrypted_profile_backup(profile_json: &str) -> HostResult<String> {
    create_encrypted_profile_backup_json(profile_json)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn derive_profile_backup_conversation_key_hex(share_secret: &str) -> HostResult<String> {
    let key = rust_derive_profile_backup_conversation_key(share_secret)
        .map_err(|error| to_host_error(error.to_string()))?;
    Ok(hex::encode(key))
}

pub fn encrypt_profile_backup_content_json(
    backup_json: &str,
    share_secret: &str,
) -> HostResult<String> {
    let backup =
        payload_backup_from_browser(parse_json(backup_json, "encrypted profile backup")?);
    rust_encrypt_profile_backup_content(&backup, share_secret)
        .map_err(|error| to_host_error(error.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encrypt_profile_backup_content(backup_json: &str, share_secret: &str) -> HostResult<String> {
    encrypt_profile_backup_content_json(backup_json, share_secret)
}

pub fn decrypt_profile_backup_content_json(
    ciphertext: &str,
    share_secret: &str,
) -> HostResult<String> {
    let backup = rust_decrypt_profile_backup_content(ciphertext, share_secret)
        .map_err(|error| to_host_error(error.to_string()))?;
    to_json(&browser_backup_from_payload(&backup), "encrypted profile backup")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decrypt_profile_backup_content(ciphertext: &str, share_secret: &str) -> HostResult<String> {
    decrypt_profile_backup_content_json(ciphertext, share_secret)
}

pub fn build_profile_backup_event_json(
    share_secret: &str,
    backup_json: &str,
    created_at_seconds: Option<u32>,
) -> HostResult<String> {
    let backup =
        payload_backup_from_browser(parse_json(backup_json, "encrypted profile backup")?);
    let event =
        rust_build_profile_backup_event(share_secret, &backup, created_at_seconds.map(u64::from))
            .map_err(|error| to_host_error(error.to_string()))?;
    to_json(&event, "profile backup event")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn build_profile_backup_event(
    share_secret: &str,
    backup_json: &str,
    created_at_seconds: Option<u32>,
) -> HostResult<String> {
    build_profile_backup_event_json(share_secret, backup_json, created_at_seconds)
}

pub fn parse_profile_backup_event_json(event_json: &str, share_secret: &str) -> HostResult<String> {
    let event: Event = parse_json(event_json, "profile backup event")?;
    let backup = rust_parse_profile_backup_event(&event, share_secret)
        .map_err(|error| to_host_error(error.to_string()))?;
    to_json(&browser_backup_from_payload(&backup), "encrypted profile backup")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn parse_profile_backup_event(event_json: &str, share_secret: &str) -> HostResult<String> {
    parse_profile_backup_event_json(event_json, share_secret)
}

pub fn recover_profile_from_share_and_backup_json(
    share_json: &str,
    backup_json: &str,
) -> HostResult<String> {
    let share: BrowserSharePackagePayload = parse_json(share_json, "bfshare payload")?;
    let backup: BrowserEncryptedProfileBackup =
        parse_json(backup_json, "encrypted profile backup")?;
    let profile = BrowserProfilePackagePayload {
        profile_id: derive_profile_id_for_share_secret(&share.share_secret)
            .map_err(|error| to_host_error(error.to_string()))?,
        version: backup.version,
        device: BrowserProfilePackageDevice {
            name: backup.device.name,
            share_secret: share.share_secret,
            manual_peer_policy_overrides: backup.device.manual_peer_policy_overrides,
            relays: backup.device.relays,
        },
        group_package: backup.group_package,
    };
    to_json(&profile, "recovered profile payload")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn recover_profile_from_share_and_backup(
    share_json: &str,
    backup_json: &str,
) -> HostResult<String> {
    recover_profile_from_share_and_backup_json(share_json, backup_json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frostr_utils::{CreateKeysetConfig, create_keyset};

    fn sample_profile_payload() -> BrowserProfilePackagePayload {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Managed WASM".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        BrowserProfilePackagePayload {
            profile_id: derive_profile_id_for_share_secret(&hex::encode(share.seckey))
                .expect("profile id"),
            version: 1,
            device: BrowserProfilePackageDevice {
                name: "Browser Device".to_string(),
                share_secret: hex::encode(share.seckey),
                manual_peer_policy_overrides: Vec::new(),
                relays: vec!["wss://relay.example.test".to_string()],
            },
            group_package: BrowserGroupPackage {
                group_name: "Managed WASM".to_string(),
                group_pk: hex::encode(bundle.group.group_pk),
                threshold: bundle.group.threshold,
                members: bundle
                    .group
                    .members
                    .into_iter()
                    .map(|member| BrowserGroupPackageMember {
                        idx: member.idx,
                        pubkey: hex::encode(member.pubkey),
                    })
                    .collect(),
            },
        }
    }

    fn sample_profile_payload_json() -> String {
        serde_json::to_string(&sample_profile_payload()).expect("serialize payload")
    }

    fn sample_onboard_payload_json(share_secret: &str) -> String {
        serde_json::to_string(&BrowserOnboardPackagePayload {
            share_secret: share_secret.to_string(),
            relays: vec!["wss://relay.example.test".to_string()],
            peer_pubkey: "66".repeat(32),
        })
        .expect("serialize bfonboard payload")
    }

    #[test]
    fn relay_profile_validation_round_trips_json() {
        let profile = r#"{"id":"local","label":"Local","relays":["wss://relay.example.test"]}"#;
        let json = validate_relay_profile_json(profile).expect("validate");
        let parsed: RelayProfile = serde_json::from_str(&json).expect("parse validated profile");
        assert_eq!(parsed.id, "local");
    }

    #[test]
    fn bfprofile_encode_decode_and_preview_round_trip() {
        let payload_json = sample_profile_payload_json();
        let encoded =
            encode_bfprofile_package_json(&payload_json, "test-password").expect("encode");
        let decoded_json =
            decode_bfprofile_package_json(&encoded, "test-password").expect("decode");
        let preview_json =
            preview_bfprofile_package_json(&encoded, "test-password", None).expect("preview");
        let decoded: BrowserProfilePackagePayload =
            serde_json::from_str(&decoded_json).expect("decoded payload");
        let preview: serde_json::Value =
            serde_json::from_str(&preview_json).expect("preview payload");
        assert_eq!(
            decoded.profile_id,
            preview["profile_id"].as_str().expect("profile id")
        );
        assert_eq!(preview["source"].as_str().expect("source"), "bfprofile");
    }

    #[test]
    fn bfshare_recovery_preview_exposes_profile_id() {
        let encoded = encode_bfshare_package_json(
            r#"{"shareSecret":"11aa22bb33cc44dd55ee66ff77889900112233445566778899aabbccddeeff00","relays":["wss://relay.example.test"]}"#,
            "test-password",
        )
        .expect("encode bfshare");
        let preview_json =
            preview_bfshare_recovery_json(&encoded, "test-password").expect("preview bfshare");
        let preview: serde_json::Value =
            serde_json::from_str(&preview_json).expect("parse preview");
        assert!(preview["profileId"].as_str().expect("profile id").len() > 10);
        assert_eq!(
            preview["share"]["relays"][0].as_str().expect("relay"),
            "wss://relay.example.test"
        );
    }

    #[test]
    fn constants_and_id_helpers_match_profile_package_contract() {
        assert_eq!(bf_package_version(), 1);
        assert_eq!(bfshare_prefix(), "bfshare");
        assert_eq!(bfonboard_prefix(), "bfonboard");
        assert_eq!(bfprofile_prefix(), "bfprofile");
        assert_eq!(profile_backup_event_kind(), 10_000);
        assert_eq!(profile_backup_key_domain(), "frostr-profile-backup/v1");

        let payload = sample_profile_payload();
        let backup_json =
            create_encrypted_profile_backup_json(&serde_json::to_string(&payload).expect("serialize"))
                .expect("create backup");
        let backup: BrowserEncryptedProfileBackup =
            serde_json::from_str(&backup_json).expect("parse backup");

        let from_secret = derive_profile_id_from_share_secret_export(&payload.device.share_secret)
            .expect("profile id from secret");
        let from_pubkey =
            derive_profile_id_from_share_pubkey_export(&backup.device.share_public_key)
                .expect("profile id from share pubkey");
        assert_eq!(from_secret, payload.profile_id);
        assert_eq!(from_pubkey, payload.profile_id);
    }

    #[test]
    fn bfonboard_encode_decode_round_trips() {
        let payload = sample_profile_payload();
        let payload_json = sample_onboard_payload_json(&payload.device.share_secret);
        let encoded =
            encode_bfonboard_package_json(&payload_json, "test-password").expect("encode");
        let decoded_json =
            decode_bfonboard_package_json(&encoded, "test-password").expect("decode");
        let decoded: BrowserOnboardPackagePayload =
            serde_json::from_str(&decoded_json).expect("parse decoded payload");
        assert_eq!(decoded.share_secret, payload.device.share_secret);
        assert_eq!(decoded.peer_pubkey, "66".repeat(32));
    }

    #[test]
    fn create_profile_package_pair_matches_export_wrappers() {
        let payload_json = sample_profile_payload_json();
        let pair_json =
            create_profile_package_pair_json(&payload_json, "test-password").expect("pair");
        let pair: BrowserProfilePackagePair =
            serde_json::from_str(&pair_json).expect("parse pair");

        assert!(pair.profile_string.starts_with("bfprofile1"));
        assert!(pair.share_string.starts_with("bfshare1"));

        let decoded_profile_json =
            decode_bfprofile_package_json(&pair.profile_string, "test-password")
                .expect("decode profile package");
        let decoded_profile: BrowserProfilePackagePayload =
            serde_json::from_str(&decoded_profile_json).expect("parse profile package");
        assert_eq!(
            decoded_profile.profile_id,
            serde_json::from_str::<BrowserProfilePackagePayload>(&payload_json)
                .expect("parse input payload")
                .profile_id
        );

        let decoded_share_json = decode_bfshare_package_json(&pair.share_string, "test-password")
            .expect("decode share package");
        let decoded_share: BrowserSharePackagePayload =
            serde_json::from_str(&decoded_share_json).expect("parse share package");
        assert_eq!(decoded_share.relays, vec!["wss://relay.example.test"]);
    }

    #[test]
    fn backup_wrappers_round_trip() {
        let payload = sample_profile_payload();
        let payload_json = serde_json::to_string(&payload).expect("serialize payload");
        let backup_json =
            create_encrypted_profile_backup_json(&payload_json).expect("create backup json");
        let backup: BrowserEncryptedProfileBackup =
            serde_json::from_str(&backup_json).expect("parse backup");
        assert_eq!(backup.device.name, payload.device.name);

        let key_hex = derive_profile_backup_conversation_key_hex(&payload.device.share_secret)
            .expect("derive backup conversation key");
        assert_eq!(key_hex.len(), 64);

        let ciphertext =
            encrypt_profile_backup_content_json(&backup_json, &payload.device.share_secret)
                .expect("encrypt backup");
        let decrypted_json =
            decrypt_profile_backup_content_json(&ciphertext, &payload.device.share_secret)
                .expect("decrypt backup");
        let decrypted: BrowserEncryptedProfileBackup =
            serde_json::from_str(&decrypted_json).expect("parse decrypted backup");
        assert_eq!(decrypted, backup);

        let event_json = build_profile_backup_event_json(
            &payload.device.share_secret,
            &backup_json,
            Some(1_700_000_000),
        )
        .expect("build event");
        let reparsed_json =
            parse_profile_backup_event_json(&event_json, &payload.device.share_secret)
                .expect("parse event");
        let reparsed: BrowserEncryptedProfileBackup =
            serde_json::from_str(&reparsed_json).expect("parse reparsed backup");
        assert_eq!(reparsed, backup);
    }

    #[test]
    fn recover_profile_from_share_and_backup_rebuilds_browser_payload() {
        let payload = sample_profile_payload();
        let backup_json =
            create_encrypted_profile_backup_json(&serde_json::to_string(&payload).expect("serialize"))
                .expect("create backup");
        let share_json = serde_json::to_string(&BrowserSharePackagePayload {
            share_secret: payload.device.share_secret.clone(),
            relays: payload.device.relays.clone(),
        })
        .expect("serialize share");
        let recovered_json =
            recover_profile_from_share_and_backup_json(&share_json, &backup_json).expect("recover");
        let recovered: BrowserProfilePackagePayload =
            serde_json::from_str(&recovered_json).expect("parse recovered profile");
        assert_eq!(recovered.profile_id, payload.profile_id);
        assert_eq!(recovered.device.share_secret, payload.device.share_secret);
    }

    #[test]
    fn malformed_json_and_wrong_password_return_host_errors() {
        let parse_error =
            encode_bfprofile_package_json("{", "test-password").expect_err("invalid json");
        assert!(parse_error.contains("parse bfprofile payload"));

        let payload_json = sample_profile_payload_json();
        let encoded =
            encode_bfprofile_package_json(&payload_json, "test-password").expect("encode");
        let decode_error =
            decode_bfprofile_package_json(&encoded, "wrong-password").expect_err("wrong password");
        assert!(
            decode_error.contains("password")
                || decode_error.contains("decrypt")
                || decode_error.contains("Invalid")
        );
    }

    #[test]
    fn parse_profile_backup_event_rejects_malformed_payload_content() {
        let payload = sample_profile_payload();
        let payload_json = serde_json::to_string(&payload).expect("serialize payload");
        let backup_json =
            create_encrypted_profile_backup_json(&payload_json).expect("create backup json");
        let event_json = build_profile_backup_event_json(
            &payload.device.share_secret,
            &backup_json,
            Some(1_700_000_000),
        )
        .expect("build event");
        let mut event: serde_json::Value =
            serde_json::from_str(&event_json).expect("parse event json");
        event["content"] = serde_json::Value::String("{}".to_string());
        let malformed_event_json = serde_json::to_string(&event).expect("serialize event");
        let error =
            parse_profile_backup_event_json(&malformed_event_json, &payload.device.share_secret)
                .expect_err("invalid backup event payload");
        assert!(error.contains("backup") || error.contains("decrypt") || error.contains("Invalid"));
    }
}
