use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use argon2::Argon2;
use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
use bifrost_core::get_group_id;
use bifrost_core::types::{GroupPackage, SharePackage};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    ENCRYPTED_PROFILE_VERSION, EncryptedProfileRecord, ProfileManifest, ProfileManifestStore,
    RelayProfile, RelayProfileStore, ShellConfig, build_policy_overrides_value,
    build_profile_manifest, derive_profile_id_for_share_secret, empty_policy_overrides_value,
    find_member_index_for_share_secret, group_from_payload, hex_to_bytes32,
    traits::EncryptedProfileStore,
};
use frostr_utils::BfProfilePayload;

pub fn load_shell_config_file(path: &Path) -> Result<ShellConfig> {
    if !path.exists() {
        return Ok(ShellConfig::default());
    }
    read_json(path)
}

pub fn save_shell_config_file(path: &Path, config: &ShellConfig) -> Result<()> {
    write_json(path, config)
}

pub fn load_relay_profiles_file(path: &Path) -> Result<Vec<RelayProfile>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut profiles: Vec<RelayProfile> = read_json(path)?;
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(profiles)
}

pub fn save_relay_profiles_file(path: &Path, profiles: &[RelayProfile]) -> Result<()> {
    write_json(path, profiles)
}

#[derive(Debug, Clone)]
pub struct FilesystemProfileDomain {
    profiles: FilesystemProfileManifestStore,
    relays: FilesystemRelayProfileStore,
    encrypted_profiles: FilesystemEncryptedProfileStore,
    config_path: PathBuf,
    groups_dir: PathBuf,
    state_profiles_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ImportedProfileArtifacts {
    pub profile: ProfileManifest,
    pub encrypted_profile: EncryptedProfileRecord,
}

impl FilesystemProfileDomain {
    pub fn new(
        config_path: impl Into<PathBuf>,
        relay_profiles_path: impl Into<PathBuf>,
        profiles_dir: impl Into<PathBuf>,
        groups_dir: impl Into<PathBuf>,
        encrypted_profiles_dir: impl Into<PathBuf>,
        state_profiles_dir: impl Into<PathBuf>,
    ) -> Self {
        let config_path = config_path.into();
        let relay_profiles_path = relay_profiles_path.into();
        let profiles_dir = profiles_dir.into();
        let groups_dir = groups_dir.into();
        let encrypted_profiles_dir = encrypted_profiles_dir.into();
        let state_profiles_dir = state_profiles_dir.into();

        Self {
            profiles: FilesystemProfileManifestStore::new(profiles_dir),
            relays: FilesystemRelayProfileStore::new(relay_profiles_path),
            encrypted_profiles: FilesystemEncryptedProfileStore::new(
                &encrypted_profiles_dir,
                &encrypted_profiles_dir,
            ),
            config_path,
            groups_dir,
            state_profiles_dir,
        }
    }

    pub fn resolve_relay_profile_id(&self, requested: Option<String>) -> Result<String> {
        if let Some(profile_id) = requested {
            self.read_relay_profile(&profile_id)?;
            return Ok(profile_id);
        }

        let config = load_shell_config_file(&self.config_path)?;
        if let Some(profile_id) = config.default_relay_profile_id {
            self.read_relay_profile(&profile_id)?;
            return Ok(profile_id);
        }

        let profiles = self.relays.list_relay_profiles()?;
        let Some(first) = profiles.first() else {
            bail!("no relay profile configured; use `igloo-shell relays set ...` first");
        };
        Ok(first.id.clone())
    }

    pub fn ensure_onboarding_relay_profile(
        &self,
        requested: Option<String>,
        label: Option<&str>,
        relays: &[String],
        now_unix_secs: u64,
    ) -> Result<String> {
        if let Some(profile_id) = requested {
            if self.read_relay_profile(&profile_id).is_ok() {
                return Ok(profile_id);
            }
            self.replace_relay_profile(RelayProfile {
                id: profile_id.clone(),
                label: label.unwrap_or(&profile_id).to_string(),
                relays: relays.to_vec(),
            })?;
            return Ok(profile_id);
        }

        if let Some(existing) = self
            .relays
            .list_relay_profiles()?
            .into_iter()
            .find(|profile| profile.relays == relays)
        {
            return Ok(existing.id);
        }

        let profile_id = format!("onboarding-{now_unix_secs}");
        self.replace_relay_profile(RelayProfile {
            id: profile_id.clone(),
            label: label.unwrap_or("Imported Onboarding Package").to_string(),
            relays: relays.to_vec(),
        })?;
        Ok(profile_id)
    }

    pub fn ensure_profile_id_unused(&self, profile_id: &str) -> Result<()> {
        if self.profiles.profile_path(profile_id).exists() {
            bail!("profile {} already exists", profile_id);
        }
        Ok(())
    }

    pub fn touch_last_used_profile(&self, profile_id: &str) -> Result<()> {
        let mut config = load_shell_config_file(&self.config_path)?;
        config.last_used_profile_id = Some(profile_id.to_string());
        save_shell_config_file(&self.config_path, &config)
    }

    pub fn store_group_package(&self, group: &GroupPackage) -> Result<String> {
        let group_id = get_group_id(group).context("derive group id")?;
        let path = self
            .groups_dir
            .join(format!("{}.json", hex::encode(group_id)));
        if !path.exists() {
            write_json(&path, &GroupPackageWire::from(group.clone()))?;
        }
        Ok(path.display().to_string())
    }

    pub fn import_profile_from_files(
        &self,
        group: &GroupPackage,
        share: &SharePackage,
        share_raw: &str,
        label: Option<String>,
        relay_profile: Option<String>,
        passphrase: &str,
        now_unix_secs: u64,
    ) -> Result<ImportedProfileArtifacts> {
        let profile_id = derive_profile_id_for_share_secret(&hex::encode(share.seckey))?;
        self.ensure_profile_id_unused(&profile_id)?;
        let relay_profile_id = self.resolve_relay_profile_id(relay_profile)?;
        let group_ref = self.store_group_package(group)?;
        let encrypted_profile = self.encrypted_profiles.store_encrypted_profile(
            "share_package",
            "file_import",
            share_raw,
            passphrase,
            now_unix_secs,
        )?;
        let profile = self.write_imported_profile(
            &profile_id,
            label.unwrap_or_else(|| format!("device-{}", share.idx)),
            group_ref,
            encrypted_profile.id.clone(),
            relay_profile_id,
            now_unix_secs,
            empty_policy_overrides_value(),
        )?;
        self.touch_last_used_profile(&profile.id)?;
        Ok(ImportedProfileArtifacts {
            profile,
            encrypted_profile,
        })
    }

    pub fn import_profile_from_payload(
        &self,
        payload: &BfProfilePayload,
        label: Option<String>,
        relay_profile: Option<String>,
        passphrase: &str,
        now_unix_secs: u64,
    ) -> Result<ImportedProfileArtifacts> {
        let relay_profile_id = self.ensure_onboarding_relay_profile(
            relay_profile,
            Some(label.as_deref().unwrap_or(&payload.device.name)),
            &payload.device.relays,
            now_unix_secs,
        )?;
        let group = group_from_payload(payload)?;
        let share = SharePackage {
            idx: find_member_index_for_share_secret(&group, &payload.device.share_secret)?,
            seckey: hex_to_bytes32(&payload.device.share_secret)?,
        };
        let share_raw = serde_json::to_string_pretty(&SharePackageWire::from(share))
            .context("serialize bfprofile share package")?;
        let group_ref = self.store_group_package(&group)?;
        let encrypted_profile = self.encrypted_profiles.store_encrypted_profile(
            "share_package",
            "bfprofile_import",
            &share_raw,
            passphrase,
            now_unix_secs,
        )?;
        let profile = self.write_imported_profile(
            &payload.profile_id,
            label.unwrap_or_else(|| payload.device.name.clone()),
            group_ref,
            encrypted_profile.id.clone(),
            relay_profile_id,
            now_unix_secs,
            build_policy_overrides_value(&payload.device.manual_peer_policy_overrides)?,
        )?;
        self.touch_last_used_profile(&profile.id)?;
        Ok(ImportedProfileArtifacts {
            profile,
            encrypted_profile,
        })
    }

    pub fn finalize_onboarding_import(
        &self,
        group: &GroupPackage,
        share: &SharePackage,
        label: Option<String>,
        relay_profile_id: String,
        encrypted_profile: EncryptedProfileRecord,
        now_unix_secs: u64,
    ) -> Result<ImportedProfileArtifacts> {
        let profile_id = derive_profile_id_for_share_secret(&hex::encode(share.seckey))?;
        self.ensure_profile_id_unused(&profile_id)?;
        let group_ref = self.store_group_package(group)?;
        let profile = self.write_imported_profile(
            &profile_id,
            label.unwrap_or_else(|| format!("onboarded-{}", share.idx)),
            group_ref,
            encrypted_profile.id.clone(),
            relay_profile_id,
            now_unix_secs,
            empty_policy_overrides_value(),
        )?;
        self.touch_last_used_profile(&profile.id)?;
        Ok(ImportedProfileArtifacts {
            profile,
            encrypted_profile,
        })
    }

    pub fn read_relay_profile(&self, relay_profile_id: &str) -> Result<RelayProfile> {
        self.relays
            .list_relay_profiles()?
            .into_iter()
            .find(|profile| profile.id == relay_profile_id)
            .ok_or_else(|| anyhow!("unknown relay profile {relay_profile_id}"))
    }

    pub fn replace_relay_profile(&self, next: RelayProfile) -> Result<()> {
        crate::validate_relay_profile(&next)?;
        let mut profiles = self.relays.list_relay_profiles()?;
        profiles.retain(|entry| entry.id != next.id);
        profiles.push(next);
        profiles.sort_by(|a, b| a.id.cmp(&b.id));
        self.relays.write_relay_profiles(&profiles)
    }

    fn write_imported_profile(
        &self,
        profile_id: &str,
        label: String,
        group_ref: String,
        encrypted_profile_ref: String,
        relay_profile: String,
        created_at: u64,
        policy_overrides: serde_json::Value,
    ) -> Result<ProfileManifest> {
        let state_dir = self.state_profiles_dir.join(profile_id);
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("create {}", state_dir.display()))?;
        let mut profile = build_profile_manifest(
            profile_id,
            label,
            group_ref,
            encrypted_profile_ref,
            relay_profile,
            state_dir.join("signer-state.bin").display().to_string(),
            state_dir.join("daemon.sock").display().to_string(),
            created_at,
        );
        profile.policy_overrides = policy_overrides;
        self.profiles.write_profile(&profile)?;
        Ok(profile)
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemProfileManifestStore {
    profiles_dir: PathBuf,
}

impl FilesystemProfileManifestStore {
    pub fn new(profiles_dir: impl Into<PathBuf>) -> Self {
        Self {
            profiles_dir: profiles_dir.into(),
        }
    }

    pub fn remove_profile(&self, profile_id: &str) -> Result<()> {
        let path = self.profile_path(profile_id);
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        }
        Ok(())
    }

    fn profile_path(&self, profile_id: &str) -> PathBuf {
        self.profiles_dir.join(format!("{profile_id}.json"))
    }
}

impl ProfileManifestStore for FilesystemProfileManifestStore {
    fn list_profiles(&self) -> Result<Vec<ProfileManifest>> {
        if !self.profiles_dir.exists() {
            return Ok(Vec::new());
        }

        let mut profiles: Vec<ProfileManifest> = Vec::new();
        for entry in fs::read_dir(&self.profiles_dir)
            .with_context(|| format!("read {}", self.profiles_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            profiles.push(read_json(&path)?);
        }

        profiles.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));
        Ok(profiles)
    }

    fn read_profile(&self, profile_id: &str) -> Result<ProfileManifest> {
        let path = self.profile_path(profile_id);
        if !path.exists() {
            bail!("unknown profile {profile_id}");
        }
        read_json(&path)
    }

    fn write_profile(&self, profile: &ProfileManifest) -> Result<()> {
        write_json(&self.profile_path(&profile.id), profile)
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemRelayProfileStore {
    relay_profiles_path: PathBuf,
}

impl FilesystemRelayProfileStore {
    pub fn new(relay_profiles_path: impl Into<PathBuf>) -> Self {
        Self {
            relay_profiles_path: relay_profiles_path.into(),
        }
    }
}

impl RelayProfileStore for FilesystemRelayProfileStore {
    fn list_relay_profiles(&self) -> Result<Vec<RelayProfile>> {
        load_relay_profiles_file(&self.relay_profiles_path)
    }

    fn write_relay_profiles(&self, profiles: &[RelayProfile]) -> Result<()> {
        save_relay_profiles_file(&self.relay_profiles_path, profiles)
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemEncryptedProfileStore {
    metadata_dir: PathBuf,
    ciphertext_dir: PathBuf,
}

impl FilesystemEncryptedProfileStore {
    pub fn new(metadata_dir: impl Into<PathBuf>, ciphertext_dir: impl Into<PathBuf>) -> Self {
        Self {
            metadata_dir: metadata_dir.into(),
            ciphertext_dir: ciphertext_dir.into(),
        }
    }

    pub fn store_encrypted_profile(
        &self,
        kind: &str,
        source: &str,
        payload: &str,
        passphrase: &str,
        now_unix_secs: u64,
    ) -> Result<EncryptedProfileRecord> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = derive_profile_encryption_key(passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), payload.as_bytes())
            .map_err(|_| anyhow!("encrypted profile encryption failure"))?;
        let mut envelope = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
        envelope.push(ENCRYPTED_PROFILE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);

        let id = format!("encrypted-profile-{now_unix_secs}-{}", random_hex(4));
        let ciphertext_path = self.ciphertext_path(&id);
        if let Some(parent) = ciphertext_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(&ciphertext_path, envelope)
            .with_context(|| format!("write {}", ciphertext_path.display()))?;

        let record = EncryptedProfileRecord {
            id: id.clone(),
            kind: kind.to_string(),
            source: source.to_string(),
            ciphertext_path: ciphertext_path.display().to_string(),
            key_source: "passphrase".to_string(),
            salt_hex: hex::encode(salt),
            created_at: now_unix_secs,
            updated_at: now_unix_secs,
        };
        self.write_encrypted_profile(&record)?;
        Ok(record)
    }

    pub fn decrypt_encrypted_profile(
        &self,
        record: &EncryptedProfileRecord,
        passphrase: &str,
    ) -> Result<String> {
        let salt = hex::decode(&record.salt_hex).context("decode encrypted profile salt")?;
        let envelope = fs::read(&record.ciphertext_path)
            .with_context(|| format!("read {}", record.ciphertext_path))?;
        if envelope.len() < 1 + 12 + 16 {
            bail!("encrypted profile ciphertext is too short");
        }
        if envelope[0] != ENCRYPTED_PROFILE_VERSION {
            bail!("unsupported encrypted profile version {}", envelope[0]);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&envelope[1..13]);
        let key = derive_profile_encryption_key(passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new((&key).into());
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), &envelope[13..])
            .map_err(|_| anyhow!("encrypted profile decryption failure"))?;
        String::from_utf8(plaintext).context("encrypted profile plaintext is not utf8")
    }

    pub fn remove_encrypted_profile(&self, encrypted_profile_id: &str) -> Result<()> {
        let record = self.read_encrypted_profile(encrypted_profile_id)?;
        let metadata_path = self.metadata_path(encrypted_profile_id);
        if metadata_path.exists() {
            fs::remove_file(&metadata_path)
                .with_context(|| format!("remove {}", metadata_path.display()))?;
        }
        if Path::new(&record.ciphertext_path).exists() {
            fs::remove_file(&record.ciphertext_path)
                .with_context(|| format!("remove {}", record.ciphertext_path))?;
        }
        Ok(())
    }

    fn metadata_path(&self, encrypted_profile_id: &str) -> PathBuf {
        self.metadata_dir
            .join(format!("{encrypted_profile_id}.json"))
    }

    fn ciphertext_path(&self, encrypted_profile_id: &str) -> PathBuf {
        self.ciphertext_dir
            .join(format!("{encrypted_profile_id}.enc"))
    }
}

impl crate::EncryptedProfileStore for FilesystemEncryptedProfileStore {
    fn read_encrypted_profile(&self, encrypted_profile_id: &str) -> Result<EncryptedProfileRecord> {
        let path = self.metadata_path(encrypted_profile_id);
        if !path.exists() {
            bail!("unknown encrypted profile {encrypted_profile_id}");
        }
        read_json(&path)
    }

    fn write_encrypted_profile(&self, record: &EncryptedProfileRecord) -> Result<()> {
        write_json(&self.metadata_path(&record.id), record)
    }
}

fn derive_profile_encryption_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| anyhow!("derive profile encryption key: {error}"))?;
    Ok(key)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(value).context("serialize json")?;
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}

fn random_hex(bytes_len: usize) -> String {
    let mut bytes = vec![0u8; bytes_len];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let id = format!(
            "bifrost-profile-native-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        );
        std::env::temp_dir().join(id)
    }

    #[test]
    fn filesystem_encrypted_profile_store_round_trips_ciphertext() {
        let root = temp_dir("encrypted-profile");
        let store = FilesystemEncryptedProfileStore::new(&root, &root);
        let record = store
            .store_encrypted_profile("share_package", "test", "{\"share\":1}", "passphrase", 42)
            .expect("store encrypted profile");

        let decrypted = store
            .decrypt_encrypted_profile(&record, "passphrase")
            .expect("decrypt encrypted profile");
        assert_eq!(decrypted, "{\"share\":1}");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn filesystem_profile_manifest_store_sorts_profiles_stably() {
        let root = temp_dir("profiles");
        let store = FilesystemProfileManifestStore::new(&root);
        store
            .write_profile(&ProfileManifest {
                id: "b".to_string(),
                label: "B".to_string(),
                group_ref: "group-b".to_string(),
                encrypted_profile_ref: "encrypted-b".to_string(),
                relay_profile: "local".to_string(),
                runtime_options: serde_json::Value::Null,
                policy_overrides: serde_json::json!({}),
                state_path: "state-b".to_string(),
                daemon_socket_path: "daemon-b".to_string(),
                created_at: 2,
                last_used_at: Some(2),
            })
            .expect("write profile b");
        store
            .write_profile(&ProfileManifest {
                id: "a".to_string(),
                label: "A".to_string(),
                group_ref: "group-a".to_string(),
                encrypted_profile_ref: "encrypted-a".to_string(),
                relay_profile: "local".to_string(),
                runtime_options: serde_json::Value::Null,
                policy_overrides: serde_json::json!({}),
                state_path: "state-a".to_string(),
                daemon_socket_path: "daemon-a".to_string(),
                created_at: 1,
                last_used_at: Some(1),
            })
            .expect("write profile a");

        let profiles = store.list_profiles().expect("list profiles");
        assert_eq!(
            profiles
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );

        let _ = fs::remove_dir_all(root);
    }
}
