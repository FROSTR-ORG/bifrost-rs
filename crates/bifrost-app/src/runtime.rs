use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use bifrost_bridge_tokio::{
    DEFAULT_COMMAND_OVERFLOW_POLICY, DEFAULT_COMMAND_QUEUE_CAPACITY, DEFAULT_EXPIRE_TICK_MS,
    DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT, DEFAULT_INBOUND_OVERFLOW_POLICY,
    DEFAULT_INBOUND_QUEUE_CAPACITY, DEFAULT_OUTBOUND_OVERFLOW_POLICY, DEFAULT_OUTBOUND_QUEUE_CAPACITY,
    DEFAULT_RELAY_BACKOFF_MS, QueueOverflowPolicy,
};
use bifrost_codec::{parse_group_package, parse_share_package};
use bifrost_core::types::{PeerPolicy, SharePackage};
use bifrost_signer::{
    DeviceConfig, DeviceState, DeviceStore, PeerSelectionStrategy, SigningDevice,
};
use bincode::{DefaultOptions, Options};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub group_path: String,
    pub share_path: String,
    pub state_path: String,
    pub relays: Vec<String>,
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub options: AppOptions,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerConfig {
    pub pubkey: String,
    #[serde(default)]
    pub policy: PeerPolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppOptions {
    #[serde(default = "default_sign_timeout")]
    pub sign_timeout_secs: u64,
    #[serde(default = "default_ecdh_timeout")]
    pub ecdh_timeout_secs: u64,
    #[serde(default = "default_ping_timeout")]
    pub ping_timeout_secs: u64,
    #[serde(default = "default_onboard_timeout")]
    pub onboard_timeout_secs: u64,
    #[serde(default = "default_request_ttl")]
    pub request_ttl_secs: u64,
    #[serde(default = "default_max_future_skew_secs")]
    pub max_future_skew_secs: u64,
    #[serde(default = "default_request_cache_limit")]
    pub request_cache_limit: usize,
    #[serde(default = "default_ecdh_cache_capacity")]
    pub ecdh_cache_capacity: usize,
    #[serde(default = "default_ecdh_cache_ttl_secs")]
    pub ecdh_cache_ttl_secs: u64,
    #[serde(default = "default_sig_cache_capacity")]
    pub sig_cache_capacity: usize,
    #[serde(default = "default_sig_cache_ttl_secs")]
    pub sig_cache_ttl_secs: u64,
    #[serde(default = "default_state_save_interval")]
    pub state_save_interval_secs: u64,
    #[serde(default = "default_event_kind")]
    pub event_kind: u64,
    #[serde(default = "default_peer_selection_strategy")]
    pub peer_selection_strategy: PeerSelectionStrategy,
    #[serde(default = "default_router_expire_tick_ms")]
    pub router_expire_tick_ms: u64,
    #[serde(default = "default_router_relay_backoff_ms")]
    pub router_relay_backoff_ms: u64,
    #[serde(default = "default_router_command_queue_capacity")]
    pub router_command_queue_capacity: usize,
    #[serde(default = "default_router_inbound_queue_capacity")]
    pub router_inbound_queue_capacity: usize,
    #[serde(default = "default_router_outbound_queue_capacity")]
    pub router_outbound_queue_capacity: usize,
    #[serde(default = "default_router_command_overflow_policy")]
    pub router_command_overflow_policy: QueueOverflowPolicyConfig,
    #[serde(default = "default_router_inbound_overflow_policy")]
    pub router_inbound_overflow_policy: QueueOverflowPolicyConfig,
    #[serde(default = "default_router_outbound_overflow_policy")]
    pub router_outbound_overflow_policy: QueueOverflowPolicyConfig,
    #[serde(default = "default_router_inbound_dedupe_cache_limit")]
    pub router_inbound_dedupe_cache_limit: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueOverflowPolicyConfig {
    Fail,
    DropOldest,
}

impl From<QueueOverflowPolicyConfig> for QueueOverflowPolicy {
    fn from(value: QueueOverflowPolicyConfig) -> Self {
        match value {
            QueueOverflowPolicyConfig::Fail => QueueOverflowPolicy::Fail,
            QueueOverflowPolicyConfig::DropOldest => QueueOverflowPolicy::DropOldest,
        }
    }
}

impl From<QueueOverflowPolicy> for QueueOverflowPolicyConfig {
    fn from(value: QueueOverflowPolicy) -> Self {
        match value {
            QueueOverflowPolicy::Fail => QueueOverflowPolicyConfig::Fail,
            QueueOverflowPolicy::DropOldest => QueueOverflowPolicyConfig::DropOldest,
        }
    }
}

impl Default for AppOptions {
    fn default() -> Self {
        Self {
            sign_timeout_secs: default_sign_timeout(),
            ecdh_timeout_secs: default_ecdh_timeout(),
            ping_timeout_secs: default_ping_timeout(),
            onboard_timeout_secs: default_onboard_timeout(),
            request_ttl_secs: default_request_ttl(),
            max_future_skew_secs: default_max_future_skew_secs(),
            request_cache_limit: default_request_cache_limit(),
            ecdh_cache_capacity: default_ecdh_cache_capacity(),
            ecdh_cache_ttl_secs: default_ecdh_cache_ttl_secs(),
            sig_cache_capacity: default_sig_cache_capacity(),
            sig_cache_ttl_secs: default_sig_cache_ttl_secs(),
            state_save_interval_secs: default_state_save_interval(),
            event_kind: default_event_kind(),
            peer_selection_strategy: default_peer_selection_strategy(),
            router_expire_tick_ms: default_router_expire_tick_ms(),
            router_relay_backoff_ms: default_router_relay_backoff_ms(),
            router_command_queue_capacity: default_router_command_queue_capacity(),
            router_inbound_queue_capacity: default_router_inbound_queue_capacity(),
            router_outbound_queue_capacity: default_router_outbound_queue_capacity(),
            router_command_overflow_policy: default_router_command_overflow_policy(),
            router_inbound_overflow_policy: default_router_inbound_overflow_policy(),
            router_outbound_overflow_policy: default_router_outbound_overflow_policy(),
            router_inbound_dedupe_cache_limit: default_router_inbound_dedupe_cache_limit(),
        }
    }
}

fn default_sign_timeout() -> u64 {
    30
}
fn default_ecdh_timeout() -> u64 {
    30
}
fn default_ping_timeout() -> u64 {
    15
}
fn default_onboard_timeout() -> u64 {
    30
}
fn default_request_ttl() -> u64 {
    300
}
fn default_max_future_skew_secs() -> u64 {
    30
}
fn default_request_cache_limit() -> usize {
    2048
}
fn default_ecdh_cache_capacity() -> usize {
    256
}
fn default_ecdh_cache_ttl_secs() -> u64 {
    300
}
fn default_sig_cache_capacity() -> usize {
    256
}
fn default_sig_cache_ttl_secs() -> u64 {
    120
}
fn default_state_save_interval() -> u64 {
    30
}
fn default_event_kind() -> u64 {
    20_000
}
fn default_peer_selection_strategy() -> PeerSelectionStrategy {
    PeerSelectionStrategy::DeterministicSorted
}
fn default_router_expire_tick_ms() -> u64 {
    DEFAULT_EXPIRE_TICK_MS
}
fn default_router_relay_backoff_ms() -> u64 {
    DEFAULT_RELAY_BACKOFF_MS
}
fn default_router_command_queue_capacity() -> usize {
    DEFAULT_COMMAND_QUEUE_CAPACITY
}
fn default_router_inbound_queue_capacity() -> usize {
    DEFAULT_INBOUND_QUEUE_CAPACITY
}
fn default_router_outbound_queue_capacity() -> usize {
    DEFAULT_OUTBOUND_QUEUE_CAPACITY
}
fn default_router_command_overflow_policy() -> QueueOverflowPolicyConfig {
    DEFAULT_COMMAND_OVERFLOW_POLICY.into()
}
fn default_router_inbound_overflow_policy() -> QueueOverflowPolicyConfig {
    DEFAULT_INBOUND_OVERFLOW_POLICY.into()
}
fn default_router_outbound_overflow_policy() -> QueueOverflowPolicyConfig {
    DEFAULT_OUTBOUND_OVERFLOW_POLICY.into()
}
fn default_router_inbound_dedupe_cache_limit() -> usize {
    DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT
}

pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    path.to_string()
}

pub fn load_config(path: &Path) -> Result<AppConfig> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: AppConfig = serde_json::from_str(&raw).context("parse config")?;
    if cfg.relays.is_empty() {
        return Err(anyhow!("config.relays must not be empty"));
    }
    Ok(cfg)
}

pub fn load_share(path: &str) -> Result<SharePackage> {
    let path = expand_tilde(path);
    let raw = fs::read_to_string(&path).with_context(|| format!("read share file {path}"))?;
    parse_share_package(&raw).context("parse share package")
}

pub fn load_or_init_signer<S: DeviceStore>(config: &AppConfig, store: &S) -> Result<SigningDevice> {
    let group_path = expand_tilde(&config.group_path);
    let share_path = expand_tilde(&config.share_path);

    let group_raw = fs::read_to_string(&group_path)
        .with_context(|| format!("read group package {group_path}"))?;
    let share_raw = fs::read_to_string(&share_path)
        .with_context(|| format!("read share package {share_path}"))?;

    let group = parse_group_package(&group_raw).context("parse group package")?;
    let share = parse_share_package(&share_raw).context("parse share package")?;

    let state_path = PathBuf::from(expand_tilde(&config.state_path));
    let state = if store.exists() {
        let mut state = store.load().context("load state")?;
        if !last_shutdown_clean(&state_path, &state) {
            state.discard_volatile_for_dirty_restart(share.idx, share.seckey);
        }
        state
    } else {
        DeviceState::new(share.idx, share.seckey)
    };

    let mut signer = SigningDevice::new(
        group,
        share,
        config.peers.iter().map(|p| p.pubkey.clone()).collect(),
        state,
        DeviceConfig {
            sign_timeout_secs: config.options.sign_timeout_secs,
            ecdh_timeout_secs: config.options.ecdh_timeout_secs,
            ping_timeout_secs: config.options.ping_timeout_secs,
            onboard_timeout_secs: config.options.onboard_timeout_secs,
            request_ttl_secs: config.options.request_ttl_secs,
            max_future_skew_secs: config.options.max_future_skew_secs,
            request_cache_limit: config.options.request_cache_limit,
            ecdh_cache_capacity: config.options.ecdh_cache_capacity,
            ecdh_cache_ttl_secs: config.options.ecdh_cache_ttl_secs,
            sig_cache_capacity: config.options.sig_cache_capacity,
            sig_cache_ttl_secs: config.options.sig_cache_ttl_secs,
            state_save_interval_secs: config.options.state_save_interval_secs,
            event_kind: config.options.event_kind,
            peer_selection_strategy: config.options.peer_selection_strategy,
        },
    )?;

    for peer in &config.peers {
        signer.set_peer_policy(&peer.pubkey, peer.policy.clone())?;
    }

    Ok(signer)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RunMarker {
    clean_shutdown: bool,
    run_id: String,
    state_hash: Option<String>,
    updated_at: u64,
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run_marker_path(state_path: &Path) -> PathBuf {
    state_path.with_extension("run.json")
}

fn hash_state(state: &DeviceState) -> Result<String> {
    let bytes = DefaultOptions::new()
        .with_limit(MAX_STATE_PLAINTEXT_BYTES as u64)
        .serialize(state)?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(digest))
}

pub fn last_shutdown_clean(state_path: &Path, state: &DeviceState) -> bool {
    let path = run_marker_path(state_path);
    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let marker = match serde_json::from_str::<RunMarker>(&raw) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if !marker.clean_shutdown {
        return false;
    }
    let Some(expected_hash) = marker.state_hash else {
        return false;
    };
    hash_state(state)
        .map(|actual_hash| actual_hash == expected_hash)
        .unwrap_or(false)
}

pub fn begin_run(state_path: &Path) -> Result<String> {
    let mut run_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut run_bytes);
    let run_id = hex::encode(run_bytes);
    let marker = RunMarker {
        clean_shutdown: false,
        run_id: run_id.clone(),
        state_hash: None,
        updated_at: now_unix_secs(),
    };
    let path = run_marker_path(state_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec(&marker)?)?;
    Ok(run_id)
}

pub fn complete_clean_run(state_path: &Path, run_id: &str, state: &DeviceState) -> Result<()> {
    let marker = RunMarker {
        clean_shutdown: true,
        run_id: run_id.to_string(),
        state_hash: Some(hash_state(state)?),
        updated_at: now_unix_secs(),
    };
    let path = run_marker_path(state_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec(&marker)?)?;
    Ok(())
}

pub struct EncryptedFileStore {
    path: PathBuf,
    key: [u8; 32],
}

const MAX_STATE_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_STATE_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024 + 1 + 12 + 16;

impl EncryptedFileStore {
    pub fn new(path: PathBuf, share: SharePackage) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(share.seckey);
        hasher.update(b"bifrost-device-state");
        let key_bytes = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Self { path, key }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| anyhow!("state encryption failure"))?;

        let mut out = Vec::with_capacity(1 + 12 + ciphertext.len());
        out.push(1u8);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 1 + 12 + 16 {
            return Err(anyhow!("state ciphertext is too short"));
        }
        let version = ciphertext[0];
        if version != 1 {
            return Err(anyhow!("unsupported state ciphertext version"));
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&ciphertext[1..13]);
        let payload = &ciphertext[13..];

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), payload)
            .map_err(|_| anyhow!("state decryption failure"))
    }
}

impl DeviceStore for EncryptedFileStore {
    fn load(&self) -> bifrost_signer::Result<DeviceState> {
        let ciphertext = fs::read(&self.path)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        if ciphertext.len() > MAX_STATE_CIPHERTEXT_BYTES {
            return Err(bifrost_signer::SignerError::StateCorrupted(
                "state ciphertext exceeds maximum size".to_string(),
            ));
        }
        let plaintext = self
            .decrypt(&ciphertext)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        if plaintext.len() > MAX_STATE_PLAINTEXT_BYTES {
            return Err(bifrost_signer::SignerError::StateCorrupted(
                "state plaintext exceeds maximum size".to_string(),
            ));
        }
        DefaultOptions::new()
            .with_limit(MAX_STATE_PLAINTEXT_BYTES as u64)
            .deserialize(&plaintext)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))
    }

    fn save(&self, state: &DeviceState) -> bifrost_signer::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        }
        let plaintext = DefaultOptions::new()
            .with_limit(MAX_STATE_PLAINTEXT_BYTES as u64)
            .serialize(state)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        if plaintext.len() > MAX_STATE_PLAINTEXT_BYTES {
            return Err(bifrost_signer::SignerError::StateCorrupted(
                "state plaintext exceeds maximum size".to_string(),
            ));
        }
        let ciphertext = self
            .encrypt(&plaintext)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, ciphertext)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        fs::rename(&tmp, &self.path)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        Ok(())
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }
}

pub struct DeviceLock {
    _file: File,
}

impl DeviceLock {
    pub fn acquire_exclusive(state_path: &Path) -> Result<Self> {
        let lock_path = state_path.with_extension("lock");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open lock {}", lock_path.display()))?;

        match file.try_lock_exclusive() {
            Ok(()) => {
                file.set_len(0)?;
                write!(&mut file, "{}", std::process::id())?;
                Ok(Self { _file: file })
            }
            Err(_) => {
                let pid = read_lock_holder(&lock_path);
                Err(anyhow!("device is locked by another process (PID: {pid})"))
            }
        }
    }

    pub fn acquire_shared(state_path: &Path) -> Result<Self> {
        let lock_path = state_path.with_extension("lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open lock {}", lock_path.display()))?;

        match file.try_lock_shared() {
            Ok(()) => Ok(Self { _file: file }),
            Err(_) => {
                let pid = read_lock_holder(&lock_path);
                Err(anyhow!("device is locked by another process (PID: {pid})"))
            }
        }
    }
}

fn read_lock_holder(lock_path: &Path) -> String {
    fs::read_to_string(lock_path)
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
