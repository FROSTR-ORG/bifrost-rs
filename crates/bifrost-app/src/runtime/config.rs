use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, anyhow};
use bifrost_bridge_tokio::{
    DEFAULT_COMMAND_OVERFLOW_POLICY, DEFAULT_COMMAND_QUEUE_CAPACITY, DEFAULT_EXPIRE_TICK_MS,
    DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT, DEFAULT_INBOUND_OVERFLOW_POLICY,
    DEFAULT_INBOUND_QUEUE_CAPACITY, DEFAULT_OUTBOUND_OVERFLOW_POLICY,
    DEFAULT_OUTBOUND_QUEUE_CAPACITY, DEFAULT_RELAY_BACKOFF_MS, QueueOverflowPolicy,
};
use bifrost_core::types::{GroupPackage, PeerPolicyOverride, SharePackage};
use bifrost_signer::PeerSelectionStrategy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub group_path: String,
    pub share_path: String,
    pub state_path: String,
    pub relays: Vec<String>,
    pub peers: Vec<String>,
    #[serde(default)]
    pub manual_policy_overrides: HashMap<String, PeerPolicyOverride>,
    #[serde(default)]
    pub options: AppOptions,
}

#[derive(Debug, Clone)]
pub struct ResolvedAppConfig {
    pub group: GroupPackage,
    pub share: SharePackage,
    pub state_path: std::path::PathBuf,
    pub relays: Vec<String>,
    pub peers: Vec<String>,
    pub manual_policy_overrides: HashMap<String, PeerPolicyOverride>,
    pub options: AppOptions,
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

pub fn load_config(path: &Path) -> Result<AppConfig> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: AppConfig = serde_json::from_str(&raw).context("parse config")?;
    if cfg.relays.is_empty() {
        return Err(anyhow!("config.relays must not be empty"));
    }
    Ok(cfg)
}

use anyhow::Context;
