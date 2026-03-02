use bifrost_core::nonce::NoncePoolConfig;
use serde::{Deserialize, Serialize};

pub const NODE_ENVELOPE_VERSION: u16 = 1;
pub const DEFAULT_SIGN_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_ECDH_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_PING_TIMEOUT_MS: u64 = 15_000;
pub const DEFAULT_REQUEST_TTL_SECS: u64 = 300;
pub const DEFAULT_REQUEST_CACHE_LIMIT: usize = 4096;
pub const DEFAULT_MAX_SIGN_BATCH: usize = 100;
pub const DEFAULT_MAX_ECDH_BATCH: usize = 100;
pub const DEFAULT_MAX_REQUEST_ID_LEN: usize = 256;
pub const DEFAULT_MAX_SENDER_LEN: usize = 256;
pub const DEFAULT_MAX_ECHO_LEN: usize = 8192;
pub const DEFAULT_MAX_SIGN_CONTENT_LEN: usize = 16_384;
pub const DEFAULT_ECDH_CACHE_TTL_SECS: u64 = 300;
pub const DEFAULT_ECDH_CACHE_MAX_ENTRIES: usize = 1024;
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    Online,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodPolicy {
    pub echo: bool,
    pub ping: bool,
    pub onboard: bool,
    pub sign: bool,
    pub ecdh: bool,
}

impl Default for MethodPolicy {
    fn default() -> Self {
        Self {
            echo: true,
            ping: true,
            onboard: true,
            sign: true,
            ecdh: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PeerPolicy {
    pub block_all: bool,
    pub request: MethodPolicy,
    pub respond: MethodPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerData {
    pub pubkey: String,
    pub status: PeerStatus,
    pub policy: PeerPolicy,
    pub updated: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerNonceHealth {
    pub member_idx: u16,
    pub incoming_available: usize,
    pub outgoing_available: usize,
    pub outgoing_spent: usize,
    pub can_sign: bool,
    pub should_send_nonces: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BifrostNodeOptions {
    pub sign_timeout_ms: u64,
    pub ecdh_timeout_ms: u64,
    pub ping_timeout_ms: u64,
    pub request_ttl_secs: u64,
    pub request_cache_limit: usize,
    pub max_sign_batch: usize,
    pub max_ecdh_batch: usize,
    pub max_request_id_len: usize,
    pub max_sender_len: usize,
    pub max_echo_len: usize,
    pub max_sign_content_len: usize,
    pub ecdh_cache_ttl_secs: u64,
    pub ecdh_cache_max_entries: usize,
    pub nonce_pool: NoncePoolConfig,
}

impl Default for BifrostNodeOptions {
    fn default() -> Self {
        Self {
            sign_timeout_ms: DEFAULT_SIGN_TIMEOUT_MS,
            ecdh_timeout_ms: DEFAULT_ECDH_TIMEOUT_MS,
            ping_timeout_ms: DEFAULT_PING_TIMEOUT_MS,
            request_ttl_secs: DEFAULT_REQUEST_TTL_SECS,
            request_cache_limit: DEFAULT_REQUEST_CACHE_LIMIT,
            max_sign_batch: DEFAULT_MAX_SIGN_BATCH,
            max_ecdh_batch: DEFAULT_MAX_ECDH_BATCH,
            max_request_id_len: DEFAULT_MAX_REQUEST_ID_LEN,
            max_sender_len: DEFAULT_MAX_SENDER_LEN,
            max_echo_len: DEFAULT_MAX_ECHO_LEN,
            max_sign_content_len: DEFAULT_MAX_SIGN_CONTENT_LEN,
            ecdh_cache_ttl_secs: DEFAULT_ECDH_CACHE_TTL_SECS,
            ecdh_cache_max_entries: DEFAULT_ECDH_CACHE_MAX_ENTRIES,
            nonce_pool: NoncePoolConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BifrostNodeConfig {
    pub options: BifrostNodeOptions,
    pub peers: Vec<PeerData>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    Ready,
    Closed,
    Message(String),
    Bounced(String),
    Info(String),
    Error(String),
}
