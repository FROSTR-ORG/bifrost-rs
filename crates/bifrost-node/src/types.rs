use bifrost_core::nonce::NoncePoolConfig;
use serde::{Deserialize, Serialize};

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
            sign_timeout_ms: 30_000,
            ecdh_timeout_ms: 30_000,
            ping_timeout_ms: 15_000,
            request_ttl_secs: 300,
            request_cache_limit: 4096,
            max_sign_batch: 100,
            max_ecdh_batch: 100,
            max_request_id_len: 256,
            max_sender_len: 256,
            max_echo_len: 8192,
            max_sign_content_len: 16384,
            ecdh_cache_ttl_secs: 300,
            ecdh_cache_max_entries: 1024,
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
