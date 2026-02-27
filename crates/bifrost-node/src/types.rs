use bifrost_core::nonce::NoncePoolConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    Online,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerPolicy {
    pub send: bool,
    pub recv: bool,
}

impl Default for PeerPolicy {
    fn default() -> Self {
        Self {
            send: true,
            recv: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerData {
    pub pubkey: String,
    pub status: PeerStatus,
    pub policy: PeerPolicy,
    pub updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BifrostNodeOptions {
    pub sign_timeout_ms: u64,
    pub ecdh_timeout_ms: u64,
    pub ping_timeout_ms: u64,
    pub max_sign_batch: usize,
    pub max_ecdh_batch: usize,
    pub nonce_pool: NoncePoolConfig,
}

impl Default for BifrostNodeOptions {
    fn default() -> Self {
        Self {
            sign_timeout_ms: 30_000,
            ecdh_timeout_ms: 30_000,
            ping_timeout_ms: 15_000,
            max_sign_batch: 100,
            max_ecdh_batch: 100,
            nonce_pool: NoncePoolConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BifrostNodeConfig {
    pub options: BifrostNodeOptions,
    pub peers: Vec<PeerData>,
}

#[derive(Debug, Clone)]
pub enum NodeEvent {
    Ready,
    Closed,
    Message(String),
    Bounced(String),
    Info(String),
    Error(String),
}
