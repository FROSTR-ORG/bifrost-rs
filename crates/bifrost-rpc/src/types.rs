use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequestEnvelope {
    pub id: u64,
    pub request: BifrostRpcRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponseEnvelope {
    pub id: u64,
    pub response: BifrostRpcResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum BifrostRpcRequest {
    Health,
    Status,
    Events { limit: usize },
    Echo { peer: String, message: String },
    Ping { peer: String },
    Onboard { peer: String },
    Sign { message32_hex: String },
    Ecdh { pubkey33_hex: String },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", content = "data")]
pub enum BifrostRpcResponse {
    Ok(serde_json::Value),
    Err { code: i32, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub ready: bool,
    pub share_idx: u16,
    pub nonce_pool_size: usize,
    pub nonce_pool_min_threshold: usize,
    pub nonce_pool_critical_threshold: usize,
    pub peers: Vec<PeerView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerView {
    pub pubkey: String,
    pub status: String,
    pub send: bool,
    pub recv: bool,
    pub updated: u64,
    pub member_idx: u16,
    pub nonce_incoming_available: usize,
    pub nonce_outgoing_available: usize,
    pub nonce_outgoing_spent: usize,
    pub nonce_can_sign: bool,
    pub nonce_should_send: bool,
}
