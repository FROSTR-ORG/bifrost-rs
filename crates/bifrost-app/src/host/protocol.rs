use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlRequest {
    pub request_id: String,
    pub token: String,
    #[serde(flatten)]
    pub command: ControlCommand,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlCommand {
    Status,
    SetPolicyOverride {
        peer: String,
        policy_override_json: String,
    },
    ClearPeerPolicyOverrides,
    Ping {
        peer: String,
        timeout_secs: Option<u64>,
    },
    Onboard {
        peer: String,
        timeout_secs: Option<u64>,
    },
    Sign {
        message_hex32: String,
        timeout_secs: Option<u64>,
    },
    Ecdh {
        pubkey_hex32: String,
        timeout_secs: Option<u64>,
    },
    ReadConfig,
    UpdateConfig {
        config_patch_json: String,
    },
    PeerStatus,
    Readiness,
    RuntimeStatus,
    RuntimeMetadata,
    RuntimeDiagnostics,
    WipeState,
    Shutdown,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlResponse {
    pub request_id: String,
    pub ok: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

pub(crate) fn next_request_id() -> String {
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("req-{counter}")
}
