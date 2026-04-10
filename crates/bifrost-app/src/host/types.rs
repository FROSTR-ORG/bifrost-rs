use std::path::PathBuf;
use std::time::Duration;

use bifrost_bridge_tokio::BridgeConfig;
use bifrost_signer::{
    DeviceConfig, DeviceStatus, PeerStatus, RuntimeMetadata, RuntimeReadiness, RuntimeStatusSummary,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::runtime::ResolvedAppConfig;

#[derive(Debug, Clone, Copy)]
pub struct LogOptions {
    pub verbose: bool,
    pub debug: bool,
}

#[derive(Debug, Clone)]
pub enum HostCommand {
    Sign {
        message_hex32: String,
    },
    Ecdh {
        pubkey_hex32: String,
    },
    Ping {
        peer: String,
    },
    Onboard {
        peer: String,
    },
    Listen {
        control_socket: Option<PathBuf>,
        control_token: Option<String>,
    },
    Status,
    StateHealth,
    SetPolicyOverride {
        peer: String,
        policy_json: String,
    },
    ClearPeerPolicyOverrides,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostCommandResult {
    Sign {
        request_id: String,
        signatures_hex: Vec<String>,
    },
    Ecdh {
        request_id: String,
        shared_secret_hex32: String,
    },
    Ping {
        request_id: String,
        peer: String,
    },
    Onboard {
        request_id: String,
        group_member_count: usize,
    },
    Status {
        status: DeviceStatus,
    },
    StateHealth {
        report: serde_json::Value,
    },
    PolicyUpdated {
        peer: String,
    },
    Listen,
}

#[derive(Debug, Clone)]
pub struct DaemonTransportConfig {
    pub socket_path: PathBuf,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct StatusPayload(pub DeviceStatus);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ReadConfigPayload(pub DeviceConfig);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct PeerStatusPayload(pub Vec<PeerStatus>);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ReadinessPayload(pub RuntimeReadiness);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct RuntimeStatusPayload(pub RuntimeStatusSummary);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeDiagnosticsSnapshot {
    pub runtime_status: RuntimeStatusPayload,
}

pub type RuntimeDiagnosticsPayload = RuntimeDiagnosticsSnapshot;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct RuntimeMetadataPayload(pub RuntimeMetadata);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PingPayload {
    pub request_id: String,
    pub peer: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OnboardPayload {
    pub request_id: String,
    pub group_member_count: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignPayload {
    pub request_id: String,
    pub signatures_hex: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcdhPayload {
    pub request_id: String,
    pub shared_secret_hex32: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdatedPayload {
    pub updated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WipedPayload {
    pub wiped: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShutdownPayload {
    pub shutdown: bool,
}

#[derive(Debug, Clone)]
pub enum ControlResultPayload {
    Status(StatusPayload),
    ReadConfig(ReadConfigPayload),
    PeerStatus(PeerStatusPayload),
    Readiness(ReadinessPayload),
    RuntimeStatus(RuntimeStatusPayload),
    RuntimeDiagnostics(RuntimeDiagnosticsPayload),
    RuntimeMetadata(RuntimeMetadataPayload),
    Sign(SignPayload),
    Ecdh(EcdhPayload),
    Ping(PingPayload),
    Onboard(OnboardPayload),
    Updated(UpdatedPayload),
    Wiped(WipedPayload),
    Shutdown(ShutdownPayload),
}

impl ControlResultPayload {
    pub fn into_value(self) -> Value {
        match self {
            ControlResultPayload::Status(value) => json!(value),
            ControlResultPayload::ReadConfig(value) => json!(value),
            ControlResultPayload::PeerStatus(value) => json!(value),
            ControlResultPayload::Readiness(value) => json!(value),
            ControlResultPayload::RuntimeStatus(value) => json!(value),
            ControlResultPayload::RuntimeDiagnostics(value) => json!(value),
            ControlResultPayload::RuntimeMetadata(value) => json!(value),
            ControlResultPayload::Sign(value) => json!(value),
            ControlResultPayload::Ecdh(value) => json!(value),
            ControlResultPayload::Ping(value) => json!(value),
            ControlResultPayload::Onboard(value) => json!(value),
            ControlResultPayload::Updated(value) => json!(value),
            ControlResultPayload::Wiped(value) => json!(value),
            ControlResultPayload::Shutdown(value) => json!(value),
        }
    }
}

pub(crate) fn bridge_config(config: &ResolvedAppConfig) -> BridgeConfig {
    BridgeConfig {
        expire_tick: Duration::from_millis(config.options.router_expire_tick_ms),
        relay_backoff: Duration::from_millis(config.options.router_relay_backoff_ms),
        command_queue_capacity: config.options.router_command_queue_capacity,
        inbound_queue_capacity: config.options.router_inbound_queue_capacity,
        outbound_queue_capacity: config.options.router_outbound_queue_capacity,
        command_overflow_policy: config.options.router_command_overflow_policy.into(),
        inbound_overflow_policy: config.options.router_inbound_overflow_policy.into(),
        outbound_overflow_policy: config.options.router_outbound_overflow_policy.into(),
        inbound_dedupe_cache_limit: config.options.router_inbound_dedupe_cache_limit,
    }
}
