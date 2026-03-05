use anyhow::{Result, anyhow};
use bifrost_bridge_core::{BridgeCommand, BridgeConfig, BridgeCore};
use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
use bifrost_core::types::{MethodPolicy, PeerPolicy};
use bifrost_signer::{
    CompletedOperation, DeviceConfig, DeviceState, OperationFailure, SigningDevice,
};
use frostr_utils::decode_onboarding_package;
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use nostr::Event;
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
type HostError = JsValue;
#[cfg(not(target_arch = "wasm32"))]
type HostError = String;

type HostResult<T> = std::result::Result<T, HostError>;

#[cfg(target_arch = "wasm32")]
fn to_host_error(message: impl Into<String>) -> HostError {
    JsValue::from_str(&message.into())
}

#[cfg(not(target_arch = "wasm32"))]
fn to_host_error(message: impl Into<String>) -> HostError {
    message.into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeConfigInput {
    #[serde(default)]
    device: Option<DeviceConfig>,
    #[serde(default)]
    bridge: Option<BridgeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeBootstrapInput {
    group: GroupPackageWire,
    share: SharePackageWire,
    peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeSnapshot {
    bootstrap: RuntimeBootstrapInput,
    state: DeviceState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DecodedOnboarding {
    share: SharePackageWire,
    share_pubkey33: String,
    peer_pk_xonly: String,
    relays: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CommandInput {
    Sign { message_hex_32: String },
    Ecdh { pubkey33_hex: String },
    Ping { peer_pubkey33_hex: String },
    Onboard { peer_pubkey33_hex: String },
}

#[derive(Debug, Clone, Deserialize)]
struct SetPolicyInput {
    peer: String,
    send: bool,
    receive: bool,
}

struct RuntimeState {
    core: BridgeCore,
    bootstrap: RuntimeBootstrapInput,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum PendingOpTypeJson {
    Sign,
    Ecdh,
    Ping,
    Onboard,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum OperationFailureCodeJson {
    Timeout,
    InvalidLockedPeerResponse,
    PeerRejected,
}

#[derive(Debug, Clone, Serialize)]
struct OperationFailureJson {
    request_id: String,
    op_type: PendingOpTypeJson,
    code: OperationFailureCodeJson,
    message: String,
    failed_peer: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
enum CompletedOperationJson {
    Sign {
        request_id: String,
        signatures_hex64: Vec<String>,
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
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct WasmBridgeRuntime {
    state: Option<RuntimeState>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl WasmBridgeRuntime {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        #[cfg(all(target_arch = "wasm32", debug_assertions))]
        console_error_panic_hook::set_once();
        Self { state: None }
    }

    pub fn init_runtime(&mut self, config_json: String, bootstrap_json: String) -> HostResult<()> {
        let config: RuntimeConfigInput =
            serde_json::from_str(&config_json).map_err(|e| to_host_error(e.to_string()))?;
        let bootstrap: RuntimeBootstrapInput =
            serde_json::from_str(&bootstrap_json).map_err(|e| to_host_error(e.to_string()))?;
        let core =
            build_core(&config, &bootstrap, None).map_err(|e| to_host_error(e.to_string()))?;
        self.state = Some(RuntimeState { core, bootstrap });
        Ok(())
    }

    pub fn restore_runtime(
        &mut self,
        config_json: String,
        snapshot_json: String,
    ) -> HostResult<()> {
        let config: RuntimeConfigInput =
            serde_json::from_str(&config_json).map_err(|e| to_host_error(e.to_string()))?;
        let snapshot: RuntimeSnapshot =
            serde_json::from_str(&snapshot_json).map_err(|e| to_host_error(e.to_string()))?;
        let core = build_core(&config, &snapshot.bootstrap, Some(snapshot.state))
            .map_err(|e| to_host_error(e.to_string()))?;
        self.state = Some(RuntimeState {
            core,
            bootstrap: snapshot.bootstrap,
        });
        Ok(())
    }

    pub fn handle_command(&mut self, command_json: String) -> HostResult<()> {
        let command: CommandInput =
            serde_json::from_str(&command_json).map_err(|e| to_host_error(e.to_string()))?;
        let bridge_command = parse_command(command).map_err(|e| to_host_error(e.to_string()))?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        state
            .core
            .enqueue_command(bridge_command)
            .map_err(|e| to_host_error(e.to_string()))?;
        Ok(())
    }

    pub fn handle_inbound_event(&mut self, event_json: String) -> HostResult<()> {
        let event: Event =
            serde_json::from_str(&event_json).map_err(|e| to_host_error(e.to_string()))?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        let dropped = state.core.enqueue_inbound_event(event);
        if dropped {
            return Err(to_host_error("inbound queue overflow"));
        }
        Ok(())
    }

    pub fn tick(&mut self, now_unix_secs: u64) -> HostResult<()> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        state.core.tick(now_unix_secs);
        Ok(())
    }

    pub fn drain_outbound_events_json(&mut self) -> HostResult<String> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        let events = state.core.drain_outbound_events();
        serde_json::to_string(&events).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn drain_completions_json(&mut self) -> HostResult<String> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        let completions: Vec<CompletedOperationJson> = state
            .core
            .drain_completions()
            .into_iter()
            .map(CompletedOperationJson::from)
            .collect();
        serde_json::to_string(&completions).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn drain_failures_json(&mut self) -> HostResult<String> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        let failures: Vec<OperationFailureJson> = state
            .core
            .drain_failures()
            .into_iter()
            .map(OperationFailureJson::from)
            .collect();
        serde_json::to_string(&failures).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn snapshot_state_json(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        let snapshot = RuntimeSnapshot {
            bootstrap: state.bootstrap.clone(),
            state: state.core.snapshot_state(),
        };
        serde_json::to_string(&snapshot).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn status_json(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&state.core.status()).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn policies_json(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&state.core.policies()).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn set_policy(&mut self, policy_json: String) -> HostResult<()> {
        let input: SetPolicyInput =
            serde_json::from_str(&policy_json).map_err(|e| to_host_error(e.to_string()))?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;

        let request = MethodPolicy {
            echo: input.send,
            ping: input.send,
            onboard: input.send,
            sign: input.send,
            ecdh: input.send,
        };
        let respond = MethodPolicy {
            echo: input.receive,
            ping: input.receive,
            onboard: input.receive,
            sign: input.receive,
            ecdh: input.receive,
        };

        state
            .core
            .set_policy(
                input.peer,
                PeerPolicy {
                    block_all: !input.send && !input.receive,
                    request,
                    respond,
                },
            )
            .map_err(|e| to_host_error(e.to_string()))
    }

    pub fn decode_onboarding_package_json(&self, value: String) -> HostResult<String> {
        let decoded =
            decode_onboarding_package(&value).map_err(|e| to_host_error(e.to_string()))?;
        let secret = SecretKey::from_slice(&decoded.share.seckey)
            .map_err(|e| to_host_error(format!("invalid share seckey: {e}")))?;
        let point = secret.public_key().to_encoded_point(true);
        let payload = DecodedOnboarding {
            share: SharePackageWire::from(decoded.share),
            share_pubkey33: hex::encode(point.as_bytes()),
            peer_pk_xonly: hex::encode(decoded.peer_pk),
            relays: decoded.relays,
        };
        serde_json::to_string(&payload).map_err(|e| to_host_error(e.to_string()))
    }
}

impl Default for WasmBridgeRuntime {
    fn default() -> Self {
        Self::new()
    }
}

fn build_core(
    config: &RuntimeConfigInput,
    bootstrap: &RuntimeBootstrapInput,
    state: Option<DeviceState>,
) -> Result<BridgeCore> {
    let group = bootstrap.group.clone().try_into()?;
    let share = bootstrap.share.clone().try_into()?;
    let peers = bootstrap.peers.clone();

    let device_cfg = config.device.clone().unwrap_or_default();
    let signer = match state {
        Some(existing) => SigningDevice::new(group, share, peers, existing, device_cfg)?,
        None => SigningDevice::init(group, share, peers, device_cfg)?,
    };

    let bridge_cfg = config.bridge.clone().unwrap_or_default();
    BridgeCore::new(signer, bridge_cfg)
}

fn parse_command(input: CommandInput) -> Result<BridgeCommand> {
    match input {
        CommandInput::Sign { message_hex_32 } => Ok(BridgeCommand::Sign {
            message: decode_fixed_hex::<32>(&message_hex_32, "message_hex_32")?,
        }),
        CommandInput::Ecdh { pubkey33_hex } => Ok(BridgeCommand::Ecdh {
            pubkey: decode_fixed_hex::<33>(&pubkey33_hex, "pubkey33_hex")?,
        }),
        CommandInput::Ping { peer_pubkey33_hex } => Ok(BridgeCommand::Ping {
            peer: peer_pubkey33_hex,
        }),
        CommandInput::Onboard { peer_pubkey33_hex } => Ok(BridgeCommand::Onboard {
            peer: peer_pubkey33_hex,
        }),
    }
}

fn decode_fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).map_err(|e| anyhow!("invalid {field}: {e}"))?;
    if bytes.len() != N {
        return Err(anyhow!("invalid {field}: expected {N} bytes"));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

impl From<bifrost_signer::PendingOpType> for PendingOpTypeJson {
    fn from(value: bifrost_signer::PendingOpType) -> Self {
        match value {
            bifrost_signer::PendingOpType::Sign => PendingOpTypeJson::Sign,
            bifrost_signer::PendingOpType::Ecdh => PendingOpTypeJson::Ecdh,
            bifrost_signer::PendingOpType::Ping => PendingOpTypeJson::Ping,
            bifrost_signer::PendingOpType::Onboard => PendingOpTypeJson::Onboard,
        }
    }
}

impl From<bifrost_signer::OperationFailureCode> for OperationFailureCodeJson {
    fn from(value: bifrost_signer::OperationFailureCode) -> Self {
        match value {
            bifrost_signer::OperationFailureCode::Timeout => OperationFailureCodeJson::Timeout,
            bifrost_signer::OperationFailureCode::InvalidLockedPeerResponse => {
                OperationFailureCodeJson::InvalidLockedPeerResponse
            }
            bifrost_signer::OperationFailureCode::PeerRejected => {
                OperationFailureCodeJson::PeerRejected
            }
        }
    }
}

impl From<OperationFailure> for OperationFailureJson {
    fn from(value: OperationFailure) -> Self {
        Self {
            request_id: value.request_id,
            op_type: value.op_type.into(),
            code: value.code.into(),
            message: value.message,
            failed_peer: value.failed_peer,
        }
    }
}

impl From<CompletedOperation> for CompletedOperationJson {
    fn from(value: CompletedOperation) -> Self {
        match value {
            CompletedOperation::Sign {
                request_id,
                signatures,
            } => Self::Sign {
                request_id,
                signatures_hex64: signatures.into_iter().map(hex::encode).collect(),
            },
            CompletedOperation::Ecdh {
                request_id,
                shared_secret,
            } => Self::Ecdh {
                request_id,
                shared_secret_hex32: hex::encode(shared_secret),
            },
            CompletedOperation::Ping { request_id, peer } => Self::Ping { request_id, peer },
            CompletedOperation::Onboard {
                request_id,
                group_member_count,
            } => Self::Onboard {
                request_id,
                group_member_count,
            },
        }
    }
}
