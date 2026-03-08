use anyhow::{Result, anyhow};
use bifrost_codec::wire::{DerivedPublicNonceWire, GroupPackageWire, SharePackageWire};
use bifrost_core::types::{GroupPackage, MethodPolicy, PeerPolicy};
use bifrost_router::{BridgeCommand, BridgeConfig, BridgeCore, QueueOverflowPolicy};
use bifrost_signer::{
    CompletedOperation, DeviceConfig, DeviceState, OperationFailure, SigningDevice,
};
use frostr_utils::decode_onboarding_package;
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use nostr::Event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

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
    bridge: Option<BridgeConfigInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BridgeConfigInput {
    #[serde(default)]
    expire_tick_ms: Option<u64>,
    #[serde(default)]
    command_queue_capacity: Option<usize>,
    #[serde(default)]
    inbound_queue_capacity: Option<usize>,
    #[serde(default)]
    outbound_queue_capacity: Option<usize>,
    #[serde(default)]
    command_overflow_policy: Option<QueueOverflowPolicy>,
    #[serde(default)]
    inbound_overflow_policy: Option<QueueOverflowPolicy>,
    #[serde(default)]
    outbound_overflow_policy: Option<QueueOverflowPolicy>,
    #[serde(default)]
    inbound_dedupe_cache_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeBootstrapInput {
    group: GroupPackageWire,
    share: SharePackageWire,
    peers: Vec<String>,
    #[serde(default)]
    initial_peer_nonces: Vec<BootstrapPeerNoncesInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BootstrapPeerNoncesInput {
    peer: String,
    nonces: Vec<DerivedPublicNonceWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeSnapshot {
    bootstrap: RuntimeBootstrapInput,
    state_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeSnapshotExport {
    bootstrap: RuntimeBootstrapInput,
    state_hex: String,
    status: bifrost_signer::DeviceStatus,
    state: DeviceStateSnapshotJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceStateSnapshotJson {
    version: u32,
    last_active: u64,
    request_seq: u64,
    replay_cache_size: usize,
    ecdh_cache_size: usize,
    sig_cache_size: usize,
    policies: HashMap<String, PeerPolicy>,
    remote_scoped_policies: HashMap<String, bifrost_core::types::PeerScopedPolicyProfile>,
    pending_operations: HashMap<String, bifrost_signer::PendingOperation>,
    nonce_pool: NoncePoolSnapshotJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NoncePoolSnapshotJson {
    peers: Vec<NoncePeerSnapshotJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NoncePeerSnapshotJson {
    idx: u16,
    pubkey: String,
    incoming_available: usize,
    outgoing_available: usize,
    outgoing_spent: usize,
    can_sign: bool,
    should_send_nonces: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DecodedOnboarding {
    share: SharePackageWire,
    share_pubkey32: String,
    peer_pk_xonly: String,
    relays: Vec<String>,
    challenge_hex32: Option<String>,
    created_at: Option<u64>,
    expires_at: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CommandInput {
    Sign { message_hex_32: String },
    Ecdh { pubkey32_hex: String },
    Ping { peer_pubkey32_hex: String },
    Onboard {
        peer_pubkey32_hex: String,
        challenge_hex32: Option<String>,
    },
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
        let state = decode_device_state_hex(&snapshot.state_hex)
            .map_err(|e| to_host_error(e.to_string()))?;
        let core = build_core(&config, &snapshot.bootstrap, Some(state))
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

    pub fn tick(&mut self, now_unix_ms: u64) -> HostResult<()> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        state.core.tick(now_unix_ms);
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
        let device_state = state.core.snapshot_state();
        let snapshot = RuntimeSnapshotExport {
            bootstrap: state.bootstrap.clone(),
            state_hex: encode_device_state_hex(&device_state)
                .map_err(|e| to_host_error(e.to_string()))?,
            status: state.core.status(),
            state: device_state_snapshot_json(&device_state, &state.bootstrap)
                .map_err(|e| to_host_error(e.to_string()))?,
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

    pub fn decode_onboarding_package_json_with_password(
        &self,
        value: String,
        password: String,
    ) -> HostResult<String> {
        let decoded = decode_onboarding_package(&value, Some(password.as_str()))
            .map_err(|e| to_host_error(e.to_string()))?;
        self.encode_decoded_onboarding(decoded)
    }

    fn encode_decoded_onboarding(&self, decoded: frostr_utils::OnboardingPackage) -> HostResult<String> {
        let secret = SecretKey::from_slice(&decoded.share.seckey)
            .map_err(|e| to_host_error(format!("invalid share seckey: {e}")))?;
        let point = secret.public_key().to_encoded_point(true);
        let payload = DecodedOnboarding {
            share: SharePackageWire::from(decoded.share),
            share_pubkey32: hex::encode(&point.as_bytes()[1..]),
            peer_pk_xonly: hex::encode(decoded.peer_pk),
            relays: decoded.relays,
            challenge_hex32: decoded.challenge.map(hex::encode),
            created_at: decoded.created_at,
            expires_at: decoded.expires_at,
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
        None => {
            let mut initial_state = DeviceState::new(share.idx, share.seckey);
            seed_initial_peer_nonces(
                &mut initial_state,
                &group,
                &bootstrap.initial_peer_nonces,
            )?;
            SigningDevice::new(group, share, peers, initial_state, device_cfg)?
        }
    };

    let bridge_cfg = bridge_config_from_input(config.bridge.clone());
    BridgeCore::new(signer, bridge_cfg)
}

fn seed_initial_peer_nonces(
    state: &mut DeviceState,
    group: &GroupPackage,
    initial_peer_nonces: &[BootstrapPeerNoncesInput],
) -> Result<()> {
    for entry in initial_peer_nonces {
        if entry.nonces.is_empty() {
            continue;
        }

        let peer_idx = decode_member_index(group, &entry.peer)?;
        let nonces = entry
            .nonces
            .iter()
            .cloned()
            .map(TryInto::try_into)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e: bifrost_codec::CodecError| anyhow!(e.to_string()))?;
        state.nonce_pool.store_incoming(peer_idx, nonces);
    }

    Ok(())
}

fn decode_member_index(group: &GroupPackage, peer: &str) -> Result<u16> {
    if peer != peer.to_ascii_lowercase() {
        return Err(anyhow!("peer pubkey must be lowercase hex"));
    }

    let expected = hex::decode(peer).map_err(|_| anyhow!("invalid peer pubkey encoding"))?;
    if expected.len() != 32 {
        return Err(anyhow!("peer pubkey must be 32-byte x-only"));
    }

    for member in &group.members {
        if member.pubkey[1..] == expected[..] {
            return Ok(member.idx);
        }
    }

    Err(anyhow!("unknown peer {}", peer))
}

fn device_state_snapshot_json(
    state: &DeviceState,
    bootstrap: &RuntimeBootstrapInput,
) -> Result<DeviceStateSnapshotJson> {
    Ok(DeviceStateSnapshotJson {
        version: state.version,
        last_active: state.last_active,
        request_seq: state.request_seq,
        replay_cache_size: state.replay_cache.len(),
        ecdh_cache_size: state.ecdh_cache.len(),
        sig_cache_size: state.sig_cache.len(),
        policies: state.policies.clone(),
        remote_scoped_policies: state.remote_scoped_policies.clone(),
        pending_operations: state.pending_operations.clone(),
        nonce_pool: nonce_pool_snapshot_json(state, bootstrap)?,
    })
}

fn encode_device_state_hex(state: &DeviceState) -> Result<String> {
    let encoded =
        bincode::serialize(state).map_err(|e| anyhow!("failed to encode device state: {e}"))?;
    Ok(hex::encode(encoded))
}

fn decode_device_state_hex(state_hex: &str) -> Result<DeviceState> {
    let bytes = hex::decode(state_hex)
        .map_err(|e| anyhow!("failed to decode device state snapshot hex: {e}"))?;
    bincode::deserialize(&bytes).map_err(|e| anyhow!("failed to decode device state snapshot: {e}"))
}

fn nonce_pool_snapshot_json(
    state: &DeviceState,
    bootstrap: &RuntimeBootstrapInput,
) -> Result<NoncePoolSnapshotJson> {
    let group: GroupPackage = bootstrap.group.clone().try_into()?;
    let mut peers = Vec::with_capacity(bootstrap.peers.len());

    for peer in &bootstrap.peers {
        let idx = decode_member_index(&group, peer)?;
        let stats = state.nonce_pool.peer_stats(idx);
        peers.push(NoncePeerSnapshotJson {
            idx,
            pubkey: peer.clone(),
            incoming_available: stats.incoming_available,
            outgoing_available: stats.outgoing_available,
            outgoing_spent: stats.outgoing_spent,
            can_sign: stats.can_sign,
            should_send_nonces: stats.should_send_nonces,
        });
    }

    peers.sort_by_key(|entry| entry.idx);
    Ok(NoncePoolSnapshotJson { peers })
}

fn bridge_config_from_input(input: Option<BridgeConfigInput>) -> BridgeConfig {
    let mut cfg = BridgeConfig::default();
    if let Some(input) = input {
        if let Some(expire_tick_ms) = input.expire_tick_ms {
            cfg.expire_tick = Duration::from_millis(expire_tick_ms.max(1));
        }
        if let Some(capacity) = input.command_queue_capacity {
            cfg.command_queue_capacity = capacity;
        }
        if let Some(capacity) = input.inbound_queue_capacity {
            cfg.inbound_queue_capacity = capacity;
        }
        if let Some(capacity) = input.outbound_queue_capacity {
            cfg.outbound_queue_capacity = capacity;
        }
        if let Some(policy) = input.command_overflow_policy {
            cfg.command_overflow_policy = policy;
        }
        if let Some(policy) = input.inbound_overflow_policy {
            cfg.inbound_overflow_policy = policy;
        }
        if let Some(policy) = input.outbound_overflow_policy {
            cfg.outbound_overflow_policy = policy;
        }
        if let Some(limit) = input.inbound_dedupe_cache_limit {
            cfg.inbound_dedupe_cache_limit = limit;
        }
    }
    cfg
}

fn parse_command(input: CommandInput) -> Result<BridgeCommand> {
    match input {
        CommandInput::Sign { message_hex_32 } => Ok(BridgeCommand::Sign {
            message: decode_fixed_hex::<32>(&message_hex_32, "message_hex_32")?,
        }),
        CommandInput::Ecdh { pubkey32_hex } => Ok(BridgeCommand::Ecdh {
            pubkey: decode_fixed_hex::<32>(&pubkey32_hex, "pubkey32_hex")?,
        }),
        CommandInput::Ping { peer_pubkey32_hex } => Ok(BridgeCommand::Ping {
            peer: peer_pubkey32_hex,
        }),
        CommandInput::Onboard {
            peer_pubkey32_hex,
            challenge_hex32,
        } => Ok(BridgeCommand::Onboard {
            peer: peer_pubkey32_hex,
            challenge: challenge_hex32
                .as_deref()
                .map(|value| decode_fixed_hex::<32>(value, "challenge_hex32"))
                .transpose()?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use frostr_utils::{CreateKeysetConfig, create_keyset};

    #[test]
    fn build_core_seeds_initial_peer_nonces_into_runtime_state() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let group = bundle.group;
        let local_share = bundle.shares[0].clone();
        let peer_share = bundle.shares[1].clone();
        let peer_pubkey = hex::encode(&group.members[1].pubkey[1..]);

        let mut peer_state = DeviceState::new(peer_share.idx, peer_share.seckey);
        let generated = peer_state
            .nonce_pool
            .generate_for_peer(local_share.idx, 3)
            .expect("generate peer nonces");

        let bootstrap = RuntimeBootstrapInput {
            group: GroupPackageWire::from(group.clone()),
            share: SharePackageWire::from(local_share.clone()),
            peers: vec![peer_pubkey.clone()],
            initial_peer_nonces: vec![BootstrapPeerNoncesInput {
                peer: peer_pubkey,
                nonces: generated.into_iter().map(Into::into).collect(),
            }],
        };

        let core = build_core(
            &RuntimeConfigInput {
                device: None,
                bridge: None,
            },
            &bootstrap,
            None,
        )
        .expect("build core");

        let mut state = core.snapshot_state();
        let peer_stats = state.nonce_pool.peer_stats(peer_share.idx);
        assert_eq!(peer_stats.incoming_available, 3);
        assert!(state.nonce_pool.consume_incoming(peer_share.idx).is_some());
    }

    #[test]
    fn snapshot_json_serializes_nonce_pool_stats() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let group = bundle.group.clone();
        let local_share = bundle.shares[0].clone();
        let peer_share = bundle.shares[1].clone();
        let peer_pubkey = hex::encode(&group.members[1].pubkey[1..]);

        let mut peer_state = DeviceState::new(peer_share.idx, peer_share.seckey);
        let generated = peer_state
            .nonce_pool
            .generate_for_peer(local_share.idx, 2)
            .expect("generate peer nonces");

        let bootstrap = RuntimeBootstrapInput {
            group: GroupPackageWire::from(group),
            share: SharePackageWire::from(local_share),
            peers: vec![peer_pubkey.clone()],
            initial_peer_nonces: vec![BootstrapPeerNoncesInput {
                peer: peer_pubkey.clone(),
                nonces: generated.into_iter().map(Into::into).collect(),
            }],
        };

        let mut runtime = WasmBridgeRuntime::new();
        runtime
            .init_runtime("{}".to_string(), serde_json::to_string(&bootstrap).expect("bootstrap"))
            .expect("init runtime");

        let snapshot_json = runtime.snapshot_state_json().expect("snapshot json");
        let snapshot: RuntimeSnapshotExport =
            serde_json::from_str(&snapshot_json).expect("deserialize snapshot");
        let peer = &snapshot.state.nonce_pool.peers[0];
        assert_eq!(peer.pubkey, peer_pubkey);
        assert_eq!(peer.incoming_available, 2);
        assert!(!peer.can_sign);
    }
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
