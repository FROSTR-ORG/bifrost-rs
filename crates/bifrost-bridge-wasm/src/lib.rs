use anyhow::{Result, anyhow};
use bifrost_codec::{
    error::CodecError,
    wire::{DerivedPublicNonceWire, GroupPackageWire, SharePackageWire},
};
use bifrost_core::types::{GroupPackage, PeerPolicyOverride, PolicyOverrideValue};
use bifrost_core::{get_group_id, nonce::NoncePoolConfig};
use bifrost_router::{BridgeCommand, BridgeConfig, BridgeCore, QueueOverflowPolicy};
use bifrost_signer::{
    CompletedOperation, DeviceConfig, DeviceConfigPatch, DeviceState, OperationFailure,
    PeerNonceInventoryObservation, RuntimeStatusSummary, SigningDevice,
    finalize_onboarding_bootstrap_seed,
    generate_onboarding_bootstrap_seed,
};
use frostr_utils::{
    BF_PACKAGE_VERSION, BfOnboardPayload, BfProfilePayload, BfSharePayload, CreateKeysetConfig,
    EncryptedProfileBackup, PREFIX_BFONBOARD, PREFIX_BFPROFILE, PREFIX_BFSHARE,
    PROFILE_BACKUP_EVENT_KIND, PROFILE_BACKUP_KEY_DOMAIN, ProfilePackagePair, RotateKeysetRequest,
    build_onboard_request_event as rust_build_onboard_request_event,
    build_profile_backup_event as rust_build_profile_backup_event,
    create_encrypted_profile_backup as rust_create_encrypted_profile_backup,
    create_keyset as rust_create_keyset,
    create_profile_package_pair as rust_create_profile_package_pair,
    decode_bfonboard_package as rust_decode_bfonboard_package,
    decode_bfprofile_package as rust_decode_bfprofile_package,
    decode_bfshare_package as rust_decode_bfshare_package,
    decrypt_profile_backup_content as rust_decrypt_profile_backup_content,
    derive_profile_backup_conversation_key as rust_derive_profile_backup_conversation_key,
    derive_profile_id_from_share_pubkey as rust_derive_profile_id_from_share_pubkey,
    derive_profile_id_from_share_secret as rust_derive_profile_id_from_share_secret,
    encode_bfonboard_package as rust_encode_bfonboard_package,
    encode_bfprofile_package as rust_encode_bfprofile_package,
    encode_bfshare_package as rust_encode_bfshare_package,
    encrypt_profile_backup_content as rust_encrypt_profile_backup_content,
    generate_opaque_request_id as rust_generate_opaque_request_id,
    parse_profile_backup_event as rust_parse_profile_backup_event,
    rotate_keyset_dealer as rust_rotate_keyset_dealer,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use nostr::Event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

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
    manual_policy_overrides: HashMap<String, PeerPolicyOverride>,
    remote_scoped_policies: HashMap<String, bifrost_core::types::PeerScopedPolicyProfile>,
    remote_nonce_inventory_observations: HashMap<String, PeerNonceInventoryObservation>,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CommandInput {
    Sign { message_hex_32: String },
    Ecdh { pubkey32_hex: String },
    Ping { peer_pubkey32_hex: String },
    RefreshPeer { peer_pubkey32_hex: String },
    RefreshAllPeers,
    Onboard { peer_pubkey32_hex: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PolicyDirectionInput {
    Request,
    Respond,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PolicyMethodInput {
    Ping,
    Onboard,
    Sign,
    Ecdh,
}

#[derive(Debug, Clone, Deserialize)]
struct SetPolicyOverrideInput {
    peer: String,
    direction: PolicyDirectionInput,
    method: PolicyMethodInput,
    value: PolicyOverrideValue,
}

struct RuntimeState {
    core: BridgeCore,
    bootstrap: RuntimeBootstrapInput,
    last_runtime_status_json: Option<String>,
    runtime_events: Vec<RuntimeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RuntimeEventKind {
    Initialized,
    StatusChanged,
    CommandQueued,
    InboundAccepted,
    ConfigUpdated,
    PolicyUpdated,
    StateWiped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeEvent {
    kind: RuntimeEventKind,
    status: RuntimeStatusSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeDiagnosticsExport {
    runtime_status: RuntimeStatusSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RotateKeysetBundleInput {
    group: GroupPackageWire,
    shares: Vec<SharePackageWire>,
    threshold: u16,
    count: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeysetBundleExport {
    group: GroupPackageWire,
    shares: Vec<SharePackageWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RotateKeysetBundleExport {
    previous_group_id: String,
    next_group_id: String,
    next: KeysetBundleExport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OnboardingRequestBundleExport {
    request_id: String,
    local_pubkey32: String,
    request_nonces: Vec<DerivedPublicNonceWire>,
    bootstrap_state_hex: String,
    event_json: String,
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
        group: GroupPackageWire,
        nonces: Vec<DerivedPublicNonceWire>,
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
        let mut state = RuntimeState {
            core,
            bootstrap,
            last_runtime_status_json: None,
            runtime_events: Vec::new(),
        };
        queue_runtime_status_event(&mut state, RuntimeEventKind::Initialized)
            .map_err(|e| to_host_error(e.to_string()))?;
        self.state = Some(state);
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
        let mut state = RuntimeState {
            core,
            bootstrap: snapshot.bootstrap,
            last_runtime_status_json: None,
            runtime_events: Vec::new(),
        };
        queue_runtime_status_event(&mut state, RuntimeEventKind::Initialized)
            .map_err(|e| to_host_error(e.to_string()))?;
        self.state = Some(state);
        Ok(())
    }

    pub fn handle_command(&mut self, command_json: String) -> HostResult<()> {
        let command: CommandInput =
            serde_json::from_str(&command_json).map_err(|e| to_host_error(e.to_string()))?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        match command {
            CommandInput::RefreshPeer { peer_pubkey32_hex } => state
                .core
                .enqueue_command(BridgeCommand::Ping {
                    peer: peer_pubkey32_hex,
                })
                .map_err(|e| to_host_error(e.to_string()))?,
            CommandInput::RefreshAllPeers => {
                for peer in state.core.runtime_metadata().peers {
                    state
                        .core
                        .enqueue_command(BridgeCommand::Ping { peer })
                        .map_err(|e| to_host_error(e.to_string()))?;
                }
            }
            other => {
                let bridge_command =
                    parse_command(other).map_err(|e| to_host_error(e.to_string()))?;
                state
                    .core
                    .enqueue_command(bridge_command)
                    .map_err(|e| to_host_error(e.to_string()))?;
            }
        }
        queue_runtime_status_event(state, RuntimeEventKind::CommandQueued)
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
        queue_runtime_status_event(state, RuntimeEventKind::InboundAccepted)
            .map_err(|e| to_host_error(e.to_string()))?;
        Ok(())
    }

    pub fn tick(&mut self, now_unix_ms: u64) -> HostResult<()> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        state.core.tick(now_unix_ms);
        queue_runtime_status_event(state, RuntimeEventKind::StatusChanged)
            .map_err(|e| to_host_error(e.to_string()))?;
        Ok(())
    }

    pub fn drain_outbound_events(&mut self) -> HostResult<String> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        let events = state.core.drain_outbound_events();
        serde_json::to_string(&events).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn drain_completions(&mut self) -> HostResult<String> {
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

    pub fn drain_failures(&mut self) -> HostResult<String> {
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

    pub fn snapshot_state(&self) -> HostResult<String> {
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

    pub fn status(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&state.core.status()).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn peer_permission_states(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&state.core.peer_permission_states())
            .map_err(|e| to_host_error(e.to_string()))
    }

    pub fn read_config(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&state.core.read_config()).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn update_config(&mut self, config_patch: String) -> HostResult<()> {
        let patch: DeviceConfigPatch =
            serde_json::from_str(&config_patch).map_err(|e| to_host_error(e.to_string()))?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        state
            .core
            .update_config(patch)
            .map_err(|e| to_host_error(e.to_string()))?;
        queue_runtime_status_event(state, RuntimeEventKind::ConfigUpdated)
            .map_err(|e| to_host_error(e.to_string()))?;
        Ok(())
    }

    pub fn peer_status(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&state.core.peer_status()).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn readiness(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&state.core.readiness()).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn runtime_status(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&state.core.runtime_status())
            .map_err(|e| to_host_error(e.to_string()))
    }

    pub fn runtime_diagnostics(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&runtime_diagnostics_export(state))
            .map_err(|e| to_host_error(e.to_string()))
    }

    pub fn drain_runtime_events(&mut self) -> HostResult<String> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        let events = state.runtime_events.drain(..).collect::<Vec<_>>();
        serde_json::to_string(&events).map_err(|e| to_host_error(e.to_string()))
    }

    pub fn wipe_state(&mut self) -> HostResult<()> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        state.core.wipe_state();
        state.last_runtime_status_json = None;
        queue_runtime_status_event(state, RuntimeEventKind::StateWiped)
            .map_err(|e| to_host_error(e.to_string()))?;
        Ok(())
    }

    pub fn runtime_metadata(&self) -> HostResult<String> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        serde_json::to_string(&state.core.runtime_metadata())
            .map_err(|e| to_host_error(e.to_string()))
    }

    pub fn set_policy_override(&mut self, policy_json: String) -> HostResult<()> {
        let input: SetPolicyOverrideInput =
            serde_json::from_str(&policy_json).map_err(|e| to_host_error(e.to_string()))?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;

        let mut override_policy = state
            .core
            .peer_permission_states()
            .into_iter()
            .find(|entry| entry.pubkey == input.peer)
            .map(|entry| entry.manual_override)
            .unwrap_or_default();

        let target = match input.direction {
            PolicyDirectionInput::Request => &mut override_policy.request,
            PolicyDirectionInput::Respond => &mut override_policy.respond,
        };
        match input.method {
            PolicyMethodInput::Ping => target.ping = input.value,
            PolicyMethodInput::Onboard => target.onboard = input.value,
            PolicyMethodInput::Sign => target.sign = input.value,
            PolicyMethodInput::Ecdh => target.ecdh = input.value,
        }

        state
            .core
            .set_policy_override(input.peer, override_policy)
            .map_err(|e| to_host_error(e.to_string()))?;
        queue_runtime_status_event(state, RuntimeEventKind::PolicyUpdated)
            .map_err(|e| to_host_error(e.to_string()))?;
        Ok(())
    }

    pub fn clear_policy_overrides(&mut self) -> HostResult<()> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| to_host_error("runtime not initialized"))?;
        state.core.clear_policy_overrides();
        queue_runtime_status_event(state, RuntimeEventKind::PolicyUpdated)
            .map_err(|e| to_host_error(e.to_string()))?;
        Ok(())
    }
}

impl Default for WasmBridgeRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn bf_package_version() -> u8 {
    BF_PACKAGE_VERSION
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn bfshare_prefix() -> String {
    PREFIX_BFSHARE.to_string()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn bfonboard_prefix() -> String {
    PREFIX_BFONBOARD.to_string()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn bfprofile_prefix() -> String {
    PREFIX_BFPROFILE.to_string()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn profile_backup_event_kind() -> u16 {
    PROFILE_BACKUP_EVENT_KIND
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn profile_backup_key_domain() -> String {
    PROFILE_BACKUP_KEY_DOMAIN.to_string()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encode_bfshare_package(payload_json: String, password: String) -> HostResult<String> {
    let payload: BfSharePayload =
        serde_json::from_str(&payload_json).map_err(|e| to_host_error(e.to_string()))?;
    rust_encode_bfshare_package(&payload, &password).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decode_bfshare_package(package_text: String, password: String) -> HostResult<String> {
    let payload = rust_decode_bfshare_package(&package_text, &password)
        .map_err(|e| to_host_error(e.to_string()))?;
    serde_json::to_string(&payload).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encode_bfonboard_package(payload_json: String, password: String) -> HostResult<String> {
    let payload: BfOnboardPayload =
        serde_json::from_str(&payload_json).map_err(|e| to_host_error(e.to_string()))?;
    rust_encode_bfonboard_package(&payload, &password).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decode_bfonboard_package(package_text: String, password: String) -> HostResult<String> {
    let payload = rust_decode_bfonboard_package(&package_text, &password)
        .map_err(|e| to_host_error(e.to_string()))?;
    serde_json::to_string(&payload).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn create_onboarding_request_bundle(
    share_secret: String,
    peer_pubkey32_hex: String,
    event_kind: u64,
    sent_at_seconds: Option<u32>,
) -> HostResult<String> {
    let share = decode_hex32(&share_secret).map_err(|e| to_host_error(e.to_string()))?;
    let local_pubkey32 =
        derive_member_pubkey32_hex(share).map_err(|e| to_host_error(e.to_string()))?;
    let request_id = rust_generate_opaque_request_id();
    let seed = generate_onboarding_bootstrap_seed(share, NoncePoolConfig::default().pool_size)
        .map_err(|e| to_host_error(e.to_string()))?;
    let event = rust_build_onboard_request_event(
        share,
        &peer_pubkey32_hex,
        event_kind,
        &request_id,
        sent_at_seconds.map(u64::from).unwrap_or_else(now_unix_secs),
        &seed.request_nonces,
    )
    .map_err(|e| to_host_error(e.to_string()))?;
    let bundle = OnboardingRequestBundleExport {
        request_id,
        local_pubkey32,
        request_nonces: seed.request_nonces.into_iter().map(Into::into).collect(),
        bootstrap_state_hex: encode_device_state_hex(&seed.state)
            .map_err(|e| to_host_error(e.to_string()))?,
        event_json: serde_json::to_string(&event).map_err(|e| to_host_error(e.to_string()))?,
    };
    serde_json::to_string(&bundle).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn build_onboarding_runtime_snapshot(
    group_json: String,
    share_secret: String,
    peer_pubkey32_hex: String,
    response_nonces_json: String,
    bootstrap_state_hex: String,
) -> HostResult<String> {
    let group_wire: GroupPackageWire =
        serde_json::from_str(&group_json).map_err(|e| to_host_error(e.to_string()))?;
    let group: GroupPackage = group_wire
        .clone()
        .try_into()
        .map_err(|e: bifrost_codec::CodecError| to_host_error(e.to_string()))?;
    let share = decode_hex32(&share_secret).map_err(|e| to_host_error(e.to_string()))?;
    let local_idx = local_member_index(&group, share).map_err(|e| to_host_error(e.to_string()))?;
    let inviter_idx = member_index_for_peer(&group, &peer_pubkey32_hex)
        .map_err(|e| to_host_error(e.to_string()))?;
    let response_nonces_wire: Vec<DerivedPublicNonceWire> =
        serde_json::from_str(&response_nonces_json).map_err(|e| to_host_error(e.to_string()))?;
    let response_nonces = response_nonces_wire
        .into_iter()
        .map(TryInto::try_into)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e: bifrost_codec::CodecError| to_host_error(e.to_string()))?;
    let seed_state =
        decode_device_state_hex(&bootstrap_state_hex).map_err(|e| to_host_error(e.to_string()))?;
    let finalized_state =
        finalize_onboarding_bootstrap_seed(seed_state, local_idx, inviter_idx, response_nonces)
            .map_err(|e| to_host_error(e.to_string()))?;
    let peers = group
        .members
        .iter()
        .filter(|member| member.idx != local_idx)
        .map(|member| hex::encode(&member.pubkey[1..]))
        .collect::<Vec<_>>();
    let snapshot = RuntimeSnapshot {
        bootstrap: RuntimeBootstrapInput {
            group: group_wire,
            share: SharePackageWire {
                idx: local_idx,
                seckey: hex::encode(share),
            },
            peers,
            initial_peer_nonces: Vec::new(),
        },
        state_hex: encode_device_state_hex(&finalized_state)
            .map_err(|e| to_host_error(e.to_string()))?,
    };
    serde_json::to_string(&snapshot).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encode_bfprofile_package(payload_json: String, password: String) -> HostResult<String> {
    let payload: BfProfilePayload =
        serde_json::from_str(&payload_json).map_err(|e| to_host_error(e.to_string()))?;
    rust_encode_bfprofile_package(&payload, &password).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decode_bfprofile_package(package_text: String, password: String) -> HostResult<String> {
    let payload = rust_decode_bfprofile_package(&package_text, &password)
        .map_err(|e| to_host_error(e.to_string()))?;
    serde_json::to_string(&payload).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn derive_profile_id_from_share_secret(share_secret: String) -> HostResult<String> {
    rust_derive_profile_id_from_share_secret(&share_secret)
        .map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn derive_profile_id_from_share_pubkey(share_pubkey: String) -> HostResult<String> {
    rust_derive_profile_id_from_share_pubkey(&share_pubkey)
        .map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn create_profile_package_pair(payload_json: String, password: String) -> HostResult<String> {
    let payload: BfProfilePayload =
        serde_json::from_str(&payload_json).map_err(|e| to_host_error(e.to_string()))?;
    let pair: ProfilePackagePair = rust_create_profile_package_pair(&payload, &password)
        .map_err(|e| to_host_error(e.to_string()))?;
    serde_json::to_string(&pair).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn create_keyset_bundle(config_json: String) -> HostResult<String> {
    let config: CreateKeysetConfig =
        serde_json::from_str(&config_json).map_err(|e| to_host_error(e.to_string()))?;
    let bundle = rust_create_keyset(config).map_err(|e| to_host_error(e.to_string()))?;
    let exported = KeysetBundleExport {
        group: GroupPackageWire::from(bundle.group),
        shares: bundle
            .shares
            .into_iter()
            .map(SharePackageWire::from)
            .collect(),
    };
    serde_json::to_string(&exported).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn rotate_keyset_bundle(input_json: String) -> HostResult<String> {
    let input: RotateKeysetBundleInput =
        serde_json::from_str(&input_json).map_err(|e| to_host_error(e.to_string()))?;
    let group: GroupPackage = input
        .group
        .try_into()
        .map_err(|e: CodecError| to_host_error(e.to_string()))?;
    let shares = input
        .shares
        .into_iter()
        .map(|share| {
            share
                .try_into()
                .map_err(|e: CodecError| anyhow!(e.to_string()))
        })
        .collect::<Result<Vec<_>>>()
        .map_err(|e| to_host_error(e.to_string()))?;
    let rotated = rust_rotate_keyset_dealer(
        &group,
        RotateKeysetRequest {
            shares,
            threshold: input.threshold,
            count: input.count,
        },
    )
    .map_err(|e| to_host_error(e.to_string()))?;
    let exported = RotateKeysetBundleExport {
        previous_group_id: hex::encode(rotated.previous_group_id),
        next_group_id: hex::encode(rotated.next_group_id),
        next: KeysetBundleExport {
            group: GroupPackageWire::from(rotated.next.group),
            shares: rotated
                .next
                .shares
                .into_iter()
                .map(SharePackageWire::from)
                .collect(),
        },
    };
    serde_json::to_string(&exported).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn derive_group_id(group_json: String) -> HostResult<String> {
    let group_wire: GroupPackageWire =
        serde_json::from_str(&group_json).map_err(|e| to_host_error(e.to_string()))?;
    let group: GroupPackage = group_wire
        .try_into()
        .map_err(|e: CodecError| to_host_error(e.to_string()))?;
    let group_id = get_group_id(&group).map_err(|e| to_host_error(e.to_string()))?;
    Ok(hex::encode(group_id))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn create_encrypted_profile_backup(profile_json: String) -> HostResult<String> {
    let profile: BfProfilePayload =
        serde_json::from_str(&profile_json).map_err(|e| to_host_error(e.to_string()))?;
    let backup =
        rust_create_encrypted_profile_backup(&profile).map_err(|e| to_host_error(e.to_string()))?;
    serde_json::to_string(&backup).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn derive_profile_backup_conversation_key_hex(share_secret: String) -> HostResult<String> {
    let key = rust_derive_profile_backup_conversation_key(&share_secret)
        .map_err(|e| to_host_error(e.to_string()))?;
    Ok(hex::encode(key))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn encrypt_profile_backup_content(
    backup_json: String,
    share_secret: String,
) -> HostResult<String> {
    let backup: EncryptedProfileBackup =
        serde_json::from_str(&backup_json).map_err(|e| to_host_error(e.to_string()))?;
    rust_encrypt_profile_backup_content(&backup, &share_secret)
        .map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn decrypt_profile_backup_content(
    ciphertext: String,
    share_secret: String,
) -> HostResult<String> {
    let backup = rust_decrypt_profile_backup_content(&ciphertext, &share_secret)
        .map_err(|e| to_host_error(e.to_string()))?;
    serde_json::to_string(&backup).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn build_profile_backup_event(
    share_secret: String,
    backup_json: String,
    created_at_seconds: Option<u32>,
) -> HostResult<String> {
    let backup: EncryptedProfileBackup =
        serde_json::from_str(&backup_json).map_err(|e| to_host_error(e.to_string()))?;
    let event =
        rust_build_profile_backup_event(&share_secret, &backup, created_at_seconds.map(u64::from))
            .map_err(|e| to_host_error(e.to_string()))?;
    serde_json::to_string(&event).map_err(|e| to_host_error(e.to_string()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn parse_profile_backup_event(event_json: String, share_secret: String) -> HostResult<String> {
    let event: Event =
        serde_json::from_str(&event_json).map_err(|e| to_host_error(e.to_string()))?;
    let backup = rust_parse_profile_backup_event(&event, &share_secret)
        .map_err(|e| to_host_error(e.to_string()))?;
    serde_json::to_string(&backup).map_err(|e| to_host_error(e.to_string()))
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
            seed_initial_peer_nonces(&mut initial_state, &group, &bootstrap.initial_peer_nonces)?;
            SigningDevice::new(group, share, peers, initial_state, device_cfg)?
        }
    };

    let bridge_cfg = bridge_config_from_input(config.bridge.clone());
    BridgeCore::new(signer, bridge_cfg)
}

fn runtime_diagnostics_export(state: &RuntimeState) -> RuntimeDiagnosticsExport {
    RuntimeDiagnosticsExport {
        runtime_status: state.core.runtime_status(),
    }
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

fn decode_hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|e| anyhow!("decode hex32: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32-byte hex"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn derive_member_pubkey32_hex(share_seckey: [u8; 32]) -> Result<String> {
    let key = k256::SecretKey::from_slice(&share_seckey)
        .map_err(|e| anyhow!("invalid share secret: {e}"))?;
    let pubkey = key.public_key();
    let encoded = pubkey.to_encoded_point(true);
    Ok(hex::encode(&encoded.as_bytes()[1..]))
}

fn local_member_index(group: &GroupPackage, share_seckey: [u8; 32]) -> Result<u16> {
    let expected = derive_member_pubkey32_hex(share_seckey)?;
    decode_member_index(group, &expected)
}

fn member_index_for_peer(group: &GroupPackage, peer_pubkey32_hex: &str) -> Result<u16> {
    decode_member_index(group, &peer_pubkey32_hex.to_ascii_lowercase())
}

fn now_unix_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0).floor() as u64
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }
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
        manual_policy_overrides: state.manual_policy_overrides.clone(),
        remote_scoped_policies: state.remote_scoped_policies.clone(),
        remote_nonce_inventory_observations: state.remote_nonce_inventory_observations.clone(),
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
        let current_codes = state.nonce_pool.outgoing_public_nonce_codes(idx);
        let current_code_set = current_codes.into_iter().collect::<std::collections::HashSet<_>>();
        let observed_count = state
            .remote_nonce_inventory_observations
            .get(peer)
            .map(|observation| {
                observation
                    .held_codes
                    .iter()
                    .filter(|code| current_code_set.contains(*code))
                    .count()
            })
            .unwrap_or(0);
        peers.push(NoncePeerSnapshotJson {
            idx,
            pubkey: peer.clone(),
            incoming_available: stats.incoming_available,
            outgoing_available: stats.outgoing_available,
            outgoing_spent: stats.outgoing_spent,
            can_sign: stats.can_sign,
            should_send_nonces: observed_count < state.nonce_pool.config().min_threshold,
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
        CommandInput::RefreshPeer { peer_pubkey32_hex } => Ok(BridgeCommand::Ping {
            peer: peer_pubkey32_hex,
        }),
        CommandInput::RefreshAllPeers => Err(anyhow!("refresh_all_peers must be handled directly")),
        CommandInput::Onboard { peer_pubkey32_hex } => Ok(BridgeCommand::Onboard {
            peer: peer_pubkey32_hex,
        }),
    }
}

fn queue_runtime_status_event(state: &mut RuntimeState, kind: RuntimeEventKind) -> Result<()> {
    let status = state.core.runtime_status();
    let status_json = serde_json::to_string(&status)?;
    if matches!(kind, RuntimeEventKind::StatusChanged)
        && state.last_runtime_status_json.as_deref() == Some(status_json.as_str())
    {
        return Ok(());
    }

    state.last_runtime_status_json = Some(status_json);
    state.runtime_events.push(RuntimeEvent { kind, status });
    Ok(())
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
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use bifrost_signer::PeerPermissionState;
    use frostr_utils::{
        BfOnboardPayload, CreateKeysetConfig, create_keyset, encode_bfonboard_package,
    };

    fn bootstrap_for_bundle(
        bundle: &frostr_utils::KeysetBundle,
        local_idx: usize,
    ) -> RuntimeBootstrapInput {
        let group = bundle.group.clone();
        let local_share = bundle.shares[local_idx].clone();
        let peers = group
            .members
            .iter()
            .filter(|member| member.idx != local_share.idx)
            .map(|member| hex::encode(&member.pubkey[1..]))
            .collect::<Vec<_>>();

        RuntimeBootstrapInput {
            group: GroupPackageWire::from(group),
            share: SharePackageWire::from(local_share),
            peers,
            initial_peer_nonces: Vec::new(),
        }
    }

    #[test]
    fn public_runtime_methods_require_initialization() {
        let mut runtime = WasmBridgeRuntime::new();

        assert!(runtime.status().is_err());
        assert!(runtime.runtime_status().is_err());
        assert!(runtime.runtime_diagnostics().is_err());
        assert!(runtime.drain_runtime_events().is_err());
        assert!(
            runtime
                .handle_command(r#"{"type":"refresh_all_peers"}"#.to_string())
                .is_err()
        );
    }

    #[test]
    fn build_core_seeds_initial_peer_nonces_into_runtime_state() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
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
            group_name: "Test Group".to_string(),
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
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");

        let snapshot_json = runtime.snapshot_state().expect("snapshot json");
        let snapshot: RuntimeSnapshotExport =
            serde_json::from_str(&snapshot_json).expect("deserialize snapshot");
        let peer = &snapshot.state.nonce_pool.peers[0];
        assert_eq!(peer.pubkey, peer_pubkey);
        assert_eq!(peer.incoming_available, 2);
        assert!(!peer.can_sign);
    }

    #[test]
    fn read_and_update_config_round_trip() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let group = bundle.group.clone();
        let local_share = bundle.shares[0].clone();
        let peer_pubkey = hex::encode(&group.members[1].pubkey[1..]);

        let bootstrap = RuntimeBootstrapInput {
            group: GroupPackageWire::from(group),
            share: SharePackageWire::from(local_share),
            peers: vec![peer_pubkey],
            initial_peer_nonces: Vec::new(),
        };

        let mut runtime = WasmBridgeRuntime::new();
        runtime
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");

        let before: DeviceConfig =
            serde_json::from_str(&runtime.read_config().expect("read config")).expect("config");
        assert_eq!(before.sign_timeout_secs, 30);
        assert_eq!(
            before.peer_selection_strategy,
            bifrost_signer::PeerSelectionStrategy::DeterministicSorted
        );

        runtime
            .update_config(
                serde_json::json!({
                    "sign_timeout_secs": 45,
                    "ping_timeout_secs": 22,
                    "request_ttl_secs": 600,
                    "state_save_interval_secs": 10,
                    "peer_selection_strategy": "random"
                })
                .to_string(),
            )
            .expect("update config");

        let after: DeviceConfig =
            serde_json::from_str(&runtime.read_config().expect("read config")).expect("config");
        assert_eq!(after.sign_timeout_secs, 45);
        assert_eq!(after.ping_timeout_secs, 22);
        assert_eq!(after.request_ttl_secs, 600);
        assert_eq!(after.state_save_interval_secs, 10);
        assert_eq!(
            after.peer_selection_strategy,
            bifrost_signer::PeerSelectionStrategy::Random
        );
    }

    #[test]
    fn readiness_reports_capability_counts() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
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
            .generate_for_peer(local_share.idx, 10)
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
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");

        runtime
            .handle_command(
                serde_json::json!({
                    "type": "refresh_peer",
                    "peer_pubkey32_hex": peer_pubkey
                })
                .to_string(),
            )
            .expect("refresh peer");

        let readiness: bifrost_signer::RuntimeReadiness =
            serde_json::from_str(&runtime.readiness().expect("readiness")).expect("readiness");
        assert!(readiness.restore_complete);
        assert!(readiness.sign_ready);
        assert!(!readiness.ecdh_ready);
        assert!(!readiness.runtime_ready);
        assert!(
            readiness
                .degraded_reasons
                .contains(&bifrost_signer::RuntimeDegradedReason::InsufficientEcdhPeers)
        );
    }

    #[test]
    fn runtime_diagnostics_reports_operation_readiness_fields() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
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
            .generate_for_peer(local_share.idx, 10)
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
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");
        runtime
            .handle_command(
                serde_json::json!({
                    "type": "refresh_peer",
                    "peer_pubkey32_hex": peer_pubkey
                })
                .to_string(),
            )
            .expect("refresh peer");

        let diagnostics: RuntimeDiagnosticsExport =
            serde_json::from_str(&runtime.runtime_diagnostics().expect("runtime diagnostics"))
                .expect("deserialize runtime diagnostics");

        assert!(diagnostics.runtime_status.readiness.sign_ready);
        assert_eq!(diagnostics.runtime_status.readiness.signing_peer_count, 1);
    }

    #[test]
    fn runtime_diagnostics_matches_runtime_status_contract() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let group = bundle.group.clone();
        let local_share = bundle.shares[0].clone();
        let peer_pubkey = hex::encode(&group.members[1].pubkey[1..]);

        let bootstrap = RuntimeBootstrapInput {
            group: GroupPackageWire::from(group),
            share: SharePackageWire::from(local_share),
            peers: vec![peer_pubkey],
            initial_peer_nonces: Vec::new(),
        };

        let mut runtime = WasmBridgeRuntime::new();
        runtime
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");

        let readiness: bifrost_signer::RuntimeReadiness =
            serde_json::from_str(&runtime.readiness().expect("readiness")).expect("readiness");
        let diagnostics: RuntimeDiagnosticsExport =
            serde_json::from_str(&runtime.runtime_diagnostics().expect("runtime diagnostics"))
                .expect("deserialize runtime diagnostics");

        assert_eq!(
            diagnostics.runtime_status.readiness.runtime_ready,
            readiness.runtime_ready
        );
        assert_eq!(
            diagnostics.runtime_status.readiness.sign_ready,
            readiness.sign_ready
        );
        assert_eq!(
            diagnostics.runtime_status.readiness.ecdh_ready,
            readiness.ecdh_ready
        );
    }

    #[test]
    fn init_runtime_rejects_invalid_bridge_config_and_bad_command_hex() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let bootstrap = bootstrap_for_bundle(&bundle, 0);
        let mut runtime = WasmBridgeRuntime::new();

        let err = runtime
            .init_runtime(
                serde_json::json!({
                    "bridge": {
                        "command_queue_capacity": 0
                    }
                })
                .to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect_err("zero command queue capacity must fail");
        assert!(err.to_string().contains("queue"));

        runtime
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");
        let err = runtime
            .handle_command(
                serde_json::json!({
                    "type": "sign",
                    "message_hex_32": "abc"
                })
                .to_string(),
            )
            .expect_err("invalid sign hex must fail");
        assert!(err.to_string().contains("message_hex_32"));
    }

    #[test]
    fn restore_runtime_round_trip_preserves_runtime_metadata_and_status() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let bootstrap = bootstrap_for_bundle(&bundle, 0);
        let mut runtime = WasmBridgeRuntime::new();
        runtime
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");

        let snapshot_json = runtime.snapshot_state().expect("snapshot");
        let runtime_status_before = runtime.runtime_status().expect("status before");
        let metadata_before = runtime.runtime_metadata().expect("metadata before");

        let mut restored = WasmBridgeRuntime::new();
        restored
            .restore_runtime("{}".to_string(), snapshot_json)
            .expect("restore runtime");

        assert_eq!(
            restored.runtime_metadata().expect("metadata after"),
            metadata_before
        );
        let mut status_after: serde_json::Value =
            serde_json::from_str(&restored.runtime_status().expect("status after"))
                .expect("status after json");
        let mut status_before: serde_json::Value =
            serde_json::from_str(&runtime_status_before).expect("status before json");
        let after_last_active = status_after["status"]["last_active"]
            .as_i64()
            .expect("status after last_active");
        let before_last_active = status_before["status"]["last_active"]
            .as_i64()
            .expect("status before last_active");
        assert!(after_last_active >= before_last_active);
        status_after["status"]["last_active"] = serde_json::Value::Null;
        status_before["status"]["last_active"] = serde_json::Value::Null;
        assert_eq!(status_after, status_before);
    }

    #[test]
    fn decode_bfonboard_package_round_trips_and_rejects_wrong_password() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let group = bundle.group.clone();
        let share = bundle.shares[1].clone();
        let payload = BfOnboardPayload {
            share_secret: hex::encode(share.seckey),
            relays: vec!["wss://relay.example".to_string()],
            peer_pk: hex::encode(&group.members[0].pubkey[1..]),
        };
        let encoded = encode_bfonboard_package(&payload, "password123").expect("encode package");

        let decoded: BfOnboardPayload = serde_json::from_str(
            &decode_bfonboard_package(encoded.clone(), "password123".to_string())
                .expect("decode package"),
        )
        .expect("decoded onboarding");
        assert_eq!(decoded.relays, payload.relays);
        assert_eq!(decoded.peer_pk, payload.peer_pk);

        let err = decode_bfonboard_package(encoded, "wrongpass".to_string())
            .expect_err("wrong password must fail");
        let err = err.to_string();
        assert!(err.contains("password") || err.contains("decrypt") || err.contains("invalid"));
    }

    #[test]
    fn refresh_all_peers_policy_updates_and_runtime_events_round_trip() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let bootstrap = bootstrap_for_bundle(&bundle, 0);
        let first_peer = bootstrap.peers[0].clone();

        let mut runtime = WasmBridgeRuntime::new();
        runtime
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");

        runtime
            .handle_command(r#"{"type":"refresh_all_peers"}"#.to_string())
            .expect("refresh all peers");
        runtime
            .set_policy_override(
                serde_json::json!({
                    "peer": first_peer,
                    "direction": "request",
                    "method": "sign",
                    "value": "deny"
                })
                .to_string(),
            )
            .expect("set policy override");

        let states: Vec<PeerPermissionState> = serde_json::from_str(
            &runtime
                .peer_permission_states()
                .expect("peer permission states"),
        )
        .expect("decode peer permission states");
        let stored = states
            .iter()
            .find(|entry| entry.pubkey == first_peer)
            .expect("stored state");
        assert_eq!(
            stored.manual_override.request.sign,
            PolicyOverrideValue::Deny
        );

        let events: Vec<RuntimeEvent> =
            serde_json::from_str(&runtime.drain_runtime_events().expect("runtime events"))
                .expect("decode runtime events");
        assert!(
            events
                .iter()
                .any(|event| event.kind == RuntimeEventKind::Initialized)
        );
        assert!(
            events
                .iter()
                .any(|event| event.kind == RuntimeEventKind::CommandQueued)
        );
        assert!(
            events
                .iter()
                .any(|event| event.kind == RuntimeEventKind::PolicyUpdated)
        );
    }

    #[test]
    fn wipe_state_clears_runtime_status_and_emits_state_wiped_event() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let bootstrap = bootstrap_for_bundle(&bundle, 0);

        let mut runtime = WasmBridgeRuntime::new();
        runtime
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");

        runtime
            .handle_command(r#"{"type":"refresh_all_peers"}"#.to_string())
            .expect("queue refresh-all");
        runtime.wipe_state().expect("wipe state");
        let after: RuntimeStatusSummary =
            serde_json::from_str(&runtime.runtime_status().expect("runtime status"))
                .expect("status");
        assert!(after.pending_operations.is_empty());

        let events: Vec<RuntimeEvent> =
            serde_json::from_str(&runtime.drain_runtime_events().expect("runtime events"))
                .expect("decode runtime events");
        assert!(
            events
                .iter()
                .any(|event| event.kind == RuntimeEventKind::StateWiped)
        );
    }

    #[test]
    fn runtime_metadata_peer_status_and_empty_drains_are_queryable() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let bootstrap = bootstrap_for_bundle(&bundle, 0);

        let mut runtime = WasmBridgeRuntime::new();
        runtime
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");

        let metadata: serde_json::Value =
            serde_json::from_str(&runtime.runtime_metadata().expect("runtime metadata"))
                .expect("decode metadata");
        assert_eq!(metadata["member_idx"], 1);
        assert_eq!(
            metadata["peers"].as_array().expect("metadata peers").len(),
            2
        );

        let peer_status: serde_json::Value =
            serde_json::from_str(&runtime.peer_status().expect("peer status"))
                .expect("decode peer status");
        assert!(peer_status.is_array());

        let completions: serde_json::Value =
            serde_json::from_str(&runtime.drain_completions().expect("drain completions"))
                .expect("decode completions");
        assert_eq!(completions.as_array().expect("completion array").len(), 0);

        let failures: serde_json::Value =
            serde_json::from_str(&runtime.drain_failures().expect("drain failures"))
                .expect("decode failures");
        assert_eq!(failures.as_array().expect("failure array").len(), 0);
    }

    #[test]
    fn helper_functions_cover_bridge_config_and_command_parsing() {
        let cfg = bridge_config_from_input(Some(BridgeConfigInput {
            expire_tick_ms: Some(0),
            command_queue_capacity: Some(3),
            inbound_queue_capacity: Some(4),
            outbound_queue_capacity: Some(5),
            command_overflow_policy: Some(QueueOverflowPolicy::DropOldest),
            inbound_overflow_policy: Some(QueueOverflowPolicy::Fail),
            outbound_overflow_policy: Some(QueueOverflowPolicy::DropOldest),
            inbound_dedupe_cache_limit: Some(9),
        }));
        assert_eq!(cfg.expire_tick, Duration::from_millis(1));
        assert_eq!(cfg.command_queue_capacity, 3);
        assert_eq!(cfg.inbound_queue_capacity, 4);
        assert_eq!(cfg.outbound_queue_capacity, 5);
        assert_eq!(cfg.command_overflow_policy, QueueOverflowPolicy::DropOldest);
        assert_eq!(cfg.inbound_overflow_policy, QueueOverflowPolicy::Fail);
        assert_eq!(
            cfg.outbound_overflow_policy,
            QueueOverflowPolicy::DropOldest
        );
        assert_eq!(cfg.inbound_dedupe_cache_limit, 9);

        match parse_command(CommandInput::Sign {
            message_hex_32: "11".repeat(32),
        })
        .expect("parse sign")
        {
            BridgeCommand::Sign { message } => assert_eq!(message, [0x11; 32]),
            other => panic!("unexpected sign command: {other:?}"),
        }
        match parse_command(CommandInput::Ecdh {
            pubkey32_hex: "22".repeat(32),
        })
        .expect("parse ecdh")
        {
            BridgeCommand::Ecdh { pubkey } => assert_eq!(pubkey, [0x22; 32]),
            other => panic!("unexpected ecdh command: {other:?}"),
        }
        match parse_command(CommandInput::Ping {
            peer_pubkey32_hex: "peer-a".to_string(),
        })
        .expect("parse ping")
        {
            BridgeCommand::Ping { peer } => assert_eq!(peer, "peer-a"),
            other => panic!("unexpected ping command: {other:?}"),
        }
        match parse_command(CommandInput::Onboard {
            peer_pubkey32_hex: "peer-b".to_string(),
        })
        .expect("parse onboard")
        {
            BridgeCommand::Onboard { peer } => {
                assert_eq!(peer, "peer-b");
            }
            other => panic!("unexpected onboard command: {other:?}"),
        }

        let err = parse_command(CommandInput::RefreshAllPeers).expect_err("refresh all must fail");
        assert!(err.to_string().contains("handled directly"));

        assert_eq!(
            decode_fixed_hex::<32>(&"44".repeat(32), "field").expect("decode"),
            [0x44; 32]
        );
        assert!(decode_fixed_hex::<32>("zz", "field").is_err());
        assert!(decode_fixed_hex::<32>(&"55".repeat(31), "field").is_err());
    }

    #[test]
    fn queue_runtime_status_event_dedupes_unchanged_status_changed_events() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let bootstrap = bootstrap_for_bundle(&bundle, 0);
        let core = build_core(
            &RuntimeConfigInput {
                device: None,
                bridge: None,
            },
            &bootstrap,
            None,
        )
        .expect("build core");
        let mut state = RuntimeState {
            core,
            bootstrap,
            last_runtime_status_json: None,
            runtime_events: Vec::new(),
        };

        queue_runtime_status_event(&mut state, RuntimeEventKind::Initialized)
            .expect("initialized event");
        queue_runtime_status_event(&mut state, RuntimeEventKind::StatusChanged)
            .expect("first unchanged status changed");
        queue_runtime_status_event(&mut state, RuntimeEventKind::StatusChanged)
            .expect("second unchanged status changed");

        assert_eq!(state.runtime_events.len(), 1);
        assert_eq!(state.runtime_events[0].kind, RuntimeEventKind::Initialized);
    }

    #[test]
    fn public_runtime_error_paths_cover_invalid_input_helpers() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let bootstrap = bootstrap_for_bundle(&bundle, 0);
        let mut runtime = WasmBridgeRuntime::new();
        runtime
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&bootstrap).expect("bootstrap"),
            )
            .expect("init runtime");

        let err = runtime
            .handle_inbound_event("{".to_string())
            .expect_err("invalid inbound event json must fail");
        assert!(err.to_string().contains("EOF") || err.to_string().contains("expected"));

        let err = runtime
            .update_config("{".to_string())
            .expect_err("invalid config patch must fail");
        assert!(err.to_string().contains("EOF") || err.to_string().contains("expected"));

        let err = runtime
            .set_policy_override("{".to_string())
            .expect_err("invalid policy override json must fail");
        assert!(err.to_string().contains("EOF") || err.to_string().contains("expected"));
    }

    #[test]
    fn ping_round_trip_flows_through_outbound_inbound_tick_and_completions() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let alice_bootstrap = bootstrap_for_bundle(&bundle, 0);
        let bob_bootstrap = bootstrap_for_bundle(&bundle, 1);
        let bob_peer = alice_bootstrap.peers[0].clone();
        let now = 1_700_000_000_000u64;

        let mut alice = WasmBridgeRuntime::new();
        alice
            .init_runtime(
                "{}".to_string(),
                serde_json::to_string(&alice_bootstrap).expect("alice bootstrap"),
            )
            .expect("init alice");

        let mut bob = WasmBridgeRuntime::new();
        bob.init_runtime(
            "{}".to_string(),
            serde_json::to_string(&bob_bootstrap).expect("bob bootstrap"),
        )
        .expect("init bob");

        alice
            .handle_command(
                serde_json::json!({
                    "type": "ping",
                    "peer_pubkey32_hex": bob_peer,
                })
                .to_string(),
            )
            .expect("queue ping");
        alice.tick(now).expect("tick alice command");

        let outbound: Vec<Event> =
            serde_json::from_str(&alice.drain_outbound_events().expect("alice outbound"))
                .expect("decode alice outbound");
        assert_eq!(outbound.len(), 1);

        bob.handle_inbound_event(
            serde_json::to_string(&outbound[0]).expect("encode inbound event"),
        )
        .expect("bob handle inbound");
        bob.tick(now + 1).expect("tick bob response");

        let bob_outbound: Vec<Event> =
            serde_json::from_str(&bob.drain_outbound_events().expect("bob outbound"))
                .expect("decode bob outbound");
        assert_eq!(bob_outbound.len(), 1);

        alice
            .handle_inbound_event(serde_json::to_string(&bob_outbound[0]).expect("encode reply"))
            .expect("alice handle reply");
        alice.tick(now + 2).expect("tick alice completion");

        let completions: serde_json::Value =
            serde_json::from_str(&alice.drain_completions().expect("alice completions"))
                .expect("decode completions");
        let completion_array = completions.as_array().expect("completion array");
        assert_eq!(completion_array.len(), 1);
        assert_eq!(completion_array[0]["Ping"]["peer"], bob_peer);

        let events: Vec<RuntimeEvent> =
            serde_json::from_str(&alice.drain_runtime_events().expect("alice runtime events"))
                .expect("decode alice runtime events");
        assert!(
            events
                .iter()
                .any(|event| event.kind == RuntimeEventKind::CommandQueued)
        );
        assert!(
            events
                .iter()
                .any(|event| event.kind == RuntimeEventKind::InboundAccepted)
        );
        assert!(
            events
                .iter()
                .any(|event| event.kind == RuntimeEventKind::StatusChanged)
        );
    }

    #[test]
    fn timeout_flow_surfaces_failures_through_runtime_wrapper() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let alice_bootstrap = bootstrap_for_bundle(&bundle, 0);
        let bob_peer = alice_bootstrap.peers[0].clone();
        let device = DeviceConfig {
            ping_timeout_secs: 1,
            ..DeviceConfig::default()
        };
        let mut alice = WasmBridgeRuntime::new();
        alice
            .init_runtime(
                serde_json::json!({
                    "device": device,
                    "bridge": {
                        "expire_tick_ms": 1
                    }
                })
                .to_string(),
                serde_json::to_string(&alice_bootstrap).expect("alice bootstrap"),
            )
            .expect("init alice");

        alice
            .handle_command(
                serde_json::json!({
                    "type": "ping",
                    "peer_pubkey32_hex": bob_peer,
                })
                .to_string(),
            )
            .expect("queue ping");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_millis() as u64;
        alice.tick(now_ms).expect("tick alice");

        let outbound: Vec<Event> =
            serde_json::from_str(&alice.drain_outbound_events().expect("drain outbound"))
                .expect("decode outbound");
        assert_eq!(outbound.len(), 1);

        alice.tick(now_ms + 5_000).expect("tick alice past timeout");

        let failures: serde_json::Value =
            serde_json::from_str(&alice.drain_failures().expect("drain failures"))
                .expect("decode failures");
        let failure_array = failures.as_array().expect("failure array");
        assert_eq!(failure_array.len(), 1);
        assert_eq!(failure_array[0]["code"], "timeout");
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
                group,
                nonces,
            } => Self::Onboard {
                request_id,
                group_member_count,
                group: GroupPackageWire::from(group),
                nonces: nonces.into_iter().map(Into::into).collect(),
            },
        }
    }
}
