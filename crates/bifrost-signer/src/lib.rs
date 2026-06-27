use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::{Display, Formatter};

use bifrost_codec::wire::{
    EcdhPackageWire, OnboardRequestWire, OnboardResponseWire, PartialSigPackageWire,
    PingPayloadWire, SignSessionPackageWire,
};
use bifrost_codec::{
    BridgeEnvelope, BridgePayload, decode_bridge_envelope, encode_bridge_envelope,
};
use bifrost_core::create_session_package;
use bifrost_core::nonce::{NoncePool, NoncePoolConfig};
use bifrost_core::secret::{EcdhSharedSecret, NoncePoolSecret};
use bifrost_core::types::{
    Bytes32, DerivedPublicNonce, EcdhPackage, GroupPackage, OnboardResponse, PartialSigPackage,
    PeerPolicy, PeerPolicyOverride, PeerScopedPolicyProfile, PingPayload, PolicyOverrideValue,
    SharePackage, SignSessionPackage, SignSessionTemplate,
};
use frostr_utils::{
    ecdh_create_from_share, ecdh_finalize, sign_create_partial, sign_finalize, sign_verify_partial,
    validate_sign_session,
};
use nostr::{Alphabet, Event, Filter, SingleLetterTag, TagKind};
use serde::{Deserialize, Serialize};
use tracing::debug;

mod crypto;
mod error;
mod event_io;
mod util;
use crypto::{decrypt_content_from_peer, encrypt_content_for_peer};
pub use error::{Result, SignerError};
use event_io::{build_signed_event, event_content, event_kind, event_pubkey_xonly};
use util::{
    decode_32, decode_member_index, decode_member_pubkey, decode_pubkey32, is_valid_pubkey32_hex,
    now_unix_millis, now_unix_secs, random_request_id, shuffle_strings,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for DeviceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

pub trait DeviceStore {
    fn load(&self) -> Result<DeviceState>;
    fn save(&self, state: &DeviceState) -> Result<()>;
    fn exists(&self) -> bool;
}

#[derive(Debug, Default)]
pub struct InMemoryStore {
    state: std::sync::Mutex<Option<DeviceState>>,
}

impl DeviceStore for InMemoryStore {
    fn load(&self) -> Result<DeviceState> {
        let state = self
            .state
            .lock()
            .map_err(|_| SignerError::StateCorrupted("store lock poisoned".to_string()))?;
        state
            .clone()
            .ok_or_else(|| SignerError::StateCorrupted("missing state".to_string()))
    }

    fn save(&self, state: &DeviceState) -> Result<()> {
        let mut lock = self
            .state
            .lock()
            .map_err(|_| SignerError::StateCorrupted("store lock poisoned".to_string()))?;
        *lock = Some(state.clone());
        Ok(())
    }

    fn exists(&self) -> bool {
        self.state.lock().is_ok_and(|v| v.is_some())
    }
}

/// Runtime-only secrets held alongside a [`DeviceState`].
///
/// This substruct never crosses the persistence boundary — the
/// [`DeviceStatePersisted`] DTO does not carry it. Secrets are rebuilt from
/// the share (and other source material) every time a [`DeviceState`] is
/// restored from disk or a WASM snapshot.
///
/// The ECDH cache also lives here: its entries carry [`EcdhSharedSecret`]
/// values which must not be persisted. On restart the cache starts empty.
///
/// `Clone` is implemented manually (not derived) so the `ZeroizeOnDrop`
/// contract on each newtype is preserved on both the original and the clone.
pub struct DeviceSecrets {
    pub nonce_pool_secret: NoncePoolSecret,
    pub ecdh_cache: HashMap<String, EcdhCacheEntryLive>,
    pub ecdh_cache_order: VecDeque<String>,
}

impl DeviceSecrets {
    pub fn new(share_seckey: [u8; 32]) -> Self {
        Self {
            nonce_pool_secret: NoncePoolSecret::new(share_seckey),
            ecdh_cache: HashMap::new(),
            ecdh_cache_order: VecDeque::new(),
        }
    }
}

impl std::fmt::Debug for DeviceSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceSecrets")
            .field("nonce_pool_secret", &self.nonce_pool_secret)
            .field("ecdh_cache_len", &self.ecdh_cache.len())
            .finish()
    }
}

impl Clone for DeviceSecrets {
    fn clone(&self) -> Self {
        let mut ecdh_cache = HashMap::with_capacity(self.ecdh_cache.len());
        for (key, entry) in &self.ecdh_cache {
            ecdh_cache.insert(key.clone(), entry.clone());
        }
        Self {
            nonce_pool_secret: NoncePoolSecret::new(*self.nonce_pool_secret.expose_bytes()),
            ecdh_cache,
            ecdh_cache_order: self.ecdh_cache_order.clone(),
        }
    }
}

/// Live runtime device state.
///
/// Held in memory, shared across the signer, router, and bridge. Not itself
/// `Serialize`/`Deserialize`: every persistence boundary goes through
/// [`DeviceStatePersisted`].
#[derive(Debug, Clone)]
pub struct DeviceState {
    pub secrets: DeviceSecrets,
    pub nonce_pool: NoncePool,
    pub replay_cache: HashMap<String, u64>,
    pub sig_cache: HashMap<String, SigCacheEntry>,
    pub sig_cache_order: VecDeque<String>,
    pub manual_policy_overrides: HashMap<String, PeerPolicyOverride>,
    pub remote_scoped_policies: HashMap<String, PeerScopedPolicyProfile>,
    pub remote_nonce_inventory_observations: HashMap<String, PeerNonceInventoryObservation>,
    pub pending_operations: HashMap<String, PendingOperation>,
    pub peer_last_seen: HashMap<String, u64>,
    pub request_seq: u64,
    pub last_active: u64,
    pub version: u32,
    /// Runtime-only telemetry (never persisted — excluded from
    /// [`DeviceStatePersisted`], like the ECDH cache). Reset on every restore;
    /// rebuilds from live traffic.
    ///
    /// Millisecond send time of each in-flight PING op, keyed by request id, so a
    /// later response can compute round-trip latency. Removed when the op
    /// completes / expires / fails.
    pub op_started_ms: HashMap<String, u64>,
    /// Bounded ring of recent PING round-trip latencies (ms) per peer pubkey.
    pub rtt_samples_ms: HashMap<String, VecDeque<u64>>,
    /// Bounded ring of `(ts, held_count)` nonce-inventory samples per peer pubkey.
    pub nonce_history: HashMap<String, VecDeque<(u64, u32)>>,
    /// Runtime-only queue of inbound requests parked awaiting an operator
    /// decision (the `Ask` policy disposition). Keyed by request id. Never
    /// persisted — on restore the queue starts empty and parked peers re-send
    /// (or their own op times out). Resolved via [`SignerInput::ResolveApproval`].
    pub pending_approvals: HashMap<String, PendingApproval>,
}

impl DeviceState {
    pub const VERSION: u32 = 7;
    /// Bound on per-peer telemetry rings (RTT samples, nonce-history points).
    const RTT_SAMPLE_WINDOW: usize = 16;
    const NONCE_HISTORY_WINDOW: usize = 32;

    pub fn new(group_member_idx: u16, share_seckey: [u8; 32]) -> Self {
        let mut nonce_pool = NoncePool::new(group_member_idx, NoncePoolConfig::default());
        nonce_pool.init_peer(group_member_idx);
        Self {
            secrets: DeviceSecrets::new(share_seckey),
            nonce_pool,
            replay_cache: HashMap::new(),
            sig_cache: HashMap::new(),
            sig_cache_order: VecDeque::new(),
            manual_policy_overrides: HashMap::new(),
            remote_scoped_policies: HashMap::new(),
            remote_nonce_inventory_observations: HashMap::new(),
            pending_operations: HashMap::new(),
            peer_last_seen: HashMap::new(),
            request_seq: 1,
            last_active: now_unix_secs(),
            version: Self::VERSION,
            op_started_ms: HashMap::new(),
            rtt_samples_ms: HashMap::new(),
            nonce_history: HashMap::new(),
            pending_approvals: HashMap::new(),
        }
    }

    pub fn discard_volatile_for_dirty_restart(
        &mut self,
        group_member_idx: u16,
        share_seckey: [u8; 32],
    ) {
        self.secrets = DeviceSecrets::new(share_seckey);
        self.nonce_pool = NoncePool::new(group_member_idx, NoncePoolConfig::default());
        self.pending_operations.clear();
        self.remote_nonce_inventory_observations.clear();
        self.op_started_ms.clear();
        self.rtt_samples_ms.clear();
        self.nonce_history.clear();
        self.pending_approvals.clear();
        self.last_active = now_unix_secs();
    }

    /// Rebuild a live [`DeviceState`] from a persisted DTO plus runtime-only
    /// secrets supplied by the host. The ECDH cache starts empty on every
    /// restore — it is not serialized into [`DeviceStatePersisted`].
    pub fn from_persisted(secrets: DeviceSecrets, persisted: DeviceStatePersisted) -> Self {
        Self {
            secrets,
            nonce_pool: persisted.nonce_pool,
            replay_cache: persisted.replay_cache,
            sig_cache: persisted.sig_cache,
            sig_cache_order: persisted.sig_cache_order,
            manual_policy_overrides: persisted.manual_policy_overrides,
            remote_scoped_policies: persisted.remote_scoped_policies,
            remote_nonce_inventory_observations: persisted.remote_nonce_inventory_observations,
            pending_operations: persisted.pending_operations,
            peer_last_seen: persisted.peer_last_seen,
            request_seq: persisted.request_seq,
            last_active: persisted.last_active,
            version: persisted.version,
            op_started_ms: HashMap::new(),
            rtt_samples_ms: HashMap::new(),
            nonce_history: HashMap::new(),
            pending_approvals: HashMap::new(),
        }
    }

    /// Record a PING round-trip latency sample for a peer, bounded to the most
    /// recent [`RTT_SAMPLE_WINDOW`](Self::RTT_SAMPLE_WINDOW) samples.
    fn record_rtt_sample(&mut self, peer: &str, rtt_ms: u64) {
        let ring = self.rtt_samples_ms.entry(peer.to_string()).or_default();
        ring.push_back(rtt_ms);
        while ring.len() > Self::RTT_SAMPLE_WINDOW {
            ring.pop_front();
        }
    }

    /// Append a nonce-held observation for a peer, bounded to the most recent
    /// [`NONCE_HISTORY_WINDOW`](Self::NONCE_HISTORY_WINDOW) points.
    fn record_nonce_history(&mut self, peer: &str, ts: u64, held: u32) {
        let ring = self.nonce_history.entry(peer.to_string()).or_default();
        ring.push_back((ts, held));
        while ring.len() > Self::NONCE_HISTORY_WINDOW {
            ring.pop_front();
        }
    }

    /// `(last, rolling_mean)` PING latency in ms for a peer, or `(None, None)`
    /// when no samples have been collected yet.
    fn latency_summary(&self, peer: &str) -> (Option<u64>, Option<u64>) {
        match self.rtt_samples_ms.get(peer) {
            Some(ring) if !ring.is_empty() => {
                let sum: u64 = ring.iter().sum();
                (ring.back().copied(), Some(sum / ring.len() as u64))
            }
            _ => (None, None),
        }
    }

    /// The peer's bounded nonce-held history, oldest first.
    fn nonce_history_points(&self, peer: &str) -> Vec<NonceHistoryPoint> {
        self.nonce_history
            .get(peer)
            .map(|ring| {
                ring.iter()
                    .map(|(ts, held)| NonceHistoryPoint {
                        ts: *ts,
                        held: *held,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Serialization-only DTO for [`DeviceState`].
///
/// Explicitly does **not** carry the runtime-only secrets from
/// [`DeviceSecrets`] (the FROST nonce-pool seckey and the ECDH cache).
/// `version` is pinned to [`DeviceState::VERSION`] on encode; any mismatch
/// on decode surfaces as [`SignerError::UnsupportedVersion`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatePersisted {
    pub version: u32,
    pub nonce_pool: NoncePool,
    pub replay_cache: HashMap<String, u64>,
    pub sig_cache: HashMap<String, SigCacheEntry>,
    pub sig_cache_order: VecDeque<String>,
    #[serde(default)]
    pub manual_policy_overrides: HashMap<String, PeerPolicyOverride>,
    pub remote_scoped_policies: HashMap<String, PeerScopedPolicyProfile>,
    #[serde(default)]
    pub remote_nonce_inventory_observations: HashMap<String, PeerNonceInventoryObservation>,
    pub pending_operations: HashMap<String, PendingOperation>,
    #[serde(default)]
    pub peer_last_seen: HashMap<String, u64>,
    pub request_seq: u64,
    pub last_active: u64,
}

impl From<&DeviceState> for DeviceStatePersisted {
    fn from(state: &DeviceState) -> Self {
        Self {
            version: state.version,
            nonce_pool: state.nonce_pool.clone(),
            replay_cache: state.replay_cache.clone(),
            sig_cache: state.sig_cache.clone(),
            sig_cache_order: state.sig_cache_order.clone(),
            manual_policy_overrides: state.manual_policy_overrides.clone(),
            remote_scoped_policies: state.remote_scoped_policies.clone(),
            remote_nonce_inventory_observations: state.remote_nonce_inventory_observations.clone(),
            pending_operations: state.pending_operations.clone(),
            peer_last_seen: state.peer_last_seen.clone(),
            request_seq: state.request_seq,
            last_active: state.last_active,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerNonceInventoryObservation {
    #[serde(default)]
    pub held_codes: Vec<Bytes32>,
    pub updated_at: u64,
    /// The peer's nonce-pool generation as last advertised. A change means the
    /// peer reset its outgoing pool, so the nonces we hold from it are dead.
    #[serde(default)]
    pub peer_generation: Bytes32,
}

#[derive(Debug, Clone)]
pub struct OnboardingBootstrapSeed {
    pub request_nonces: Vec<DerivedPublicNonce>,
    pub state: DeviceState,
}

const ONBOARD_BOOTSTRAP_LOCAL_IDX: u16 = 0;
const ONBOARD_BOOTSTRAP_PEER_IDX: u16 = 1;

pub fn generate_onboarding_bootstrap_seed(
    share_seckey: [u8; 32],
    count: usize,
) -> Result<OnboardingBootstrapSeed> {
    let mut state = DeviceState::new(ONBOARD_BOOTSTRAP_LOCAL_IDX, share_seckey);
    let DeviceState {
        ref mut nonce_pool,
        ref secrets,
        ..
    } = state;
    let request_nonces = nonce_pool
        .generate_for_peer(
            ONBOARD_BOOTSTRAP_PEER_IDX,
            count,
            &secrets.nonce_pool_secret,
        )
        .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
    Ok(OnboardingBootstrapSeed {
        request_nonces,
        state,
    })
}

pub fn finalize_onboarding_bootstrap_seed(
    mut state: DeviceState,
    local_member_idx: u16,
    inviter_member_idx: u16,
    inviter_nonces: Vec<DerivedPublicNonce>,
) -> Result<DeviceState> {
    let mut index_map = HashMap::new();
    index_map.insert(ONBOARD_BOOTSTRAP_LOCAL_IDX, local_member_idx);
    index_map.insert(ONBOARD_BOOTSTRAP_PEER_IDX, inviter_member_idx);
    state
        .nonce_pool
        .remap_peer_indexes(local_member_idx, &index_map);
    state
        .nonce_pool
        .store_incoming(inviter_member_idx, inviter_nonces);
    state.pending_operations.clear();
    state.last_active = now_unix_secs();
    Ok(state)
}

/// Default approval-queue retention: long enough for an operator to notice and
/// decide, well beyond the peer-response timeouts.
fn default_approval_timeout_secs() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub sign_timeout_secs: u64,
    pub ecdh_timeout_secs: u64,
    pub ping_timeout_secs: u64,
    pub onboard_timeout_secs: u64,
    /// How long an inbound request parked by the `Ask` disposition stays in the
    /// approval queue before it is silently dropped. Generous (operator-facing)
    /// relative to the peer-response timeouts above.
    #[serde(default = "default_approval_timeout_secs")]
    pub approval_timeout_secs: u64,
    pub request_ttl_secs: u64,
    pub max_future_skew_secs: u64,
    pub request_cache_limit: usize,
    pub state_save_interval_secs: u64,
    pub event_kind: u64,
    pub peer_selection_strategy: PeerSelectionStrategy,
    pub ecdh_cache_capacity: usize,
    pub ecdh_cache_ttl_secs: u64,
    pub sig_cache_capacity: usize,
    pub sig_cache_ttl_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceConfigPatch {
    #[serde(default)]
    pub sign_timeout_secs: Option<u64>,
    #[serde(default)]
    pub ping_timeout_secs: Option<u64>,
    #[serde(default)]
    pub request_ttl_secs: Option<u64>,
    #[serde(default)]
    pub state_save_interval_secs: Option<u64>,
    #[serde(default)]
    pub peer_selection_strategy: Option<PeerSelectionStrategy>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            sign_timeout_secs: 30,
            ecdh_timeout_secs: 30,
            ping_timeout_secs: 15,
            onboard_timeout_secs: 30,
            approval_timeout_secs: default_approval_timeout_secs(),
            request_ttl_secs: 300,
            max_future_skew_secs: 30,
            request_cache_limit: 2048,
            state_save_interval_secs: 30,
            event_kind: 20_000,
            peer_selection_strategy: PeerSelectionStrategy::DeterministicSorted,
            ecdh_cache_capacity: 256,
            ecdh_cache_ttl_secs: 300,
            sig_cache_capacity: 256,
            sig_cache_ttl_secs: 120,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub device_id: String,
    pub pending_ops: usize,
    pub last_active: u64,
    pub known_peers: usize,
    pub request_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeMetadata {
    pub device_id: String,
    pub member_idx: u16,
    pub share_public_key: String,
    pub group_public_key: String,
    pub peers: Vec<String>,
}

/// A single sample in a peer's nonce-held history, for the dashboard sparkline.
/// `held` is the count of our outgoing nonce codes the peer reported holding at
/// `ts` (a PING-response observation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceHistoryPoint {
    pub ts: u64,
    pub held: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub idx: u16,
    pub pubkey: String,
    pub known: bool,
    pub last_seen: Option<u64>,
    pub online: bool,
    pub incoming_available: usize,
    pub outgoing_available: usize,
    pub outgoing_spent: usize,
    pub can_sign: bool,
    /// Capable of ECDH right now: online and the effective policy permits an
    /// outbound ECDH request to this peer.
    pub can_ecdh: bool,
    /// Capable of PING right now: online and the effective policy permits an
    /// outbound ping to this peer.
    pub can_ping: bool,
    pub should_send_nonces: bool,
    /// Most recent PING round-trip latency to this peer, in milliseconds.
    /// `None` until at least one ping has completed.
    pub last_response_latency_ms: Option<u64>,
    /// Rolling-window mean of recent PING round-trip latencies, in milliseconds.
    pub avg_latency_ms: Option<u64>,
    /// Bounded recent history of the peer's held nonce count (for the sparkline),
    /// oldest first.
    pub nonce_history: Vec<NonceHistoryPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeReadiness {
    pub runtime_ready: bool,
    pub restore_complete: bool,
    pub sign_ready: bool,
    pub ecdh_ready: bool,
    pub threshold: usize,
    pub signing_peer_count: usize,
    pub ecdh_peer_count: usize,
    pub last_refresh_at: Option<u64>,
    pub degraded_reasons: Vec<RuntimeDegradedReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDegradedReason {
    PendingOperationsRecovered,
    InsufficientSigningPeers,
    InsufficientEcdhPeers,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStatusSummary {
    pub status: DeviceStatus,
    pub metadata: RuntimeMetadata,
    pub readiness: RuntimeReadiness,
    pub peers: Vec<PeerStatus>,
    pub peer_permission_states: Vec<PeerPermissionState>,
    #[serde(default)]
    pub onboarding_statuses: Vec<OnboardingStatus>,
    pub pending_operations: Vec<PendingOperation>,
    /// Inbound requests parked awaiting an operator decision (the `Ask` policy
    /// disposition). Empty unless a peer+method is set to `Ask`.
    #[serde(default)]
    pub pending_approvals: Vec<PendingApprovalSummary>,
    /// Most recent `Sign` operation failure retained for host display (e.g. a
    /// "signing failed" banner). Runtime-only; `None` until a sign op fails,
    /// cleared on the next successful sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sign_failure: Option<OperationFailureSummary>,
    /// Currently-connected relay URLs. **Host/bridge-enriched, not owned by the
    /// signer core** — relay sockets live in the bridge layer, so the core
    /// always emits `None` here and the Tokio bridge (native) / browser bridge
    /// (WASM, in TS) fill it. `None` means "not reported"; `Some(empty)` means
    /// "reported, zero connected" (drives the all-relays-offline condition).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_relays: Option<Vec<String>>,
    /// Configured relay URLs the host attempts to connect. Host/bridge-enriched
    /// (see [`connected_relays`](Self::connected_relays)); gives "N of M
    /// connected" context. `None` from the core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured_relays: Option<Vec<String>>,
    /// Most recent profile load/restore failure. **Host/bridge-enriched** —
    /// restore errors are returned at call time, not retained by the core, so
    /// the core emits `None` and the bridge layer caches and fills it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_load_error: Option<LoadErrorSummary>,
}

/// Serializable host/bridge-enriched record of the most recent profile
/// load/restore failure (see [`RuntimeStatusSummary::last_load_error`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoadErrorSummary {
    pub message: String,
    /// Unix seconds when the load/restore failure was observed.
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingStatusStage {
    DeviceContactedHost,
    HandshakeCompleted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingStatus {
    pub pubkey: String,
    pub stage: OnboardingStatusStage,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPermissionState {
    pub pubkey: String,
    pub manual_override: PeerPolicyOverride,
    pub remote_observation: Option<PeerScopedPolicyProfile>,
    pub effective_policy: PeerPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOperation {
    pub op_type: PendingOpType,
    pub request_id: String,
    pub started_at: u64,
    pub timeout_at: u64,
    pub target_peers: Vec<String>,
    pub threshold: usize,
    pub collected_responses: Vec<CollectedResponse>,
    pub context: PendingOpContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PendingOpType {
    Sign,
    Ecdh,
    Ping,
    Onboard,
}

/// An inbound request parked awaiting an operator decision (the `Ask` policy
/// disposition). Runtime-only; holds the decrypted envelope so the request can
/// be re-dispatched verbatim once approved. See [`SignerInput::ResolveApproval`].
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub peer: String,
    pub method: String,
    pub envelope: BridgeEnvelope,
    pub queued_at: u64,
    pub expires_at: u64,
}

/// Serializable projection of a [`PendingApproval`] for `runtime_status()`.
/// Excludes the envelope payload (operators decide on peer + method, not on the
/// raw request bytes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingApprovalSummary {
    pub request_id: String,
    pub peer: String,
    pub method: String,
    pub queued_at: u64,
    pub expires_at: u64,
}

/// Outcome of the inbound policy check (see `inbound_disposition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundDisposition {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerSelectionStrategy {
    DeterministicSorted,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendingOpContext {
    SignSession {
        session: SignSessionPackage,
        partials: Vec<PartialSigPackage>,
    },
    EcdhRequest {
        target: String,
        local_pkg: EcdhPackage,
        responses: Vec<EcdhPackage>,
    },
    PingRequest,
    OnboardRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedResponse {
    pub peer: String,
    pub request_id: String,
    pub envelope_id: String,
    pub seen_at: u64,
}

#[derive(Debug, Clone)]
pub enum CompletedOperation {
    Sign {
        request_id: String,
        signatures: Vec<[u8; 64]>,
    },
    Ecdh {
        request_id: String,
        shared_secret: [u8; 32],
    },
    Ping {
        request_id: String,
        peer: String,
    },
    /// Recorded by the responder after it answers a ping request.
    PingServed {
        request_id: String,
        peer: String,
    },
    /// Recorded by the responder after it returns a signing share.
    SignServed {
        request_id: String,
        peer: String,
    },
    Onboard {
        request_id: String,
        group_member_count: usize,
        group: GroupPackage,
        nonces: Vec<DerivedPublicNonce>,
    },
    /// Recorded by the responder after it serves an onboard response to a peer.
    /// `peer` is the onboarding device's x-only pubkey; hosts use it to mark the
    /// matching share as onboarded.
    OnboardServed {
        request_id: String,
        peer: String,
    },
}

impl CompletedOperation {
    pub fn request_id(&self) -> &str {
        match self {
            CompletedOperation::Sign { request_id, .. }
            | CompletedOperation::Ecdh { request_id, .. }
            | CompletedOperation::Ping { request_id, .. }
            | CompletedOperation::PingServed { request_id, .. }
            | CompletedOperation::SignServed { request_id, .. }
            | CompletedOperation::Onboard { request_id, .. }
            | CompletedOperation::OnboardServed { request_id, .. } => request_id,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SignerInput {
    BeginSign {
        message: [u8; 32],
    },
    BeginEcdh {
        pubkey: [u8; 32],
    },
    BeginPing {
        peer: String,
    },
    BeginOnboard {
        peer: String,
    },
    ProcessEvent {
        event: Event,
    },
    Expire {
        now: u64,
    },
    FailRequest {
        request_id: String,
        code: OperationFailureCode,
        message: String,
    },
    /// Resolve a parked approval (the `Ask` disposition). `approved` re-dispatches
    /// the stored request and emits its response; otherwise the requester gets an
    /// `operator_denied` error. A no-op if the request id is no longer queued.
    ResolveApproval {
        request_id: String,
        approved: bool,
    },
}

#[derive(Debug, Clone, Default)]
pub struct SignerEffects {
    pub outbound: Vec<Event>,
    pub completions: Vec<CompletedOperation>,
    pub failures: Vec<OperationFailure>,
    pub latest_request_id: Option<String>,
    pub persistence_hint: PersistenceHint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PersistenceHint {
    #[default]
    None,
    Batch,
    Immediate,
}

impl PersistenceHint {
    pub fn merge(self, other: PersistenceHint) -> PersistenceHint {
        use PersistenceHint::{Batch, Immediate, None};
        match (self, other) {
            (Immediate, _) | (_, Immediate) => Immediate,
            (Batch, _) | (_, Batch) => Batch,
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationFailureCode {
    Timeout,
    InvalidLockedPeerResponse,
    PeerRejected,
}

#[derive(Debug, Clone)]
pub struct OperationFailure {
    pub request_id: String,
    pub op_type: PendingOpType,
    pub code: OperationFailureCode,
    pub message: String,
    pub failed_peer: Option<String>,
}

/// Serializable projection of the most-recent operation failure for
/// `runtime_status()`. Runtime-only (never persisted) — surfaced so hosts can
/// render a "signing failed" condition without consuming the lossy
/// `take_failures()` drain. Carries a `failed_at` wall-clock stamp the raw
/// [`OperationFailure`] lacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationFailureSummary {
    pub request_id: String,
    pub op_type: PendingOpType,
    pub code: OperationFailureCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_peer: Option<String>,
    pub failed_at: u64,
}

impl OperationFailureSummary {
    fn from_failure(failure: &OperationFailure, failed_at: u64) -> Self {
        Self {
            request_id: failure.request_id.clone(),
            op_type: failure.op_type.clone(),
            code: failure.code,
            message: failure.message.clone(),
            failed_peer: failure.failed_peer.clone(),
            failed_at,
        }
    }
}

/// Runtime-only ECDH cache entry.
///
/// Holds an [`EcdhSharedSecret`] which is zeroized on drop. Not
/// `Serialize`/`Deserialize`: the ECDH cache is runtime-only and does not
/// cross the [`DeviceStatePersisted`] boundary.
#[derive(Debug)]
pub struct EcdhCacheEntryLive {
    pub key_hex: String,
    pub shared_secret: EcdhSharedSecret,
    pub stored_at: u64,
    pub last_accessed_at: u64,
}

impl Clone for EcdhCacheEntryLive {
    fn clone(&self) -> Self {
        Self {
            key_hex: self.key_hex.clone(),
            shared_secret: EcdhSharedSecret::new(*self.shared_secret.expose_bytes()),
            stored_at: self.stored_at,
            last_accessed_at: self.last_accessed_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigCacheEntry {
    pub key_hex: String,
    pub signatures_hex: Vec<String>,
    pub stored_at: u64,
    pub last_accessed_at: u64,
}

pub struct SigningDevice {
    group: GroupPackage,
    share: SharePackage,
    peers: Vec<String>,
    member_idx_by_pubkey: HashMap<String, u16>,
    share_public_key_hex: String,
    state: DeviceState,
    config: DeviceConfig,
    device_id: DeviceId,
    completions: VecDeque<CompletedOperation>,
    failures: VecDeque<OperationFailure>,
    /// Runtime-only retention of the most recent `Sign` failure for host
    /// display. Independent of the lossy `failures` drain; cleared on the next
    /// successful sign and on `wipe_state`.
    last_sign_failure: Option<OperationFailureSummary>,
    onboarding_statuses: HashMap<String, OnboardingStatus>,
    latest_request_id: Option<String>,
    runtime_persistence_hint: PersistenceHint,
}

impl SigningDevice {
    const PEER_ONLINE_GRACE_SECS: u64 = 120;

    pub fn new(
        group: GroupPackage,
        share: SharePackage,
        peers: Vec<String>,
        mut state: DeviceState,
        config: DeviceConfig,
    ) -> Result<Self> {
        if group.threshold == 0 || group.members.is_empty() {
            return Err(SignerError::InvalidConfig("invalid group".to_string()));
        }
        if state.version != DeviceState::VERSION {
            return Err(SignerError::UnsupportedVersion(state.version));
        }

        let share_idx = share.idx;
        let share_public_key_hex = decode_member_pubkey(&group, share_idx)?;
        let mut member_idx_by_pubkey = HashMap::new();
        for peer in &peers {
            if !is_valid_pubkey32_hex(peer) {
                return Err(SignerError::InvalidConfig(
                    "peer public keys must be x-only secp256k1 hex".to_string(),
                ));
            }
            let idx = decode_member_index(&group.members, peer)?;
            member_idx_by_pubkey.insert(peer.clone(), idx);
            state.nonce_pool.init_peer(idx);
        }

        state.nonce_pool.init_peer(share_idx);
        state.last_active = now_unix_secs();
        let device_id = DeviceId::new(format!("{}-{}", share_public_key_hex, share_idx));
        let DeviceSecrets {
            ecdh_cache,
            ecdh_cache_order,
            ..
        } = &mut state.secrets;
        ecdh_cache_order.retain(|k| ecdh_cache.contains_key(k));
        state
            .sig_cache_order
            .retain(|k| state.sig_cache.contains_key(k));

        Ok(Self {
            group,
            share,
            peers,
            member_idx_by_pubkey,
            share_public_key_hex: share_public_key_hex.clone(),
            state,
            config,
            device_id,
            completions: VecDeque::new(),
            failures: VecDeque::new(),
            last_sign_failure: None,
            onboarding_statuses: HashMap::new(),
            latest_request_id: None,
            runtime_persistence_hint: PersistenceHint::None,
        })
    }

    pub fn init(
        group: GroupPackage,
        share: SharePackage,
        peers: Vec<String>,
        config: DeviceConfig,
    ) -> Result<Self> {
        let state = DeviceState::new(share.idx, *share.seckey.expose_bytes());
        Self::new(group, share, peers, state, config)
    }

    pub fn state(&self) -> &DeviceState {
        &self.state
    }

    pub fn set_remote_policy_observation(
        &mut self,
        peer: &str,
        observation: PeerScopedPolicyProfile,
    ) -> Result<()> {
        if !self.member_idx_by_pubkey.contains_key(peer) {
            return Err(SignerError::UnknownPeer(peer.to_string()));
        }
        self.state
            .remote_scoped_policies
            .insert(peer.to_string(), observation);
        self.state.last_active = now_unix_secs();
        self.mark_persistence_hint(PersistenceHint::Immediate);
        Ok(())
    }

    pub fn read_config(&self) -> DeviceConfig {
        self.config.clone()
    }

    pub fn wipe_state(&mut self) {
        self.state = DeviceState::new(self.share.idx, *self.share.seckey.expose_bytes());
        for peer in &self.peers {
            if let Some(idx) = self.member_idx_by_pubkey.get(peer).copied() {
                self.state.nonce_pool.init_peer(idx);
            }
        }
        self.state.nonce_pool.init_peer(self.share.idx);
        self.completions.clear();
        self.failures.clear();
        self.last_sign_failure = None;
        self.onboarding_statuses.clear();
        self.latest_request_id = None;
        self.runtime_persistence_hint = PersistenceHint::Immediate;
    }

    pub fn update_config(&mut self, patch: DeviceConfigPatch) -> Result<()> {
        if let Some(value) = patch.sign_timeout_secs {
            if value == 0 {
                return Err(SignerError::InvalidConfig(
                    "sign_timeout_secs must be greater than zero".to_string(),
                ));
            }
            self.config.sign_timeout_secs = value;
        }
        if let Some(value) = patch.ping_timeout_secs {
            if value == 0 {
                return Err(SignerError::InvalidConfig(
                    "ping_timeout_secs must be greater than zero".to_string(),
                ));
            }
            self.config.ping_timeout_secs = value;
        }
        if let Some(value) = patch.request_ttl_secs {
            if value == 0 {
                return Err(SignerError::InvalidConfig(
                    "request_ttl_secs must be greater than zero".to_string(),
                ));
            }
            self.config.request_ttl_secs = value;
        }
        if let Some(value) = patch.state_save_interval_secs {
            if value == 0 {
                return Err(SignerError::InvalidConfig(
                    "state_save_interval_secs must be greater than zero".to_string(),
                ));
            }
            self.config.state_save_interval_secs = value;
        }
        if let Some(value) = patch.peer_selection_strategy {
            self.config.peer_selection_strategy = value;
        }

        self.state.last_active = now_unix_secs();
        self.mark_persistence_hint(PersistenceHint::Immediate);
        Ok(())
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn latest_request_id(&self) -> Option<String> {
        self.latest_request_id.clone()
    }

    pub fn local_pubkey32(&self) -> &str {
        &self.share_public_key_hex
    }

    pub fn runtime_metadata(&self) -> RuntimeMetadata {
        let mut peers = self.peers.clone();
        peers.sort_unstable();
        RuntimeMetadata {
            device_id: self.device_id.to_string(),
            member_idx: self.share.idx,
            share_public_key: self.share_public_key_hex.clone(),
            group_public_key: hex::encode(self.group.group_pk),
            peers,
        }
    }

    fn manual_policy_override_for(&self, peer: &str) -> PeerPolicyOverride {
        self.state
            .manual_policy_overrides
            .get(peer)
            .cloned()
            .unwrap_or_default()
    }

    fn apply_override_value(default: bool, value: PolicyOverrideValue) -> bool {
        match value {
            PolicyOverrideValue::Unset => default,
            PolicyOverrideValue::Allow => true,
            PolicyOverrideValue::Deny => false,
            // "Ask" is capability-allowed for readiness/`can_sign`: the peer may
            // act, just interactively. The deferral is enforced separately in
            // `inbound_disposition`, which reads the raw override before this
            // bool collapse.
            PolicyOverrideValue::Ask => true,
        }
    }

    fn local_policy_for_peer(&self, peer: &str) -> PeerPolicy {
        let override_policy = self.manual_policy_override_for(peer);
        let default_request = bifrost_core::types::MethodPolicy::default();
        let default_respond = bifrost_core::types::MethodPolicy::default();
        let request = bifrost_core::types::MethodPolicy {
            echo: Self::apply_override_value(default_request.echo, override_policy.request.echo),
            ping: Self::apply_override_value(default_request.ping, override_policy.request.ping),
            onboard: Self::apply_override_value(
                default_request.onboard,
                override_policy.request.onboard,
            ),
            sign: Self::apply_override_value(default_request.sign, override_policy.request.sign),
            ecdh: Self::apply_override_value(default_request.ecdh, override_policy.request.ecdh),
        };
        let respond = bifrost_core::types::MethodPolicy {
            echo: Self::apply_override_value(default_respond.echo, override_policy.respond.echo),
            ping: Self::apply_override_value(default_respond.ping, override_policy.respond.ping),
            onboard: Self::apply_override_value(
                default_respond.onboard,
                override_policy.respond.onboard,
            ),
            sign: Self::apply_override_value(default_respond.sign, override_policy.respond.sign),
            ecdh: Self::apply_override_value(default_respond.ecdh, override_policy.respond.ecdh),
        };
        PeerPolicy {
            block_all: !(request.echo
                || request.ping
                || request.onboard
                || request.sign
                || request.ecdh
                || respond.echo
                || respond.ping
                || respond.onboard
                || respond.sign
                || respond.ecdh),
            request,
            respond,
        }
    }

    fn effective_policy_for_peer(&self, peer: &str) -> PeerPolicy {
        let local = self.local_policy_for_peer(peer);
        let remote = self.state.remote_scoped_policies.get(peer);
        let request = bifrost_core::types::MethodPolicy {
            echo: local.request.echo,
            ping: local.request.ping,
            onboard: local.request.onboard,
            sign: local.request.sign && remote.map(|profile| profile.respond.sign).unwrap_or(true),
            ecdh: local.request.ecdh && remote.map(|profile| profile.respond.ecdh).unwrap_or(true),
        };
        PeerPolicy {
            block_all: !(request.echo
                || request.ping
                || request.onboard
                || request.sign
                || request.ecdh
                || local.respond.echo
                || local.respond.ping
                || local.respond.onboard
                || local.respond.sign
                || local.respond.ecdh),
            request,
            respond: local.respond,
        }
    }

    fn inbound_allowed(&self, peer: &str, method: &str) -> bool {
        let respond = &self.local_policy_for_peer(peer).respond;
        match method {
            "ping" => respond.ping,
            "onboard" => respond.onboard,
            "sign" => respond.sign,
            "ecdh" => respond.ecdh,
            "echo" => respond.echo,
            _ => true,
        }
    }

    /// Raw local `respond` override value for a method, before the bool collapse.
    /// Lets `inbound_disposition` see `Ask` (which `apply_override_value` flattens
    /// to `true`).
    fn respond_override_value(&self, peer: &str, method: &str) -> PolicyOverrideValue {
        let respond = self.manual_policy_override_for(peer).respond;
        match method {
            "ping" => respond.ping,
            "onboard" => respond.onboard,
            "sign" => respond.sign,
            "ecdh" => respond.ecdh,
            "echo" => respond.echo,
            _ => PolicyOverrideValue::Unset,
        }
    }

    /// Decide how to handle an inbound request for `method` from `peer`. When
    /// `forced` (resuming an approved request) the answer is always `Allow`.
    /// A local `respond` override of `Ask` parks the request; otherwise the
    /// existing allow/deny policy applies.
    fn inbound_disposition(&self, peer: &str, method: &str, forced: bool) -> InboundDisposition {
        if forced {
            return InboundDisposition::Allow;
        }
        if matches!(
            self.respond_override_value(peer, method),
            PolicyOverrideValue::Ask
        ) {
            return InboundDisposition::Ask;
        }
        if self.inbound_allowed(peer, method) {
            InboundDisposition::Allow
        } else {
            InboundDisposition::Deny
        }
    }

    pub fn peer_status(&self) -> Vec<PeerStatus> {
        let now = now_unix_secs();
        let mut peers = self
            .peers
            .iter()
            .filter_map(|peer| {
                let idx = self.member_idx_by_pubkey.get(peer).copied()?;
                let stats = self.state.nonce_pool.peer_stats(idx);
                let last_seen = self.state.peer_last_seen.get(peer).copied();
                let online = last_seen
                    .map(|seen| now.saturating_sub(seen) <= Self::PEER_ONLINE_GRACE_SECS)
                    .unwrap_or(false);
                // Capability badges mirror the readiness pattern (online + the
                // effective outbound policy for the method); `can_sign` stays
                // nonce-availability based, as before.
                let policy = self.effective_policy_for_peer(peer);
                let (last_response_latency_ms, avg_latency_ms) = self.state.latency_summary(peer);
                Some(PeerStatus {
                    idx,
                    pubkey: peer.clone(),
                    known: true,
                    last_seen,
                    online,
                    incoming_available: stats.incoming_available,
                    outgoing_available: stats.outgoing_available,
                    outgoing_spent: stats.outgoing_spent,
                    can_sign: stats.can_sign,
                    can_ecdh: online && policy.request.ecdh,
                    can_ping: online && policy.request.ping,
                    should_send_nonces: self.peer_needs_nonce_refill(peer, idx),
                    last_response_latency_ms,
                    avg_latency_ms,
                    nonce_history: self.state.nonce_history_points(peer),
                })
            })
            .collect::<Vec<_>>();
        peers.sort_by_key(|entry| entry.idx);
        peers
    }

    pub fn readiness(&self) -> RuntimeReadiness {
        let peers = self.peer_status();
        self.readiness_from_peers(&peers)
    }

    pub fn pending_operations(&self) -> Vec<PendingOperation> {
        let mut operations = self
            .state
            .pending_operations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        operations.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        operations
    }

    pub fn onboarding_statuses(&self) -> Vec<OnboardingStatus> {
        let mut statuses = self
            .onboarding_statuses
            .values()
            .cloned()
            .collect::<Vec<_>>();
        statuses.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
        statuses
    }

    /// Operator-facing projection of the parked-approval queue, oldest first.
    pub fn pending_approvals(&self) -> Vec<PendingApprovalSummary> {
        let mut approvals = self
            .state
            .pending_approvals
            .iter()
            .map(|(request_id, approval)| PendingApprovalSummary {
                request_id: request_id.clone(),
                peer: approval.peer.clone(),
                method: approval.method.clone(),
                queued_at: approval.queued_at,
                expires_at: approval.expires_at,
            })
            .collect::<Vec<_>>();
        approvals.sort_by(|a, b| {
            a.queued_at
                .cmp(&b.queued_at)
                .then_with(|| a.request_id.cmp(&b.request_id))
        });
        approvals
    }

    pub fn runtime_status(&self) -> RuntimeStatusSummary {
        let peers = self.peer_status();
        RuntimeStatusSummary {
            status: self.status(),
            metadata: self.runtime_metadata(),
            readiness: self.readiness_from_peers(&peers),
            peers,
            peer_permission_states: self.peer_permission_states(),
            onboarding_statuses: self.onboarding_statuses(),
            pending_operations: self.pending_operations(),
            pending_approvals: self.pending_approvals(),
            last_sign_failure: self.last_sign_failure.clone(),
            // Host/bridge-enriched (relay sockets + load errors live outside the
            // signer core); the bridge layer overwrites these post-call.
            connected_relays: None,
            configured_relays: None,
            last_load_error: None,
        }
    }

    pub fn peer_permission_states(&self) -> Vec<PeerPermissionState> {
        let mut peers = self.peers.clone();
        peers.sort_unstable();
        peers
            .into_iter()
            .map(|peer| PeerPermissionState {
                pubkey: peer.clone(),
                manual_override: self.manual_policy_override_for(&peer),
                remote_observation: self.state.remote_scoped_policies.get(&peer).cloned(),
                effective_policy: self.effective_policy_for_peer(&peer),
            })
            .collect()
    }

    fn note_onboarding_status(
        &mut self,
        peer: &str,
        stage: OnboardingStatusStage,
        updated_at: u64,
        error: Option<String>,
    ) {
        let normalized = peer.to_ascii_lowercase();
        if !self.member_idx_by_pubkey.contains_key(&normalized) {
            return;
        }

        if matches!(stage, OnboardingStatusStage::DeviceContactedHost)
            && matches!(
                self.onboarding_statuses
                    .get(&normalized)
                    .map(|status| &status.stage),
                Some(OnboardingStatusStage::HandshakeCompleted)
            )
        {
            return;
        }

        self.onboarding_statuses.insert(
            normalized.clone(),
            OnboardingStatus {
                pubkey: normalized,
                stage,
                updated_at,
                error,
            },
        );
    }

    fn readiness_from_peers(&self, peers: &[PeerStatus]) -> RuntimeReadiness {
        let threshold = self.group.threshold.saturating_sub(1) as usize;
        let signing_peer_count = peers
            .iter()
            .filter(|peer| {
                peer.can_sign && self.effective_policy_for_peer(&peer.pubkey).request.sign
            })
            .count();
        let ecdh_peer_count = peers
            .iter()
            .filter(|peer| peer.online && self.effective_policy_for_peer(&peer.pubkey).request.ecdh)
            .count();
        let last_refresh_at = peers.iter().filter_map(|peer| peer.last_seen).max();
        let sign_ready = signing_peer_count >= threshold;
        let ecdh_ready = ecdh_peer_count >= threshold;
        let restore_complete = self.state.pending_operations.is_empty();
        let mut degraded_reasons = Vec::new();
        if !restore_complete {
            degraded_reasons.push(RuntimeDegradedReason::PendingOperationsRecovered);
        }
        if !sign_ready {
            degraded_reasons.push(RuntimeDegradedReason::InsufficientSigningPeers);
        }
        if !ecdh_ready {
            degraded_reasons.push(RuntimeDegradedReason::InsufficientEcdhPeers);
        }

        RuntimeReadiness {
            runtime_ready: degraded_reasons.is_empty(),
            restore_complete,
            sign_ready,
            ecdh_ready,
            threshold,
            signing_peer_count,
            ecdh_peer_count,
            last_refresh_at,
            degraded_reasons,
        }
    }

    pub fn has_exact_local_recipient_tag(&self, event: &Event) -> bool {
        let recipients = extract_recipient_p_tags(event);
        recipients.len() == 1 && recipients[0] == self.share_public_key_hex
    }

    fn mark_persistence_hint(&mut self, hint: PersistenceHint) {
        self.runtime_persistence_hint = self.runtime_persistence_hint.merge(hint);
    }

    fn take_runtime_persistence_hint(&mut self) -> PersistenceHint {
        let hint = self.runtime_persistence_hint;
        self.runtime_persistence_hint = PersistenceHint::None;
        hint
    }

    fn ecdh_cache_get(&mut self, target: [u8; 32], now: u64) -> Option<[u8; 32]> {
        let key = hex::encode(target);
        let ttl = self.config.ecdh_cache_ttl_secs;
        let DeviceSecrets {
            ecdh_cache,
            ecdh_cache_order,
            ..
        } = &mut self.state.secrets;
        ecdh_cache.retain(|_, entry| now.saturating_sub(entry.stored_at) <= ttl);
        ecdh_cache_order.retain(|k| ecdh_cache.contains_key(k));
        let entry = ecdh_cache.get_mut(&key)?;
        entry.last_accessed_at = now;
        Self::touch_lru_key(ecdh_cache_order, &key);
        Some(*entry.shared_secret.expose_bytes())
    }

    fn ecdh_cache_put(&mut self, target: [u8; 32], secret: [u8; 32], now: u64) {
        let key = hex::encode(target);
        let capacity = self.config.ecdh_cache_capacity;
        let DeviceSecrets {
            ecdh_cache,
            ecdh_cache_order,
            ..
        } = &mut self.state.secrets;
        ecdh_cache.insert(
            key.clone(),
            EcdhCacheEntryLive {
                key_hex: key.clone(),
                shared_secret: EcdhSharedSecret::new(secret),
                stored_at: now,
                last_accessed_at: now,
            },
        );
        Self::touch_lru_key(ecdh_cache_order, &key);
        Self::evict_lru(ecdh_cache, ecdh_cache_order, capacity);
    }

    fn sig_cache_get(&mut self, message: [u8; 32], now: u64) -> Option<Vec<[u8; 64]>> {
        let key = hex::encode(message);
        self.state.sig_cache.retain(|_, entry| {
            now.saturating_sub(entry.stored_at) <= self.config.sig_cache_ttl_secs
        });
        self.state
            .sig_cache_order
            .retain(|k| self.state.sig_cache.contains_key(k));
        let entry = self.state.sig_cache.get_mut(&key)?;
        entry.last_accessed_at = now;
        Self::touch_lru_key(&mut self.state.sig_cache_order, &key);
        let mut out = Vec::with_capacity(entry.signatures_hex.len());
        for hex_sig in &entry.signatures_hex {
            let bytes = hex::decode(hex_sig).ok()?;
            if bytes.len() != 64 {
                return None;
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&bytes);
            out.push(sig);
        }
        Some(out)
    }

    fn sig_cache_put(&mut self, message: [u8; 32], signatures: Vec<[u8; 64]>, now: u64) {
        let key = hex::encode(message);
        self.state.sig_cache.insert(
            key.clone(),
            SigCacheEntry {
                key_hex: key.clone(),
                signatures_hex: signatures.into_iter().map(hex::encode).collect(),
                stored_at: now,
                last_accessed_at: now,
            },
        );
        Self::touch_lru_key(&mut self.state.sig_cache_order, &key);
        Self::evict_lru(
            &mut self.state.sig_cache,
            &mut self.state.sig_cache_order,
            self.config.sig_cache_capacity,
        );
    }

    fn touch_lru_key(order: &mut VecDeque<String>, key: &str) {
        order.retain(|k| k != key);
        order.push_back(key.to_string());
    }

    fn evict_lru<V>(map: &mut HashMap<String, V>, order: &mut VecDeque<String>, capacity: usize) {
        while map.len() > capacity {
            if let Some(oldest) = order.pop_front() {
                map.remove(&oldest);
            } else {
                break;
            }
        }
    }

    pub fn subscription_filters(&self) -> Result<Vec<Filter>> {
        let mut authors = self.peers.clone();
        authors.sort_unstable();
        authors.dedup();

        let raw = serde_json::json!({
            "kinds": [self.config.event_kind],
            "authors": authors,
            "#p": [self.share_public_key_hex],
        });
        serde_json::from_value::<Filter>(raw)
            .map(|v| vec![v])
            .map_err(|e| SignerError::InvalidConfig(format!("invalid subscription filters: {e}")))
    }

    pub fn process_event(&mut self, event: &Event) -> Result<Vec<Event>> {
        let kind = event_kind(event)?;
        if kind != self.config.event_kind {
            return Ok(Vec::new());
        }

        if !self.has_exact_local_recipient_tag(event) {
            return Ok(Vec::new());
        }

        let sender_xonly = event_pubkey_xonly(event)?;
        if sender_xonly == self.share_public_key_hex {
            return Ok(Vec::new());
        }
        if !self.member_idx_by_pubkey.contains_key(&sender_xonly) {
            return Err(SignerError::UnknownPeer(sender_xonly));
        }
        let sender = sender_xonly;

        let envelope = self.decrypt_event(event, &sender)?;
        let now = now_unix_secs();
        self.state.peer_last_seen.insert(sender.clone(), now);
        self.record_request(&sender, &envelope.request_id, envelope.sent_at, now)?;

        let mut outbound = if self
            .state
            .pending_operations
            .contains_key(&envelope.request_id)
        {
            match self.match_pending_response(&envelope, &sender) {
                Ok(outbound) => outbound,
                Err(err) => {
                    let code = match &envelope.payload {
                        BridgePayload::Error(_) => OperationFailureCode::PeerRejected,
                        _ => OperationFailureCode::InvalidLockedPeerResponse,
                    };
                    self.fail_pending_operation(
                        &envelope.request_id,
                        code,
                        err.to_string(),
                        Some(sender.clone()),
                    );
                    Vec::new()
                }
            }
        } else {
            // Classify the op type from the request payload BEFORE handling, so a
            // handler error (e.g. a sign/ecdh nonce miss) surfaces a correctly-typed
            // failure. Propagating `?` here would let the router blind-label it as a
            // ping (it can't decrypt the envelope to know better).
            let op_type = inbound_op_type(&envelope.payload);
            let request_id = envelope.request_id.clone();
            match self.handle_inbound_request(envelope, sender.clone(), false) {
                Ok(outbound) => outbound,
                Err(err) => {
                    self.failures.push_back(OperationFailure {
                        request_id,
                        op_type,
                        code: OperationFailureCode::PeerRejected,
                        message: err.to_string(),
                        failed_peer: Some(sender),
                    });
                    Vec::new()
                }
            }
        };

        self.state.last_active = now;

        // Ensure deterministic outbound ordering for easier runtime logging.
        outbound.sort_by_key(|ev| ev.created_at.as_secs());
        Ok(outbound)
    }

    pub fn initiate_sign(&mut self, message: [u8; 32]) -> Result<Vec<Event>> {
        let now = now_unix_secs();
        let request_id = self.next_request_id();
        self.latest_request_id = Some(request_id.clone());
        if let Some(signatures) = self.sig_cache_get(message, now) {
            self.completions.push_back(CompletedOperation::Sign {
                request_id,
                signatures,
            });
            return Ok(Vec::new());
        }

        let needed = self.group.threshold.saturating_sub(1) as usize;
        let selected = self.select_signing_peers(needed)?;

        let mut members = Vec::with_capacity(selected.len() + 1);
        members.push(self.share.idx);
        for peer in &selected {
            let idx = self
                .member_idx_by_pubkey
                .get(peer)
                .copied()
                .ok_or_else(|| SignerError::UnknownPeer(peer.clone()))?;
            members.push(idx);
        }
        members.sort_unstable();

        let mut member_nonce_sets = Vec::with_capacity(members.len());
        for peer in &selected {
            let idx = self
                .member_idx_by_pubkey
                .get(peer)
                .copied()
                .ok_or_else(|| SignerError::UnknownPeer(peer.clone()))?;
            let nonce = self
                .state
                .nonce_pool
                .consume_latest_incoming(idx)
                .ok_or(SignerError::NonceUnavailable)?;
            member_nonce_sets.push(bifrost_core::types::MemberNonceCommitmentSet {
                idx,
                entries: vec![bifrost_core::types::IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: nonce.binder_pn,
                    hidden_pn: nonce.hidden_pn,
                    code: nonce.code,
                }],
            });
        }

        let DeviceState {
            nonce_pool,
            secrets,
            ..
        } = &mut self.state;
        let local_generated = nonce_pool
            .generate_for_peer(self.share.idx, 1, &secrets.nonce_pool_secret)
            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
        let local_nonce = local_generated
            .first()
            .cloned()
            .ok_or(SignerError::NonceUnavailable)?;
        let local_signing_nonces = self
            .state
            .nonce_pool
            .take_outgoing_signing_nonces_many(self.share.idx, &[local_nonce.code])
            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;

        member_nonce_sets.push(bifrost_core::types::MemberNonceCommitmentSet {
            idx: self.share.idx,
            entries: vec![bifrost_core::types::IndexedPublicNonceCommitment {
                hash_index: 0,
                binder_pn: local_nonce.binder_pn,
                hidden_pn: local_nonce.hidden_pn,
                code: local_nonce.code,
            }],
        });
        member_nonce_sets.sort_by_key(|v| v.idx);

        let mut session = create_session_package(
            &self.group,
            SignSessionTemplate {
                members,
                hashes: vec![message],
                content: None,
                kind: "message".to_string(),
                stamp: now_unix_secs() as u32,
            },
        )
        .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
        session.nonces = Some(member_nonce_sets);
        validate_sign_session(&self.group, &session)
            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;

        let self_partial = sign_create_partial(
            &self.group,
            &session,
            &self.share,
            &local_signing_nonces,
            None,
        )
        .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;

        self.state.pending_operations.insert(
            request_id.clone(),
            PendingOperation {
                op_type: PendingOpType::Sign,
                request_id: request_id.clone(),
                started_at: now,
                timeout_at: now.saturating_add(self.config.sign_timeout_secs),
                target_peers: selected.clone(),
                threshold: self.group.threshold as usize,
                collected_responses: Vec::new(),
                context: PendingOpContext::SignSession {
                    session: session.clone(),
                    partials: vec![self_partial],
                },
            },
        );
        self.latest_request_id = Some(request_id.clone());

        let envelope = BridgeEnvelope {
            request_id,
            sent_at: now,
            payload: BridgePayload::SignRequest(SignSessionPackageWire::from(session)),
        };
        self.encrypt_for_peers(&selected, &envelope)
    }

    pub fn initiate_ecdh(&mut self, target: [u8; 32]) -> Result<Vec<Event>> {
        let now = now_unix_secs();
        let request_id = self.next_request_id();
        self.latest_request_id = Some(request_id.clone());
        if let Some(shared_secret) = self.ecdh_cache_get(target, now) {
            self.completions.push_back(CompletedOperation::Ecdh {
                request_id,
                shared_secret,
            });
            return Ok(Vec::new());
        }

        let needed = self.group.threshold.saturating_sub(1) as usize;
        let selected = self.select_ecdh_peers(needed)?;

        let mut members = Vec::with_capacity(selected.len() + 1);
        members.push(self.share.idx);
        for peer in &selected {
            let idx = self
                .member_idx_by_pubkey
                .get(peer)
                .copied()
                .ok_or_else(|| SignerError::UnknownPeer(peer.clone()))?;
            members.push(idx);
        }
        members.sort_unstable();
        members.dedup();

        let local_pkg = ecdh_create_from_share(&members, &self.share, &[target])
            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
        if needed == 0 {
            let shared_secret = ecdh_finalize(&[local_pkg], target)
                .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
            self.ecdh_cache_put(target, shared_secret, now);
            self.completions.push_back(CompletedOperation::Ecdh {
                request_id,
                shared_secret,
            });
            return Ok(Vec::new());
        }

        self.state.pending_operations.insert(
            request_id.clone(),
            PendingOperation {
                op_type: PendingOpType::Ecdh,
                request_id: request_id.clone(),
                started_at: now,
                timeout_at: now.saturating_add(self.config.ecdh_timeout_secs),
                target_peers: selected.clone(),
                threshold: needed,
                collected_responses: Vec::new(),
                context: PendingOpContext::EcdhRequest {
                    target: hex::encode(target),
                    local_pkg: local_pkg.clone(),
                    responses: Vec::new(),
                },
            },
        );

        let envelope = BridgeEnvelope {
            request_id,
            sent_at: now,
            payload: BridgePayload::EcdhRequest(EcdhPackageWire::from(local_pkg)),
        };

        self.encrypt_for_peers(&selected, &envelope)
    }

    pub fn initiate_ping(&mut self, peer: &str) -> Result<Vec<Event>> {
        if !self.member_idx_by_pubkey.contains_key(peer) {
            return Err(SignerError::UnknownPeer(peer.to_string()));
        }
        if !self.effective_policy_for_peer(peer).request.ping {
            return Err(SignerError::InvalidRequest(format!(
                "peer policy denies outbound ping for {peer}"
            )));
        }
        let peer_idx = *self
            .member_idx_by_pubkey
            .get(peer)
            .ok_or_else(|| SignerError::UnknownPeer(peer.to_string()))?;
        let payload = self.ping_payload(peer, peer_idx, None)?;

        let request_id = self.next_request_id();
        self.latest_request_id = Some(request_id.clone());
        let now = now_unix_secs();

        self.state.pending_operations.insert(
            request_id.clone(),
            PendingOperation {
                op_type: PendingOpType::Ping,
                request_id: request_id.clone(),
                started_at: now,
                timeout_at: now.saturating_add(self.config.ping_timeout_secs),
                target_peers: vec![peer.to_string()],
                threshold: 1,
                collected_responses: Vec::new(),
                context: PendingOpContext::PingRequest,
            },
        );
        // Telemetry: stamp the ms send time so the ping response can compute
        // round-trip latency. Cleared when the op completes / expires / fails.
        self.state
            .op_started_ms
            .insert(request_id.clone(), now_unix_millis());

        let envelope = BridgeEnvelope {
            request_id,
            sent_at: now,
            payload: BridgePayload::PingRequest(PingPayloadWire::from(payload)),
        };
        self.encrypt_for_peers(&[peer.to_string()], &envelope)
    }

    pub fn initiate_onboard(&mut self, peer: &str) -> Result<Vec<Event>> {
        if !self.member_idx_by_pubkey.contains_key(peer) {
            return Err(SignerError::UnknownPeer(peer.to_string()));
        }
        if !self.effective_policy_for_peer(peer).request.onboard {
            return Err(SignerError::InvalidRequest(format!(
                "peer policy denies outbound onboard for {peer}"
            )));
        }
        let peer_idx = *self
            .member_idx_by_pubkey
            .get(peer)
            .ok_or_else(|| SignerError::UnknownPeer(peer.to_string()))?;
        let request_id = self.next_request_id();
        self.latest_request_id = Some(request_id.clone());
        let now = now_unix_secs();
        let request_nonces = {
            let DeviceState {
                nonce_pool,
                secrets,
                ..
            } = &mut self.state;
            nonce_pool
                .generate_for_peer(
                    peer_idx,
                    NoncePoolConfig::default().pool_size,
                    &secrets.nonce_pool_secret,
                )
                .map_err(|e| SignerError::InvalidRequest(e.to_string()))?
        };

        self.state.pending_operations.insert(
            request_id.clone(),
            PendingOperation {
                op_type: PendingOpType::Onboard,
                request_id: request_id.clone(),
                started_at: now,
                timeout_at: now.saturating_add(self.config.onboard_timeout_secs),
                target_peers: vec![peer.to_string()],
                threshold: 1,
                collected_responses: Vec::new(),
                context: PendingOpContext::OnboardRequest,
            },
        );

        let envelope = BridgeEnvelope {
            request_id,
            sent_at: now,
            payload: BridgePayload::OnboardRequest(OnboardRequestWire {
                version: 1,
                nonces: request_nonces.into_iter().map(Into::into).collect(),
            }),
        };
        self.encrypt_for_peers(&[peer.to_string()], &envelope)
    }

    pub fn apply(&mut self, input: SignerInput) -> Result<SignerEffects> {
        let mut effects = SignerEffects::default();
        match input {
            SignerInput::BeginSign { message } => {
                effects.outbound = self.initiate_sign(message)?;
                effects.latest_request_id = self.latest_request_id();
                effects.persistence_hint = PersistenceHint::Batch;
            }
            SignerInput::BeginEcdh { pubkey } => {
                effects.outbound = self.initiate_ecdh(pubkey)?;
                effects.latest_request_id = self.latest_request_id();
                effects.persistence_hint = PersistenceHint::Batch;
            }
            SignerInput::BeginPing { peer } => {
                effects.outbound = self.initiate_ping(&peer)?;
                effects.latest_request_id = self.latest_request_id();
                effects.persistence_hint = PersistenceHint::Batch;
            }
            SignerInput::BeginOnboard { peer } => {
                effects.outbound = self.initiate_onboard(&peer)?;
                effects.latest_request_id = self.latest_request_id();
                effects.persistence_hint = PersistenceHint::Batch;
            }
            SignerInput::ProcessEvent { event } => {
                effects.outbound = self.process_event(&event)?;
                effects.persistence_hint =
                    PersistenceHint::Batch.merge(self.take_runtime_persistence_hint());
            }
            SignerInput::Expire { now } => {
                effects.failures.extend(self.expire_stale(now));
                let runtime_hint = self.take_runtime_persistence_hint();
                if !effects.failures.is_empty() || !matches!(runtime_hint, PersistenceHint::None) {
                    effects.persistence_hint = PersistenceHint::Batch.merge(runtime_hint);
                }
            }
            SignerInput::FailRequest {
                request_id,
                code,
                message,
            } => {
                self.fail_request(&request_id, code, message);
                effects.persistence_hint = PersistenceHint::Batch;
            }
            SignerInput::ResolveApproval {
                request_id,
                approved,
            } => {
                effects.outbound = self.resolve_approval(&request_id, approved)?;
                effects.persistence_hint = PersistenceHint::Batch;
            }
        }
        effects.completions.extend(self.take_completions());
        effects.failures.extend(self.take_failures());
        self.note_last_sign_failure(&effects.completions, &effects.failures);
        Ok(effects)
    }

    /// Maintain the host-facing `last_sign_failure` retention: a successful sign
    /// clears it; the newest `Sign` failure in this batch sets it. Non-sign ops
    /// are ignored. Order: clear-then-set so a same-batch failure wins.
    fn note_last_sign_failure(
        &mut self,
        completions: &[CompletedOperation],
        failures: &[OperationFailure],
    ) {
        if completions
            .iter()
            .any(|completion| matches!(completion, CompletedOperation::Sign { .. }))
        {
            self.last_sign_failure = None;
        }
        if let Some(failure) = failures
            .iter()
            .rev()
            .find(|failure| matches!(failure.op_type, PendingOpType::Sign))
        {
            self.last_sign_failure = Some(OperationFailureSummary::from_failure(
                failure,
                now_unix_secs(),
            ));
        }
    }

    pub fn take_completions(&mut self) -> Vec<CompletedOperation> {
        self.completions.drain(..).collect()
    }

    pub fn take_failures(&mut self) -> Vec<OperationFailure> {
        self.failures.drain(..).collect()
    }

    pub fn fail_request(
        &mut self,
        request_id: &str,
        code: OperationFailureCode,
        message: impl Into<String>,
    ) {
        self.fail_pending_operation(request_id, code, message.into(), None);
    }

    pub fn expire_stale(&mut self, now: u64) -> Vec<OperationFailure> {
        let mut stale = Vec::new();
        self.state.pending_operations.retain(|id, op| {
            if op.timeout_at <= now {
                stale.push(OperationFailure {
                    request_id: id.clone(),
                    op_type: op.op_type.clone(),
                    code: OperationFailureCode::Timeout,
                    message: "locked peer response timeout".to_string(),
                    failed_peer: None,
                });
                false
            } else {
                true
            }
        });
        for failure in &stale {
            self.state.op_started_ms.remove(&failure.request_id);
        }
        // Drop parked approvals the operator never resolved. Silent: the
        // requester's own operation has already timed out by now, so there is no
        // peer left waiting for a response.
        self.state
            .pending_approvals
            .retain(|_, approval| approval.expires_at > now);
        stale
    }

    pub fn status(&self) -> DeviceStatus {
        DeviceStatus {
            device_id: self.device_id.to_string(),
            pending_ops: self.state.pending_operations.len(),
            last_active: self.state.last_active,
            known_peers: self.peers.len(),
            request_seq: self.state.request_seq,
        }
    }

    pub fn set_peer_policy(&mut self, peer: &str, policy: PeerPolicy) -> Result<()> {
        if !self.member_idx_by_pubkey.contains_key(peer) {
            return Err(SignerError::UnknownPeer(peer.to_string()));
        }
        self.state.manual_policy_overrides.insert(
            peer.to_string(),
            PeerPolicyOverride::from_peer_policy(&policy),
        );
        self.state.last_active = now_unix_secs();
        self.mark_persistence_hint(PersistenceHint::Immediate);
        Ok(())
    }

    pub fn set_peer_policy_override(
        &mut self,
        peer: &str,
        policy: PeerPolicyOverride,
    ) -> Result<()> {
        if !self.member_idx_by_pubkey.contains_key(peer) {
            return Err(SignerError::UnknownPeer(peer.to_string()));
        }
        self.state
            .manual_policy_overrides
            .insert(peer.to_string(), policy);
        self.state.last_active = now_unix_secs();
        self.mark_persistence_hint(PersistenceHint::Immediate);
        Ok(())
    }

    pub fn clear_peer_policy_overrides(&mut self) {
        self.state.manual_policy_overrides.clear();
        self.state.last_active = now_unix_secs();
        self.mark_persistence_hint(PersistenceHint::Immediate);
    }

    fn select_ecdh_peers(&self, needed: usize) -> Result<Vec<String>> {
        if self.peers.len() < needed {
            return Err(SignerError::InvalidConfig(
                "insufficient peers for threshold round".to_string(),
            ));
        }

        let now = now_unix_secs();
        let mut online = self
            .peers
            .iter()
            .filter(|peer| {
                self.state
                    .peer_last_seen
                    .get(*peer)
                    .copied()
                    .map(|seen| now.saturating_sub(seen) <= Self::PEER_ONLINE_GRACE_SECS)
                    .unwrap_or(false)
                    && self.effective_policy_for_peer(peer).request.ecdh
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut fallback = self
            .peers
            .iter()
            .filter(|peer| {
                !online.contains(*peer) && self.effective_policy_for_peer(peer).request.ecdh
            })
            .cloned()
            .collect::<Vec<_>>();

        match self.config.peer_selection_strategy {
            PeerSelectionStrategy::DeterministicSorted => {
                online.sort_unstable();
                fallback.sort_unstable();
            }
            PeerSelectionStrategy::Random => {
                shuffle_strings(&mut online);
                shuffle_strings(&mut fallback);
            }
        }

        let mut selected = online;
        if selected.len() < needed {
            selected.extend(fallback);
        }
        selected.truncate(needed);
        Ok(selected)
    }

    fn select_signing_peers(&self, needed: usize) -> Result<Vec<String>> {
        let mut selected = self
            .peers
            .iter()
            .filter(|peer| {
                self.member_idx_by_pubkey
                    .get(*peer)
                    .copied()
                    .map(|idx| {
                        self.state.nonce_pool.can_sign(idx)
                            && self.effective_policy_for_peer(peer).request.sign
                    })
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>();

        if selected.len() < needed {
            return Err(SignerError::NonceUnavailable);
        }

        match self.config.peer_selection_strategy {
            PeerSelectionStrategy::DeterministicSorted => selected.sort_unstable(),
            PeerSelectionStrategy::Random => shuffle_strings(&mut selected),
        }
        selected.truncate(needed);
        Ok(selected)
    }

    fn fail_pending_operation(
        &mut self,
        request_id: &str,
        code: OperationFailureCode,
        message: String,
        failed_peer: Option<String>,
    ) {
        if let Some(op) = self.state.pending_operations.remove(request_id) {
            self.state.op_started_ms.remove(request_id);
            self.failures.push_back(OperationFailure {
                request_id: request_id.to_string(),
                op_type: op.op_type,
                code,
                message,
                failed_peer,
            });
        }
    }

    fn decrypt_event(&self, event: &Event, sender33: &str) -> Result<BridgeEnvelope> {
        let ciphertext = event_content(event)?;
        let plaintext =
            decrypt_content_from_peer(*self.share.seckey.expose_bytes(), sender33, &ciphertext)?;
        decode_bridge_envelope(&plaintext).map_err(|e| SignerError::InvalidRequest(e.to_string()))
    }

    fn encrypt_for_peers(&self, peers: &[String], envelope: &BridgeEnvelope) -> Result<Vec<Event>> {
        peers
            .iter()
            .map(|peer| self.encrypt_for_peer(peer, envelope))
            .collect()
    }

    fn encrypt_for_peer(&self, peer: &str, envelope: &BridgeEnvelope) -> Result<Event> {
        let plaintext = encode_bridge_envelope(envelope)
            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
        let content =
            encrypt_content_for_peer(*self.share.seckey.expose_bytes(), peer, &plaintext)?;
        let tags = vec![vec!["p".to_string(), peer.to_string()]];
        build_signed_event(
            *self.share.seckey.expose_bytes(),
            self.config.event_kind,
            tags,
            content,
        )
    }

    /// Handle a decrypted inbound request. `forced` is set only when resuming an
    /// operator-approved request from the queue — it bypasses the policy check so
    /// the same envelope re-runs verbatim through the per-method handlers below.
    fn handle_inbound_request(
        &mut self,
        envelope: BridgeEnvelope,
        sender: String,
        forced: bool,
    ) -> Result<Vec<Event>> {
        let sender_idx = self
            .member_idx_by_pubkey
            .get(&sender)
            .copied()
            .ok_or_else(|| SignerError::UnknownPeer(sender.clone()))?;
        let now = now_unix_secs();

        // Single policy gate for every inbound method (ping/onboard/sign/ecdh):
        // deny rejects, ask parks the request for the operator, allow falls
        // through to the handlers. Response payloads have no method and skip this.
        if let Some(method) = inbound_method_name(&envelope.payload) {
            match self.inbound_disposition(&sender, method, forced) {
                InboundDisposition::Allow => {}
                InboundDisposition::Deny => {
                    if method == "onboard" {
                        self.note_onboarding_status(
                            &sender,
                            OnboardingStatusStage::Failed,
                            now,
                            Some("inbound onboard denied by local policy".to_string()),
                        );
                    }
                    return self.reject_request(
                        &sender,
                        envelope.request_id,
                        "peer_denied",
                        &format!("inbound {method} denied by local policy"),
                    );
                }
                InboundDisposition::Ask => {
                    return Ok(self.queue_pending_approval(
                        sender,
                        method.to_string(),
                        envelope,
                        now,
                    ));
                }
            }
        }

        match envelope.payload {
            BridgePayload::PingRequest(wire) => {
                let ping: PingPayload =
                    wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                        SignerError::InvalidRequest(e.to_string())
                    })?;
                let peer_generation = ping.nonce_pool_generation;
                let recognized_peer_nonce_codes = self
                    .recognized_peer_nonce_codes_for_reported_inventory(
                        sender_idx,
                        &ping.held_peer_nonce_codes,
                    );
                self.reconcile_peer_generation(&sender, sender_idx, peer_generation);
                self.apply_ping_nonce_payload(sender_idx, &ping);
                self.store_remote_nonce_inventory_observation(
                    &sender,
                    sender_idx,
                    ping.held_peer_nonce_codes,
                    peer_generation,
                    now,
                );
                if let Some(profile) = ping.policy_profile {
                    self.store_remote_scoped_policy(&sender, profile)?;
                }

                let served_request_id = envelope.request_id;
                let served_peer = sender.clone();
                let response = BridgeEnvelope {
                    request_id: served_request_id.clone(),
                    sent_at: now,
                    payload: BridgePayload::PingResponse(PingPayloadWire::from(
                        self.ping_payload(
                            &sender,
                            sender_idx,
                            Some(recognized_peer_nonce_codes),
                        )?,
                    )),
                };
                let outbound = self.encrypt_for_peers(&[sender], &response)?;
                self.completions.push_back(CompletedOperation::PingServed {
                    request_id: served_request_id,
                    peer: served_peer,
                });
                Ok(outbound)
            }
            BridgePayload::OnboardRequest(wire) => {
                let request: bifrost_core::types::OnboardRequest =
                    wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                        SignerError::InvalidRequest(e.to_string())
                    })?;
                debug!(
                    device_id = %self.device_id,
                    sender = %sender,
                    sender_idx,
                    request_version = request.version,
                    request_nonce_count = request.nonces.len(),
                    "received onboard request"
                );
                if request.version != 1 {
                    self.note_onboarding_status(
                        &sender,
                        OnboardingStatusStage::Failed,
                        now,
                        Some(format!(
                            "unsupported onboard request version {}",
                            request.version
                        )),
                    );
                    return Err(SignerError::InvalidRequest(format!(
                        "unsupported onboard request version {}",
                        request.version
                    )));
                }
                if request.nonces.is_empty() {
                    self.note_onboarding_status(
                        &sender,
                        OnboardingStatusStage::Failed,
                        now,
                        Some("onboard bootstrap nonces missing".to_string()),
                    );
                    return Err(SignerError::InvalidRequest(
                        "onboard bootstrap nonces missing".to_string(),
                    ));
                }
                self.note_onboarding_status(
                    &sender,
                    OnboardingStatusStage::DeviceContactedHost,
                    now,
                    None,
                );
                self.state
                    .nonce_pool
                    .store_incoming(sender_idx, request.nonces);

                let generate_result = {
                    let DeviceState {
                        nonce_pool,
                        secrets,
                        ..
                    } = &mut self.state;
                    nonce_pool.generate_for_peer(
                        sender_idx,
                        NoncePoolConfig::default().pool_size,
                        &secrets.nonce_pool_secret,
                    )
                };
                if let Err(error) = generate_result {
                    self.note_onboarding_status(
                        &sender,
                        OnboardingStatusStage::Failed,
                        now,
                        Some(error.to_string()),
                    );
                    return Err(SignerError::InvalidRequest(error.to_string()));
                }
                let nonces = self.state.nonce_pool.outgoing_public_nonces(sender_idx);
                if nonces.is_empty() {
                    self.note_onboarding_status(
                        &sender,
                        OnboardingStatusStage::Failed,
                        now,
                        Some("onboard bootstrap nonces unavailable".to_string()),
                    );
                    return Err(SignerError::InvalidRequest(
                        "onboard bootstrap nonces unavailable".to_string(),
                    ));
                }
                let onboard = OnboardResponse {
                    group: self.group.clone(),
                    nonces,
                };

                let response = BridgeEnvelope {
                    request_id: envelope.request_id,
                    sent_at: now,
                    payload: BridgePayload::OnboardResponse(OnboardResponseWire::from(onboard)),
                };
                debug!(
                    device_id = %self.device_id,
                    sender = %sender,
                    request_id = %response.request_id,
                    group_member_count = self.group.members.len(),
                    "sending onboard response"
                );
                let served_request_id = response.request_id.clone();
                let served_peer = sender.clone();
                let outbound = self.encrypt_for_peers(std::slice::from_ref(&sender), &response)?;
                self.note_onboarding_status(
                    &sender,
                    OnboardingStatusStage::HandshakeCompleted,
                    now,
                    None,
                );
                // Record that we served an onboard response so hosts can mark the
                // onboarding device's share as onboarded.
                self.completions
                    .push_back(CompletedOperation::OnboardServed {
                        request_id: served_request_id,
                        peer: served_peer,
                    });
                Ok(outbound)
            }
            BridgePayload::SignRequest(wire) => {
                let session: SignSessionPackage =
                    wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                        SignerError::InvalidRequest(e.to_string())
                    })?;
                validate_sign_session(&self.group, &session)
                    .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;

                if !session.members.contains(&sender_idx) {
                    return Err(SignerError::InvalidSenderBinding(
                        "sign session missing sender".to_string(),
                    ));
                }
                let our_nonce_set = session
                    .nonces
                    .as_ref()
                    .and_then(|sets| sets.iter().find(|entry| entry.idx == self.share.idx))
                    .ok_or(SignerError::NonceUnavailable)?;
                if our_nonce_set.entries.len() != session.hashes.len() {
                    return Err(SignerError::InvalidRequest(
                        "nonce entries must match hash count".to_string(),
                    ));
                }

                let mut codes_by_hash: Vec<Bytes32> = vec![[0u8; 32]; session.hashes.len()];
                let mut seen = HashSet::new();
                for entry in &our_nonce_set.entries {
                    let hash_index = entry.hash_index as usize;
                    if hash_index >= session.hashes.len() {
                        return Err(SignerError::InvalidRequest(
                            "nonce hash index out of range".to_string(),
                        ));
                    }
                    if !seen.insert(hash_index) {
                        return Err(SignerError::InvalidRequest(
                            "duplicate nonce hash index".to_string(),
                        ));
                    }
                    codes_by_hash[hash_index] = entry.code;
                }

                let signing_nonces = self
                    .state
                    .nonce_pool
                    .take_outgoing_signing_nonces_many(sender_idx, &codes_by_hash)
                    .map_err(|_| SignerError::NonceUnavailable)?;

                let mut partial =
                    sign_create_partial(&self.group, &session, &self.share, &signing_nonces, None)
                        .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;

                let replenish = self.advertised_nonces_for_peer(&sender, sender_idx)?;
                if !replenish.is_empty() {
                    partial.replenish = Some(replenish);
                }

                let served_request_id = envelope.request_id;
                let served_peer = sender.clone();
                let response = BridgeEnvelope {
                    request_id: served_request_id.clone(),
                    sent_at: now,
                    payload: BridgePayload::SignResponse(PartialSigPackageWire::from(partial)),
                };
                let outbound = self.encrypt_for_peers(&[sender], &response)?;
                self.completions.push_back(CompletedOperation::SignServed {
                    request_id: served_request_id,
                    peer: served_peer,
                });
                Ok(outbound)
            }
            BridgePayload::EcdhRequest(wire) => {
                let req: EcdhPackage =
                    wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                        SignerError::InvalidRequest(e.to_string())
                    })?;
                self.validate_ecdh_request(&req, sender_idx)?;

                let targets = req
                    .entries
                    .iter()
                    .map(|entry| entry.ecdh_pk)
                    .collect::<Vec<_>>();
                let response = ecdh_create_from_share(&req.members, &self.share, &targets)
                    .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;

                let envelope = BridgeEnvelope {
                    request_id: envelope.request_id,
                    sent_at: now,
                    payload: BridgePayload::EcdhResponse(EcdhPackageWire::from(response)),
                };
                self.encrypt_for_peers(&[sender], &envelope)
            }
            BridgePayload::Error(_) => Ok(Vec::new()),
            BridgePayload::PingResponse(_) => {
                debug!(
                    device_id = %self.device_id,
                    sender = %sender,
                    request_id = %envelope.request_id,
                    "ignoring stale ping response without matching pending request"
                );
                Ok(Vec::new())
            }
            BridgePayload::OnboardResponse(_)
            | BridgePayload::SignResponse(_)
            | BridgePayload::EcdhResponse(_) => Err(SignerError::InvalidRequest(
                "response payload without pending request".to_string(),
            )),
        }
    }

    fn match_pending_response(
        &mut self,
        envelope: &BridgeEnvelope,
        sender: &str,
    ) -> Result<Vec<Event>> {
        let request_id = envelope.request_id.clone();
        let now = now_unix_secs();

        let mut should_complete = false;
        let mut completion: Option<CompletedOperation> = None;

        let Some(mut op) = self.state.pending_operations.get(&request_id).cloned() else {
            return Ok(Vec::new());
        };

        if !op.target_peers.iter().any(|peer| peer == sender) {
            return Err(SignerError::InvalidSenderBinding(
                "response sender is not a target peer".to_string(),
            ));
        }

        match (&op.op_type, &envelope.payload) {
            (PendingOpType::Ping, BridgePayload::PingResponse(wire)) => {
                let ping: PingPayload =
                    wire.clone()
                        .try_into()
                        .map_err(|e: bifrost_codec::CodecError| {
                            SignerError::InvalidRequest(e.to_string())
                        })?;
                let sender_idx = self
                    .member_idx_by_pubkey
                    .get(sender)
                    .copied()
                    .ok_or_else(|| SignerError::UnknownPeer(sender.to_string()))?;
                let peer_generation = ping.nonce_pool_generation;
                self.reconcile_peer_generation(sender, sender_idx, peer_generation);
                self.apply_ping_nonce_payload(sender_idx, &ping);
                self.store_remote_nonce_inventory_observation(
                    sender,
                    sender_idx,
                    ping.held_peer_nonce_codes,
                    peer_generation,
                    now,
                );
                if let Some(profile) = ping.policy_profile {
                    self.store_remote_scoped_policy(sender, profile)?;
                }
                // Telemetry: record this ping's round-trip latency (ms). An op that
                // began before a restore has no start stamp, so its sample is skipped.
                if let Some(started_ms) = self.state.op_started_ms.get(&request_id).copied() {
                    self.state
                        .record_rtt_sample(sender, now_unix_millis().saturating_sub(started_ms));
                }
                completion = Some(CompletedOperation::Ping {
                    request_id: request_id.clone(),
                    peer: sender.to_string(),
                });
                should_complete = true;
            }
            (PendingOpType::Onboard, BridgePayload::OnboardResponse(wire)) => {
                let onboard: OnboardResponse =
                    wire.clone()
                        .try_into()
                        .map_err(|e: bifrost_codec::CodecError| {
                            SignerError::InvalidRequest(e.to_string())
                        })?;
                let sender_idx = self
                    .member_idx_by_pubkey
                    .get(sender)
                    .copied()
                    .ok_or_else(|| SignerError::UnknownPeer(sender.to_string()))?;
                self.state
                    .nonce_pool
                    .store_incoming(sender_idx, onboard.nonces.clone());
                completion = Some(CompletedOperation::Onboard {
                    request_id: request_id.clone(),
                    group_member_count: onboard.group.members.len(),
                    group: onboard.group.clone(),
                    nonces: onboard.nonces.clone(),
                });
                should_complete = true;
            }
            (PendingOpType::Ecdh, BridgePayload::EcdhResponse(wire)) => {
                let sender_idx = self
                    .member_idx_by_pubkey
                    .get(sender)
                    .copied()
                    .ok_or_else(|| SignerError::UnknownPeer(sender.to_string()))?;
                let package: EcdhPackage =
                    wire.clone()
                        .try_into()
                        .map_err(|e: bifrost_codec::CodecError| {
                            SignerError::InvalidRequest(e.to_string())
                        })?;
                self.validate_ecdh_request(&package, sender_idx)?;

                if let PendingOpContext::EcdhRequest {
                    target,
                    local_pkg,
                    responses,
                } = &mut op.context
                {
                    self.validate_ecdh_response_matches_request(&package, local_pkg)?;
                    if responses.iter().any(|item| item.idx == sender_idx) {
                        return Err(SignerError::InvalidRequest(
                            "duplicate ecdh response".to_string(),
                        ));
                    }
                    responses.push(package.clone());

                    if responses.len() >= op.threshold {
                        let mut all = Vec::with_capacity(1 + responses.len());
                        all.push(local_pkg.clone());
                        all.extend(responses.iter().cloned());
                        let target_key = target.clone();
                        let target = decode_pubkey32(&target_key)?;
                        let shared_secret = ecdh_finalize(&all, target)
                            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
                        self.ecdh_cache_put(target, shared_secret, now);
                        completion = Some(CompletedOperation::Ecdh {
                            request_id: request_id.clone(),
                            shared_secret,
                        });
                        should_complete = true;
                    }
                }
            }
            (PendingOpType::Sign, BridgePayload::SignResponse(wire)) => {
                let partial: PartialSigPackage =
                    wire.clone()
                        .try_into()
                        .map_err(|e: bifrost_codec::CodecError| {
                            SignerError::InvalidRequest(e.to_string())
                        })?;

                if let PendingOpContext::SignSession { session, partials } = &mut op.context {
                    sign_verify_partial(&self.group, session, &partial)
                        .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;

                    if partials.iter().any(|p| p.idx == partial.idx) {
                        return Err(SignerError::InvalidRequest(
                            "duplicate sign response".to_string(),
                        ));
                    }
                    if let Some(replenish) = partial.replenish.clone() {
                        let sender_idx = self
                            .member_idx_by_pubkey
                            .get(sender)
                            .copied()
                            .ok_or_else(|| SignerError::UnknownPeer(sender.to_string()))?;
                        self.state.nonce_pool.store_incoming(sender_idx, replenish);
                    }
                    partials.push(partial);

                    if partials.len() >= op.threshold {
                        let signatures = sign_finalize(&self.group, session, partials)
                            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
                        if let Some(message) = session.hashes.first().copied() {
                            self.sig_cache_put(
                                message,
                                signatures.iter().map(|s| s.signature).collect(),
                                now,
                            );
                        }
                        completion = Some(CompletedOperation::Sign {
                            request_id: request_id.clone(),
                            signatures: signatures.into_iter().map(|s| s.signature).collect(),
                        });
                        should_complete = true;
                    }
                }
            }
            (_, BridgePayload::Error(err)) => {
                return Err(SignerError::InvalidRequest(format!(
                    "peer rejected request: {}:{}",
                    err.code, err.message
                )));
            }
            _ => {
                return Err(SignerError::InvalidRequest(
                    "unexpected response payload for pending operation".to_string(),
                ));
            }
        }

        op.collected_responses.push(CollectedResponse {
            peer: sender.to_string(),
            request_id: request_id.clone(),
            envelope_id: request_id.clone(),
            seen_at: now,
        });

        if should_complete {
            self.state.pending_operations.remove(&request_id);
            self.state.op_started_ms.remove(&request_id);
            if let Some(done) = completion {
                self.completions.push_back(done);
            }
        } else {
            self.state.pending_operations.insert(request_id, op);
        }

        Ok(Vec::new())
    }

    fn validate_ecdh_request(&self, package: &EcdhPackage, sender_idx: u16) -> Result<()> {
        if package.idx != sender_idx {
            return Err(SignerError::InvalidSenderBinding(
                "ecdh package idx does not match sender".to_string(),
            ));
        }
        if package.members.len() < self.group.threshold as usize {
            return Err(SignerError::InvalidRequest(
                "ecdh package members below threshold".to_string(),
            ));
        }
        let mut members = package.members.clone();
        members.sort_unstable();
        if members != package.members {
            return Err(SignerError::InvalidRequest(
                "ecdh package members must be sorted".to_string(),
            ));
        }
        for pair in members.windows(2) {
            if pair[0] == pair[1] {
                return Err(SignerError::InvalidRequest(
                    "ecdh package members contain duplicates".to_string(),
                ));
            }
        }
        if !members.contains(&self.share.idx) {
            return Err(SignerError::InvalidRequest(
                "ecdh package must include local member".to_string(),
            ));
        }
        if !members.contains(&sender_idx) {
            return Err(SignerError::InvalidRequest(
                "ecdh package must include sender".to_string(),
            ));
        }
        if package.entries.is_empty() {
            return Err(SignerError::InvalidRequest(
                "ecdh package missing targets".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_ecdh_response_matches_request(
        &self,
        response: &EcdhPackage,
        request: &EcdhPackage,
    ) -> Result<()> {
        if response.members != request.members {
            return Err(SignerError::InvalidRequest(
                "ecdh response members mismatch".to_string(),
            ));
        }
        for entry in &request.entries {
            if !response
                .entries
                .iter()
                .any(|candidate| candidate.ecdh_pk == entry.ecdh_pk)
            {
                return Err(SignerError::InvalidRequest(
                    "ecdh response missing request target".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn store_remote_scoped_policy(
        &mut self,
        peer: &str,
        profile: PeerScopedPolicyProfile,
    ) -> Result<()> {
        let local = decode_32(&self.share_public_key_hex)?;
        if profile.for_peer != local {
            return Ok(());
        }
        self.state
            .remote_scoped_policies
            .insert(peer.to_string(), profile);
        Ok(())
    }

    fn local_policy_profile_for(&self, peer: &str) -> Result<PeerScopedPolicyProfile> {
        let now = now_unix_secs();
        let policy = self.local_policy_for_peer(peer);
        Ok(PeerScopedPolicyProfile {
            for_peer: decode_32(peer)?,
            revision: now,
            updated: now,
            block_all: policy.block_all,
            request: policy.request,
            respond: policy.respond,
        })
    }

    fn nonce_sync_target_size(&self) -> usize {
        let cfg = self.state.nonce_pool.config();
        cfg.pool_size
            .min(cfg.min_threshold.saturating_add(cfg.replenish_count))
    }

    fn normalized_remote_held_nonce_codes(&self, peer: &str, peer_idx: u16) -> Vec<Bytes32> {
        let current_codes = self.state.nonce_pool.outgoing_public_nonce_codes(peer_idx);
        if current_codes.is_empty() {
            return Vec::new();
        }
        let current_code_set = current_codes.into_iter().collect::<HashSet<_>>();
        let mut held_codes = self
            .state
            .remote_nonce_inventory_observations
            .get(peer)
            .map(|observation| {
                observation
                    .held_codes
                    .iter()
                    .copied()
                    .filter(|code| current_code_set.contains(code))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        held_codes.sort_unstable();
        held_codes.dedup();
        held_codes
    }

    fn recognized_peer_nonce_codes_for_reported_inventory(
        &self,
        peer_idx: u16,
        held_codes: &[Bytes32],
    ) -> Vec<Bytes32> {
        let current_codes = self.state.nonce_pool.outgoing_public_nonce_codes(peer_idx);
        if current_codes.is_empty() || held_codes.is_empty() {
            return Vec::new();
        }
        let current_code_set = current_codes.into_iter().collect::<HashSet<_>>();
        let mut recognized_codes = held_codes
            .iter()
            .copied()
            .filter(|code| current_code_set.contains(code))
            .collect::<Vec<_>>();
        recognized_codes.sort_unstable();
        recognized_codes.dedup();
        recognized_codes
    }

    fn peer_needs_nonce_refill(&self, peer: &str, peer_idx: u16) -> bool {
        self.normalized_remote_held_nonce_codes(peer, peer_idx)
            .len()
            < self.state.nonce_pool.config().min_threshold
    }

    /// Detect a peer that reset its outgoing nonce pool: if its advertised
    /// generation differs from the one we last recorded, the public nonces we
    /// hold from it are dead — discard them so we don't reference a nonce the
    /// peer can no longer honor. No-op on first contact (no recorded generation)
    /// or when either side is the all-zero "unknown" generation (legacy peers).
    fn reconcile_peer_generation(&mut self, peer: &str, peer_idx: u16, generation: Bytes32) {
        if generation == bifrost_core::nonce::UNKNOWN_POOL_GENERATION {
            return;
        }
        let reset = self
            .state
            .remote_nonce_inventory_observations
            .get(peer)
            .map(|observation| observation.peer_generation)
            .is_some_and(|previous| {
                previous != bifrost_core::nonce::UNKNOWN_POOL_GENERATION && previous != generation
            });
        if reset {
            self.state.nonce_pool.clear_incoming(peer_idx);
        }
    }

    fn store_remote_nonce_inventory_observation(
        &mut self,
        peer: &str,
        peer_idx: u16,
        held_codes: Vec<Bytes32>,
        generation: Bytes32,
        updated_at: u64,
    ) {
        let current_codes = self.state.nonce_pool.outgoing_public_nonce_codes(peer_idx);
        let current_code_set = current_codes.into_iter().collect::<HashSet<_>>();
        let mut normalized_codes = held_codes
            .into_iter()
            .filter(|code| current_code_set.contains(code))
            .collect::<Vec<_>>();
        normalized_codes.sort_unstable();
        normalized_codes.dedup();
        // Telemetry: sample the held-nonce count for the dashboard sparkline.
        self.state
            .record_nonce_history(peer, updated_at, normalized_codes.len() as u32);
        self.state.remote_nonce_inventory_observations.insert(
            peer.to_string(),
            PeerNonceInventoryObservation {
                held_codes: normalized_codes,
                updated_at,
                peer_generation: generation,
            },
        );
    }

    fn advertised_nonces_for_peer(
        &mut self,
        peer: &str,
        peer_idx: u16,
    ) -> Result<Vec<DerivedPublicNonce>> {
        let observed_codes = self.normalized_remote_held_nonce_codes(peer, peer_idx);
        let cfg = self.state.nonce_pool.config().clone();
        if observed_codes.len() >= cfg.min_threshold {
            return Ok(Vec::new());
        }

        let target_size = self.nonce_sync_target_size();
        let current_available = self
            .state
            .nonce_pool
            .outgoing_public_nonce_codes(peer_idx)
            .len();
        if current_available < target_size {
            let DeviceState {
                nonce_pool,
                secrets,
                ..
            } = &mut self.state;
            nonce_pool
                .generate_for_peer(
                    peer_idx,
                    target_size.saturating_sub(current_available),
                    &secrets.nonce_pool_secret,
                )
                .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
        }

        let observed_code_set = observed_codes.into_iter().collect::<HashSet<_>>();
        let advertise_limit = target_size.saturating_sub(observed_code_set.len());
        Ok(self
            .state
            .nonce_pool
            .outgoing_public_nonces(peer_idx)
            .into_iter()
            .filter(|nonce| !observed_code_set.contains(&nonce.code))
            .take(advertise_limit)
            .collect())
    }

    fn ping_payload(
        &mut self,
        peer: &str,
        peer_idx: u16,
        recognized_peer_nonce_codes: Option<Vec<Bytes32>>,
    ) -> Result<PingPayload> {
        Ok(PingPayload {
            version: 2,
            advertised_nonces: self.advertised_nonces_for_peer(peer, peer_idx)?,
            held_peer_nonce_codes: self.state.nonce_pool.incoming_nonce_codes(peer_idx),
            recognized_peer_nonce_codes: Some(recognized_peer_nonce_codes.unwrap_or_else(|| {
                self.normalized_remote_held_nonce_codes(peer, peer_idx)
            })),
            policy_profile: Some(self.local_policy_profile_for(peer)?),
            nonce_pool_generation: self.state.nonce_pool.generation(),
        })
    }

    fn apply_ping_nonce_payload(&mut self, peer_idx: u16, payload: &PingPayload) {
        if let Some(recognized_codes) = payload.recognized_peer_nonce_codes.as_ref() {
            let mut retained = recognized_codes.clone();
            retained.extend(payload.advertised_nonces.iter().map(|nonce| nonce.code));
            retained.sort_unstable();
            retained.dedup();
            self.state
                .nonce_pool
                .retain_incoming_codes(peer_idx, &retained);
        }
        if !payload.advertised_nonces.is_empty() {
            self.state
                .nonce_pool
                .store_incoming(peer_idx, payload.advertised_nonces.clone());
        }
    }

    fn reject_request(
        &self,
        peer: &str,
        request_id: String,
        code: &str,
        message: &str,
    ) -> Result<Vec<Event>> {
        let response = BridgeEnvelope {
            request_id,
            sent_at: now_unix_secs(),
            payload: BridgePayload::Error(bifrost_codec::wire::PeerErrorWire {
                code: code.to_string(),
                message: message.to_string(),
            }),
        };
        self.encrypt_for_peers(&[peer.to_string()], &response)
    }

    /// Park an inbound request awaiting an operator decision (the `Ask`
    /// disposition). Stores the decrypted envelope so the request can be replayed
    /// verbatim on approval. Returns no outbound — the peer waits.
    fn queue_pending_approval(
        &mut self,
        peer: String,
        method: String,
        envelope: BridgeEnvelope,
        now: u64,
    ) -> Vec<Event> {
        let request_id = envelope.request_id.clone();
        let expires_at = now.saturating_add(self.config.approval_timeout_secs);
        debug!(
            device_id = %self.device_id,
            peer = %peer,
            method = %method,
            request_id = %request_id,
            "parking inbound request for operator approval"
        );
        self.state.pending_approvals.insert(
            request_id,
            PendingApproval {
                peer,
                method,
                envelope,
                queued_at: now,
                expires_at,
            },
        );
        Vec::new()
    }

    /// Resolve a parked approval. Approving replays the stored request through the
    /// normal handler (`forced`, so the policy gate is skipped); denying sends an
    /// `operator_denied` error. Unknown / already-expired ids are a no-op.
    fn resolve_approval(&mut self, request_id: &str, approved: bool) -> Result<Vec<Event>> {
        let Some(approval) = self.state.pending_approvals.remove(request_id) else {
            debug!(
                device_id = %self.device_id,
                request_id = %request_id,
                "resolve_approval: no parked request for id (no-op)"
            );
            return Ok(Vec::new());
        };
        if !approved {
            return self.reject_request(
                &approval.peer,
                request_id.to_string(),
                "operator_denied",
                "request denied by operator",
            );
        }
        // Replay the stored request verbatim. Classify the op type before the
        // move so a handler error (e.g. a nonce miss) surfaces correctly typed,
        // mirroring `process_event`, rather than aborting the whole `apply`.
        let op_type = inbound_op_type(&approval.envelope.payload);
        let peer = approval.peer.clone();
        match self.handle_inbound_request(approval.envelope, approval.peer, true) {
            Ok(outbound) => Ok(outbound),
            Err(err) => {
                self.failures.push_back(OperationFailure {
                    request_id: request_id.to_string(),
                    op_type,
                    code: OperationFailureCode::PeerRejected,
                    message: err.to_string(),
                    failed_peer: Some(peer),
                });
                Ok(Vec::new())
            }
        }
    }

    fn record_request(
        &mut self,
        sender: &str,
        request_id: &str,
        sent_at: u64,
        now: u64,
    ) -> Result<()> {
        if request_id.is_empty() {
            return Err(SignerError::InvalidRequest(
                "request id must not be empty".to_string(),
            ));
        }
        if sent_at > now.saturating_add(self.config.max_future_skew_secs) {
            return Err(SignerError::InvalidRequest(
                "request sent_at is too far in the future".to_string(),
            ));
        }
        if now > sent_at.saturating_add(self.config.request_ttl_secs) {
            return Err(SignerError::InvalidRequest("stale request".to_string()));
        }

        let key = format!("{sender}:{request_id}");
        self.state
            .replay_cache
            .retain(|_, seen_at| now.saturating_sub(*seen_at) <= self.config.request_ttl_secs);
        if self.state.replay_cache.contains_key(&key) {
            return Err(SignerError::ReplayDetected(request_id.to_string()));
        }
        self.state.replay_cache.insert(key, now);

        if self.state.replay_cache.len() > self.config.request_cache_limit {
            let mut entries = self
                .state
                .replay_cache
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect::<Vec<_>>();
            entries.sort_by_key(|(_, v)| *v);
            let drop_count = entries
                .len()
                .saturating_sub(self.config.request_cache_limit);
            for (key, _) in entries.into_iter().take(drop_count) {
                self.state.replay_cache.remove(&key);
            }
        }

        Ok(())
    }

    fn next_request_id(&mut self) -> String {
        let id = random_request_id();
        self.state.request_seq = self.state.request_seq.saturating_add(1);
        id
    }
}

/// Map an inbound bridge payload to the operation type it belongs to, so a
/// failure handling it is reported under the correct op type rather than a
/// generic ping. Responses are mapped to their request family.
fn inbound_op_type(payload: &BridgePayload) -> PendingOpType {
    match payload {
        BridgePayload::SignRequest(_) | BridgePayload::SignResponse(_) => PendingOpType::Sign,
        BridgePayload::EcdhRequest(_) | BridgePayload::EcdhResponse(_) => PendingOpType::Ecdh,
        BridgePayload::OnboardRequest(_) | BridgePayload::OnboardResponse(_) => {
            PendingOpType::Onboard
        }
        BridgePayload::PingRequest(_)
        | BridgePayload::PingResponse(_)
        | BridgePayload::Error(_) => PendingOpType::Ping,
    }
}

/// Policy method name for an inbound *request* payload, or `None` for responses
/// and errors (which carry no method and bypass the policy gate).
fn inbound_method_name(payload: &BridgePayload) -> Option<&'static str> {
    match payload {
        BridgePayload::PingRequest(_) => Some("ping"),
        BridgePayload::OnboardRequest(_) => Some("onboard"),
        BridgePayload::SignRequest(_) => Some("sign"),
        BridgePayload::EcdhRequest(_) => Some("ecdh"),
        _ => None,
    }
}

fn extract_recipient_p_tags(event: &Event) -> Vec<String> {
    let p_tag = SingleLetterTag::lowercase(Alphabet::P);
    event
        .tags
        .iter()
        .filter_map(|tag| match tag.kind() {
            TagKind::SingleLetter(letter) if letter == p_tag => tag.content().map(str::to_string),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_codec::wire::{DerivedPublicNonceWire, OnboardRequestWire};
    use bifrost_core::MethodPolicy;
    use frostr_utils::{CreateKeysetConfig, create_keyset};

    struct Fixture {
        signer: SigningDevice,
        group: GroupPackage,
        shares: Vec<SharePackage>,
        local_share: SharePackage,
    }

    fn fixture(strategy: PeerSelectionStrategy) -> Fixture {
        let bundle =
            create_keyset(CreateKeysetConfig::new("Test Group", 2, 3)).expect("create keyset");

        let group = bundle.group.clone();
        let shares = bundle.shares.clone();
        let local_share = shares.first().cloned().expect("local share");
        let peers = group
            .members
            .iter()
            .filter(|member| member.idx != local_share.idx)
            .map(|member| hex::encode(&member.pubkey[1..]))
            .collect::<Vec<_>>();

        let signer = SigningDevice::new(
            group.clone(),
            local_share.clone(),
            peers,
            DeviceState::new(local_share.idx, *local_share.seckey.expose_bytes()),
            DeviceConfig {
                peer_selection_strategy: strategy,
                ..DeviceConfig::default()
            },
        )
        .expect("signer");

        Fixture {
            signer,
            group,
            shares,
            local_share,
        }
    }

    fn first_peer(fixture: &Fixture) -> (String, u16) {
        let member = fixture
            .group
            .members
            .iter()
            .find(|member| member.idx != fixture.local_share.idx)
            .expect("a peer member");
        (hex::encode(&member.pubkey[1..]), member.idx)
    }

    fn dummy_nonce(code: u8) -> DerivedPublicNonce {
        DerivedPublicNonce {
            binder_pn: [1u8; 33],
            hidden_pn: [2u8; 33],
            code: [code; 32],
        }
    }

    #[test]
    fn reconcile_peer_generation_discards_stale_nonces_on_change() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let (peer, peer_idx) = first_peer(&fixture);

        // First advertisement (generation g1): store the peer's nonces + record g1.
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(peer_idx, vec![dummy_nonce(1), dummy_nonce(2)]);
        fixture.signer.store_remote_nonce_inventory_observation(
            &peer,
            peer_idx,
            Vec::new(),
            [0x11u8; 32],
            100,
        );
        assert_eq!(
            fixture
                .signer
                .state
                .nonce_pool
                .peer_stats(peer_idx)
                .incoming_available,
            2
        );

        // Same generation again → nonces are kept.
        fixture
            .signer
            .reconcile_peer_generation(&peer, peer_idx, [0x11u8; 32]);
        assert_eq!(
            fixture
                .signer
                .state
                .nonce_pool
                .peer_stats(peer_idx)
                .incoming_available,
            2
        );

        // A new generation means the peer reset its outgoing pool — the nonces we
        // hold from it are dead and must be discarded.
        fixture
            .signer
            .reconcile_peer_generation(&peer, peer_idx, [0x22u8; 32]);
        assert_eq!(
            fixture
                .signer
                .state
                .nonce_pool
                .peer_stats(peer_idx)
                .incoming_available,
            0
        );
    }

    #[test]
    fn reconcile_peer_generation_keeps_nonces_on_first_contact() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let (peer, peer_idx) = first_peer(&fixture);
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(peer_idx, vec![dummy_nonce(5)]);

        // No generation recorded yet → first contact must not discard anything.
        fixture
            .signer
            .reconcile_peer_generation(&peer, peer_idx, [0x33u8; 32]);
        assert_eq!(
            fixture
                .signer
                .state
                .nonce_pool
                .peer_stats(peer_idx)
                .incoming_available,
            1
        );
    }

    fn share_for_peer(group: &GroupPackage, shares: &[SharePackage], peer: &str) -> SharePackage {
        let idx = decode_member_index(&group.members, peer).expect("peer idx");
        shares
            .iter()
            .find(|share| share.idx == idx)
            .cloned()
            .expect("peer share")
    }

    fn build_peer_signer(group: &GroupPackage, share: &SharePackage) -> SigningDevice {
        let peers = group
            .members
            .iter()
            .filter(|member| member.idx != share.idx)
            .map(|member| hex::encode(&member.pubkey[1..]))
            .collect::<Vec<_>>();

        SigningDevice::new(
            group.clone(),
            share.clone(),
            peers,
            DeviceState::new(share.idx, *share.seckey.expose_bytes()),
            DeviceConfig::default(),
        )
        .expect("peer signer")
    }

    fn decode_envelope_for_local(
        local_share: &SharePackage,
        sender_pubkey32: &str,
        event: &Event,
    ) -> BridgeEnvelope {
        let ciphertext = event_content(event).expect("event content");
        let plaintext = decrypt_content_from_peer(
            *local_share.seckey.expose_bytes(),
            sender_pubkey32,
            &ciphertext,
        )
        .expect("decrypt envelope");
        decode_bridge_envelope(&plaintext).expect("decode envelope")
    }

    #[test]
    fn deterministic_strategy_selects_sorted_ecdh_peers() {
        let fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let selected = fixture.signer.select_ecdh_peers(2).expect("select");

        let mut expected = fixture.signer.peers.clone();
        expected.sort_unstable();
        expected.truncate(2);
        assert_eq!(selected, expected);
    }

    #[test]
    fn random_strategy_selects_unique_subset_of_ecdh_peers() {
        let fixture = fixture(PeerSelectionStrategy::Random);
        let selected = fixture.signer.select_ecdh_peers(2).expect("select");

        assert_eq!(selected.len(), 2);
        let unique = selected.iter().cloned().collect::<HashSet<_>>();
        assert_eq!(unique.len(), 2);
        assert!(
            selected
                .iter()
                .all(|peer| fixture.signer.peers.contains(peer))
        );
    }

    #[test]
    fn sign_selection_prefers_nonce_ready_peers() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let mut sorted_peers = fixture.signer.peers.clone();
        sorted_peers.sort_unstable();
        let chosen_peer = sorted_peers[1].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &chosen_peer);
        let mut peer_state = DeviceState::new(peer_share.idx, *peer_share.seckey.expose_bytes());
        let generated = peer_state
            .nonce_pool
            .generate_for_peer(
                fixture.local_share.idx,
                10,
                &peer_state.secrets.nonce_pool_secret,
            )
            .expect("generate peer nonces");
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(peer_share.idx, generated.clone());

        let selected = fixture
            .signer
            .select_signing_peers(1)
            .expect("select signing peer");
        assert_eq!(selected, vec![chosen_peer]);
    }

    #[test]
    fn ecdh_selection_prefers_recently_seen_peers() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let mut sorted_peers = fixture.signer.peers.clone();
        sorted_peers.sort_unstable();
        let chosen_peer = sorted_peers[1].clone();
        fixture
            .signer
            .state
            .peer_last_seen
            .insert(chosen_peer.clone(), now_unix_secs());

        let selected = fixture
            .signer
            .select_ecdh_peers(1)
            .expect("select ecdh peer");
        assert_eq!(selected, vec![chosen_peer]);
    }

    #[test]
    fn initiate_sign_succeeds_with_mixed_nonce_readiness() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let mut sorted_peers = fixture.signer.peers.clone();
        sorted_peers.sort_unstable();
        let ready_peer = sorted_peers[1].clone();
        let ready_share = share_for_peer(&fixture.group, &fixture.shares, &ready_peer);
        let mut peer_state = DeviceState::new(ready_share.idx, *ready_share.seckey.expose_bytes());
        let generated = peer_state
            .nonce_pool
            .generate_for_peer(
                fixture.local_share.idx,
                10,
                &peer_state.secrets.nonce_pool_secret,
            )
            .expect("generate peer nonces");
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(ready_share.idx, generated);

        let outbound = fixture
            .signer
            .initiate_sign([42u8; 32])
            .expect("initiate sign");

        assert_eq!(outbound.len(), 1);

        let request_id = fixture
            .signer
            .latest_request_id()
            .expect("latest request id");
        let pending = fixture
            .signer
            .state
            .pending_operations
            .get(&request_id)
            .expect("pending sign operation");

        assert!(matches!(pending.op_type, PendingOpType::Sign));
        assert_eq!(pending.target_peers, vec![ready_peer.clone()]);

        let PendingOpContext::SignSession { session, .. } = &pending.context else {
            panic!("expected sign-session context");
        };

        let ready_idx =
            decode_member_index(&fixture.group.members, &ready_peer).expect("ready idx");
        assert_eq!(session.members, vec![fixture.local_share.idx, ready_idx]);

        let responder_peers = fixture
            .group
            .members
            .iter()
            .filter(|member| member.idx != ready_share.idx)
            .map(|member| hex::encode(&member.pubkey[1..]))
            .collect::<Vec<_>>();
        let mut responder = SigningDevice::new(
            fixture.group.clone(),
            ready_share,
            responder_peers,
            peer_state,
            DeviceConfig::default(),
        )
        .expect("ready peer signer");
        let responder_effects = responder
            .apply(SignerInput::ProcessEvent {
                event: outbound[0].clone(),
            })
            .expect("process sign request");
        assert_eq!(responder_effects.outbound.len(), 1);
        let sign_served_peer = responder_effects
            .completions
            .iter()
            .find_map(|completion| match completion {
                CompletedOperation::SignServed { peer, .. } => Some(peer.clone()),
                _ => None,
            })
            .expect("expected sign-served completion");
        assert_eq!(sign_served_peer, fixture.signer.local_pubkey32());
    }

    #[test]
    fn ping_refill_prunes_stale_peer_nonces_before_signing() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);

        let mut stale_peer_state =
            DeviceState::new(peer_share.idx, *peer_share.seckey.expose_bytes());
        let stale_nonces = stale_peer_state
            .nonce_pool
            .generate_for_peer(
                fixture.local_share.idx,
                10,
                &stale_peer_state.secrets.nonce_pool_secret,
            )
            .expect("generate stale peer nonces");
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(peer_share.idx, stale_nonces);
        assert!(fixture.signer.state.nonce_pool.can_sign(peer_share.idx));

        let mut current_peer = build_peer_signer(&fixture.group, &peer_share);
        let ping = fixture
            .signer
            .apply(SignerInput::BeginPing { peer: peer.clone() })
            .expect("begin sync ping")
            .outbound;
        assert_eq!(ping.len(), 1);

        let response = current_peer
            .process_event(&ping[0])
            .expect("peer processes sync ping");
        assert_eq!(response.len(), 1);
        fixture
            .signer
            .process_event(&response[0])
            .expect("requester processes sync response");

        let request = fixture
            .signer
            .initiate_sign([0x66; 32])
            .expect("initiate sign after sync");
        assert_eq!(request.len(), 1);

        let effects = current_peer
            .apply(SignerInput::ProcessEvent {
                event: request[0].clone(),
            })
            .expect("current peer processes sign request");
        assert_eq!(effects.outbound.len(), 1);
    }

    #[test]
    fn initiate_sign_prefers_newly_advertised_peer_nonces() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);

        let mut stale_peer_state =
            DeviceState::new(peer_share.idx, *peer_share.seckey.expose_bytes());
        let stale_nonces = stale_peer_state
            .nonce_pool
            .generate_for_peer(
                fixture.local_share.idx,
                10,
                &stale_peer_state.secrets.nonce_pool_secret,
            )
            .expect("generate stale peer nonces");
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(peer_share.idx, stale_nonces);

        let mut current_peer = build_peer_signer(&fixture.group, &peer_share);
        let fresh_nonces = current_peer
            .state
            .nonce_pool
            .generate_for_peer(
                fixture.local_share.idx,
                10,
                &current_peer.state.secrets.nonce_pool_secret,
            )
            .expect("generate fresh peer nonces");
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(peer_share.idx, fresh_nonces);

        let request = fixture
            .signer
            .initiate_sign([0x77; 32])
            .expect("initiate sign with mixed stale and fresh nonces");
        assert_eq!(request.len(), 1);

        let effects = current_peer
            .apply(SignerInput::ProcessEvent {
                event: request[0].clone(),
            })
            .expect("current peer processes sign request");
        assert_eq!(effects.outbound.len(), 1);
    }

    #[test]
    fn update_config_applies_safe_subset() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);

        fixture
            .signer
            .update_config(DeviceConfigPatch {
                sign_timeout_secs: Some(41),
                ping_timeout_secs: Some(19),
                request_ttl_secs: Some(480),
                state_save_interval_secs: Some(9),
                peer_selection_strategy: Some(PeerSelectionStrategy::Random),
            })
            .expect("update config");

        let config = fixture.signer.read_config();
        assert_eq!(config.sign_timeout_secs, 41);
        assert_eq!(config.ping_timeout_secs, 19);
        assert_eq!(config.request_ttl_secs, 480);
        assert_eq!(config.state_save_interval_secs, 9);
        assert_eq!(
            config.peer_selection_strategy,
            PeerSelectionStrategy::Random
        );
    }

    #[test]
    fn peer_status_reports_last_seen_and_online() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        fixture
            .signer
            .state
            .peer_last_seen
            .insert(peer.clone(), now_unix_secs());

        let statuses = fixture.signer.peer_status();
        let status = statuses
            .into_iter()
            .find(|entry| entry.pubkey == peer)
            .expect("peer status");

        assert!(status.known);
        assert!(status.online);
        assert!(status.last_seen.is_some());
        // Capability badges: online + permissive default policy → both capable.
        assert!(status.can_ping);
        assert!(status.can_ecdh);
        // No telemetry recorded yet.
        assert!(status.last_response_latency_ms.is_none());
        assert!(status.avg_latency_ms.is_none());
        assert!(status.nonce_history.is_empty());
    }

    #[test]
    fn peer_status_capability_badges_are_false_when_offline() {
        // A fixture peer with no recorded `last_seen` is offline, so its ECDH/PING
        // capability badges are false even though the default policy permits them.
        let fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();

        let status = fixture
            .signer
            .peer_status()
            .into_iter()
            .find(|entry| entry.pubkey == peer)
            .expect("peer status");

        assert!(!status.online);
        assert!(!status.can_ping);
        assert!(!status.can_ecdh);
    }

    #[test]
    fn peer_status_projects_recorded_latency_and_nonce_history() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        fixture
            .signer
            .state
            .peer_last_seen
            .insert(peer.clone(), now_unix_secs());

        // Two RTT samples → last is the newest, avg is the rolling mean.
        fixture.signer.state.record_rtt_sample(&peer, 100);
        fixture.signer.state.record_rtt_sample(&peer, 300);
        fixture.signer.state.record_nonce_history(&peer, 1_700, 5);
        fixture.signer.state.record_nonce_history(&peer, 1_701, 7);

        let status = fixture
            .signer
            .peer_status()
            .into_iter()
            .find(|entry| entry.pubkey == peer)
            .expect("peer status");

        assert_eq!(status.last_response_latency_ms, Some(300));
        assert_eq!(status.avg_latency_ms, Some(200));
        assert_eq!(status.nonce_history.len(), 2);
        assert_eq!(status.nonce_history[0].ts, 1_700);
        assert_eq!(status.nonce_history[0].held, 5);
        assert_eq!(status.nonce_history[1].held, 7);
    }

    #[test]
    fn peer_status_reports_latest_response_latency() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let request_id = "req-latency".to_string();
        let sender = fixture.signer.peers[0].clone();
        let now = now_unix_secs();
        fixture
            .signer
            .state
            .peer_last_seen
            .insert(sender.clone(), now);
        fixture.signer.state.pending_operations.insert(
            request_id.clone(),
            PendingOperation {
                op_type: PendingOpType::Ping,
                request_id: request_id.clone(),
                started_at: now.saturating_sub(2),
                timeout_at: now + 30,
                target_peers: vec![sender.clone()],
                threshold: 1,
                collected_responses: vec![],
                context: PendingOpContext::PingRequest,
            },
        );
        fixture.signer.state.op_started_ms.insert(
            request_id.clone(),
            now_unix_millis().saturating_sub(2_000),
        );

        let response = BridgeEnvelope {
            request_id,
            sent_at: now,
            payload: BridgePayload::PingResponse(PingPayloadWire::from(PingPayload {
                version: 2,
                advertised_nonces: Vec::new(),
                held_peer_nonce_codes: Vec::new(),
                recognized_peer_nonce_codes: None,
                policy_profile: None,
                nonce_pool_generation: fixture.signer.state.nonce_pool.generation(),
            })),
        };

        fixture
            .signer
            .match_pending_response(&response, &sender)
            .expect("match ping response");

        let status = fixture
            .signer
            .peer_status()
            .into_iter()
            .find(|entry| entry.pubkey == sender)
            .expect("peer status");
        let latency_ms = status.last_response_latency_ms.expect("latency");

        assert!(latency_ms >= 2_000);
        assert!(latency_ms < 3_500);
    }

    #[test]
    fn telemetry_rings_are_bounded() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();

        for i in 0..(DeviceState::RTT_SAMPLE_WINDOW as u64 + 20) {
            fixture.signer.state.record_rtt_sample(&peer, i);
        }
        for i in 0..(DeviceState::NONCE_HISTORY_WINDOW as u64 + 20) {
            fixture
                .signer
                .state
                .record_nonce_history(&peer, i, i as u32);
        }

        assert_eq!(
            fixture.signer.state.rtt_samples_ms[&peer].len(),
            DeviceState::RTT_SAMPLE_WINDOW
        );
        assert_eq!(
            fixture.signer.state.nonce_history[&peer].len(),
            DeviceState::NONCE_HISTORY_WINDOW
        );
        // The oldest samples were evicted: newest RTT is the last pushed value.
        let (last, _) = fixture.signer.state.latency_summary(&peer);
        assert_eq!(last, Some(DeviceState::RTT_SAMPLE_WINDOW as u64 + 19));
    }

    #[test]
    fn readiness_reports_sign_and_ecdh_capability() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        fixture
            .signer
            .state
            .peer_last_seen
            .insert(peer.clone(), now_unix_secs());

        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);
        let mut peer_state = DeviceState::new(peer_share.idx, *peer_share.seckey.expose_bytes());
        let generated = peer_state
            .nonce_pool
            .generate_for_peer(
                fixture.local_share.idx,
                10,
                &peer_state.secrets.nonce_pool_secret,
            )
            .expect("generate peer nonces");
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(peer_share.idx, generated);

        let readiness = fixture.signer.readiness();
        assert!(readiness.runtime_ready);
        assert!(readiness.restore_complete);
        assert!(readiness.sign_ready);
        assert!(readiness.ecdh_ready);
        assert_eq!(readiness.threshold, 1);
        assert_eq!(readiness.signing_peer_count, 1);
        assert_eq!(readiness.ecdh_peer_count, 1);
        assert!(readiness.last_refresh_at.is_some());
        assert!(readiness.degraded_reasons.is_empty());
    }

    #[test]
    fn scoped_policy_storage_and_local_policy_profile_respect_target_peer() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        let local_bytes = decode_32(fixture.signer.local_pubkey32()).expect("local pubkey bytes");
        let wrong_target = decode_32(&fixture.signer.peers[1]).expect("wrong target bytes");

        let local_profile = fixture
            .signer
            .local_policy_profile_for(&peer)
            .expect("local policy profile");
        assert_eq!(
            local_profile.for_peer,
            decode_32(&peer).expect("peer bytes")
        );
        assert!(!local_profile.block_all);

        fixture
            .signer
            .store_remote_scoped_policy(
                &peer,
                PeerScopedPolicyProfile {
                    for_peer: wrong_target,
                    revision: 1,
                    updated: 1,
                    block_all: true,
                    request: MethodPolicy::default(),
                    respond: MethodPolicy::default(),
                },
            )
            .expect("ignore wrong target");
        assert!(fixture.signer.state.remote_scoped_policies.is_empty());

        fixture
            .signer
            .store_remote_scoped_policy(
                &peer,
                PeerScopedPolicyProfile {
                    for_peer: local_bytes,
                    revision: 2,
                    updated: 2,
                    block_all: true,
                    request: MethodPolicy::default(),
                    respond: MethodPolicy::default(),
                },
            )
            .expect("store matching target");
        assert_eq!(
            fixture
                .signer
                .state
                .remote_scoped_policies
                .get(&peer)
                .expect("stored profile")
                .revision,
            2
        );
    }

    #[test]
    fn onboard_response_includes_bootstrap_nonces_even_after_prior_ping() {
        let mut inviter = fixture(PeerSelectionStrategy::DeterministicSorted);
        let inviter_pubkey =
            decode_member_pubkey(&inviter.group, inviter.local_share.idx).expect("inviter pubkey");
        let requester_share = inviter.shares[1].clone();
        let requester_peers = inviter
            .group
            .members
            .iter()
            .filter(|member| member.idx != requester_share.idx)
            .map(|member| hex::encode(&member.pubkey[1..]))
            .collect::<Vec<_>>();
        let mut requester = SigningDevice::new(
            inviter.group.clone(),
            requester_share.clone(),
            requester_peers,
            DeviceState::new(requester_share.idx, *requester_share.seckey.expose_bytes()),
            DeviceConfig::default(),
        )
        .expect("requester signer");
        let requester_pubkey =
            decode_member_pubkey(&inviter.group, requester_share.idx).expect("requester pubkey");

        let ping = requester
            .apply(SignerInput::BeginPing {
                peer: inviter_pubkey.clone(),
            })
            .expect("begin ping")
            .outbound;
        assert_eq!(ping.len(), 1);
        let ping_effects = inviter
            .signer
            .apply(SignerInput::ProcessEvent {
                event: ping[0].clone(),
            })
            .expect("process ping");
        assert_eq!(ping_effects.outbound.len(), 1);
        let ping_served_peer = ping_effects
            .completions
            .iter()
            .find_map(|completion| match completion {
                CompletedOperation::PingServed { peer, .. } => Some(peer.clone()),
                _ => None,
            })
            .expect("expected ping-served completion");
        assert_eq!(ping_served_peer, requester_pubkey);

        let onboard = requester
            .apply(SignerInput::BeginOnboard {
                peer: inviter_pubkey,
            })
            .expect("begin onboard")
            .outbound;
        assert_eq!(onboard.len(), 1);
        let inviter_effects = inviter
            .signer
            .apply(SignerInput::ProcessEvent {
                event: onboard[0].clone(),
            })
            .expect("process onboard");
        assert_eq!(inviter_effects.outbound.len(), 1);
        // The responder records an OnboardServed completion carrying the
        // requester's x-only pubkey so hosts can mark its share onboarded.
        let served_peer = inviter_effects
            .completions
            .iter()
            .find_map(|completion| match completion {
                CompletedOperation::OnboardServed { peer, .. } => Some(peer.clone()),
                _ => None,
            })
            .expect("expected onboard-served completion");
        assert_eq!(served_peer, requester_pubkey);
        let onboard_response = inviter_effects.outbound;

        let effects = requester
            .apply(SignerInput::ProcessEvent {
                event: onboard_response[0].clone(),
            })
            .expect("apply onboard response");
        let Some(CompletedOperation::Onboard { nonces, .. }) = effects
            .completions
            .into_iter()
            .find(|completion| matches!(completion, CompletedOperation::Onboard { .. }))
        else {
            panic!("expected onboard completion");
        };
        assert!(!nonces.is_empty());
    }

    #[test]
    fn ping_resends_available_public_nonces_after_a_timed_out_attempt() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);
        let mut peer_signer = build_peer_signer(&fixture.group, &peer_share);

        let first_ping = fixture
            .signer
            .apply(SignerInput::BeginPing { peer: peer.clone() })
            .expect("begin first ping")
            .outbound;
        assert_eq!(first_ping.len(), 1);

        let expired = fixture
            .signer
            .apply(SignerInput::Expire {
                now: now_unix_secs() + fixture.signer.config.ping_timeout_secs + 1,
            })
            .expect("expire timed-out ping");
        assert_eq!(expired.failures.len(), 1);

        let second_ping = fixture
            .signer
            .apply(SignerInput::BeginPing { peer: peer.clone() })
            .expect("begin second ping")
            .outbound;
        assert_eq!(second_ping.len(), 1);

        let response = peer_signer
            .process_event(&second_ping[0])
            .expect("peer processes second ping");
        assert_eq!(response.len(), 1);

        let peer_status = peer_signer
            .peer_status()
            .into_iter()
            .find(|entry| entry.pubkey == fixture.signer.local_pubkey32())
            .expect("local peer status");
        assert!(peer_status.can_sign);
        assert!(peer_status.incoming_available > 0);
    }

    #[test]
    fn ping_stops_advertising_after_peer_reports_sufficient_inventory() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);

        let first_ping = fixture
            .signer
            .apply(SignerInput::BeginPing { peer: peer.clone() })
            .expect("begin first ping")
            .outbound;
        assert_eq!(first_ping.len(), 1);

        let decoded =
            decode_envelope_for_local(&peer_share, fixture.signer.local_pubkey32(), &first_ping[0]);
        let BridgePayload::PingRequest(wire) = decoded.payload else {
            panic!("expected ping request");
        };
        let payload = PingPayload::try_from(wire).expect("decode ping payload");
        assert!(!payload.advertised_nonces.is_empty());
        assert!(payload.held_peer_nonce_codes.is_empty());

        let mut peer_signer = build_peer_signer(&fixture.group, &peer_share);
        let response = peer_signer
            .process_event(&first_ping[0])
            .expect("peer processes first ping");
        assert_eq!(response.len(), 1);
        fixture
            .signer
            .process_event(&response[0])
            .expect("process ping response");

        let second_ping = fixture
            .signer
            .apply(SignerInput::BeginPing { peer: peer.clone() })
            .expect("begin second ping")
            .outbound;
        assert_eq!(second_ping.len(), 1);

        let decoded = decode_envelope_for_local(
            &peer_share,
            fixture.signer.local_pubkey32(),
            &second_ping[0],
        );
        let BridgePayload::PingRequest(wire) = decoded.payload else {
            panic!("expected ping request");
        };
        let payload = PingPayload::try_from(wire).expect("decode ping payload");
        assert!(payload.advertised_nonces.is_empty());
    }

    #[test]
    fn ping_refills_after_peer_observed_inventory_drops_below_threshold() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);
        let peer_idx = decode_member_index(&fixture.group.members, &peer).expect("peer idx");

        let first_ping = fixture
            .signer
            .apply(SignerInput::BeginPing { peer: peer.clone() })
            .expect("begin first ping")
            .outbound;
        assert_eq!(first_ping.len(), 1);

        let mut peer_signer = build_peer_signer(&fixture.group, &peer_share);
        let response = peer_signer
            .process_event(&first_ping[0])
            .expect("peer processes first ping");
        assert_eq!(response.len(), 1);
        fixture
            .signer
            .process_event(&response[0])
            .expect("process ping response");

        let cfg = fixture.signer.state.nonce_pool.config().clone();
        let remaining_target = cfg.min_threshold.saturating_sub(1);
        let outgoing_codes = fixture
            .signer
            .state
            .nonce_pool
            .outgoing_public_nonce_codes(peer_idx);
        let spend_count = outgoing_codes.len().saturating_sub(remaining_target);
        fixture
            .signer
            .state
            .nonce_pool
            .take_outgoing_signing_nonces_many(peer_idx, &outgoing_codes[..spend_count])
            .expect("consume local outgoing nonces");

        let refill_ping = fixture
            .signer
            .apply(SignerInput::BeginPing { peer: peer.clone() })
            .expect("begin refill ping")
            .outbound;
        assert_eq!(refill_ping.len(), 1);

        let decoded = decode_envelope_for_local(
            &peer_share,
            fixture.signer.local_pubkey32(),
            &refill_ping[0],
        );
        let BridgePayload::PingRequest(wire) = decoded.payload else {
            panic!("expected ping request");
        };
        let payload = PingPayload::try_from(wire).expect("decode ping payload");
        assert_eq!(payload.advertised_nonces.len(), spend_count);
    }

    #[test]
    fn invalid_locked_peer_response_fails_round_terminally() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let locked_peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &locked_peer);
        let local_pubkey =
            decode_member_pubkey(&fixture.group, fixture.local_share.idx).expect("local pubkey");
        let now = now_unix_secs();
        let request_id = "opaque-request-id".to_string();

        fixture.signer.state.pending_operations.insert(
            request_id.clone(),
            PendingOperation {
                op_type: PendingOpType::Ping,
                request_id: request_id.clone(),
                started_at: now,
                timeout_at: now + 30,
                target_peers: vec![locked_peer.clone()],
                threshold: 1,
                collected_responses: Vec::new(),
                context: PendingOpContext::PingRequest,
            },
        );

        let inbound = BridgeEnvelope {
            request_id: request_id.clone(),
            sent_at: now,
            payload: BridgePayload::OnboardRequest(OnboardRequestWire {
                version: 1,
                nonces: vec![DerivedPublicNonceWire {
                    binder_pn: hex::encode([1u8; 33]),
                    hidden_pn: hex::encode([2u8; 33]),
                    code: hex::encode([3u8; 32]),
                }],
            }),
        };
        let plaintext = encode_bridge_envelope(&inbound).expect("encode envelope");
        let content = super::crypto::encrypt_content_for_peer_with_nonce(
            *peer_share.seckey.expose_bytes(),
            &local_pubkey,
            &plaintext,
            [9u8; 32],
        )
        .expect("encrypt");
        let event = build_signed_event(
            *peer_share.seckey.expose_bytes(),
            fixture.signer.config.event_kind,
            vec![vec!["p".to_string(), local_pubkey.clone()]],
            content,
        )
        .expect("build event");

        let outbound = fixture.signer.process_event(&event).expect("process event");
        assert!(outbound.is_empty());
        assert!(
            !fixture
                .signer
                .state
                .pending_operations
                .contains_key(&request_id)
        );

        let failures = fixture.signer.take_failures();
        assert_eq!(failures.len(), 1);
        let failure = &failures[0];
        assert_eq!(failure.request_id, request_id);
        assert!(matches!(failure.op_type, PendingOpType::Ping));
        assert_eq!(
            failure.code,
            OperationFailureCode::InvalidLockedPeerResponse
        );
        assert_eq!(failure.failed_peer, Some(locked_peer));
    }

    #[test]
    fn inbound_sign_request_failure_reports_sign_op_type() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let locked_peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &locked_peer);
        let mut peer_signer = build_peer_signer(&fixture.group, &peer_share);

        let advertised = peer_signer
            .state
            .nonce_pool
            .generate_for_peer(
                fixture.local_share.idx,
                10,
                &peer_signer.state.secrets.nonce_pool_secret,
            )
            .expect("generate peer nonces");
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(peer_share.idx, advertised.clone());

        let request = fixture
            .signer
            .initiate_sign([0x55; 32])
            .expect("initiate sign");
        assert_eq!(request.len(), 1);
        let envelope =
            decode_envelope_for_local(&peer_share, fixture.signer.local_pubkey32(), &request[0]);
        let BridgePayload::SignRequest(wire) = envelope.payload.clone() else {
            panic!("expected sign request");
        };
        let session = SignSessionPackage::try_from(wire).expect("decode sign request");
        let peer_nonce_set = session
            .nonces
            .as_ref()
            .and_then(|sets| sets.iter().find(|entry| entry.idx == peer_share.idx))
            .expect("peer nonce set");
        let mut codes_by_hash: Vec<Bytes32> = vec![[0u8; 32]; session.hashes.len()];
        for entry in &peer_nonce_set.entries {
            codes_by_hash[entry.hash_index as usize] = entry.code;
        }

        peer_signer
            .state
            .nonce_pool
            .take_outgoing_signing_nonces_many(fixture.local_share.idx, &codes_by_hash)
            .expect("spend referenced peer nonce");

        let outbound = peer_signer
            .process_event(&request[0])
            .expect("inbound failure is surfaced through failures");
        assert!(outbound.is_empty());

        let failures = peer_signer.take_failures();
        assert_eq!(failures.len(), 1);
        let failure = &failures[0];
        assert_eq!(failure.request_id, envelope.request_id);
        assert!(matches!(failure.op_type, PendingOpType::Sign));
        assert_eq!(failure.code, OperationFailureCode::PeerRejected);
        assert!(
            failure
                .message
                .to_ascii_lowercase()
                .contains("nonce unavailable")
        );
        assert_eq!(
            failure.failed_peer.as_deref(),
            Some(fixture.signer.local_pubkey32())
        );
    }

    #[test]
    fn inbound_onboard_request_rejects_unsupported_version() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let sender = fixture.signer.peers[0].clone();

        let unsupported_version = BridgeEnvelope {
            request_id: "req-onboard-unsupported-version".to_string(),
            sent_at: now_unix_secs(),
            payload: BridgePayload::OnboardRequest(OnboardRequestWire {
                version: 2,
                nonces: vec![DerivedPublicNonceWire {
                    binder_pn: hex::encode([4u8; 33]),
                    hidden_pn: hex::encode([5u8; 33]),
                    code: hex::encode([6u8; 32]),
                }],
            }),
        };
        let err = fixture
            .signer
            .handle_inbound_request(unsupported_version, sender, false)
            .expect_err("unsupported version must fail");
        assert!(matches!(err, SignerError::InvalidRequest(_)));
        assert_eq!(fixture.signer.onboarding_statuses().len(), 1);
        let status = &fixture.signer.onboarding_statuses()[0];
        assert_eq!(status.pubkey, fixture.signer.peers[0]);
        assert_eq!(status.stage, OnboardingStatusStage::Failed);
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|message| message.contains("unsupported onboard request version"))
        );
    }

    #[test]
    fn inbound_onboard_request_updates_runtime_onboarding_status() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let sender = fixture.signer.peers[0].clone();

        let request = BridgeEnvelope {
            request_id: "req-onboard-status".to_string(),
            sent_at: now_unix_secs(),
            payload: BridgePayload::OnboardRequest(OnboardRequestWire {
                version: 1,
                nonces: vec![DerivedPublicNonceWire {
                    binder_pn: hex::encode([7u8; 33]),
                    hidden_pn: hex::encode([8u8; 33]),
                    code: hex::encode([9u8; 32]),
                }],
            }),
        };

        let outbound = fixture
            .signer
            .handle_inbound_request(request, sender.clone(), false)
            .expect("valid onboard request should produce response");
        assert_eq!(outbound.len(), 1);

        let statuses = fixture.signer.onboarding_statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].pubkey, sender);
        assert_eq!(statuses[0].stage, OnboardingStatusStage::HandshakeCompleted);
        assert!(statuses[0].error.is_none());

        let runtime_status = fixture.signer.runtime_status();
        assert_eq!(runtime_status.onboarding_statuses.len(), 1);
        assert_eq!(
            runtime_status.onboarding_statuses[0].stage,
            OnboardingStatusStage::HandshakeCompleted
        );
    }

    #[test]
    fn handle_inbound_response_without_pending_request_rejects_non_ping_payloads() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let sender = fixture.signer.peers[0].clone();
        let response = BridgeEnvelope {
            request_id: "req-orphan-response".to_string(),
            sent_at: now_unix_secs(),
            payload: BridgePayload::OnboardResponse(OnboardResponseWire::from(OnboardResponse {
                group: fixture.group.clone(),
                nonces: vec![],
            })),
        };
        let err = fixture
            .signer
            .handle_inbound_request(response, sender, false)
            .expect_err("orphan response must fail");
        assert!(matches!(err, SignerError::InvalidRequest(_)));
    }

    // ---- Interactive approval queue (the `Ask` disposition) ----

    fn ping_request_envelope(request_id: &str) -> BridgeEnvelope {
        BridgeEnvelope {
            request_id: request_id.to_string(),
            sent_at: now_unix_secs(),
            payload: BridgePayload::PingRequest(PingPayloadWire::from(PingPayload {
                version: 2,
                advertised_nonces: Vec::new(),
                held_peer_nonce_codes: Vec::new(),
                recognized_peer_nonce_codes: None,
                policy_profile: None,
                nonce_pool_generation: bifrost_core::nonce::UNKNOWN_POOL_GENERATION,
            })),
        }
    }

    fn set_respond_ping_ask(signer: &mut SigningDevice, peer: &str) {
        let mut override_policy = PeerPolicyOverride::default();
        override_policy.respond.ping = PolicyOverrideValue::Ask;
        signer
            .set_peer_policy_override(peer, override_policy)
            .expect("set ask override");
    }

    fn local_sender_pubkey(fixture: &Fixture) -> String {
        let member = fixture
            .group
            .members
            .iter()
            .find(|member| member.idx == fixture.local_share.idx)
            .expect("local member");
        hex::encode(&member.pubkey[1..])
    }

    #[test]
    fn ask_disposition_parks_inbound_request_without_responding() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let (peer, _) = first_peer(&fixture);
        set_respond_ping_ask(&mut fixture.signer, &peer);

        let outbound = fixture
            .signer
            .handle_inbound_request(ping_request_envelope("req-ask-1"), peer.clone(), false)
            .expect("ask parks without error");
        assert!(outbound.is_empty(), "parked request must not respond yet");

        let summary = fixture.signer.runtime_status();
        assert_eq!(summary.pending_approvals.len(), 1);
        let parked = &summary.pending_approvals[0];
        assert_eq!(parked.request_id, "req-ask-1");
        assert_eq!(parked.peer, peer);
        assert_eq!(parked.method, "ping");
        // The `Ask` peer is still capability-allowed for readiness purposes.
        assert!(fixture.signer.inbound_allowed(&peer, "ping"));
    }

    #[test]
    fn forced_replay_bypasses_ask_and_responds() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let (peer, _) = first_peer(&fixture);
        set_respond_ping_ask(&mut fixture.signer, &peer);

        // `forced` (resuming an approved request) must not re-park.
        let outbound = fixture
            .signer
            .handle_inbound_request(ping_request_envelope("req-ask-forced"), peer.clone(), true)
            .expect("forced replay responds");
        assert_eq!(outbound.len(), 1);
        assert!(fixture.signer.state.pending_approvals.is_empty());
    }

    #[test]
    fn resolve_approval_approved_emits_response_and_clears_queue() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let (peer, peer_idx) = first_peer(&fixture);
        set_respond_ping_ask(&mut fixture.signer, &peer);
        fixture
            .signer
            .handle_inbound_request(ping_request_envelope("req-ask-2"), peer.clone(), false)
            .expect("park");

        let outbound = fixture
            .signer
            .resolve_approval("req-ask-2", true)
            .expect("approve");
        assert_eq!(outbound.len(), 1, "approval emits the deferred response");
        assert!(fixture.signer.state.pending_approvals.is_empty());

        // The emitted event decrypts to a real ping response for the requester.
        let peer_share = fixture
            .shares
            .iter()
            .find(|share| share.idx == peer_idx)
            .cloned()
            .expect("peer share");
        let decoded =
            decode_envelope_for_local(&peer_share, &local_sender_pubkey(&fixture), &outbound[0]);
        assert!(matches!(decoded.payload, BridgePayload::PingResponse(_)));
    }

    #[test]
    fn resolve_approval_denied_emits_operator_denied_error() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let (peer, peer_idx) = first_peer(&fixture);
        set_respond_ping_ask(&mut fixture.signer, &peer);
        fixture
            .signer
            .handle_inbound_request(ping_request_envelope("req-ask-3"), peer.clone(), false)
            .expect("park");

        let outbound = fixture
            .signer
            .resolve_approval("req-ask-3", false)
            .expect("deny");
        assert_eq!(outbound.len(), 1);
        assert!(fixture.signer.state.pending_approvals.is_empty());

        let peer_share = fixture
            .shares
            .iter()
            .find(|share| share.idx == peer_idx)
            .cloned()
            .expect("peer share");
        let decoded =
            decode_envelope_for_local(&peer_share, &local_sender_pubkey(&fixture), &outbound[0]);
        match decoded.payload {
            BridgePayload::Error(err) => assert_eq!(err.code, "operator_denied"),
            other => panic!("expected operator_denied error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_approval_unknown_id_is_noop() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let outbound = fixture
            .signer
            .resolve_approval("no-such-request", true)
            .expect("unknown id is a no-op");
        assert!(outbound.is_empty());
    }

    #[test]
    fn expire_stale_drops_parked_approvals_silently() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let (peer, _) = first_peer(&fixture);
        set_respond_ping_ask(&mut fixture.signer, &peer);
        fixture
            .signer
            .handle_inbound_request(ping_request_envelope("req-ask-4"), peer.clone(), false)
            .expect("park");
        assert_eq!(fixture.signer.state.pending_approvals.len(), 1);

        let expires_at = fixture.signer.state.pending_approvals["req-ask-4"].expires_at;
        let failures = fixture.signer.expire_stale(expires_at + 1);
        assert!(
            failures.is_empty(),
            "dropping a parked approval emits no failure"
        );
        assert!(fixture.signer.state.pending_approvals.is_empty());
    }

    #[test]
    fn runtime_status_json_carries_pending_approvals_field() {
        let fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let json = serde_json::to_string(&fixture.signer.runtime_status()).expect("serialize");
        assert!(
            json.contains("\"pending_approvals\""),
            "runtime_status JSON must expose pending_approvals"
        );
    }

    #[test]
    fn last_sign_failure_retention_tracks_sign_failures_only_and_clears_on_success() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        assert!(fixture.signer.runtime_status().last_sign_failure.is_none());

        // A non-sign failure must not set the sign-failure retention.
        fixture.signer.note_last_sign_failure(
            &[],
            &[OperationFailure {
                request_id: "ping-1".to_string(),
                op_type: PendingOpType::Ping,
                code: OperationFailureCode::Timeout,
                message: "ping timeout".to_string(),
                failed_peer: None,
            }],
        );
        assert!(fixture.signer.runtime_status().last_sign_failure.is_none());

        // A sign failure sets it (newest in the batch wins).
        fixture.signer.note_last_sign_failure(
            &[],
            &[
                OperationFailure {
                    request_id: "sign-old".to_string(),
                    op_type: PendingOpType::Sign,
                    code: OperationFailureCode::Timeout,
                    message: "old".to_string(),
                    failed_peer: None,
                },
                OperationFailure {
                    request_id: "sign-new".to_string(),
                    op_type: PendingOpType::Sign,
                    code: OperationFailureCode::PeerRejected,
                    message: "peer rejected".to_string(),
                    failed_peer: Some("peerhex".to_string()),
                },
            ],
        );
        let retained = fixture
            .signer
            .runtime_status()
            .last_sign_failure
            .expect("sign failure retained");
        assert_eq!(retained.request_id, "sign-new");
        assert_eq!(retained.op_type, PendingOpType::Sign);
        assert_eq!(retained.code, OperationFailureCode::PeerRejected);
        assert_eq!(retained.failed_peer.as_deref(), Some("peerhex"));

        // A successful sign clears it.
        fixture.signer.note_last_sign_failure(
            &[CompletedOperation::Sign {
                request_id: "sign-ok".to_string(),
                signatures: vec![],
            }],
            &[],
        );
        assert!(fixture.signer.runtime_status().last_sign_failure.is_none());
    }

    #[test]
    fn runtime_status_last_sign_failure_round_trips_and_omits_when_absent() {
        // Absent → omitted from JSON (skip_serializing_if); present → wire
        // round-trip preserves the serializable summary. A wire test, not a
        // handler test: a serde-shape regression on the new field would slip a
        // handler-only assertion.
        let fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let json = serde_json::to_string(&fixture.signer.runtime_status()).expect("serialize");
        assert!(
            !json.contains("last_sign_failure"),
            "absent failure must be omitted from runtime_status JSON"
        );

        let summary = OperationFailureSummary {
            request_id: "req-sign".to_string(),
            op_type: PendingOpType::Sign,
            code: OperationFailureCode::PeerRejected,
            message: "peer rejected".to_string(),
            failed_peer: Some("peerhex".to_string()),
            failed_at: 1_700_000_123,
        };
        let encoded = serde_json::to_string(&summary).expect("serialize summary");
        assert!(encoded.contains("\"peer_rejected\""), "code is snake_case");
        let decoded: OperationFailureSummary =
            serde_json::from_str(&encoded).expect("deserialize summary");
        assert_eq!(decoded, summary);
    }

    #[test]
    fn inbound_request_failure_reports_true_op_type_not_ping() {
        // Regression: a failed inbound request must surface under its real op
        // type. Previously process_event propagated the error to the router,
        // which blind-labeled every inbound failure as a ping. Drive a request
        // the local signer rejects (onboard, unsupported version) end-to-end
        // through process_event and assert the recorded failure is onboard-typed.
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let (peer_pubkey, _) = first_peer(&fixture);
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer_pubkey);
        let peer = build_peer_signer(&fixture.group, &peer_share);

        let envelope = BridgeEnvelope {
            request_id: "req-onboard-bad-version".to_string(),
            sent_at: now_unix_secs(),
            payload: BridgePayload::OnboardRequest(OnboardRequestWire {
                version: 2,
                nonces: vec![DerivedPublicNonceWire {
                    binder_pn: hex::encode([4u8; 33]),
                    hidden_pn: hex::encode([5u8; 33]),
                    code: hex::encode([6u8; 32]),
                }],
            }),
        };
        let event = peer
            .encrypt_for_peer(fixture.signer.local_pubkey32(), &envelope)
            .expect("encrypt onboard request to local");

        let effects = fixture
            .signer
            .apply(SignerInput::ProcessEvent { event })
            .expect("process_event records the failure instead of erroring out");

        assert_eq!(
            effects.failures.len(),
            1,
            "expected exactly one typed failure"
        );
        assert!(
            matches!(effects.failures[0].op_type, PendingOpType::Onboard),
            "inbound onboard failure must be reported as onboard, not ping; got {:?}",
            effects.failures[0].op_type
        );
        assert!(effects.outbound.is_empty());
    }

    #[test]
    fn validate_ecdh_request_rejects_unsorted_duplicate_missing_local_and_empty_targets() {
        let fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let sender = fixture.signer.peers[0].clone();
        let sender_idx = decode_member_index(&fixture.group.members, &sender).expect("sender idx");

        let empty_targets = EcdhPackage {
            idx: sender_idx,
            members: vec![fixture.local_share.idx, sender_idx],
            entries: vec![],
        };
        assert!(matches!(
            fixture
                .signer
                .validate_ecdh_request(&empty_targets, sender_idx),
            Err(SignerError::InvalidRequest(_))
        ));

        let unsorted = EcdhPackage {
            idx: sender_idx,
            members: vec![sender_idx, fixture.local_share.idx],
            entries: vec![bifrost_core::types::EcdhEntry {
                ecdh_pk: [3u8; 32],
                keyshare: [4u8; 33],
            }],
        };
        assert!(matches!(
            fixture.signer.validate_ecdh_request(&unsorted, sender_idx),
            Err(SignerError::InvalidRequest(_))
        ));

        let duplicate_members = EcdhPackage {
            idx: sender_idx,
            members: vec![fixture.local_share.idx, sender_idx, sender_idx],
            entries: vec![bifrost_core::types::EcdhEntry {
                ecdh_pk: [6u8; 32],
                keyshare: [7u8; 33],
            }],
        };
        assert!(matches!(
            fixture
                .signer
                .validate_ecdh_request(&duplicate_members, sender_idx),
            Err(SignerError::InvalidRequest(_))
        ));

        let missing_local = EcdhPackage {
            idx: sender_idx,
            members: vec![sender_idx, sender_idx + 1],
            entries: vec![bifrost_core::types::EcdhEntry {
                ecdh_pk: [9u8; 32],
                keyshare: [10u8; 33],
            }],
        };
        assert!(matches!(
            fixture
                .signer
                .validate_ecdh_request(&missing_local, sender_idx),
            Err(SignerError::InvalidRequest(_))
        ));
    }

    #[test]
    fn match_pending_response_rejects_unexpected_payload_and_non_target_sender() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let request_id = "req-pending".to_string();
        let sender = fixture.signer.peers[0].clone();
        let other = fixture.signer.peers[1].clone();
        let now = now_unix_secs();

        fixture.signer.state.pending_operations.insert(
            request_id.clone(),
            PendingOperation {
                op_type: PendingOpType::Ping,
                request_id: request_id.clone(),
                started_at: now,
                timeout_at: now + 30,
                target_peers: vec![sender.clone()],
                threshold: 1,
                collected_responses: vec![],
                context: PendingOpContext::PingRequest,
            },
        );

        let wrong_sender = BridgeEnvelope {
            request_id: request_id.clone(),
            sent_at: now,
            payload: BridgePayload::PingResponse(PingPayloadWire::from(PingPayload {
                version: 2,
                advertised_nonces: Vec::new(),
                held_peer_nonce_codes: Vec::new(),
                recognized_peer_nonce_codes: None,
                policy_profile: None,
                nonce_pool_generation: bifrost_core::nonce::UNKNOWN_POOL_GENERATION,
            })),
        };
        let err = fixture
            .signer
            .match_pending_response(&wrong_sender, &other)
            .expect_err("non-target sender must fail");
        assert!(matches!(err, SignerError::InvalidSenderBinding(_)));

        let wrong_payload = BridgeEnvelope {
            request_id,
            sent_at: now,
            payload: BridgePayload::OnboardResponse(OnboardResponseWire::from(OnboardResponse {
                group: fixture.group,
                nonces: vec![],
            })),
        };
        let err = fixture
            .signer
            .match_pending_response(&wrong_payload, &sender)
            .expect_err("unexpected payload must fail");
        assert!(matches!(err, SignerError::InvalidRequest(_)));
    }

    #[test]
    fn match_pending_response_rejects_peer_error_and_duplicate_sign_response() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);

        let mut peer_state = DeviceState::new(peer_share.idx, *peer_share.seckey.expose_bytes());
        let generated = peer_state
            .nonce_pool
            .generate_for_peer(
                fixture.local_share.idx,
                10,
                &peer_state.secrets.nonce_pool_secret,
            )
            .expect("generate peer nonces");
        fixture
            .signer
            .state
            .nonce_pool
            .store_incoming(peer_share.idx, generated);

        let outbound = fixture
            .signer
            .initiate_sign([0x44; 32])
            .expect("initiate sign");
        assert_eq!(outbound.len(), 1);

        let request_id = fixture
            .signer
            .latest_request_id()
            .expect("latest request id");
        let pending = fixture
            .signer
            .state
            .pending_operations
            .get_mut(&request_id)
            .expect("pending sign");
        pending.threshold = 3;
        let PendingOpContext::SignSession { session, .. } = &pending.context else {
            panic!("expected sign session context");
        };
        let session = session.clone();

        let our_nonce_set = session
            .nonces
            .as_ref()
            .and_then(|sets| sets.iter().find(|entry| entry.idx == peer_share.idx))
            .expect("peer nonce set");
        let mut codes_by_hash: Vec<Bytes32> = vec![[0u8; 32]; session.hashes.len()];
        for entry in &our_nonce_set.entries {
            codes_by_hash[entry.hash_index as usize] = entry.code;
        }
        let signing_nonces = peer_state
            .nonce_pool
            .take_outgoing_signing_nonces_many(fixture.local_share.idx, &codes_by_hash)
            .expect("peer signing nonces");
        let partial =
            sign_create_partial(&fixture.group, &session, &peer_share, &signing_nonces, None)
                .expect("create peer partial");
        let response = BridgeEnvelope {
            request_id: request_id.clone(),
            sent_at: now_unix_secs(),
            payload: BridgePayload::SignResponse(PartialSigPackageWire::from(partial)),
        };

        let matched = fixture
            .signer
            .match_pending_response(&response, &peer)
            .expect("first sign response");
        assert!(matched.is_empty());

        let err = fixture
            .signer
            .match_pending_response(&response, &peer)
            .expect_err("duplicate sign response must fail");
        assert!(
            matches!(err, SignerError::InvalidRequest(message) if message == "duplicate sign response")
        );

        let error_response = BridgeEnvelope {
            request_id,
            sent_at: now_unix_secs(),
            payload: BridgePayload::Error(bifrost_codec::wire::PeerErrorWire {
                code: "peer_rejected".to_string(),
                message: "denied".to_string(),
            }),
        };
        let err = fixture
            .signer
            .match_pending_response(&error_response, &peer)
            .expect_err("peer error must fail");
        assert!(
            matches!(err, SignerError::InvalidRequest(message) if message == "peer rejected request: peer_rejected:denied")
        );
    }

    #[test]
    fn match_pending_response_rejects_duplicate_ecdh_response() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let target = decode_32(&fixture.signer.peers[1]).expect("valid target pubkey");

        let outbound = fixture.signer.initiate_ecdh(target).expect("initiate ecdh");
        assert_eq!(outbound.len(), 1);

        let request_id = fixture
            .signer
            .latest_request_id()
            .expect("latest request id");
        let pending = fixture
            .signer
            .state
            .pending_operations
            .get_mut(&request_id)
            .expect("pending ecdh");
        pending.threshold = 2;
        let peer = pending.target_peers[0].clone();

        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);

        let mut peer_signer = build_peer_signer(&fixture.group, &peer_share);
        let responses = peer_signer
            .process_event(&outbound[0])
            .expect("peer processes ecdh");
        assert_eq!(responses.len(), 1);
        let response = decode_envelope_for_local(&fixture.local_share, &peer, &responses[0]);

        let matched = fixture
            .signer
            .match_pending_response(&response, &peer)
            .expect("first ecdh response");
        assert!(matched.is_empty());

        let err = fixture
            .signer
            .match_pending_response(&response, &peer)
            .expect_err("duplicate ecdh response must fail");
        assert!(
            matches!(err, SignerError::InvalidRequest(message) if message == "duplicate ecdh response")
        );
    }

    #[test]
    fn recipient_tag_validation_requires_single_matching_p_tag() {
        let fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);
        let local = fixture.signer.local_pubkey32().to_string();

        let event_ok = build_signed_event(
            *peer_share.seckey.expose_bytes(),
            fixture.signer.config.event_kind,
            vec![vec!["p".to_string(), local.clone()]],
            "payload".to_string(),
        )
        .expect("event ok");
        assert!(fixture.signer.has_exact_local_recipient_tag(&event_ok));

        let event_missing = build_signed_event(
            *peer_share.seckey.expose_bytes(),
            fixture.signer.config.event_kind,
            vec![],
            "payload".to_string(),
        )
        .expect("event missing");
        assert!(!fixture.signer.has_exact_local_recipient_tag(&event_missing));

        let event_multi = build_signed_event(
            *peer_share.seckey.expose_bytes(),
            fixture.signer.config.event_kind,
            vec![
                vec!["p".to_string(), local.clone()],
                vec!["p".to_string(), peer.clone()],
            ],
            "payload".to_string(),
        )
        .expect("event multi");
        assert!(!fixture.signer.has_exact_local_recipient_tag(&event_multi));

        let event_wrong = build_signed_event(
            *peer_share.seckey.expose_bytes(),
            fixture.signer.config.event_kind,
            vec![vec!["p".to_string(), peer]],
            "payload".to_string(),
        )
        .expect("event wrong");
        assert!(!fixture.signer.has_exact_local_recipient_tag(&event_wrong));
    }

    #[test]
    fn wipe_state_clears_runtime_state_and_marks_persistence() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        fixture
            .signer
            .state
            .peer_last_seen
            .insert(peer.clone(), 123);
        fixture.signer.state.pending_operations.insert(
            "req-1".to_string(),
            PendingOperation {
                op_type: PendingOpType::Ping,
                request_id: "req-1".to_string(),
                started_at: 1,
                timeout_at: 2,
                target_peers: vec![peer],
                threshold: 1,
                collected_responses: vec![],
                context: PendingOpContext::PingRequest,
            },
        );

        fixture.signer.wipe_state();

        assert!(fixture.signer.state.pending_operations.is_empty());
        assert!(fixture.signer.state.peer_last_seen.is_empty());
        assert_eq!(fixture.signer.state.request_seq, 1);
        assert!(matches!(
            fixture.signer.take_runtime_persistence_hint(),
            PersistenceHint::Immediate
        ));
    }

    #[test]
    fn subscription_filters_include_sorted_authors_and_local_recipient_tag() {
        let fixture = fixture(PeerSelectionStrategy::DeterministicSorted);

        let filters = fixture
            .signer
            .subscription_filters()
            .expect("subscription filters");
        assert_eq!(filters.len(), 1);

        let filter_json = serde_json::to_value(&filters[0]).expect("serialize filter");
        let authors = filter_json["authors"].as_array().expect("authors");
        let author_values = authors
            .iter()
            .map(|value| value.as_str().expect("author string").to_string())
            .collect::<Vec<_>>();
        let mut sorted = author_values.clone();
        sorted.sort_unstable();
        assert_eq!(author_values, sorted);

        let recipient_tag = filter_json["#p"].as_array().expect("recipient tags");
        assert_eq!(recipient_tag.len(), 1);
        assert_eq!(
            recipient_tag[0].as_str().expect("recipient string"),
            fixture.signer.local_pubkey32()
        );
    }

    #[test]
    fn apply_uses_cached_signatures_and_ecdh_and_reports_failures() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let now = now_unix_secs();
        let sign_message = [0xAA; 32];
        let sign_key = hex::encode(sign_message);
        fixture.signer.state.sig_cache.insert(
            sign_key.clone(),
            SigCacheEntry {
                key_hex: sign_key.clone(),
                signatures_hex: vec![hex::encode([0xBB; 64])],
                stored_at: now,
                last_accessed_at: now,
            },
        );
        fixture.signer.state.sig_cache_order.push_back(sign_key);

        let sign_effects = fixture
            .signer
            .apply(SignerInput::BeginSign {
                message: sign_message,
            })
            .expect("cached sign apply");
        assert!(sign_effects.outbound.is_empty());
        assert_eq!(sign_effects.completions.len(), 1);
        assert!(matches!(
            &sign_effects.completions[0],
            CompletedOperation::Sign { signatures, .. } if signatures.len() == 1
        ));

        let ecdh_target = [0xCC; 32];
        let ecdh_key = hex::encode(ecdh_target);
        fixture.signer.state.secrets.ecdh_cache.insert(
            ecdh_key.clone(),
            EcdhCacheEntryLive {
                key_hex: ecdh_key.clone(),
                shared_secret: EcdhSharedSecret::new([0xDD; 32]),
                stored_at: now,
                last_accessed_at: now,
            },
        );
        fixture
            .signer
            .state
            .secrets
            .ecdh_cache_order
            .push_back(ecdh_key);

        let ecdh_effects = fixture
            .signer
            .apply(SignerInput::BeginEcdh {
                pubkey: ecdh_target,
            })
            .expect("cached ecdh apply");
        assert!(ecdh_effects.outbound.is_empty());
        assert_eq!(ecdh_effects.completions.len(), 1);
        assert!(matches!(
            &ecdh_effects.completions[0],
            CompletedOperation::Ecdh { shared_secret, .. } if *shared_secret == [0xDD; 32]
        ));

        let fail_request_id = "req-fail".to_string();
        fixture.signer.state.pending_operations.insert(
            fail_request_id.clone(),
            PendingOperation {
                op_type: PendingOpType::Ping,
                request_id: fail_request_id.clone(),
                started_at: now,
                timeout_at: now + 30,
                target_peers: vec![fixture.signer.peers[0].clone()],
                threshold: 1,
                collected_responses: vec![],
                context: PendingOpContext::PingRequest,
            },
        );
        let fail_effects = fixture
            .signer
            .apply(SignerInput::FailRequest {
                request_id: fail_request_id.clone(),
                code: OperationFailureCode::PeerRejected,
                message: "rejected".to_string(),
            })
            .expect("fail request apply");
        assert!(fail_effects.outbound.is_empty());
        assert_eq!(fail_effects.failures.len(), 1);
        assert_eq!(fail_effects.failures[0].request_id, fail_request_id);
        assert_eq!(fail_effects.persistence_hint, PersistenceHint::Batch);

        let expire_request_id = "req-expire".to_string();
        fixture.signer.state.pending_operations.insert(
            expire_request_id.clone(),
            PendingOperation {
                op_type: PendingOpType::Onboard,
                request_id: expire_request_id.clone(),
                started_at: now - 10,
                timeout_at: now - 1,
                target_peers: vec![fixture.signer.peers[0].clone()],
                threshold: 1,
                collected_responses: vec![],
                context: PendingOpContext::OnboardRequest,
            },
        );
        let expire_effects = fixture
            .signer
            .apply(SignerInput::Expire { now })
            .expect("expire apply");
        assert_eq!(expire_effects.failures.len(), 1);
        assert_eq!(expire_effects.failures[0].request_id, expire_request_id);
        assert_eq!(expire_effects.persistence_hint, PersistenceHint::Batch);
    }

    #[test]
    fn record_request_validates_sent_at_time_replay_and_cache_limit() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let sender = fixture.signer.peers[0].clone();
        let now = now_unix_secs();
        fixture.signer.config.request_cache_limit = 2;
        fixture.signer.config.request_ttl_secs = 60;
        fixture.signer.config.max_future_skew_secs = 5;

        let err = fixture
            .signer
            .record_request(&sender, "", now, now)
            .expect_err("empty request id must fail");
        assert!(matches!(err, SignerError::InvalidRequest(_)));

        let future = "future-request".to_string();
        let err = fixture
            .signer
            .record_request(&sender, &future, now + 10, now)
            .expect_err("future request must fail");
        assert!(matches!(err, SignerError::InvalidRequest(_)));

        let stale = "stale-request".to_string();
        let err = fixture
            .signer
            .record_request(&sender, &stale, now - 100, now)
            .expect_err("stale request must fail");
        assert!(matches!(err, SignerError::InvalidRequest(_)));

        let req1 = "req-1".to_string();
        let req2 = "req-2".to_string();
        let req3 = "req-3".to_string();
        fixture
            .signer
            .record_request(&sender, &req1, now, now)
            .expect("record req1");
        let err = fixture
            .signer
            .record_request(&sender, &req1, now, now)
            .expect_err("duplicate request must fail");
        assert!(matches!(err, SignerError::ReplayDetected(_)));

        fixture
            .signer
            .record_request(&sender, &req2, now + 1, now + 1)
            .expect("record req2");
        fixture
            .signer
            .record_request(&sender, &req3, now + 2, now + 2)
            .expect("record req3");
        assert_eq!(fixture.signer.state.replay_cache.len(), 2);
        assert!(
            !fixture
                .signer
                .state
                .replay_cache
                .contains_key(&format!("{sender}:{req1}"))
        );
    }

    #[test]
    fn caches_evict_lru_entries_when_capacity_is_exceeded() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        fixture.signer.config.ecdh_cache_capacity = 1;
        fixture.signer.config.sig_cache_capacity = 1;
        let now = now_unix_secs();

        fixture.signer.ecdh_cache_put([1u8; 32], [2u8; 32], now);
        fixture.signer.ecdh_cache_put([3u8; 32], [4u8; 32], now + 1);
        assert_eq!(fixture.signer.state.secrets.ecdh_cache.len(), 1);
        assert!(
            fixture
                .signer
                .state
                .secrets
                .ecdh_cache
                .contains_key(&hex::encode([3u8; 32]))
        );

        fixture
            .signer
            .sig_cache_put([5u8; 32], vec![[6u8; 64]], now);
        fixture
            .signer
            .sig_cache_put([7u8; 32], vec![[8u8; 64]], now + 1);
        assert_eq!(fixture.signer.state.sig_cache.len(), 1);
        assert!(
            fixture
                .signer
                .state
                .sig_cache
                .contains_key(&hex::encode([7u8; 32]))
        );
    }

    #[test]
    fn process_event_ignores_wrong_kind_wrong_recipient_and_self_authored_events() {
        let fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &peer);
        let local = fixture.signer.local_pubkey32().to_string();

        let wrong_kind = build_signed_event(
            *peer_share.seckey.expose_bytes(),
            fixture.signer.config.event_kind + 1,
            vec![vec!["p".to_string(), local.clone()]],
            "payload".to_string(),
        )
        .expect("wrong kind event");
        let mut signer = fixture.signer;
        assert!(
            signer
                .process_event(&wrong_kind)
                .expect("wrong kind")
                .is_empty()
        );

        let wrong_recipient = build_signed_event(
            *peer_share.seckey.expose_bytes(),
            signer.config.event_kind,
            vec![vec!["p".to_string(), peer.clone()]],
            "payload".to_string(),
        )
        .expect("wrong recipient event");
        assert!(
            signer
                .process_event(&wrong_recipient)
                .expect("wrong recipient")
                .is_empty()
        );

        let self_authored = build_signed_event(
            *signer.share.seckey.expose_bytes(),
            signer.config.event_kind,
            vec![vec!["p".to_string(), local]],
            "payload".to_string(),
        )
        .expect("self event");
        assert!(
            signer
                .process_event(&self_authored)
                .expect("self event")
                .is_empty()
        );
    }

    #[test]
    fn device_state_v5_rejected_with_unsupported_version_error() {
        // Hard-cut boundary: any state blob written under VERSION = 5 must
        // surface as `SignerError::UnsupportedVersion` rather than being
        // silently accepted or falling through to `StateCorrupted`.
        let bundle = create_keyset(CreateKeysetConfig::new("Test Group", 2, 3)).expect("keyset");
        let share = bundle.shares[0].clone();
        let state = DeviceState::new(share.idx, *share.seckey.expose_bytes());
        let mut persisted = DeviceStatePersisted::from(&state);
        persisted.version = 5;

        let v5_state = DeviceState::from_persisted(
            DeviceSecrets::new(*bundle.shares[0].seckey.expose_bytes()),
            persisted,
        );
        let err = match SigningDevice::new(
            bundle.group,
            share,
            Vec::new(),
            v5_state,
            DeviceConfig::default(),
        ) {
            Ok(_) => panic!("v5 state must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, SignerError::UnsupportedVersion(5)));
    }

    #[test]
    fn device_state_round_trip_through_persisted_dto_preserves_non_cache_fields() {
        let bundle = create_keyset(CreateKeysetConfig::new("Test Group", 2, 3)).expect("keyset");
        let share = bundle.shares[0].clone();
        let mut state = DeviceState::new(share.idx, *share.seckey.expose_bytes());
        state.request_seq = 99;
        state.last_active = 1_700_000_000;
        state.peer_last_seen.insert("peer-a".into(), 1_699_999_999);
        state.replay_cache.insert("some-request".into(), 42);
        state.pending_operations.insert(
            "req-1".into(),
            PendingOperation {
                op_type: PendingOpType::Ping,
                request_id: "req-1".into(),
                started_at: 1,
                timeout_at: 2,
                target_peers: vec!["peer-a".into()],
                threshold: 1,
                collected_responses: Vec::new(),
                context: PendingOpContext::PingRequest,
            },
        );

        let encoded =
            serde_json::to_string(&DeviceStatePersisted::from(&state)).expect("serialize");
        let decoded: DeviceStatePersisted = serde_json::from_str(&encoded).expect("deserialize");
        let restored =
            DeviceState::from_persisted(DeviceSecrets::new(*share.seckey.expose_bytes()), decoded);

        assert_eq!(restored.version, DeviceState::VERSION);
        assert_eq!(restored.request_seq, 99);
        assert_eq!(restored.last_active, 1_700_000_000);
        assert_eq!(
            restored.peer_last_seen.get("peer-a").copied(),
            Some(1_699_999_999)
        );
        assert_eq!(restored.replay_cache.get("some-request").copied(), Some(42));
        assert!(restored.pending_operations.contains_key("req-1"));
    }

    #[test]
    fn device_state_restore_starts_ecdh_cache_empty() {
        let bundle = create_keyset(CreateKeysetConfig::new("Test Group", 2, 3)).expect("keyset");
        let share = bundle.shares[0].clone();
        let mut state = DeviceState::new(share.idx, *share.seckey.expose_bytes());
        state.secrets.ecdh_cache.insert(
            "deadbeef".into(),
            EcdhCacheEntryLive {
                key_hex: "deadbeef".into(),
                shared_secret: EcdhSharedSecret::new([0x11; 32]),
                stored_at: 1,
                last_accessed_at: 1,
            },
        );
        state.secrets.ecdh_cache_order.push_back("deadbeef".into());

        // Round-trip through the persisted DTO — ecdh cache is not encoded.
        let encoded =
            serde_json::to_string(&DeviceStatePersisted::from(&state)).expect("serialize");
        let decoded: DeviceStatePersisted = serde_json::from_str(&encoded).expect("deserialize");
        let restored =
            DeviceState::from_persisted(DeviceSecrets::new(*share.seckey.expose_bytes()), decoded);
        assert!(restored.secrets.ecdh_cache.is_empty());
        assert!(restored.secrets.ecdh_cache_order.is_empty());
    }

    #[test]
    fn device_state_debug_does_not_leak_secret_bytes() {
        let bundle = create_keyset(CreateKeysetConfig::new("Test Group", 2, 3)).expect("keyset");
        let share = bundle.shares[0].clone();
        let mut state = DeviceState::new(share.idx, *share.seckey.expose_bytes());
        state.secrets.ecdh_cache.insert(
            "ffffffff".into(),
            EcdhCacheEntryLive {
                key_hex: "ffffffff".into(),
                shared_secret: EcdhSharedSecret::new([0xAB; 32]),
                stored_at: 1,
                last_accessed_at: 1,
            },
        );

        let rendered = format!("{:?}", state);
        // Any run of 32 or more hex digits is suspicious: that is the
        // minimum length of a leaked 16-byte secret in hex.
        for window in rendered.as_bytes().windows(32) {
            let hex_run = window.iter().all(|byte| byte.is_ascii_hexdigit());
            assert!(
                !hex_run,
                "debug output contains a 32-char hex run: {}",
                rendered,
            );
        }
    }
}
