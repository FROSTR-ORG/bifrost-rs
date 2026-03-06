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
use bifrost_core::types::{
    Bytes32, EcdhPackage, GroupPackage, OnboardResponse, PartialSigPackage, PeerPolicy,
    PeerScopedPolicyProfile, PingPayload, SharePackage, SignSessionPackage, SignSessionTemplate,
};
use frostr_utils::{
    ecdh_create_from_share, ecdh_finalize, sign_create_partial, sign_finalize, sign_verify_partial,
    validate_sign_session,
};
use nostr::{Event, Filter};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

mod crypto;
mod error;
mod event_io;
mod util;
use crypto::{decrypt_content_from_peer, encrypt_content_for_peer};
pub use error::{Result, SignerError};
use event_io::{build_signed_event, event_content, event_kind, event_pubkey_xonly};
use util::{
    decode_32, decode_member_index, decode_member_pubkey, decode_pubkey32, is_valid_pubkey32_hex,
    now_unix_secs, parse_request_id_components, shuffle_strings,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceState {
    pub nonce_pool: NoncePool,
    pub replay_cache: HashMap<String, u64>,
    pub ecdh_cache: HashMap<String, EcdhCacheEntry>,
    pub ecdh_cache_order: VecDeque<String>,
    pub sig_cache: HashMap<String, SigCacheEntry>,
    pub sig_cache_order: VecDeque<String>,
    pub policies: HashMap<String, PeerPolicy>,
    pub remote_scoped_policies: HashMap<String, PeerScopedPolicyProfile>,
    pub pending_operations: HashMap<String, PendingOperation>,
    pub request_seq: u64,
    pub last_active: u64,
    pub version: u32,
}

impl DeviceState {
    pub const VERSION: u32 = 2;

    pub fn new(group_member_idx: u16, share_seckey: [u8; 32]) -> Self {
        let mut nonce_pool =
            NoncePool::new(group_member_idx, share_seckey, NoncePoolConfig::default());
        nonce_pool.init_peer(group_member_idx);
        Self {
            nonce_pool,
            replay_cache: HashMap::new(),
            ecdh_cache: HashMap::new(),
            ecdh_cache_order: VecDeque::new(),
            sig_cache: HashMap::new(),
            sig_cache_order: VecDeque::new(),
            policies: HashMap::new(),
            remote_scoped_policies: HashMap::new(),
            pending_operations: HashMap::new(),
            request_seq: 1,
            last_active: now_unix_secs(),
            version: Self::VERSION,
        }
    }

    pub fn discard_volatile_for_dirty_restart(&mut self, group_member_idx: u16, share_seckey: [u8; 32]) {
        self.nonce_pool = NoncePool::new(group_member_idx, share_seckey, NoncePoolConfig::default());
        self.pending_operations.clear();
        self.last_active = now_unix_secs();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub sign_timeout_secs: u64,
    pub ecdh_timeout_secs: u64,
    pub ping_timeout_secs: u64,
    pub onboard_timeout_secs: u64,
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

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            sign_timeout_secs: 30,
            ecdh_timeout_secs: 30,
            ping_timeout_secs: 15,
            onboard_timeout_secs: 30,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendingOpType {
    Sign,
    Ecdh,
    Ping,
    Onboard,
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
    Onboard {
        request_id: String,
        group_member_count: usize,
    },
}

impl CompletedOperation {
    pub fn request_id(&self) -> &str {
        match self {
            CompletedOperation::Sign { request_id, .. }
            | CompletedOperation::Ecdh { request_id, .. }
            | CompletedOperation::Ping { request_id, .. }
            | CompletedOperation::Onboard { request_id, .. } => request_id,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdhCacheEntry {
    pub key_hex: String,
    pub shared_secret: [u8; 32],
    pub stored_at: u64,
    pub last_accessed_at: u64,
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
    latest_request_id: Option<String>,
    boot_nonce: u64,
}

impl SigningDevice {
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
            return Err(SignerError::StateCorrupted(format!(
                "unsupported device state version {} (expected {})",
                state.version,
                DeviceState::VERSION
            )));
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
        state.ecdh_cache_order
            .retain(|k| state.ecdh_cache.contains_key(k));
        state.sig_cache_order
            .retain(|k| state.sig_cache.contains_key(k));
        let mut boot_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut boot_bytes);
        let boot_nonce = u64::from_le_bytes(boot_bytes);

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
            latest_request_id: None,
            boot_nonce,
        })
    }

    pub fn init(
        group: GroupPackage,
        share: SharePackage,
        peers: Vec<String>,
        config: DeviceConfig,
    ) -> Result<Self> {
        let state = DeviceState::new(share.idx, share.seckey);
        Self::new(group, share, peers, state, config)
    }

    pub fn state(&self) -> &DeviceState {
        &self.state
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn latest_request_id(&self) -> Option<String> {
        self.latest_request_id.clone()
    }

    fn ecdh_cache_get(&mut self, target: [u8; 32], now: u64) -> Option<[u8; 32]> {
        let key = hex::encode(target);
        self.state
            .ecdh_cache
            .retain(|_, entry| now.saturating_sub(entry.stored_at) <= self.config.ecdh_cache_ttl_secs);
        self.state
            .ecdh_cache_order
            .retain(|k| self.state.ecdh_cache.contains_key(k));
        let entry = self.state.ecdh_cache.get_mut(&key)?;
        entry.last_accessed_at = now;
        Self::touch_lru_key(&mut self.state.ecdh_cache_order, &key);
        Some(entry.shared_secret)
    }

    fn ecdh_cache_put(&mut self, target: [u8; 32], secret: [u8; 32], now: u64) {
        let key = hex::encode(target);
        self.state.ecdh_cache.insert(
            key.clone(),
            EcdhCacheEntry {
                key_hex: key.clone(),
                shared_secret: secret,
                stored_at: now,
                last_accessed_at: now,
            },
        );
        Self::touch_lru_key(&mut self.state.ecdh_cache_order, &key);
        Self::evict_lru(
            &mut self.state.ecdh_cache,
            &mut self.state.ecdh_cache_order,
            self.config.ecdh_cache_capacity,
        );
    }

    fn sig_cache_get(&mut self, message: [u8; 32], now: u64) -> Option<Vec<[u8; 64]>> {
        let key = hex::encode(message);
        self.state
            .sig_cache
            .retain(|_, entry| now.saturating_sub(entry.stored_at) <= self.config.sig_cache_ttl_secs);
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
        self.record_request(&sender, &envelope.request_id, now)?;

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
            self.handle_inbound_request(envelope, sender)?
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
        let selected = self.select_locked_peers(needed)?;

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
                .consume_incoming(idx)
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

        let local_generated = self
            .state
            .nonce_pool
            .generate_for_peer(self.share.idx, 1)
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
        let selected = self.select_locked_peers(needed)?;

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
        let peer_idx = *self
            .member_idx_by_pubkey
            .get(peer)
            .ok_or_else(|| SignerError::UnknownPeer(peer.to_string()))?;
        let nonces = if self.state.nonce_pool.should_send_nonces_to(peer_idx) {
            Some(
                self.state
                    .nonce_pool
                    .generate_for_peer(peer_idx, NoncePoolConfig::default().replenish_count)
                    .map_err(|e| SignerError::InvalidRequest(e.to_string()))?,
            )
        } else {
            None
        };

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

        let payload = PingPayload {
            version: 1,
            nonces,
            policy_profile: Some(self.local_policy_profile_for(peer)?),
        };

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
        let request_id = self.next_request_id();
        self.latest_request_id = Some(request_id.clone());
        let now = now_unix_secs();

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
                share_pk: self.share_public_key_hex.clone(),
                idx: self.share.idx,
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
                effects.persistence_hint = PersistenceHint::Batch;
            }
            SignerInput::Expire { now } => {
                effects.failures.extend(self.expire_stale(now));
                if !effects.failures.is_empty() {
                    effects.persistence_hint = PersistenceHint::Batch;
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
        }
        effects.completions.extend(self.take_completions());
        effects.failures.extend(self.take_failures());
        Ok(effects)
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

    pub fn policies(&self) -> &HashMap<String, PeerPolicy> {
        &self.state.policies
    }

    pub fn set_peer_policy(&mut self, peer: &str, policy: PeerPolicy) -> Result<()> {
        if !self.member_idx_by_pubkey.contains_key(peer) {
            return Err(SignerError::UnknownPeer(peer.to_string()));
        }
        self.state.policies.insert(peer.to_string(), policy);
        self.state.last_active = now_unix_secs();
        Ok(())
    }

    fn select_locked_peers(&self, needed: usize) -> Result<Vec<String>> {
        let mut selected = self.peers.clone();
        if selected.len() < needed {
            return Err(SignerError::InvalidConfig(
                "insufficient peers for threshold round".to_string(),
            ));
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
        let plaintext = decrypt_content_from_peer(self.share.seckey, sender33, &ciphertext)?;
        decode_bridge_envelope(&plaintext).map_err(|e| SignerError::InvalidRequest(e.to_string()))
    }

    fn encrypt_for_peers(
        &self,
        peers: &[String],
        envelope: &BridgeEnvelope,
    ) -> Result<Vec<Event>> {
        peers
            .iter()
            .map(|peer| self.encrypt_for_peer(peer, envelope))
            .collect()
    }

    fn encrypt_for_peer(&self, peer: &str, envelope: &BridgeEnvelope) -> Result<Event> {
        let plaintext = encode_bridge_envelope(envelope)
            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
        let content = encrypt_content_for_peer(self.share.seckey, peer, &plaintext)?;
        build_signed_event(self.share.seckey, self.config.event_kind, content)
    }

    fn handle_inbound_request(
        &mut self,
        envelope: BridgeEnvelope,
        sender: String,
    ) -> Result<Vec<Event>> {
        let sender_idx = self
            .member_idx_by_pubkey
            .get(&sender)
            .copied()
            .ok_or_else(|| SignerError::UnknownPeer(sender.clone()))?;
        let now = now_unix_secs();

        match envelope.payload {
            BridgePayload::PingRequest(wire) => {
                let ping: PingPayload =
                    wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                        SignerError::InvalidRequest(e.to_string())
                    })?;
                if let Some(nonces) = ping.nonces {
                    self.state.nonce_pool.store_incoming(sender_idx, nonces);
                }
                if let Some(profile) = ping.policy_profile {
                    self.store_remote_scoped_policy(&sender, profile)?;
                }

                let nonces = if self.state.nonce_pool.should_send_nonces_to(sender_idx) {
                    Some(
                        self.state
                            .nonce_pool
                            .generate_for_peer(
                                sender_idx,
                                NoncePoolConfig::default().replenish_count,
                            )
                            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?,
                    )
                } else {
                    None
                };

                let response = BridgeEnvelope {
                    request_id: envelope.request_id,
                    sent_at: now,
                    payload: BridgePayload::PingResponse(PingPayloadWire::from(PingPayload {
                        version: 1,
                        nonces,
                        policy_profile: Some(self.local_policy_profile_for(&sender)?),
                    })),
                };
                self.encrypt_for_peers(&[sender], &response)
            }
            BridgePayload::OnboardRequest(wire) => {
                let request: bifrost_core::types::OnboardRequest =
                    wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                        SignerError::InvalidRequest(e.to_string())
                    })?;
                if request.idx != sender_idx {
                    return Err(SignerError::InvalidSenderBinding(
                        "onboard idx mismatch".to_string(),
                    ));
                }
                if hex::encode(request.share_pk) != sender {
                    return Err(SignerError::InvalidSenderBinding(
                        "onboard share_pk mismatch".to_string(),
                    ));
                }

                let nonces = self
                    .state
                    .nonce_pool
                    .generate_for_peer(sender_idx, NoncePoolConfig::default().pool_size)
                    .map_err(|e| SignerError::InvalidRequest(e.to_string()))?;
                let onboard = OnboardResponse {
                    group: self.group.clone(),
                    nonces,
                };

                let response = BridgeEnvelope {
                    request_id: envelope.request_id,
                    sent_at: now,
                    payload: BridgePayload::OnboardResponse(OnboardResponseWire::from(onboard)),
                };
                self.encrypt_for_peers(&[sender], &response)
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

                if self.state.nonce_pool.should_send_nonces_to(sender_idx) {
                    partial.replenish = Some(
                        self.state
                            .nonce_pool
                            .generate_for_peer(
                                sender_idx,
                                NoncePoolConfig::default().replenish_count,
                            )
                            .map_err(|e| SignerError::InvalidRequest(e.to_string()))?,
                    );
                }

                let response = BridgeEnvelope {
                    request_id: envelope.request_id,
                    sent_at: now,
                    payload: BridgePayload::SignResponse(PartialSigPackageWire::from(partial)),
                };
                self.encrypt_for_peers(&[sender], &response)
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
            BridgePayload::PingResponse(_)
            | BridgePayload::OnboardResponse(_)
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
                if let Some(nonces) = ping.nonces {
                    self.state.nonce_pool.store_incoming(sender_idx, nonces);
                }
                if let Some(profile) = ping.policy_profile {
                    self.store_remote_scoped_policy(sender, profile)?;
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
        let policy = self.state.policies.get(peer).cloned().unwrap_or_default();
        Ok(PeerScopedPolicyProfile {
            for_peer: decode_32(peer)?,
            revision: now,
            updated: now,
            block_all: policy.block_all,
            request: policy.request,
            respond: policy.respond,
        })
    }

    fn record_request(&mut self, sender: &str, request_id: &str, now: u64) -> Result<()> {
        if request_id.is_empty() {
            return Err(SignerError::InvalidRequest(
                "request id must not be empty".to_string(),
            ));
        }
        let (issued_at, _, _, _) = parse_request_id_components(request_id)
            .ok_or_else(|| SignerError::InvalidRequest("invalid request id format".to_string()))?;
        if issued_at > now.saturating_add(self.config.max_future_skew_secs) {
            return Err(SignerError::InvalidRequest(
                "request id is too far in the future".to_string(),
            ));
        }
        if now > issued_at.saturating_add(self.config.request_ttl_secs) {
            return Err(SignerError::InvalidRequest("stale request id".to_string()));
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
        let id = format!(
            "{}-{}-{}-{}",
            now_unix_secs(),
            self.share.idx,
            self.boot_nonce,
            self.state.request_seq
        );
        self.state.request_seq = self.state.request_seq.saturating_add(1);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_codec::wire::OnboardRequestWire;
    use frostr_utils::{CreateKeysetConfig, create_keyset};

    struct Fixture {
        signer: SigningDevice,
        group: GroupPackage,
        shares: Vec<SharePackage>,
        local_share: SharePackage,
    }

    fn fixture(strategy: PeerSelectionStrategy) -> Fixture {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");

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
            DeviceState::new(local_share.idx, local_share.seckey),
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

    fn share_for_peer(group: &GroupPackage, shares: &[SharePackage], peer: &str) -> SharePackage {
        let idx = decode_member_index(&group.members, peer).expect("peer idx");
        shares
            .iter()
            .find(|share| share.idx == idx)
            .cloned()
            .expect("peer share")
    }

    #[test]
    fn deterministic_strategy_selects_sorted_locked_peers() {
        let fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let selected = fixture.signer.select_locked_peers(2).expect("select");

        let mut expected = fixture.signer.peers.clone();
        expected.sort_unstable();
        expected.truncate(2);
        assert_eq!(selected, expected);
    }

    #[test]
    fn random_strategy_selects_unique_subset_of_peers() {
        let fixture = fixture(PeerSelectionStrategy::Random);
        let selected = fixture.signer.select_locked_peers(2).expect("select");

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
    fn invalid_locked_peer_response_fails_round_terminally() {
        let mut fixture = fixture(PeerSelectionStrategy::DeterministicSorted);
        let locked_peer = fixture.signer.peers[0].clone();
        let peer_share = share_for_peer(&fixture.group, &fixture.shares, &locked_peer);
        let local_pubkey =
            decode_member_pubkey(&fixture.group, fixture.local_share.idx).expect("local pubkey");
        let now = now_unix_secs();
        let request_id = format!(
            "{now}-{}-{}-1",
            fixture.local_share.idx, fixture.signer.boot_nonce
        );

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
                share_pk: locked_peer.clone(),
                idx: 7,
            }),
        };
        let plaintext = encode_bridge_envelope(&inbound).expect("encode envelope");
        let content = super::crypto::encrypt_content_for_peer_with_nonce(
            peer_share.seckey,
            &local_pubkey,
            &plaintext,
            [9u8; 32],
        )
        .expect("encrypt");
        let event =
            build_signed_event(peer_share.seckey, fixture.signer.config.event_kind, content)
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
}
