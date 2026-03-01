use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bifrost_codec::rpc::{RpcEnvelope, RpcPayload};
use bifrost_codec::wire::{
    EcdhPackageWire, OnboardRequestWire, OnboardResponseWire, PartialSigPackageWire, PeerErrorWire,
    PingPayloadWire, SignSessionPackageWire,
};
use bifrost_codec::{
    parse_ecdh, parse_onboard_request, parse_onboard_response, parse_ping, parse_psig,
    parse_session,
};
use bifrost_core::group::get_group_id;
use bifrost_core::nonce::{NoncePool, NoncePoolConfig};
use bifrost_core::session::{create_session_package, verify_session_package};
use bifrost_core::types::{
    EcdhPackage, GroupPackage, IndexedPublicNonceCommitment, MemberNonceCommitmentSet,
    OnboardResponse, PeerScopedPolicyProfile, PingPayload, SharePackage, SignSessionTemplate,
};
use bifrost_transport::{Clock, IncomingMessage, OutgoingMessage, ResponseHandle, Transport};
use frostr_utils::{
    ecdh_create_from_share, ecdh_finalize, sign_create_partial, sign_finalize, sign_verify_partial,
};
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use tokio::sync::broadcast;

use crate::error::{NodeError, NodeResult};
use crate::types::{
    BifrostNodeConfig, BifrostNodeOptions, MethodPolicy, NodeEvent, PeerData, PeerNonceHealth,
    PeerPolicy, PeerStatus,
};

const PEER_ENVELOPE_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationMethod {
    Echo,
    Ping,
    Onboard,
    Sign,
    Ecdh,
}

impl OperationMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Echo => "echo",
            Self::Ping => "ping",
            Self::Onboard => "onboard",
            Self::Sign => "sign",
            Self::Ecdh => "ecdh",
        }
    }
}

fn operation_from_payload(payload: &RpcPayload) -> Option<OperationMethod> {
    match payload {
        RpcPayload::Echo(_) => Some(OperationMethod::Echo),
        RpcPayload::Ping(_) => Some(OperationMethod::Ping),
        RpcPayload::OnboardRequest(_) => Some(OperationMethod::Onboard),
        RpcPayload::Sign(_) => Some(OperationMethod::Sign),
        RpcPayload::Ecdh(_) => Some(OperationMethod::Ecdh),
        RpcPayload::SignResponse(_) | RpcPayload::OnboardResponse(_) | RpcPayload::Error(_) => None,
    }
}

pub struct BifrostNode<T: Transport, C: Clock> {
    transport: Arc<T>,
    clock: Arc<C>,
    group: GroupPackage,
    share: SharePackage,
    member_idx_by_pubkey: HashMap<String, u16>,
    group_member_indices: HashSet<u16>,
    config: BifrostNodeConfig,
    policies: Arc<Mutex<HashMap<String, PeerPolicy>>>,
    remote_scoped_policies: Arc<Mutex<HashMap<String, PeerScopedPolicyProfile>>>,
    pool: Arc<Mutex<NoncePool>>,
    replay_cache: Arc<Mutex<HashMap<String, u64>>>,
    ecdh_cache: Arc<Mutex<EcdhCache>>,
    events_tx: broadcast::Sender<NodeEvent>,
    ready: AtomicBool,
    request_seq: AtomicU64,
}

#[derive(Debug, Clone)]
struct EcdhCacheEntry {
    key: [u8; 33],
    value: [u8; 32],
    stored_at: u64,
}

#[derive(Debug, Default)]
struct EcdhCache {
    map: HashMap<[u8; 33], EcdhCacheEntry>,
    order: VecDeque<[u8; 33]>,
}

impl<T: Transport, C: Clock> BifrostNode<T, C> {
    pub fn new(
        group: GroupPackage,
        share: SharePackage,
        peer_pubkeys: Vec<String>,
        transport: Arc<T>,
        clock: Arc<C>,
        options: Option<BifrostNodeOptions>,
    ) -> NodeResult<Self> {
        if group.threshold == 0 || group.members.is_empty() {
            return Err(NodeError::InvalidGroup);
        }
        get_group_id(&group).map_err(|e| NodeError::Core(e.to_string()))?;

        let now = clock.now_unix_seconds();
        let mut member_idx_by_pubkey = HashMap::with_capacity(group.members.len());
        let mut group_member_indices = HashSet::with_capacity(group.members.len());
        for member in &group.members {
            if !group_member_indices.insert(member.idx) {
                return Err(NodeError::InvalidGroup);
            }
            let pubkey = hex::encode(member.pubkey);
            if member_idx_by_pubkey.insert(pubkey, member.idx).is_some() {
                return Err(NodeError::InvalidGroup);
            }
        }
        let peers: Vec<PeerData> = peer_pubkeys
            .into_iter()
            .map(|pubkey| PeerData {
                pubkey,
                status: PeerStatus::Offline,
                policy: PeerPolicy::default(),
                updated: now,
            })
            .collect();
        let policies = peers
            .iter()
            .map(|p| (p.pubkey.clone(), p.policy))
            .collect::<HashMap<_, _>>();

        let resolved = options.unwrap_or_default();
        let (events_tx, _) = broadcast::channel(256);
        let mut pool = NoncePool::new(
            share.idx,
            share.seckey,
            NoncePoolConfig {
                pool_size: resolved.nonce_pool.pool_size,
                min_threshold: resolved.nonce_pool.min_threshold,
                critical_threshold: resolved.nonce_pool.critical_threshold,
                replenish_count: resolved.nonce_pool.replenish_count,
            },
        );

        for member in &group.members {
            pool.init_peer(member.idx);
        }

        Ok(Self {
            transport,
            clock,
            group,
            share,
            member_idx_by_pubkey,
            group_member_indices,
            config: BifrostNodeConfig {
                options: resolved,
                peers,
            },
            policies: Arc::new(Mutex::new(policies)),
            remote_scoped_policies: Arc::new(Mutex::new(HashMap::new())),
            pool: Arc::new(Mutex::new(pool)),
            replay_cache: Arc::new(Mutex::new(HashMap::new())),
            ecdh_cache: Arc::new(Mutex::new(EcdhCache::default())),
            events_tx,
            ready: AtomicBool::new(false),
            request_seq: AtomicU64::new(0),
        })
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    pub fn group(&self) -> &GroupPackage {
        &self.group
    }

    pub fn share_idx(&self) -> u16 {
        self.share.idx
    }

    pub fn peers(&self) -> &[PeerData] {
        &self.config.peers
    }

    pub fn peers_snapshot(&self) -> Vec<PeerData> {
        let policies = self.policies.lock().map(|m| m.clone()).unwrap_or_default();
        self.config
            .peers
            .iter()
            .map(|p| {
                let mut next = p.clone();
                if let Some(pol) = policies.get(&p.pubkey) {
                    next.policy = *pol;
                }
                next
            })
            .collect()
    }

    pub fn peer_policy(&self, peer: &str) -> NodeResult<PeerPolicy> {
        let policies = self
            .policies
            .lock()
            .map_err(|_| NodeError::Core("policy map poisoned".to_string()))?;
        policies.get(peer).copied().ok_or(NodeError::PeerNotFound)
    }

    pub fn set_peer_policy(&self, peer: &str, policy: PeerPolicy) -> NodeResult<()> {
        let mut policies = self
            .policies
            .lock()
            .map_err(|_| NodeError::Core("policy map poisoned".to_string()))?;
        if !self.member_idx_by_pubkey.contains_key(peer) {
            return Err(NodeError::PeerNotFound);
        }
        policies.insert(peer.to_string(), policy);
        Ok(())
    }

    pub fn peer_policies(&self) -> NodeResult<HashMap<String, PeerPolicy>> {
        let policies = self
            .policies
            .lock()
            .map_err(|_| NodeError::Core("policy map poisoned".to_string()))?;
        Ok(policies.clone())
    }

    pub fn nonce_pool_config(&self) -> NoncePoolConfig {
        self.config.options.nonce_pool.clone()
    }

    pub fn peer_nonce_health(&self, peer: &str) -> NodeResult<PeerNonceHealth> {
        let member_idx = self.member_idx_by_peer_pubkey(peer)?;
        let pool = self
            .pool
            .lock()
            .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
        let stats = pool.peer_stats(member_idx);
        Ok(PeerNonceHealth {
            member_idx,
            incoming_available: stats.incoming_available,
            outgoing_available: stats.outgoing_available,
            outgoing_spent: stats.outgoing_spent,
            can_sign: stats.can_sign,
            should_send_nonces: stats.should_send_nonces,
        })
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<NodeEvent> {
        self.events_tx.subscribe()
    }

    pub async fn connect(&self) -> NodeResult<()> {
        self.transport
            .connect()
            .await
            .map_err(|e| NodeError::Transport(e.to_string()))?;
        self.ready.store(true, Ordering::Relaxed);
        self.emit_event(NodeEvent::Ready);
        self.emit_event(NodeEvent::Info("connected".to_string()));
        Ok(())
    }

    pub async fn close(&self) -> NodeResult<()> {
        self.transport
            .close()
            .await
            .map_err(|e| NodeError::Transport(e.to_string()))?;
        self.ready.store(false, Ordering::Relaxed);
        self.emit_event(NodeEvent::Closed);
        self.emit_event(NodeEvent::Info("closed".to_string()));
        Ok(())
    }

    pub async fn echo(&self, peer: &str, challenge: &str) -> NodeResult<String> {
        self.ensure_ready()?;
        self.enforce_outbound_request_policy(peer, OperationMethod::Echo)?;

        let envelope = RpcEnvelope {
            version: 1,
            id: self.request_id(),
            sender: self.local_sender_id(),
            payload: RpcPayload::Echo(challenge.to_string()),
        };

        let req = OutgoingMessage {
            peer: peer.to_string(),
            envelope,
        };

        let res = self
            .transport
            .request(req, self.config.options.ping_timeout_ms)
            .await
            .map_err(|e| NodeError::Transport(e.to_string()))?;
        self.assert_expected_response_peer(peer, &res, "echo response")?;

        match res.envelope.payload {
            RpcPayload::Echo(value) => Ok(value),
            RpcPayload::Error(err) => Err(NodeError::Core(format!(
                "peer policy denied: {}: {}",
                err.code, err.message
            ))),
            _ => Err(NodeError::InvalidResponse),
        }
    }

    pub async fn ping(&self, peer: &str) -> NodeResult<PingPayload> {
        self.ensure_ready()?;
        self.enforce_outbound_request_policy(peer, OperationMethod::Ping)?;

        let payload = {
            let mut pool = self
                .pool
                .lock()
                .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
            let peer_idx = self.member_idx_by_peer_pubkey(peer)?;
            let nonces = if pool.should_send_nonces_to(peer_idx) {
                Some(
                    pool.generate_for_peer(
                        peer_idx,
                        self.config.options.nonce_pool.replenish_count,
                    )
                    .map_err(|e| NodeError::Core(e.to_string()))?,
                )
            } else {
                None
            };

            PingPayload {
                version: 1,
                nonces,
                policy_profile: Some(self.local_policy_profile_for(peer)?),
            }
        };

        let envelope = RpcEnvelope {
            version: 1,
            id: self.request_id(),
            sender: self.local_sender_id(),
            payload: RpcPayload::Ping(PingPayloadWire::from(payload)),
        };

        let req = OutgoingMessage {
            peer: peer.to_string(),
            envelope,
        };

        let res = self
            .transport
            .request(req, self.config.options.ping_timeout_ms)
            .await
            .map_err(|e| NodeError::Transport(e.to_string()))?;
        self.assert_expected_response_peer(peer, &res, "ping response")?;

        if let RpcPayload::Error(err) = &res.envelope.payload {
            return Err(NodeError::Core(format!(
                "peer policy denied: {}: {}",
                err.code, err.message
            )));
        }
        let parsed: PingPayload = parse_ping(&res.envelope)
            .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;

        if let Some(nonces) = parsed.nonces.clone() {
            let mut pool = self
                .pool
                .lock()
                .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
            let peer_idx = self.member_idx_by_peer_pubkey(peer)?;
            pool.store_incoming(peer_idx, nonces);
        }
        if let Some(profile) = parsed.policy_profile.clone() {
            self.store_remote_scoped_policy(peer, profile)?;
        }

        Ok(parsed)
    }

    pub async fn onboard(&self, peer: &str) -> NodeResult<OnboardResponse> {
        self.ensure_ready()?;
        self.enforce_outbound_request_policy(peer, OperationMethod::Onboard)?;

        let request = OnboardRequestWire {
            share_pk: self.local_pubkey_hex()?,
            idx: self.share.idx,
        };

        let envelope = RpcEnvelope {
            version: 1,
            id: self.request_id(),
            sender: self.local_sender_id(),
            payload: RpcPayload::OnboardRequest(request),
        };

        let res = self
            .transport
            .request(
                OutgoingMessage {
                    peer: peer.to_string(),
                    envelope,
                },
                self.config.options.ping_timeout_ms,
            )
            .await
            .map_err(|e| NodeError::Transport(e.to_string()))?;
        self.assert_expected_response_peer(peer, &res, "onboard response")?;

        if let RpcPayload::Error(err) = &res.envelope.payload {
            return Err(NodeError::Core(format!(
                "peer policy denied: {}: {}",
                err.code, err.message
            )));
        }
        let onboard: OnboardResponse = parse_onboard_response(&res.envelope)
            .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;
        let local_gid = get_group_id(&self.group).map_err(|e| NodeError::Core(e.to_string()))?;
        let onboard_gid =
            get_group_id(&onboard.group).map_err(|e| NodeError::Core(e.to_string()))?;
        if local_gid != onboard_gid {
            return Err(NodeError::InvalidResponse);
        }

        let peer_idx = self.member_idx_by_peer_pubkey(peer)?;
        let mut pool = self
            .pool
            .lock()
            .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
        pool.store_incoming(peer_idx, onboard.nonces.clone());

        Ok(onboard)
    }

    pub async fn sign(&self, _message: [u8; 32]) -> NodeResult<[u8; 64]> {
        let out = self.sign_batch(&[_message]).await?;
        let Some(first) = out.first() else {
            return Err(NodeError::InvalidResponse);
        };
        Ok(*first)
    }

    pub async fn sign_batch(&self, messages: &[[u8; 32]]) -> NodeResult<Vec<[u8; 64]>> {
        self.ensure_ready()?;
        if messages.is_empty() {
            return Err(NodeError::InvalidSignBatch(
                "message list must not be empty",
            ));
        }
        if messages.len() > self.config.options.max_sign_batch {
            return Err(NodeError::InvalidSignBatch(
                "message list exceeds max_sign_batch",
            ));
        }
        let selected = match self.select_signing_peers(OperationMethod::Sign) {
            Ok(v) => v,
            Err(NodeError::InsufficientPeers) => {
                self.refresh_unknown_policy_peers(OperationMethod::Sign)
                    .await?;
                self.select_signing_peers(OperationMethod::Sign)?
            }
            Err(err) => return Err(err),
        };
        let mut members = Vec::with_capacity(selected.len() + 1);
        members.push(self.share.idx);
        for peer in &selected {
            members.push(self.member_idx_by_peer_pubkey(peer)?);
        }
        members.sort_unstable();

        let mut member_nonce_sets: Vec<MemberNonceCommitmentSet> =
            Vec::with_capacity(members.len());
        let mut self_nonce_codes = Vec::with_capacity(messages.len());
        {
            let mut pool = self
                .pool
                .lock()
                .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;

            for peer in &selected {
                let idx = self.member_idx_by_peer_pubkey(peer)?;
                let mut entries = Vec::with_capacity(messages.len());
                for hash_index in 0..messages.len() {
                    let nonce = pool
                        .consume_incoming(idx)
                        .ok_or(NodeError::NonceUnavailable)?;
                    entries.push(IndexedPublicNonceCommitment {
                        hash_index: hash_index as u16,
                        binder_pn: nonce.binder_pn,
                        hidden_pn: nonce.hidden_pn,
                        code: nonce.code,
                    });
                }
                member_nonce_sets.push(MemberNonceCommitmentSet { idx, entries });
            }

            let generated = pool
                .generate_for_peer(self.share.idx, messages.len())
                .map_err(|e| NodeError::Core(e.to_string()))?;
            if generated.len() != messages.len() {
                return Err(NodeError::Core(
                    "failed to generate required local nonce commitments".to_string(),
                ));
            }
            let mut entries = Vec::with_capacity(messages.len());
            for (hash_index, nonce) in generated.iter().enumerate() {
                self_nonce_codes.push(nonce.code);
                entries.push(IndexedPublicNonceCommitment {
                    hash_index: hash_index as u16,
                    binder_pn: nonce.binder_pn,
                    hidden_pn: nonce.hidden_pn,
                    code: nonce.code,
                });
            }
            member_nonce_sets.push(MemberNonceCommitmentSet {
                idx: self.share.idx,
                entries,
            });
        }

        member_nonce_sets.sort_by_key(|m| m.idx);
        let template = SignSessionTemplate {
            members,
            hashes: messages.to_vec(),
            content: None,
            kind: "message".to_string(),
            stamp: self.clock.now_unix_seconds() as u32,
        };

        let mut session = create_session_package(&self.group, template)
            .map_err(|e| NodeError::Core(e.to_string()))?;
        session.nonces = Some(member_nonce_sets);
        self.validate_sign_session(&session)?;

        let wire = SignSessionPackageWire::from(session.clone());
        let envelope = RpcEnvelope {
            version: 1,
            id: self.request_id(),
            sender: self.local_sender_id(),
            payload: RpcPayload::Sign(wire),
        };

        let responses = if selected.is_empty() {
            Vec::new()
        } else {
            self.transport
                .cast(
                    OutgoingMessage {
                        peer: String::new(),
                        envelope,
                    },
                    &selected,
                    selected.len(),
                    self.config.options.sign_timeout_ms,
                )
                .await
                .map_err(|e| NodeError::Transport(e.to_string()))?
        };

        let self_signing_nonces = {
            let mut pool = self
                .pool
                .lock()
                .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
            pool.take_outgoing_signing_nonces_many(self.share.idx, &self_nonce_codes)
                .map_err(|e| NodeError::Core(e.to_string()))?
        };

        let self_pkg = sign_create_partial(
            &self.group,
            &session,
            &self.share,
            &self_signing_nonces,
            None,
        )
        .map_err(|e| NodeError::Core(e.to_string()))?;

        let mut pkgs = vec![self_pkg];
        let mut seen_responders = HashSet::new();
        for msg in responses {
            if !selected.iter().any(|p| p == &msg.peer) {
                return Err(NodeError::InvalidSenderBinding("unexpected sign responder"));
            }
            self.assert_expected_response_peer(&msg.peer, &msg, "sign response")?;
            if !seen_responders.insert(msg.peer.clone()) {
                return Err(NodeError::InvalidSenderBinding("duplicate sign responder"));
            }
            if let RpcPayload::Error(err) = &msg.envelope.payload {
                return Err(NodeError::Core(format!(
                    "sign denied by peer {}: {}: {}",
                    msg.peer, err.code, err.message
                )));
            }
            let pkg: bifrost_core::types::PartialSigPackage = parse_psig(&msg.envelope)
                .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;
            sign_verify_partial(&self.group, &session, &pkg)
                .map_err(|e| NodeError::Core(e.to_string()))?;
            pkgs.push(pkg);
        }

        let sigs = sign_finalize(&self.group, &session, &pkgs)
            .map_err(|e| NodeError::Core(e.to_string()))?;
        if sigs.len() != messages.len() {
            return Err(NodeError::InvalidResponse);
        }
        Ok(sigs.into_iter().map(|s| s.signature).collect())
    }

    pub async fn sign_queue(&self, messages: &[[u8; 32]]) -> NodeResult<Vec<[u8; 64]>> {
        self.ensure_ready()?;
        if messages.is_empty() {
            return Err(NodeError::InvalidSignBatch(
                "message queue must not be empty",
            ));
        }

        let mut queue: VecDeque<[u8; 32]> = messages.iter().copied().collect();
        let mut out = Vec::with_capacity(messages.len());
        let chunk_size = self.config.options.max_sign_batch.max(1);

        while !queue.is_empty() {
            let n = queue.len().min(chunk_size);
            let mut chunk = Vec::with_capacity(n);
            for _ in 0..n {
                if let Some(item) = queue.pop_front() {
                    chunk.push(item);
                }
            }
            out.extend(self.sign_batch(&chunk).await?);
        }

        Ok(out)
    }

    pub async fn ecdh(&self, pubkey: [u8; 33]) -> NodeResult<[u8; 32]> {
        self.ensure_ready()?;
        let now = self.clock.now_unix_seconds();
        if let Some(secret) = self.get_cached_ecdh(pubkey, now)? {
            return Ok(secret);
        }

        let selected = match self.select_signing_peers(OperationMethod::Ecdh) {
            Ok(v) => v,
            Err(NodeError::InsufficientPeers) => {
                self.refresh_unknown_policy_peers(OperationMethod::Ecdh)
                    .await?;
                self.select_signing_peers(OperationMethod::Ecdh)?
            }
            Err(err) => return Err(err),
        };
        let mut members = Vec::with_capacity(selected.len() + 1);
        members.push(self.share.idx);
        for peer in &selected {
            members.push(self.member_idx_by_peer_pubkey(peer)?);
        }
        members.sort_unstable();

        let local = ecdh_create_from_share(&members, &self.share, &[pubkey])
            .map_err(|e| NodeError::Core(e.to_string()))?;
        let wire = EcdhPackageWire::from(local.clone());

        let responses = self
            .transport
            .cast(
                OutgoingMessage {
                    peer: String::new(),
                    envelope: RpcEnvelope {
                        version: 1,
                        id: self.request_id(),
                        sender: self.local_sender_id(),
                        payload: RpcPayload::Ecdh(wire),
                    },
                },
                &selected,
                selected.len(),
                self.config.options.ecdh_timeout_ms,
            )
            .await
            .map_err(|e| NodeError::Transport(e.to_string()))?;

        let mut pkgs: Vec<EcdhPackage> = vec![local];
        let mut seen_responders = HashSet::new();
        for msg in responses {
            if !selected.iter().any(|p| p == &msg.peer) {
                return Err(NodeError::InvalidSenderBinding("unexpected ecdh responder"));
            }
            self.assert_expected_response_peer(&msg.peer, &msg, "ecdh response")?;
            if !seen_responders.insert(msg.peer.clone()) {
                return Err(NodeError::InvalidSenderBinding("duplicate ecdh responder"));
            }
            if let RpcPayload::Error(err) = &msg.envelope.payload {
                return Err(NodeError::Core(format!(
                    "ecdh denied by peer {}: {}: {}",
                    msg.peer, err.code, err.message
                )));
            }
            let pkg: EcdhPackage = parse_ecdh(&msg.envelope)
                .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;
            pkgs.push(pkg);
        }

        let secret = ecdh_finalize(&pkgs, pubkey).map_err(|e| NodeError::Core(e.to_string()))?;
        self.store_cached_ecdh(pubkey, secret, now)?;
        Ok(secret)
    }

    pub async fn ecdh_batch(&self, pubkeys: &[[u8; 33]]) -> NodeResult<Vec<[u8; 32]>> {
        self.ensure_ready()?;
        if pubkeys.is_empty() {
            return Err(NodeError::InvalidEcdhBatch(
                "pubkey queue must not be empty",
            ));
        }

        let mut queue: VecDeque<[u8; 33]> = pubkeys.iter().copied().collect();
        let mut out = Vec::with_capacity(pubkeys.len());
        let chunk_size = self.config.options.max_ecdh_batch.max(1);

        while !queue.is_empty() {
            let n = queue.len().min(chunk_size);
            for _ in 0..n {
                if let Some(pubkey) = queue.pop_front() {
                    out.push(self.ecdh(pubkey).await?);
                }
            }
        }

        Ok(out)
    }

    pub async fn handle_next_incoming(&self) -> NodeResult<IncomingMessage> {
        self.ensure_ready()?;
        self.transport
            .next_incoming()
            .await
            .map_err(|e| NodeError::Transport(e.to_string()))
    }

    pub async fn process_next_incoming(&self) -> NodeResult<()> {
        let msg = self.handle_next_incoming().await?;
        self.handle_incoming(msg).await
    }

    pub async fn handle_incoming(&self, msg: IncomingMessage) -> NodeResult<()> {
        self.ensure_ready()?;
        if msg.envelope.version != PEER_ENVELOPE_VERSION {
            return Err(NodeError::UnsupportedEnvelopeVersion(msg.envelope.version));
        }
        self.validate_payload_limits(&msg.envelope)?;

        let peer = msg.peer.clone();
        let request_id = msg.envelope.id.clone();
        let sender = msg.envelope.sender.clone();
        let version = msg.envelope.version;
        self.emit_event(NodeEvent::Message(request_id.clone()));
        self.check_and_track_request(&sender, &request_id)?;

        if let Some(method) = operation_from_payload(&msg.envelope.payload)
            && !self.is_respond_allowed(&peer, method)?
        {
            let response = OutgoingMessage {
                peer: peer.clone(),
                envelope: RpcEnvelope {
                    version: 1,
                    id: request_id.clone(),
                    sender: self.local_sender_id(),
                    payload: RpcPayload::Error(PeerErrorWire {
                        code: "POLICY_DENIED".to_string(),
                        message: format!("respond policy denies {}", method.as_str()),
                    }),
                },
            };
            self.transport
                .send_response(ResponseHandle { peer, request_id }, response)
                .await
                .map_err(|e| NodeError::Transport(e.to_string()))?;
            return Ok(());
        }

        let payload = match msg.envelope.payload {
            RpcPayload::Echo(challenge) => RpcPayload::Echo(challenge),
            RpcPayload::Ping(wire) => {
                let ping: PingPayload = parse_ping(&RpcEnvelope {
                    version,
                    id: request_id.clone(),
                    sender: sender.clone(),
                    payload: RpcPayload::Ping(wire),
                })
                .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;

                let peer_idx = self.validate_sender_binding(&peer, &sender)?;
                let mut pool = self
                    .pool
                    .lock()
                    .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;

                if let Some(nonces) = ping.nonces {
                    pool.store_incoming(peer_idx, nonces);
                }
                if let Some(profile) = ping.policy_profile {
                    self.store_remote_scoped_policy(&peer, profile)?;
                }

                let nonces = if pool.should_send_nonces_to(peer_idx) {
                    Some(
                        pool.generate_for_peer(
                            peer_idx,
                            self.config.options.nonce_pool.replenish_count,
                        )
                        .map_err(|e| NodeError::Core(e.to_string()))?,
                    )
                } else {
                    None
                };

                RpcPayload::Ping(PingPayloadWire::from(PingPayload {
                    version: 1,
                    nonces,
                    policy_profile: Some(self.local_policy_profile_for(&peer)?),
                }))
            }
            RpcPayload::OnboardRequest(wire) => {
                let sender_idx = self.validate_sender_binding(&peer, &sender)?;
                let request: bifrost_core::types::OnboardRequest =
                    parse_onboard_request(&RpcEnvelope {
                        version,
                        id: request_id.clone(),
                        sender: sender.clone(),
                        payload: RpcPayload::OnboardRequest(wire),
                    })
                    .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;
                if request.idx != sender_idx {
                    return Err(NodeError::InvalidSenderBinding(
                        "onboard idx does not match sender",
                    ));
                }
                if hex::encode(request.share_pk) != sender {
                    return Err(NodeError::InvalidSenderBinding(
                        "onboard share_pk does not match sender",
                    ));
                }

                let mut pool = self
                    .pool
                    .lock()
                    .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
                let nonces = pool
                    .generate_for_peer(request.idx, self.config.options.nonce_pool.pool_size)
                    .map_err(|e| NodeError::Core(e.to_string()))?;

                RpcPayload::OnboardResponse(OnboardResponseWire::from(OnboardResponse {
                    group: self.group.clone(),
                    nonces,
                }))
            }
            RpcPayload::Sign(wire) => {
                let session: bifrost_core::types::SignSessionPackage =
                    parse_session(&RpcEnvelope {
                        version,
                        id: request_id.clone(),
                        sender: sender.clone(),
                        payload: RpcPayload::Sign(wire),
                    })
                    .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;
                self.validate_sign_session(&session)?;
                let requester_idx = self.validate_sender_binding(&peer, &sender)?;
                if !session.members.contains(&requester_idx) {
                    return Err(NodeError::InvalidSenderBinding(
                        "sign session does not include sender idx",
                    ));
                }
                let our_nonce_set = session
                    .nonces
                    .as_ref()
                    .and_then(|n| n.iter().find(|n| n.idx == self.share.idx))
                    .ok_or(NodeError::NonceUnavailable)?;
                if our_nonce_set.entries.len() != session.hashes.len() {
                    return Err(NodeError::InvalidSignSession(
                        "nonce entries must match hash count",
                    ));
                }
                let mut seen_hash_indices = std::collections::HashSet::new();
                let mut codes_by_hash: Vec<[u8; 32]> = vec![[0u8; 32]; session.hashes.len()];
                for entry in &our_nonce_set.entries {
                    let idx = entry.hash_index as usize;
                    if idx >= session.hashes.len() {
                        return Err(NodeError::InvalidSignSession(
                            "nonce hash index out of range",
                        ));
                    }
                    if !seen_hash_indices.insert(idx) {
                        return Err(NodeError::InvalidSignSession("duplicate nonce hash index"));
                    }
                    codes_by_hash[idx] = entry.code;
                }

                let signing_nonces = {
                    let mut pool = self
                        .pool
                        .lock()
                        .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
                    pool.take_outgoing_signing_nonces_many(requester_idx, &codes_by_hash)
                        .map_err(|_| NodeError::NonceUnavailable)?
                };

                let mut pkg =
                    sign_create_partial(&self.group, &session, &self.share, &signing_nonces, None)
                        .map_err(|e| NodeError::Core(e.to_string()))?;

                {
                    let mut pool = self
                        .pool
                        .lock()
                        .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
                    if pool.should_send_nonces_to(requester_idx) {
                        pkg.replenish = Some(
                            pool.generate_for_peer(
                                requester_idx,
                                self.config.options.nonce_pool.replenish_count,
                            )
                            .map_err(|e| NodeError::Core(e.to_string()))?,
                        );
                    }
                }

                RpcPayload::SignResponse(PartialSigPackageWire::from(pkg))
            }
            RpcPayload::Ecdh(wire) => {
                let sender_idx = self.validate_sender_binding(&peer, &sender)?;
                let req: EcdhPackage = parse_ecdh(&RpcEnvelope {
                    version,
                    id: request_id.clone(),
                    sender: sender.clone(),
                    payload: RpcPayload::Ecdh(wire),
                })
                .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;
                self.validate_ecdh_request(&req, sender_idx)?;
                let ecdh_pks = req.entries.iter().map(|e| e.ecdh_pk).collect::<Vec<_>>();
                let pkg = ecdh_create_from_share(&req.members, &self.share, &ecdh_pks)
                    .map_err(|e| NodeError::Core(e.to_string()))?;
                RpcPayload::Ecdh(EcdhPackageWire::from(pkg))
            }
            RpcPayload::SignResponse(_) | RpcPayload::OnboardResponse(_) | RpcPayload::Error(_) => {
                self.emit_event(NodeEvent::Bounced("invalid response payload".to_string()));
                return Err(NodeError::InvalidResponse);
            }
        };

        let response = OutgoingMessage {
            peer: peer.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: request_id.clone(),
                sender: self.local_sender_id(),
                payload,
            },
        };

        self.transport
            .send_response(ResponseHandle { peer, request_id }, response)
            .await
            .map_err(|e| {
                let message = e.to_string();
                self.emit_event(NodeEvent::Error(message.clone()));
                NodeError::Transport(message)
            })
    }

    fn ensure_ready(&self) -> NodeResult<()> {
        if !self.is_ready() {
            return Err(NodeError::NotReady);
        }
        Ok(())
    }

    fn member_idx_by_peer_pubkey(&self, peer: &str) -> NodeResult<u16> {
        self.member_idx_by_pubkey
            .get(peer)
            .copied()
            .ok_or(NodeError::PeerNotFound)
    }

    fn validate_sender_binding(&self, peer: &str, sender: &str) -> NodeResult<u16> {
        if peer != sender {
            return Err(NodeError::InvalidSenderBinding(
                "sender does not match transport peer",
            ));
        }
        self.member_idx_by_peer_pubkey(sender)
            .map_err(|_| NodeError::InvalidSenderBinding("sender is not a group member"))
    }

    fn local_sender_id(&self) -> String {
        self.local_pubkey_hex()
            .unwrap_or_else(|_| hex::encode(self.group.group_pk))
    }

    fn request_id(&self) -> String {
        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed);
        format!(
            "{}-{}-{}",
            self.clock.now_unix_seconds(),
            self.share.idx,
            seq
        )
    }

    fn check_and_track_request(&self, sender: &str, request_id: &str) -> NodeResult<()> {
        let now = self.clock.now_unix_seconds();
        let key = format!("{sender}:{request_id}");
        let ttl = self.config.options.request_ttl_secs;
        let cache_limit = self.config.options.request_cache_limit;

        let (issued_at, _, _) =
            parse_request_id_components(request_id).ok_or(NodeError::InvalidRequestIdFormat)?;
        if now > issued_at.saturating_add(ttl) {
            return Err(NodeError::StaleEnvelope);
        }

        let mut cache = self
            .replay_cache
            .lock()
            .map_err(|_| NodeError::Core("replay cache poisoned".to_string()))?;

        cache.retain(|_, seen_at| now.saturating_sub(*seen_at) <= ttl);
        if cache.contains_key(&key) {
            return Err(NodeError::ReplayRequestId);
        }

        cache.insert(key, now);
        if cache.len() > cache_limit {
            let mut entries: Vec<(String, u64)> =
                cache.iter().map(|(k, v)| (k.clone(), *v)).collect();
            entries.sort_by_key(|(_, seen_at)| *seen_at);
            let to_drop = cache.len().saturating_sub(cache_limit);
            for (entry_key, _) in entries.into_iter().take(to_drop) {
                cache.remove(&entry_key);
            }
        }

        Ok(())
    }

    fn assert_expected_response_peer(
        &self,
        expected_peer: &str,
        response: &IncomingMessage,
        context: &'static str,
    ) -> NodeResult<()> {
        if response.peer != expected_peer {
            return Err(NodeError::InvalidSenderBinding(context));
        }
        if response.envelope.sender != expected_peer {
            return Err(NodeError::InvalidSenderBinding(context));
        }
        Ok(())
    }

    fn get_cached_ecdh(&self, key: [u8; 33], now: u64) -> NodeResult<Option<[u8; 32]>> {
        let ttl = self.config.options.ecdh_cache_ttl_secs;
        let mut cache = self
            .ecdh_cache
            .lock()
            .map_err(|_| NodeError::Core("ecdh cache poisoned".to_string()))?;

        if let Some(entry) = cache.map.get(&key).cloned() {
            if now.saturating_sub(entry.stored_at) <= ttl {
                cache.order.retain(|k| *k != key);
                cache.order.push_back(key);
                return Ok(Some(entry.value));
            }
            cache.map.remove(&key);
            cache.order.retain(|k| *k != key);
        }
        Ok(None)
    }

    fn store_cached_ecdh(&self, key: [u8; 33], value: [u8; 32], now: u64) -> NodeResult<()> {
        let ttl = self.config.options.ecdh_cache_ttl_secs;
        let max_entries = self.config.options.ecdh_cache_max_entries.max(1);
        let mut cache = self
            .ecdh_cache
            .lock()
            .map_err(|_| NodeError::Core("ecdh cache poisoned".to_string()))?;

        let expired_keys: Vec<[u8; 33]> = cache
            .map
            .values()
            .filter(|entry| now.saturating_sub(entry.stored_at) > ttl)
            .map(|entry| entry.key)
            .collect();
        for expired in expired_keys {
            cache.map.remove(&expired);
            cache.order.retain(|k| *k != expired);
        }

        cache.map.insert(
            key,
            EcdhCacheEntry {
                key,
                value,
                stored_at: now,
            },
        );
        cache.order.retain(|k| *k != key);
        cache.order.push_back(key);

        while cache.map.len() > max_entries {
            if let Some(oldest) = cache.order.pop_front() {
                cache.map.remove(&oldest);
            } else {
                break;
            }
        }

        Ok(())
    }

    fn validate_payload_limits(&self, envelope: &RpcEnvelope) -> NodeResult<()> {
        if envelope.id.len() > self.config.options.max_request_id_len {
            return Err(NodeError::PayloadLimitExceeded("request id too large"));
        }
        if envelope.sender.len() > self.config.options.max_sender_len {
            return Err(NodeError::PayloadLimitExceeded("sender too large"));
        }

        match &envelope.payload {
            RpcPayload::Echo(v) if v.len() > self.config.options.max_echo_len => {
                return Err(NodeError::PayloadLimitExceeded("echo payload too large"));
            }
            RpcPayload::Sign(w) => {
                if w.hashes.len() > self.config.options.max_sign_batch {
                    return Err(NodeError::PayloadLimitExceeded(
                        "sign hashes exceed max_sign_batch",
                    ));
                }
                if let Some(content) = &w.content
                    && content.len() > self.config.options.max_sign_content_len
                {
                    return Err(NodeError::PayloadLimitExceeded("sign content too large"));
                }
            }
            RpcPayload::Ecdh(w) if w.entries.len() > self.config.options.max_ecdh_batch => {
                return Err(NodeError::PayloadLimitExceeded(
                    "ecdh entries exceed max_ecdh_batch",
                ));
            }
            _ => {}
        }

        Ok(())
    }

    fn emit_event(&self, event: NodeEvent) {
        let _ = self.events_tx.send(event);
    }

    fn validate_sign_session(
        &self,
        session: &bifrost_core::types::SignSessionPackage,
    ) -> NodeResult<()> {
        verify_session_package(&self.group, session).map_err(|e| NodeError::Core(e.to_string()))?;

        if session.hashes.len() > self.config.options.max_sign_batch {
            return Err(NodeError::InvalidSignSession(
                "hash count exceeds max_sign_batch",
            ));
        }
        if session.members.len() < self.group.threshold as usize {
            return Err(NodeError::InvalidSignSession(
                "session member count below group threshold",
            ));
        }
        let mut sorted_members = session.members.clone();
        sorted_members.sort_unstable();
        if sorted_members != session.members {
            return Err(NodeError::InvalidSignSession(
                "session members must be sorted ascending",
            ));
        }
        if sorted_members.windows(2).any(|w| w[0] == w[1]) {
            return Err(NodeError::InvalidSignSession(
                "session members contain duplicates",
            ));
        }
        if !sorted_members
            .iter()
            .all(|idx| self.group_member_indices.contains(idx))
        {
            return Err(NodeError::InvalidSignSession(
                "session includes non-group member idx",
            ));
        }
        if session.nonces.is_none() {
            return Err(NodeError::InvalidSignSession("missing nonces"));
        }
        let nonces = session
            .nonces
            .as_ref()
            .ok_or(NodeError::InvalidSignSession("missing nonces"))?;
        if nonces.len() != session.members.len() {
            return Err(NodeError::InvalidSignSession(
                "nonce member sets must match session members",
            ));
        }
        let mut seen_members = HashSet::new();
        for member_set in nonces {
            if !seen_members.insert(member_set.idx) {
                return Err(NodeError::InvalidSignSession(
                    "duplicate nonce member commitment set",
                ));
            }
            if !session.members.contains(&member_set.idx) {
                return Err(NodeError::InvalidSignSession(
                    "nonce member idx not present in session members",
                ));
            }
            if member_set.entries.len() != session.hashes.len() {
                return Err(NodeError::InvalidSignSession(
                    "member nonce entries must match hash count",
                ));
            }
            let mut seen = HashSet::new();
            for entry in &member_set.entries {
                let idx = entry.hash_index as usize;
                if idx >= session.hashes.len() {
                    return Err(NodeError::InvalidSignSession(
                        "nonce hash index out of range",
                    ));
                }
                if !seen.insert(idx) {
                    return Err(NodeError::InvalidSignSession("duplicate nonce hash index"));
                }
            }
        }
        if !session
            .members
            .iter()
            .all(|member| seen_members.contains(member))
        {
            return Err(NodeError::InvalidSignSession(
                "missing nonce commitment set for session member",
            ));
        }

        Ok(())
    }

    fn validate_ecdh_request(&self, req: &EcdhPackage, sender_idx: u16) -> NodeResult<()> {
        if req.idx != sender_idx {
            return Err(NodeError::InvalidSenderBinding(
                "ecdh package idx does not match sender idx",
            ));
        }
        if req.members.len() < self.group.threshold as usize {
            return Err(NodeError::InvalidEcdhBatch(
                "ecdh members below group threshold",
            ));
        }
        let mut members = req.members.clone();
        members.sort_unstable();
        if members != req.members {
            return Err(NodeError::InvalidEcdhBatch(
                "ecdh members must be sorted ascending",
            ));
        }
        if members.windows(2).any(|w| w[0] == w[1]) {
            return Err(NodeError::InvalidEcdhBatch(
                "ecdh members contain duplicates",
            ));
        }
        if !members
            .iter()
            .all(|idx| self.group_member_indices.contains(idx))
        {
            return Err(NodeError::InvalidEcdhBatch(
                "ecdh request includes non-group member idx",
            ));
        }
        if !members.contains(&sender_idx) {
            return Err(NodeError::InvalidSenderBinding(
                "ecdh members do not include sender idx",
            ));
        }
        if !members.contains(&self.share.idx) {
            return Err(NodeError::InvalidEcdhBatch(
                "ecdh members do not include local idx",
            ));
        }
        let mut seen = HashSet::new();
        for entry in &req.entries {
            if !seen.insert(entry.ecdh_pk) {
                return Err(NodeError::InvalidEcdhBatch("duplicate ecdh target pubkey"));
            }
        }
        Ok(())
    }

    fn local_pubkey_hex(&self) -> NodeResult<String> {
        let sk = SecretKey::from_slice(&self.share.seckey)
            .map_err(|e| NodeError::Core(e.to_string()))?;
        Ok(hex::encode(
            sk.public_key().to_encoded_point(true).as_bytes(),
        ))
    }

    fn local_policy_profile_for(&self, peer: &str) -> NodeResult<PeerScopedPolicyProfile> {
        let now = self.clock.now_unix_seconds();
        let policies = self
            .policies
            .lock()
            .map_err(|_| NodeError::Core("policy map poisoned".to_string()))?;
        let policy = policies.get(peer).copied().ok_or(NodeError::PeerNotFound)?;
        Ok(PeerScopedPolicyProfile {
            for_peer: decode_33(peer)?,
            revision: now,
            updated: now,
            block_all: policy.block_all,
            request: core_method_policy(policy.request),
            respond: core_method_policy(policy.respond),
        })
    }

    fn store_remote_scoped_policy(
        &self,
        peer: &str,
        profile: PeerScopedPolicyProfile,
    ) -> NodeResult<()> {
        let local = self.local_pubkey_hex()?;
        if hex::encode(profile.for_peer) != local {
            return Ok(());
        }
        let mut remote = self
            .remote_scoped_policies
            .lock()
            .map_err(|_| NodeError::Core("remote policy map poisoned".to_string()))?;
        remote.insert(peer.to_string(), profile);
        Ok(())
    }

    async fn refresh_unknown_policy_peers(&self, method: OperationMethod) -> NodeResult<()> {
        let peers = self
            .config
            .peers
            .iter()
            .map(|p| p.pubkey.clone())
            .collect::<Vec<_>>();
        for peer in peers {
            if !self.has_remote_profile_for(&peer, method)? {
                let _ = self.ping(&peer).await;
            }
        }
        Ok(())
    }

    fn has_remote_profile_for(&self, peer: &str, method: OperationMethod) -> NodeResult<bool> {
        let remote = self
            .remote_scoped_policies
            .lock()
            .map_err(|_| NodeError::Core("remote policy map poisoned".to_string()))?;
        let Some(profile) = remote.get(peer) else {
            return Ok(false);
        };
        Ok(profile_method_allowed(profile, false, method))
    }

    fn enforce_outbound_request_policy(
        &self,
        peer: &str,
        method: OperationMethod,
    ) -> NodeResult<()> {
        let policies = self
            .policies
            .lock()
            .map_err(|_| NodeError::Core("policy map poisoned".to_string()))?;
        let Some(policy) = policies.get(peer).copied() else {
            return Err(NodeError::PeerNotFound);
        };
        if !method_allowed(policy, true, method) {
            return Err(NodeError::PolicyDenied(
                "outbound request denied by local policy",
            ));
        }
        Ok(())
    }

    fn is_respond_allowed(&self, peer: &str, method: OperationMethod) -> NodeResult<bool> {
        let policies = self
            .policies
            .lock()
            .map_err(|_| NodeError::Core("policy map poisoned".to_string()))?;
        let Some(policy) = policies.get(peer).copied() else {
            return Err(NodeError::PeerNotFound);
        };
        Ok(method_allowed(policy, false, method))
    }

    fn select_signing_peers(&self, method: OperationMethod) -> NodeResult<Vec<String>> {
        let needed = self.group.threshold.saturating_sub(1) as usize;
        if needed == 0 {
            return Ok(Vec::new());
        }

        let pool = self
            .pool
            .lock()
            .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;

        let mut eligible: Vec<String> = self
            .config
            .peers
            .iter()
            .filter_map(|peer| {
                let local_allowed = self
                    .policies
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&peer.pubkey).copied())
                    .map(|p| method_allowed(p, true, method))
                    .unwrap_or(false);
                if !local_allowed {
                    return None;
                }
                let idx = self.member_idx_by_peer_pubkey(&peer.pubkey).ok()?;
                if method == OperationMethod::Sign && !pool.can_sign(idx) {
                    return None;
                }
                let remote = self
                    .remote_scoped_policies
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&peer.pubkey).cloned());
                match method {
                    OperationMethod::Sign | OperationMethod::Ecdh => {
                        if remote
                            .as_ref()
                            .map(|v| profile_method_allowed(v, false, method))
                            != Some(true)
                        {
                            return None;
                        }
                    }
                    _ => {}
                }
                Some(peer.pubkey.clone())
            })
            .collect();

        if eligible.len() < needed {
            return Err(NodeError::InsufficientPeers);
        }
        shuffle_peers(&mut eligible);
        Ok(eligible.into_iter().take(needed).collect())
    }
}

fn method_allowed(policy: PeerPolicy, request_side: bool, method: OperationMethod) -> bool {
    if policy.block_all {
        return false;
    }
    let scope = if request_side {
        policy.request
    } else {
        policy.respond
    };
    match method {
        OperationMethod::Echo => scope.echo,
        OperationMethod::Ping => scope.ping,
        OperationMethod::Onboard => scope.onboard,
        OperationMethod::Sign => scope.sign,
        OperationMethod::Ecdh => scope.ecdh,
    }
}

fn profile_method_allowed(
    profile: &PeerScopedPolicyProfile,
    request_side: bool,
    method: OperationMethod,
) -> bool {
    let policy = PeerPolicy {
        block_all: profile.block_all,
        request: node_method_policy(profile.request.clone()),
        respond: node_method_policy(profile.respond.clone()),
    };
    method_allowed(policy, request_side, method)
}

fn node_method_policy(value: bifrost_core::types::MethodPolicy) -> MethodPolicy {
    MethodPolicy {
        echo: value.echo,
        ping: value.ping,
        onboard: value.onboard,
        sign: value.sign,
        ecdh: value.ecdh,
    }
}

fn core_method_policy(value: MethodPolicy) -> bifrost_core::types::MethodPolicy {
    bifrost_core::types::MethodPolicy {
        echo: value.echo,
        ping: value.ping,
        onboard: value.onboard,
        sign: value.sign,
        ecdh: value.ecdh,
    }
}

fn shuffle_peers(peers: &mut [String]) {
    if peers.len() <= 1 {
        return;
    }
    let mut rng = OsRng;
    for i in (1..peers.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        peers.swap(i, j);
    }
}

fn decode_33(hex33: &str) -> NodeResult<[u8; 33]> {
    let raw = hex::decode(hex33).map_err(|e| NodeError::Core(e.to_string()))?;
    if raw.len() != 33 {
        return Err(NodeError::Core("expected 33-byte pubkey".to_string()));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_request_id_components(request_id: &str) -> Option<(u64, u16, u64)> {
    let mut parts = request_id.split('-');
    let ts = parts.next()?.parse::<u64>().ok()?;
    let idx = parts.next()?.parse::<u16>().ok()?;
    let seq = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((ts, idx, seq))
}

#[cfg(test)]
#[allow(clippy::manual_async_fn)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use bifrost_codec::rpc::{RpcEnvelope, RpcPayload};
    use bifrost_codec::wire::{EcdhEntryWire, EcdhPackageWire, PartialSigPackageWire};
    use bifrost_codec::wire::{OnboardRequestWire, SignSessionPackageWire};
    use bifrost_core::create_session_package;
    use bifrost_core::types::{
        DerivedPublicNonce, GroupPackage, IndexedPublicNonceCommitment, MemberNonceCommitmentSet,
        MemberPackage, SharePackage, SignSessionTemplate,
    };
    use bifrost_core::{create_partial_sig_package, local_pubkey_from_share};
    use bifrost_transport::{
        Clock, IncomingMessage, OutgoingMessage, ResponseHandle, Transport, TransportError,
        TransportResult,
    };
    use frost_secp256k1_tr_unofficial as frost;
    use futures::executor::block_on;
    use k256::SecretKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::{OsRng, RngCore};

    use super::BifrostNode;
    use crate::error::NodeError;
    use crate::types::{BifrostNodeOptions, NodeEvent};

    #[derive(Default)]
    struct TestClock;

    impl Clock for TestClock {
        fn now_unix_seconds(&self) -> u64 {
            1_700_000_000
        }
    }

    struct MutableClock {
        now: Mutex<u64>,
    }

    impl MutableClock {
        fn new(now: u64) -> Self {
            Self {
                now: Mutex::new(now),
            }
        }

        fn set(&self, next: u64) {
            if let Ok(mut now) = self.now.lock() {
                *now = next;
            }
        }
    }

    impl Clock for MutableClock {
        fn now_unix_seconds(&self) -> u64 {
            self.now.lock().map(|v| *v).unwrap_or(0)
        }
    }

    #[derive(Default)]
    struct TestTransport {
        cast_responses: Mutex<Vec<Vec<IncomingMessage>>>,
        frost_peer: Mutex<Option<FrostPeerCtx>>,
        cast_count: Mutex<usize>,
    }

    struct FrostPeerCtx {
        group: GroupPackage,
        share: SharePackage,
        signing_nonces: HashMap<[u8; 32], frost::round1::SigningNonces>,
    }

    impl Transport for TestTransport {
        fn connect(&self) -> impl std::future::Future<Output = TransportResult<()>> + Send {
            async move { Ok(()) }
        }

        fn close(&self) -> impl std::future::Future<Output = TransportResult<()>> + Send {
            async move { Ok(()) }
        }

        fn request(
            &self,
            msg: OutgoingMessage,
            _timeout_ms: u64,
        ) -> impl std::future::Future<Output = TransportResult<IncomingMessage>> + Send {
            async move {
                match msg.envelope.payload {
                    RpcPayload::Echo(challenge) => Ok(IncomingMessage {
                        peer: msg.peer.clone(),
                        envelope: RpcEnvelope {
                            version: 1,
                            id: msg.envelope.id,
                            sender: msg.peer,
                            payload: RpcPayload::Echo(challenge),
                        },
                    }),
                    RpcPayload::Ping(_) => Ok(IncomingMessage {
                        peer: msg.peer.clone(),
                        envelope: RpcEnvelope {
                            version: 1,
                            id: msg.envelope.id,
                            sender: msg.peer,
                            payload: RpcPayload::Ping(bifrost_codec::wire::PingPayloadWire {
                                version: 1,
                                nonces: None,
                                policy_profile: Some(
                                    bifrost_codec::wire::PeerScopedPolicyProfileWire {
                                        for_peer: msg.envelope.sender,
                                        revision: 1,
                                        updated: 1,
                                        block_all: false,
                                        request: bifrost_codec::wire::MethodPolicyWire {
                                            echo: true,
                                            ping: true,
                                            onboard: true,
                                            sign: true,
                                            ecdh: true,
                                        },
                                        respond: bifrost_codec::wire::MethodPolicyWire {
                                            echo: true,
                                            ping: true,
                                            onboard: true,
                                            sign: true,
                                            ecdh: true,
                                        },
                                    },
                                ),
                            }),
                        },
                    }),
                    RpcPayload::OnboardRequest(_) => {
                        let group = if let Some(ctx) = self
                            .frost_peer
                            .lock()
                            .map_err(|_| TransportError::Backend("poisoned".to_string()))?
                            .as_ref()
                        {
                            ctx.group.clone()
                        } else {
                            GroupPackage {
                                group_pk: [9; 33],
                                threshold: 2,
                                members: vec![
                                    MemberPackage {
                                        idx: 1,
                                        pubkey: [2; 33],
                                    },
                                    MemberPackage {
                                        idx: 2,
                                        pubkey: [3; 33],
                                    },
                                ],
                            }
                        };
                        Ok(IncomingMessage {
                            peer: msg.peer.clone(),
                            envelope: RpcEnvelope {
                                version: 1,
                                id: msg.envelope.id,
                                sender: msg.peer,
                                payload: RpcPayload::OnboardResponse(
                                    bifrost_codec::wire::OnboardResponseWire {
                                        group: group.into(),
                                        nonces: vec![bifrost_codec::wire::DerivedPublicNonceWire {
                                            binder_pn: hex::encode([2u8; 33]),
                                            hidden_pn: hex::encode([3u8; 33]),
                                            code: hex::encode([4u8; 32]),
                                        }],
                                    },
                                ),
                            },
                        })
                    }
                    _ => Err(TransportError::Backend(
                        "request not supported in this test transport".to_string(),
                    )),
                }
            }
        }

        fn cast(
            &self,
            msg: OutgoingMessage,
            peers: &[String],
            _threshold: usize,
            _timeout_ms: u64,
        ) -> impl std::future::Future<Output = TransportResult<Vec<IncomingMessage>>> + Send
        {
            async move {
                {
                    let mut count = self
                        .cast_count
                        .lock()
                        .map_err(|_| TransportError::Backend("poisoned".to_string()))?;
                    *count = count.saturating_add(1);
                }
                if let Some(v) = self
                    .cast_responses
                    .lock()
                    .map_err(|_| TransportError::Backend("poisoned".to_string()))?
                    .pop()
                {
                    return Ok(v);
                }

                let peer = peers
                    .first()
                    .cloned()
                    .ok_or_else(|| TransportError::Backend("missing peer".to_string()))?;

                match msg.envelope.payload {
                    bifrost_codec::rpc::RpcPayload::Sign(wire) => {
                        let mut guard = self
                            .frost_peer
                            .lock()
                            .map_err(|_| TransportError::Backend("poisoned".to_string()))?;
                        let Some(ctx) = guard.as_mut() else {
                            return Err(TransportError::Backend(
                                "missing frost test context".to_string(),
                            ));
                        };

                        let session: bifrost_core::types::SignSessionPackage =
                            wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                                TransportError::Backend(e.to_string())
                            })?;
                        let member_nonce = session
                            .nonces
                            .as_ref()
                            .and_then(|n| n.iter().find(|n| n.idx == ctx.share.idx))
                            .ok_or_else(|| {
                                TransportError::Backend("missing member nonce".to_string())
                            })?;
                        let mut signing_nonces: Vec<Option<frost::round1::SigningNonces>> =
                            (0..member_nonce.entries.len()).map(|_| None).collect();
                        for entry in &member_nonce.entries {
                            let idx = entry.hash_index as usize;
                            if idx >= signing_nonces.len() {
                                return Err(TransportError::Backend(
                                    "nonce hash index out of range".to_string(),
                                ));
                            }
                            signing_nonces[idx] =
                                Some(ctx.signing_nonces.remove(&entry.code).ok_or_else(|| {
                                    TransportError::Backend("missing signing nonces".to_string())
                                })?);
                        }
                        let signing_nonces = signing_nonces
                            .into_iter()
                            .map(|v| {
                                v.ok_or_else(|| {
                                    TransportError::Backend(
                                        "missing indexed signing nonces".to_string(),
                                    )
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()?;

                        let pkg = create_partial_sig_package(
                            &ctx.group,
                            &session,
                            &ctx.share,
                            &signing_nonces,
                            local_pubkey_from_share(&ctx.share)
                                .map_err(|e| TransportError::Backend(e.to_string()))?,
                        )
                        .map_err(|e| TransportError::Backend(e.to_string()))?;

                        Ok(vec![IncomingMessage {
                            peer,
                            envelope: bifrost_codec::rpc::RpcEnvelope {
                                version: 1,
                                id: "sign-resp".to_string(),
                                sender: hex::encode(
                                    local_pubkey_from_share(&ctx.share)
                                        .map_err(|e| TransportError::Backend(e.to_string()))?,
                                ),
                                payload: bifrost_codec::rpc::RpcPayload::SignResponse(
                                    PartialSigPackageWire::from(pkg),
                                ),
                            },
                        }])
                    }
                    bifrost_codec::rpc::RpcPayload::Ecdh(wire) => {
                        let target =
                            wire.entries
                                .first()
                                .map(|e| e.ecdh_pk.clone())
                                .ok_or_else(|| {
                                    TransportError::Backend("missing ecdh target".to_string())
                                })?;

                        let sk = SecretKey::from_slice(&[14u8; 32])
                            .map_err(|e| TransportError::Backend(e.to_string()))?;
                        let keyshare =
                            hex::encode(sk.public_key().to_encoded_point(true).as_bytes());

                        Ok(vec![IncomingMessage {
                            peer,
                            envelope: bifrost_codec::rpc::RpcEnvelope {
                                version: 1,
                                id: "ecdh-resp".to_string(),
                                sender: hex::encode([3u8; 33]),
                                payload: bifrost_codec::rpc::RpcPayload::Ecdh(EcdhPackageWire {
                                    idx: 2,
                                    members: vec![1, 2],
                                    entries: vec![EcdhEntryWire {
                                        ecdh_pk: target,
                                        keyshare,
                                    }],
                                }),
                            },
                        }])
                    }
                    _ => Err(TransportError::Backend(
                        "unsupported cast payload".to_string(),
                    )),
                }
            }
        }

        fn send_response(
            &self,
            _handle: ResponseHandle,
            _response: OutgoingMessage,
        ) -> impl std::future::Future<Output = TransportResult<()>> + Send {
            async move { Ok(()) }
        }

        fn next_incoming(
            &self,
        ) -> impl std::future::Future<Output = TransportResult<IncomingMessage>> + Send {
            async move {
                Err(TransportError::Backend(
                    "next_incoming not used in this test".to_string(),
                ))
            }
        }
    }

    fn sample_group_and_share() -> (GroupPackage, SharePackage, String) {
        let peer_pubkey_hex = hex::encode([3u8; 33]);
        (
            GroupPackage {
                group_pk: [9; 33],
                threshold: 2,
                members: vec![
                    MemberPackage {
                        idx: 1,
                        pubkey: [2; 33],
                    },
                    MemberPackage {
                        idx: 2,
                        pubkey: [3; 33],
                    },
                ],
            },
            SharePackage {
                idx: 1,
                seckey: [11; 32],
            },
            peer_pubkey_hex,
        )
    }

    #[test]
    fn sign_flow_returns_signature() {
        let (shares, pubkey_pkg) =
            frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, OsRng)
                .expect("dealer");
        let mut material = Vec::new();
        for (id, secret_share) in shares {
            let key_package = frost::keys::KeyPackage::try_from(secret_share).expect("key package");
            material.push((id, key_package));
        }
        material.sort_by_key(|(id, _)| id.serialize());
        let (local_id, local_key) = material.remove(0);
        let (peer_id, peer_key) = material.remove(0);

        let mut group_pk = [0u8; 33];
        group_pk.copy_from_slice(
            &pubkey_pkg
                .verifying_key()
                .serialize()
                .expect("serialize group key"),
        );
        let mut local_member_pk = [0u8; 33];
        local_member_pk.copy_from_slice(
            &local_key
                .verifying_share()
                .serialize()
                .expect("serialize local member key"),
        );
        let mut peer_member_pk = [0u8; 33];
        peer_member_pk.copy_from_slice(
            &peer_key
                .verifying_share()
                .serialize()
                .expect("serialize peer member key"),
        );

        let local_idx = local_id.serialize()[31] as u16;
        let peer_idx = peer_id.serialize()[31] as u16;
        let mut local_seckey = [0u8; 32];
        local_seckey.copy_from_slice(&local_key.signing_share().serialize());

        let group = GroupPackage {
            group_pk,
            threshold: 2,
            members: vec![
                MemberPackage {
                    idx: local_idx,
                    pubkey: local_member_pk,
                },
                MemberPackage {
                    idx: peer_idx,
                    pubkey: peer_member_pk,
                },
            ],
        };
        let share = SharePackage {
            idx: local_idx,
            seckey: local_seckey,
        };
        let peer_pubkey_hex = hex::encode(peer_member_pk);

        let mut options = BifrostNodeOptions::default();
        options.nonce_pool.critical_threshold = 0;

        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group.clone(),
            share,
            vec![peer_pubkey_hex.clone()],
            transport.clone(),
            clock,
            Some(options),
        )
        .expect("node");

        let (peer_signing_nonces, peer_commitments) =
            frost::round1::commit(peer_key.signing_share(), &mut OsRng);
        let mut code = [0u8; 32];
        OsRng.fill_bytes(&mut code);

        let mut binder_pn = [0u8; 33];
        binder_pn.copy_from_slice(
            &peer_commitments
                .binding()
                .serialize()
                .expect("serialize binding commitment"),
        );
        let mut hidden_pn = [0u8; 33];
        hidden_pn.copy_from_slice(
            &peer_commitments
                .hiding()
                .serialize()
                .expect("serialize hiding commitment"),
        );

        {
            let mut pool = node.pool.lock().expect("pool");
            pool.store_incoming(
                peer_idx,
                vec![DerivedPublicNonce {
                    binder_pn,
                    hidden_pn,
                    code,
                }],
            );
        }
        {
            let mut ctx = transport.frost_peer.lock().expect("peer ctx");
            let mut signing_nonces = HashMap::new();
            signing_nonces.insert(code, peer_signing_nonces);
            *ctx = Some(FrostPeerCtx {
                group,
                share: SharePackage {
                    idx: peer_idx,
                    seckey: {
                        let mut s = [0u8; 32];
                        s.copy_from_slice(&peer_key.signing_share().serialize());
                        s
                    },
                },
                signing_nonces,
            });
        }

        let sighash = [8u8; 32];

        block_on(node.connect()).expect("connect");
        let sig = block_on(node.sign(sighash)).expect("sign");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_batch_flow_returns_signatures() {
        let (shares, pubkey_pkg) =
            frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, OsRng)
                .expect("dealer");
        let mut material = Vec::new();
        for (id, secret_share) in shares {
            let key_package = frost::keys::KeyPackage::try_from(secret_share).expect("key package");
            material.push((id, key_package));
        }
        material.sort_by_key(|(id, _)| id.serialize());
        let (local_id, local_key) = material.remove(0);
        let (peer_id, peer_key) = material.remove(0);

        let mut group_pk = [0u8; 33];
        group_pk.copy_from_slice(
            &pubkey_pkg
                .verifying_key()
                .serialize()
                .expect("serialize group key"),
        );
        let mut local_member_pk = [0u8; 33];
        local_member_pk.copy_from_slice(
            &local_key
                .verifying_share()
                .serialize()
                .expect("serialize local member key"),
        );
        let mut peer_member_pk = [0u8; 33];
        peer_member_pk.copy_from_slice(
            &peer_key
                .verifying_share()
                .serialize()
                .expect("serialize peer member key"),
        );

        let local_idx = local_id.serialize()[31] as u16;
        let peer_idx = peer_id.serialize()[31] as u16;
        let mut local_seckey = [0u8; 32];
        local_seckey.copy_from_slice(&local_key.signing_share().serialize());

        let group = GroupPackage {
            group_pk,
            threshold: 2,
            members: vec![
                MemberPackage {
                    idx: local_idx,
                    pubkey: local_member_pk,
                },
                MemberPackage {
                    idx: peer_idx,
                    pubkey: peer_member_pk,
                },
            ],
        };
        let share = SharePackage {
            idx: local_idx,
            seckey: local_seckey,
        };
        let peer_pubkey_hex = hex::encode(peer_member_pk);

        let mut options = BifrostNodeOptions::default();
        options.nonce_pool.critical_threshold = 0;

        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group.clone(),
            share,
            vec![peer_pubkey_hex.clone()],
            transport.clone(),
            clock,
            Some(options),
        )
        .expect("node");

        let mut incoming_nonces = Vec::new();
        let mut peer_signing_nonces_map = HashMap::new();
        for _ in 0..2 {
            let (peer_signing_nonces, peer_commitments) =
                frost::round1::commit(peer_key.signing_share(), &mut OsRng);
            let mut code = [0u8; 32];
            OsRng.fill_bytes(&mut code);

            let mut binder_pn = [0u8; 33];
            binder_pn.copy_from_slice(
                &peer_commitments
                    .binding()
                    .serialize()
                    .expect("serialize binding commitment"),
            );
            let mut hidden_pn = [0u8; 33];
            hidden_pn.copy_from_slice(
                &peer_commitments
                    .hiding()
                    .serialize()
                    .expect("serialize hiding commitment"),
            );

            incoming_nonces.push(DerivedPublicNonce {
                binder_pn,
                hidden_pn,
                code,
            });
            peer_signing_nonces_map.insert(code, peer_signing_nonces);
        }

        {
            let mut pool = node.pool.lock().expect("pool");
            pool.store_incoming(peer_idx, incoming_nonces);
        }
        {
            let mut ctx = transport.frost_peer.lock().expect("peer ctx");
            *ctx = Some(FrostPeerCtx {
                group,
                share: SharePackage {
                    idx: peer_idx,
                    seckey: {
                        let mut s = [0u8; 32];
                        s.copy_from_slice(&peer_key.signing_share().serialize());
                        s
                    },
                },
                signing_nonces: peer_signing_nonces_map,
            });
        }

        let messages = vec![[8u8; 32], [9u8; 32]];

        block_on(node.connect()).expect("connect");
        let sigs = block_on(node.sign_batch(&messages)).expect("sign batch");
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].len(), 64);
        assert_eq!(sigs[1].len(), 64);
    }

    #[test]
    fn sign_batch_rejects_empty_messages() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(group, share, vec![peer_pubkey_hex], transport, clock, None)
            .expect("node");
        block_on(node.connect()).expect("connect");
        let err = block_on(node.sign_batch(&[])).expect_err("must reject empty batch");
        assert!(matches!(err, NodeError::InvalidSignBatch(_)));
    }

    #[test]
    fn sign_queue_processes_multiple_chunks() {
        let (shares, pubkey_pkg) =
            frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, OsRng)
                .expect("dealer");
        let mut material = Vec::new();
        for (id, secret_share) in shares {
            let key_package = frost::keys::KeyPackage::try_from(secret_share).expect("key package");
            material.push((id, key_package));
        }
        material.sort_by_key(|(id, _)| id.serialize());
        let (local_id, local_key) = material.remove(0);
        let (peer_id, peer_key) = material.remove(0);

        let mut group_pk = [0u8; 33];
        group_pk.copy_from_slice(
            &pubkey_pkg
                .verifying_key()
                .serialize()
                .expect("serialize group key"),
        );
        let mut local_member_pk = [0u8; 33];
        local_member_pk.copy_from_slice(
            &local_key
                .verifying_share()
                .serialize()
                .expect("serialize local member key"),
        );
        let mut peer_member_pk = [0u8; 33];
        peer_member_pk.copy_from_slice(
            &peer_key
                .verifying_share()
                .serialize()
                .expect("serialize peer member key"),
        );

        let local_idx = local_id.serialize()[31] as u16;
        let peer_idx = peer_id.serialize()[31] as u16;
        let mut local_seckey = [0u8; 32];
        local_seckey.copy_from_slice(&local_key.signing_share().serialize());

        let group = GroupPackage {
            group_pk,
            threshold: 2,
            members: vec![
                MemberPackage {
                    idx: local_idx,
                    pubkey: local_member_pk,
                },
                MemberPackage {
                    idx: peer_idx,
                    pubkey: peer_member_pk,
                },
            ],
        };
        let share = SharePackage {
            idx: local_idx,
            seckey: local_seckey,
        };
        let peer_pubkey_hex = hex::encode(peer_member_pk);

        let mut options = BifrostNodeOptions::default();
        options.nonce_pool.critical_threshold = 0;
        options.max_sign_batch = 1;

        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group.clone(),
            share,
            vec![peer_pubkey_hex.clone()],
            transport.clone(),
            clock,
            Some(options),
        )
        .expect("node");

        let mut incoming_nonces = Vec::new();
        let mut peer_signing_nonces_map = HashMap::new();
        for _ in 0..3 {
            let (peer_signing_nonces, peer_commitments) =
                frost::round1::commit(peer_key.signing_share(), &mut OsRng);
            let mut code = [0u8; 32];
            OsRng.fill_bytes(&mut code);

            let mut binder_pn = [0u8; 33];
            binder_pn.copy_from_slice(
                &peer_commitments
                    .binding()
                    .serialize()
                    .expect("serialize binding commitment"),
            );
            let mut hidden_pn = [0u8; 33];
            hidden_pn.copy_from_slice(
                &peer_commitments
                    .hiding()
                    .serialize()
                    .expect("serialize hiding commitment"),
            );

            incoming_nonces.push(DerivedPublicNonce {
                binder_pn,
                hidden_pn,
                code,
            });
            peer_signing_nonces_map.insert(code, peer_signing_nonces);
        }

        {
            let mut pool = node.pool.lock().expect("pool");
            pool.store_incoming(peer_idx, incoming_nonces);
        }
        {
            let mut ctx = transport.frost_peer.lock().expect("peer ctx");
            *ctx = Some(FrostPeerCtx {
                group,
                share: SharePackage {
                    idx: peer_idx,
                    seckey: {
                        let mut s = [0u8; 32];
                        s.copy_from_slice(&peer_key.signing_share().serialize());
                        s
                    },
                },
                signing_nonces: peer_signing_nonces_map,
            });
        }

        block_on(node.connect()).expect("connect");
        let sigs = block_on(node.sign_queue(&[[1u8; 32], [2u8; 32], [3u8; 32]])).expect("queue");
        assert_eq!(sigs.len(), 3);
    }

    #[test]
    fn echo_ping_onboard_happy_paths() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");

        block_on(node.connect()).expect("connect");
        let echo = block_on(node.echo(&peer_pubkey_hex, "hello")).expect("echo");
        assert_eq!(echo, "hello");

        let ping = block_on(node.ping(&peer_pubkey_hex)).expect("ping");
        assert_eq!(ping.version, 1);

        let onboard = block_on(node.onboard(&peer_pubkey_hex)).expect("onboard");
        assert_eq!(onboard.group.threshold, 2);
        assert_eq!(onboard.nonces.len(), 1);
    }

    #[test]
    fn ecdh_flow_returns_secret() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport.clone(),
            clock,
            None,
        )
        .expect("node");

        {
            let mut pool = node.pool.lock().expect("pool");
            let incoming = (0..6)
                .map(|i| DerivedPublicNonce {
                    binder_pn: [2; 33],
                    hidden_pn: [3; 33],
                    code: [i as u8; 32],
                })
                .collect::<Vec<_>>();
            pool.store_incoming(2, incoming);
        }

        let sk = SecretKey::from_slice(&[13u8; 32]).expect("secret key");
        let mut target_pk = [0u8; 33];
        target_pk.copy_from_slice(sk.public_key().to_encoded_point(true).as_bytes());

        block_on(node.connect()).expect("connect");
        let secret = block_on(node.ecdh(target_pk)).expect("ecdh");
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn ecdh_batch_processes_multiple_chunks() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(MutableClock::new(1_700_000_000));
        let mut options = BifrostNodeOptions::default();
        options.nonce_pool.critical_threshold = 0;
        options.max_ecdh_batch = 1;
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport.clone(),
            clock,
            Some(options),
        )
        .expect("node");

        {
            let mut pool = node.pool.lock().expect("pool");
            let incoming = (0..6)
                .map(|i| DerivedPublicNonce {
                    binder_pn: [2; 33],
                    hidden_pn: [3; 33],
                    code: [i as u8; 32],
                })
                .collect::<Vec<_>>();
            pool.store_incoming(2, incoming);
        }

        let sk1 = SecretKey::from_slice(&[21u8; 32]).expect("secret key");
        let mut target1 = [0u8; 33];
        target1.copy_from_slice(sk1.public_key().to_encoded_point(true).as_bytes());
        let sk2 = SecretKey::from_slice(&[22u8; 32]).expect("secret key");
        let mut target2 = [0u8; 33];
        target2.copy_from_slice(sk2.public_key().to_encoded_point(true).as_bytes());

        block_on(node.connect()).expect("connect");
        let out = block_on(node.ecdh_batch(&[target1, target2])).expect("ecdh batch");
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn ecdh_uses_cache_for_repeated_pubkey() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(MutableClock::new(1_700_000_000));
        let mut options = BifrostNodeOptions::default();
        options.nonce_pool.critical_threshold = 0;
        options.ecdh_cache_ttl_secs = 300;
        options.ecdh_cache_max_entries = 16;
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport.clone(),
            clock,
            Some(options),
        )
        .expect("node");

        {
            let mut pool = node.pool.lock().expect("pool");
            pool.store_incoming(
                2,
                vec![DerivedPublicNonce {
                    binder_pn: [2; 33],
                    hidden_pn: [3; 33],
                    code: [1u8; 32],
                }],
            );
        }

        let sk = SecretKey::from_slice(&[15u8; 32]).expect("secret key");
        let mut target_pk = [0u8; 33];
        target_pk.copy_from_slice(sk.public_key().to_encoded_point(true).as_bytes());

        block_on(node.connect()).expect("connect");
        let first = block_on(node.ecdh(target_pk)).expect("ecdh");
        let second = block_on(node.ecdh(target_pk)).expect("ecdh cached");
        assert_eq!(first, second);

        let cast_count = *transport.cast_count.lock().expect("count");
        assert_eq!(cast_count, 1);
    }

    #[test]
    fn ecdh_cache_entry_expires_after_ttl() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(MutableClock::new(1_700_000_000));
        let mut options = BifrostNodeOptions::default();
        options.nonce_pool.critical_threshold = 0;
        options.ecdh_cache_ttl_secs = 1;
        options.ecdh_cache_max_entries = 16;
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport.clone(),
            clock.clone(),
            Some(options),
        )
        .expect("node");

        {
            let mut pool = node.pool.lock().expect("pool");
            pool.store_incoming(
                2,
                vec![DerivedPublicNonce {
                    binder_pn: [2; 33],
                    hidden_pn: [3; 33],
                    code: [1u8; 32],
                }],
            );
        }

        let sk = SecretKey::from_slice(&[16u8; 32]).expect("secret key");
        let mut target_pk = [0u8; 33];
        target_pk.copy_from_slice(sk.public_key().to_encoded_point(true).as_bytes());

        block_on(node.connect()).expect("connect");
        let _ = block_on(node.ecdh(target_pk)).expect("ecdh");
        clock.set(1_700_000_003);
        let _ = block_on(node.ecdh(target_pk)).expect("ecdh recalc");

        let cast_count = *transport.cast_count.lock().expect("count");
        assert_eq!(cast_count, 2);
    }

    #[test]
    fn connect_emits_ready_and_info_events() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(group, share, vec![peer_pubkey_hex], transport, clock, None)
            .expect("node");
        let mut events = node.subscribe_events();

        block_on(node.connect()).expect("connect");
        let first = block_on(events.recv()).expect("event");
        let second = block_on(events.recv()).expect("event");
        assert_eq!(first, NodeEvent::Ready);
        assert_eq!(second, NodeEvent::Info("connected".to_string()));
    }

    #[test]
    fn handle_incoming_emits_message_event() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");
        let mut events = node.subscribe_events();

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "1700000000-2-6".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Echo("hello".to_string()),
            },
        };

        block_on(node.handle_incoming(msg)).expect("handle incoming");
        let event = block_on(events.recv()).expect("event");
        assert_eq!(event, NodeEvent::Message("1700000000-2-6".to_string()));
    }

    #[test]
    fn handle_incoming_sign_rejects_missing_nonces() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group.clone(),
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let template = SignSessionTemplate {
            members: vec![1, 2],
            hashes: vec![[1u8; 32]],
            content: None,
            kind: "message".to_string(),
            stamp: 1,
        };
        let mut session = create_session_package(&group, template).expect("session");
        session.nonces = None;

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "1700000000-2-1".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Sign(SignSessionPackageWire::from(session)),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject missing nonces");
        assert!(matches!(err, NodeError::InvalidSignSession(_)));
    }

    #[test]
    fn handle_incoming_sign_rejects_malformed_nonce_hash_index() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group.clone(),
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let template = SignSessionTemplate {
            members: vec![1, 2],
            hashes: vec![[1u8; 32], [2u8; 32]],
            content: None,
            kind: "message".to_string(),
            stamp: 1,
        };
        let mut session = create_session_package(&group, template).expect("session");
        session.nonces = Some(vec![MemberNonceCommitmentSet {
            idx: 1,
            entries: vec![
                IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: [2u8; 33],
                    hidden_pn: [3u8; 33],
                    code: [4u8; 32],
                },
                IndexedPublicNonceCommitment {
                    hash_index: 5,
                    binder_pn: [2u8; 33],
                    hidden_pn: [3u8; 33],
                    code: [5u8; 32],
                },
            ],
        }]);

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "1700000000-2-2".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Sign(SignSessionPackageWire::from(session)),
            },
        };

        let err =
            block_on(node.handle_incoming(msg)).expect_err("must reject malformed nonce index");
        assert!(matches!(err, NodeError::InvalidSignSession(_)));
    }

    #[test]
    fn handle_incoming_sign_rejects_tampered_session_id() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group.clone(),
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let template = SignSessionTemplate {
            members: vec![1, 2],
            hashes: vec![[9u8; 32]],
            content: None,
            kind: "message".to_string(),
            stamp: 5,
        };
        let mut session = create_session_package(&group, template).expect("session");
        session.nonces = Some(vec![
            MemberNonceCommitmentSet {
                idx: 1,
                entries: vec![IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: [2u8; 33],
                    hidden_pn: [3u8; 33],
                    code: [4u8; 32],
                }],
            },
            MemberNonceCommitmentSet {
                idx: 2,
                entries: vec![IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: [5u8; 33],
                    hidden_pn: [6u8; 33],
                    code: [7u8; 32],
                }],
            },
        ]);
        session.sid[0] ^= 0x01;

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "1700000000-2-3".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Sign(SignSessionPackageWire::from(session)),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject tampered sid");
        match err {
            NodeError::Core(message) => assert!(
                message.contains("session sid mismatch"),
                "unexpected error: {message}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn handle_incoming_sign_rejects_sender_peer_mismatch() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group.clone(),
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let template = SignSessionTemplate {
            members: vec![1, 2],
            hashes: vec![[7u8; 32]],
            content: None,
            kind: "message".to_string(),
            stamp: 9,
        };
        let mut session = create_session_package(&group, template).expect("session");
        session.nonces = Some(vec![
            MemberNonceCommitmentSet {
                idx: 1,
                entries: vec![IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: [2u8; 33],
                    hidden_pn: [3u8; 33],
                    code: [4u8; 32],
                }],
            },
            MemberNonceCommitmentSet {
                idx: 2,
                entries: vec![IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: [5u8; 33],
                    hidden_pn: [6u8; 33],
                    code: [7u8; 32],
                }],
            },
        ]);

        let msg = IncomingMessage {
            peer: peer_pubkey_hex,
            envelope: RpcEnvelope {
                version: 1,
                id: "1700000000-2-4".to_string(),
                sender: hex::encode([8u8; 33]),
                payload: RpcPayload::Sign(SignSessionPackageWire::from(session)),
            },
        };

        let err =
            block_on(node.handle_incoming(msg)).expect_err("must reject sender/peer mismatch");
        match err {
            NodeError::InvalidSenderBinding(_) => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn handle_incoming_onboard_rejects_sender_idx_mismatch() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group.clone(),
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "1700000000-2-5".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::OnboardRequest(OnboardRequestWire {
                    share_pk: hex::encode([3u8; 33]),
                    idx: 1,
                }),
            },
        };

        let err =
            block_on(node.handle_incoming(msg)).expect_err("must reject mismatched onboard idx");
        assert!(matches!(err, NodeError::InvalidSenderBinding(_)));
    }

    #[test]
    fn handle_incoming_rejects_replayed_request_id() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "1700000000-2-8".to_string(),
                sender: peer_pubkey_hex.clone(),
                payload: RpcPayload::Echo("hello".to_string()),
            },
        };

        block_on(node.handle_incoming(msg.clone())).expect("first delivery");
        let err = block_on(node.handle_incoming(msg)).expect_err("must reject replay");
        assert!(matches!(err, NodeError::ReplayRequestId));
    }

    #[test]
    fn handle_incoming_rejects_stale_request_id() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "1699999500-2-7".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Echo("hello".to_string()),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject stale");
        assert!(matches!(err, NodeError::StaleEnvelope));
    }

    #[test]
    fn handle_incoming_rejects_invalid_request_id_format() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "invalid-request-id".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Echo("hello".to_string()),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject invalid request id");
        assert!(matches!(err, NodeError::InvalidRequestIdFormat));
    }

    #[test]
    fn handle_incoming_rejects_unsupported_envelope_version() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            None,
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 99,
                id: "1700000000-2-11".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Echo("hello".to_string()),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject envelope version");
        assert!(matches!(err, NodeError::UnsupportedEnvelopeVersion(99)));
    }

    #[test]
    fn handle_incoming_rejects_oversized_echo_payload() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let options = BifrostNodeOptions {
            max_echo_len: 4,
            ..BifrostNodeOptions::default()
        };
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            Some(options),
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "1700000000-2-9".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Echo("hello".to_string()),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject oversized echo");
        assert!(matches!(err, NodeError::PayloadLimitExceeded(_)));
    }

    #[test]
    fn handle_incoming_rejects_oversized_sign_content() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let options = BifrostNodeOptions {
            max_sign_content_len: 8,
            ..BifrostNodeOptions::default()
        };
        let node = BifrostNode::new(
            group,
            share,
            vec![peer_pubkey_hex.clone()],
            transport,
            clock,
            Some(options),
        )
        .expect("node");
        block_on(node.connect()).expect("connect");

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "1700000000-2-10".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Sign(SignSessionPackageWire {
                    gid: hex::encode([1u8; 32]),
                    sid: hex::encode([2u8; 32]),
                    members: vec![1, 2],
                    hashes: vec![hex::encode([3u8; 32])],
                    content: Some("00".repeat(10)),
                    kind: "message".to_string(),
                    stamp: 1,
                    nonces: None,
                }),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject oversized content");
        assert!(matches!(err, NodeError::PayloadLimitExceeded(_)));
    }
}
