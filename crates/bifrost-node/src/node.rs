use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bifrost_codec::rpc::{RpcEnvelope, RpcPayload};
use bifrost_codec::wire::{
    EcdhPackageWire, OnboardRequestWire, OnboardResponseWire, PartialSigPackageWire,
    PingPayloadWire, SignSessionPackageWire,
};
use bifrost_codec::{
    parse_ecdh, parse_onboard_request, parse_onboard_response, parse_ping, parse_psig,
    parse_session,
};
use bifrost_core::group::get_group_id;
use bifrost_core::nonce::{NoncePool, NoncePoolConfig};
use bifrost_core::session::{create_session_package, verify_session_package};
use bifrost_core::sign::{
    combine_signatures, create_partial_sig_package, verify_partial_sig_package,
};
use bifrost_core::types::{
    EcdhPackage, GroupPackage, OnboardResponse, PingPayload, SharePackage, SignSessionTemplate,
};
use bifrost_core::{combine_ecdh_packages, create_ecdh_package, local_pubkey_from_share};
use bifrost_transport::{Clock, IncomingMessage, OutgoingMessage, ResponseHandle, Transport};
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use tokio::sync::broadcast;

use crate::error::{NodeError, NodeResult};
use crate::types::{
    BifrostNodeConfig, BifrostNodeOptions, NodeEvent, PeerData, PeerNonceHealth, PeerPolicy,
    PeerStatus,
};

pub struct BifrostNode<T: Transport, C: Clock> {
    transport: Arc<T>,
    clock: Arc<C>,
    group: GroupPackage,
    share: SharePackage,
    config: BifrostNodeConfig,
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
        let peers = peer_pubkeys
            .into_iter()
            .map(|pubkey| PeerData {
                pubkey,
                status: PeerStatus::Offline,
                policy: PeerPolicy::default(),
                updated: now,
            })
            .collect();

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
            config: BifrostNodeConfig {
                options: resolved,
                peers,
            },
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

        match res.envelope.payload {
            RpcPayload::Echo(value) => Ok(value),
            _ => Err(NodeError::InvalidResponse),
        }
    }

    pub async fn ping(&self, peer: &str) -> NodeResult<PingPayload> {
        self.ensure_ready()?;

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

            PingPayload { version: 1, nonces }
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

        Ok(parsed)
    }

    pub async fn onboard(&self, peer: &str) -> NodeResult<OnboardResponse> {
        self.ensure_ready()?;

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

        let onboard: OnboardResponse = parse_onboard_response(&res.envelope)
            .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;

        let peer_idx = self.member_idx_by_peer_pubkey(peer)?;
        let mut pool = self
            .pool
            .lock()
            .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
        pool.store_incoming(peer_idx, onboard.nonces.clone());

        Ok(onboard)
    }

    pub async fn sign(&self, _message: [u8; 32]) -> NodeResult<[u8; 64]> {
        self.ensure_ready()?;

        let selected = self.select_signing_peers()?;
        let mut members = Vec::with_capacity(selected.len() + 1);
        members.push(self.share.idx);
        for peer in &selected {
            members.push(self.member_idx_by_peer_pubkey(peer)?);
        }
        members.sort_unstable();

        let mut nonces = Vec::with_capacity(members.len());
        let self_nonce = {
            let mut pool = self
                .pool
                .lock()
                .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;

            for peer in &selected {
                let idx = self.member_idx_by_peer_pubkey(peer)?;
                let nonce = pool
                    .consume_incoming(idx)
                    .ok_or(NodeError::NonceUnavailable)?;
                nonces.push(nonce);
            }

            let generated = pool
                .generate_for_peer(self.share.idx, 1)
                .map_err(|e| NodeError::Core(e.to_string()))?;
            let Some(derived) = generated.first() else {
                return Err(NodeError::Core("failed to generate self nonce".to_string()));
            };

            let self_nonce = bifrost_core::types::MemberPublicNonce {
                idx: self.share.idx,
                binder_pn: derived.binder_pn,
                hidden_pn: derived.hidden_pn,
                code: derived.code,
            };

            nonces.push(self_nonce.clone());
            self_nonce
        };

        let template = SignSessionTemplate {
            members,
            hashes: vec![vec![_message]],
            content: None,
            kind: "message".to_string(),
            stamp: self.clock.now_unix_seconds() as u32,
        };

        let mut session = create_session_package(&self.group, template)
            .map_err(|e| NodeError::Core(e.to_string()))?;
        session.nonces = Some(nonces);
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
            pool.take_outgoing_signing_nonces(self.share.idx, self_nonce.code)
                .map_err(|e| NodeError::Core(e.to_string()))?
        };

        let self_pkg = create_partial_sig_package(
            &self.group,
            &session,
            &self.share,
            &self_signing_nonces,
            local_pubkey_from_share(&self.share).map_err(|e| NodeError::Core(e.to_string()))?,
        )
        .map_err(|e| NodeError::Core(e.to_string()))?;

        let mut pkgs = vec![self_pkg];
        for msg in responses {
            let pkg: bifrost_core::types::PartialSigPackage = parse_psig(&msg.envelope)
                .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;
            verify_partial_sig_package(&self.group, &session, &pkg)
                .map_err(|e| NodeError::Core(e.to_string()))?;
            pkgs.push(pkg);
        }

        let sigs = combine_signatures(&self.group, &session, &pkgs)
            .map_err(|e| NodeError::Core(e.to_string()))?;
        let Some(first) = sigs.first() else {
            return Err(NodeError::InvalidResponse);
        };

        Ok(first.signature)
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

        let mut out = Vec::with_capacity(messages.len());
        for message in messages {
            out.push(self.sign(*message).await?);
        }
        Ok(out)
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

        let selected = self.select_signing_peers()?;
        let mut members = Vec::with_capacity(selected.len() + 1);
        members.push(self.share.idx);
        for peer in &selected {
            members.push(self.member_idx_by_peer_pubkey(peer)?);
        }
        members.sort_unstable();

        let local = create_ecdh_package(&members, &self.share, &[pubkey])
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
        for msg in responses {
            let pkg: EcdhPackage = parse_ecdh(&msg.envelope)
                .map_err(|e: bifrost_codec::CodecError| NodeError::Core(e.to_string()))?;
            pkgs.push(pkg);
        }

        let secret =
            combine_ecdh_packages(&pkgs, pubkey).map_err(|e| NodeError::Core(e.to_string()))?;
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
        self.validate_payload_limits(&msg.envelope)?;

        let peer = msg.peer.clone();
        let request_id = msg.envelope.id.clone();
        let sender = msg.envelope.sender.clone();
        let version = msg.envelope.version;
        self.emit_event(NodeEvent::Message(request_id.clone()));
        self.check_and_track_request(&sender, &request_id)?;

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

                RpcPayload::Ping(PingPayloadWire::from(PingPayload { version: 1, nonces }))
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
                let our_nonce = session
                    .nonces
                    .as_ref()
                    .and_then(|n| n.iter().find(|n| n.idx == self.share.idx))
                    .ok_or(NodeError::NonceUnavailable)?;

                let signing_nonces = {
                    let mut pool = self
                        .pool
                        .lock()
                        .map_err(|_| NodeError::Core("nonce pool poisoned".to_string()))?;
                    pool.take_outgoing_signing_nonces(requester_idx, our_nonce.code)
                        .map_err(|_| NodeError::NonceUnavailable)?
                };

                let mut pkg = create_partial_sig_package(
                    &self.group,
                    &session,
                    &self.share,
                    &signing_nonces,
                    local_pubkey_from_share(&self.share)
                        .map_err(|e| NodeError::Core(e.to_string()))?,
                )
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
                if !req.members.contains(&sender_idx) {
                    return Err(NodeError::InvalidSenderBinding(
                        "ecdh members do not include sender idx",
                    ));
                }
                let ecdh_pks = req.entries.iter().map(|e| e.ecdh_pk).collect::<Vec<_>>();
                let pkg = create_ecdh_package(&req.members, &self.share, &ecdh_pks)
                    .map_err(|e| NodeError::Core(e.to_string()))?;
                RpcPayload::Ecdh(EcdhPackageWire::from(pkg))
            }
            RpcPayload::SignResponse(_) | RpcPayload::OnboardResponse(_) => {
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
        let mut members: HashMap<String, u16> = HashMap::with_capacity(self.group.members.len());
        for m in &self.group.members {
            members.insert(hex::encode(m.pubkey), m.idx);
        }
        members.get(peer).copied().ok_or(NodeError::PeerNotFound)
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
        format!("{}-{}-{}", self.clock.now_unix_seconds(), self.share.idx, seq)
    }

    fn check_and_track_request(&self, sender: &str, request_id: &str) -> NodeResult<()> {
        let now = self.clock.now_unix_seconds();
        let key = format!("{sender}:{request_id}");
        let ttl = self.config.options.request_ttl_secs;
        let cache_limit = self.config.options.request_cache_limit;

        if let Some(issued_at) = parse_request_id_timestamp(request_id) {
            if now > issued_at.saturating_add(ttl) {
                return Err(NodeError::StaleEnvelope);
            }
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
                        "sign hash groups exceed max_sign_batch",
                    ));
                }
                if let Some(content) = &w.content {
                    if content.len() > self.config.options.max_sign_content_len {
                        return Err(NodeError::PayloadLimitExceeded("sign content too large"));
                    }
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
        if session.hashes.len() != 1 || session.hashes[0].len() != 1 {
            return Err(NodeError::InvalidSignSession(
                "only single-message signing is currently supported",
            ));
        }
        if session.nonces.is_none() {
            return Err(NodeError::InvalidSignSession("missing nonces"));
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

    fn select_signing_peers(&self) -> NodeResult<Vec<String>> {
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
            .filter(|p| p.policy.send)
            .filter_map(|peer| {
                self.member_idx_by_peer_pubkey(&peer.pubkey)
                    .ok()
                    .filter(|idx| pool.can_sign(*idx))
                    .map(|_| peer.pubkey.clone())
            })
            .collect();

        eligible.sort();
        if eligible.len() < needed {
            return Err(NodeError::InsufficientPeers);
        }

        Ok(eligible.into_iter().take(needed).collect())
    }
}

fn parse_request_id_timestamp(request_id: &str) -> Option<u64> {
    let ts = request_id.split('-').next()?;
    ts.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use bifrost_codec::rpc::{RpcEnvelope, RpcPayload};
    use bifrost_codec::wire::{EcdhEntryWire, EcdhPackageWire, PartialSigPackageWire};
    use bifrost_codec::wire::{OnboardRequestWire, SignSessionPackageWire};
    use bifrost_core::create_session_package;
    use bifrost_core::types::{
        DerivedPublicNonce, GroupPackage, MemberPackage, MemberPublicNonce, SharePackage,
        SignSessionTemplate,
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

    #[async_trait]
    impl Transport for TestTransport {
        async fn connect(&self) -> TransportResult<()> {
            Ok(())
        }

        async fn close(&self) -> TransportResult<()> {
            Ok(())
        }

        async fn request(
            &self,
            msg: OutgoingMessage,
            _timeout_ms: u64,
        ) -> TransportResult<IncomingMessage> {
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

        async fn cast(
            &self,
            msg: OutgoingMessage,
            peers: &[String],
            _threshold: usize,
            _timeout_ms: u64,
        ) -> TransportResult<Vec<IncomingMessage>> {
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
                    let signing_nonces =
                        ctx.signing_nonces
                            .remove(&member_nonce.code)
                            .ok_or_else(|| {
                                TransportError::Backend("missing signing nonces".to_string())
                            })?;

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
                    let keyshare = hex::encode(sk.public_key().to_encoded_point(true).as_bytes());

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

        async fn send_response(
            &self,
            _handle: ResponseHandle,
            _response: OutgoingMessage,
        ) -> TransportResult<()> {
            Ok(())
        }

        async fn next_incoming(&self) -> TransportResult<IncomingMessage> {
            Err(TransportError::Backend(
                "next_incoming not used in this test".to_string(),
            ))
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
                id: "1700000000-2".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Echo("hello".to_string()),
            },
        };

        block_on(node.handle_incoming(msg)).expect("handle incoming");
        let event = block_on(events.recv()).expect("event");
        assert_eq!(event, NodeEvent::Message("1700000000-2".to_string()));
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
            hashes: vec![vec![[1u8; 32]]],
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
                id: "req-1".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Sign(SignSessionPackageWire::from(session)),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject missing nonces");
        assert!(matches!(err, NodeError::InvalidSignSession(_)));
    }

    #[test]
    fn handle_incoming_sign_rejects_non_single_hash_shape() {
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
            hashes: vec![vec![[1u8; 32]], vec![[2u8; 32]]],
            content: None,
            kind: "message".to_string(),
            stamp: 1,
        };
        let mut session = create_session_package(&group, template).expect("session");
        session.nonces = Some(vec![MemberPublicNonce {
            idx: 1,
            binder_pn: [2u8; 33],
            hidden_pn: [3u8; 33],
            code: [4u8; 32],
        }]);

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "req-2".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Sign(SignSessionPackageWire::from(session)),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject batch hashes");
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
            hashes: vec![vec![[9u8; 32]]],
            content: None,
            kind: "message".to_string(),
            stamp: 5,
        };
        let mut session = create_session_package(&group, template).expect("session");
        session.nonces = Some(vec![MemberPublicNonce {
            idx: 1,
            binder_pn: [2u8; 33],
            hidden_pn: [3u8; 33],
            code: [4u8; 32],
        }]);
        session.sid[0] ^= 0x01;

        let msg = IncomingMessage {
            peer: peer_pubkey_hex.clone(),
            envelope: RpcEnvelope {
                version: 1,
                id: "req-3".to_string(),
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
            hashes: vec![vec![[7u8; 32]]],
            content: None,
            kind: "message".to_string(),
            stamp: 9,
        };
        let mut session = create_session_package(&group, template).expect("session");
        session.nonces = Some(vec![MemberPublicNonce {
            idx: 1,
            binder_pn: [2u8; 33],
            hidden_pn: [3u8; 33],
            code: [4u8; 32],
        }]);

        let msg = IncomingMessage {
            peer: peer_pubkey_hex,
            envelope: RpcEnvelope {
                version: 1,
                id: "req-4".to_string(),
                sender: hex::encode([8u8; 33]),
                payload: RpcPayload::Sign(SignSessionPackageWire::from(session)),
            },
        };

        let err =
            block_on(node.handle_incoming(msg)).expect_err("must reject sender/peer mismatch");
        assert!(matches!(err, NodeError::InvalidSenderBinding(_)));
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
                id: "req-5".to_string(),
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
                id: "1700000000-2".to_string(),
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
                id: "1699999500-2".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Echo("hello".to_string()),
            },
        };

        let err = block_on(node.handle_incoming(msg)).expect_err("must reject stale");
        assert!(matches!(err, NodeError::StaleEnvelope));
    }

    #[test]
    fn handle_incoming_rejects_oversized_echo_payload() {
        let (group, share, peer_pubkey_hex) = sample_group_and_share();
        let transport = Arc::new(TestTransport::default());
        let clock = Arc::new(TestClock);
        let mut options = BifrostNodeOptions::default();
        options.max_echo_len = 4;
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
                id: "1700000000-2".to_string(),
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
        let mut options = BifrostNodeOptions::default();
        options.max_sign_content_len = 8;
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
                id: "1700000000-2".to_string(),
                sender: peer_pubkey_hex,
                payload: RpcPayload::Sign(SignSessionPackageWire {
                    gid: hex::encode([1u8; 32]),
                    sid: hex::encode([2u8; 32]),
                    members: vec![1, 2],
                    hashes: vec![vec![hex::encode([3u8; 32])]],
                    content: Some("0123456789".to_string()),
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
