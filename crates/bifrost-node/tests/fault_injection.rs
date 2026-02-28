use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bifrost_codec::rpc::{RpcEnvelope, RpcPayload};
use bifrost_codec::wire::{EcdhPackageWire, PartialSigPackageWire};
use bifrost_core::nonce::NoncePoolConfig;
use bifrost_core::types::{DerivedPublicNonce, GroupPackage, MemberPackage, SharePackage};
use bifrost_core::{create_ecdh_package, create_partial_sig_package, local_pubkey_from_share};
use bifrost_node::{BifrostNode, BifrostNodeOptions, NodeError};
use bifrost_transport::{
    Clock, IncomingMessage, OutgoingMessage, ResponseHandle, Transport, TransportError,
    TransportResult,
};
use frost_secp256k1_tr_unofficial as frost;
use futures::executor::block_on;
use rand_core::{OsRng, RngCore};

#[derive(Default)]
struct TestClock;

impl Clock for TestClock {
    fn now_unix_seconds(&self) -> u64 {
        1_700_000_000
    }
}

#[derive(Debug, Clone, Copy)]
enum ChaosMode {
    Healthy,
    DropOne,
    DelayMs(u64),
    ChurnFirstFailThenHealthy,
}

struct PeerCtx {
    group: GroupPackage,
    share: SharePackage,
    signing_nonces: HashMap<[u8; 32], frost::round1::SigningNonces>,
}

struct ChaosTransport {
    mode: Mutex<ChaosMode>,
    cast_attempts: Mutex<u32>,
    peers: Mutex<HashMap<String, PeerCtx>>,
}

impl ChaosTransport {
    fn new(mode: ChaosMode, peers: HashMap<String, PeerCtx>) -> Self {
        Self {
            mode: Mutex::new(mode),
            cast_attempts: Mutex::new(0),
            peers: Mutex::new(peers),
        }
    }

    fn responder_peers(&self, peers: &[String]) -> TransportResult<Vec<String>> {
        let mode = *self
            .mode
            .lock()
            .map_err(|_| TransportError::Backend("mode lock poisoned".to_string()))?;

        match mode {
            ChaosMode::Healthy => Ok(peers.to_vec()),
            ChaosMode::DropOne => Ok(peers
                .iter()
                .take(peers.len().saturating_sub(1))
                .cloned()
                .collect()),
            ChaosMode::DelayMs(_) => Ok(peers.to_vec()),
            ChaosMode::ChurnFirstFailThenHealthy => {
                let mut attempts = self
                    .cast_attempts
                    .lock()
                    .map_err(|_| TransportError::Backend("attempt lock poisoned".to_string()))?;
                *attempts = attempts.saturating_add(1);
                if *attempts == 1 {
                    Ok(Vec::new())
                } else {
                    drop(attempts);
                    if let Ok(mut m) = self.mode.lock() {
                        *m = ChaosMode::Healthy;
                    }
                    Ok(peers.to_vec())
                }
            }
        }
    }

    fn maybe_delay(&self, timeout_ms: u64) -> TransportResult<()> {
        let mode = *self
            .mode
            .lock()
            .map_err(|_| TransportError::Backend("mode lock poisoned".to_string()))?;
        if let ChaosMode::DelayMs(delay_ms) = mode {
            if delay_ms > timeout_ms {
                return Err(TransportError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for ChaosTransport {
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
            RpcPayload::Ping(_) => {
                let mut peers = self
                    .peers
                    .lock()
                    .map_err(|_| TransportError::Backend("peer lock poisoned".to_string()))?;
                let Some(ctx) = peers.get_mut(&msg.peer) else {
                    return Err(TransportError::PeerNotFound);
                };

                let signing_share = frost::keys::SigningShare::deserialize(&ctx.share.seckey)
                    .map_err(|e| TransportError::Backend(e.to_string()))?;
                let (signing_nonces, commitments) =
                    frost::round1::commit(&signing_share, &mut OsRng);
                let mut code = [0u8; 32];
                let mut rng = OsRng;
                rng.fill_bytes(&mut code);

                let hiding = commitments
                    .hiding()
                    .serialize()
                    .map_err(|e| TransportError::Backend(e.to_string()))?;
                let binding = commitments
                    .binding()
                    .serialize()
                    .map_err(|e| TransportError::Backend(e.to_string()))?;

                let mut hidden_pn = [0u8; 33];
                hidden_pn.copy_from_slice(&hiding);
                let mut binder_pn = [0u8; 33];
                binder_pn.copy_from_slice(&binding);

                ctx.signing_nonces.insert(code, signing_nonces);

                let nonce = DerivedPublicNonce {
                    binder_pn,
                    hidden_pn,
                    code,
                };

                Ok(IncomingMessage {
                    peer: msg.peer.clone(),
                    envelope: RpcEnvelope {
                        version: 1,
                        id: msg.envelope.id,
                        sender: msg.peer,
                        payload: RpcPayload::Ping(bifrost_codec::wire::PingPayloadWire {
                            version: 1,
                            nonces: Some(vec![nonce.into()]),
                            policy_profile: Some(
                                bifrost_codec::wire::PeerScopedPolicyProfileWire {
                                    for_peer: msg.envelope.sender.clone(),
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
                })
            }
            _ => Err(TransportError::Backend(
                "unsupported request payload".to_string(),
            )),
        }
    }

    async fn cast(
        &self,
        msg: OutgoingMessage,
        peers: &[String],
        threshold: usize,
        timeout_ms: u64,
    ) -> TransportResult<Vec<IncomingMessage>> {
        self.maybe_delay(timeout_ms)?;
        let responders = self.responder_peers(peers)?;
        if responders.len() < threshold {
            return Err(TransportError::Timeout);
        }

        match msg.envelope.payload {
            RpcPayload::Sign(wire) => {
                let session: bifrost_core::types::SignSessionPackage =
                    wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                        TransportError::Backend(e.to_string())
                    })?;

                let mut out = Vec::with_capacity(responders.len());
                let mut peers_guard = self
                    .peers
                    .lock()
                    .map_err(|_| TransportError::Backend("peer lock poisoned".to_string()))?;

                for peer in responders {
                    let Some(ctx) = peers_guard.get_mut(&peer) else {
                        return Err(TransportError::PeerNotFound);
                    };

                    let nonce_set = session
                        .nonces
                        .as_ref()
                        .and_then(|sets| sets.iter().find(|s| s.idx == ctx.share.idx))
                        .ok_or_else(|| {
                            TransportError::Backend("missing nonce commitment set".to_string())
                        })?;

                    let mut signing_nonces = Vec::with_capacity(nonce_set.entries.len());
                    for entry in &nonce_set.entries {
                        signing_nonces.push(ctx.signing_nonces.remove(&entry.code).ok_or_else(
                            || {
                                TransportError::Backend(
                                    "missing signing nonce for code".to_string(),
                                )
                            },
                        )?);
                    }

                    let pkg = create_partial_sig_package(
                        &ctx.group,
                        &session,
                        &ctx.share,
                        &signing_nonces,
                        local_pubkey_from_share(&ctx.share)
                            .map_err(|e| TransportError::Backend(e.to_string()))?,
                    )
                    .map_err(|e| TransportError::Backend(e.to_string()))?;

                    out.push(IncomingMessage {
                        peer: peer.clone(),
                        envelope: RpcEnvelope {
                            version: 1,
                            id: format!("{}-resp", msg.envelope.id),
                            sender: peer,
                            payload: RpcPayload::SignResponse(PartialSigPackageWire::from(pkg)),
                        },
                    });
                }

                Ok(out)
            }
            RpcPayload::Ecdh(wire) => {
                let req: bifrost_core::types::EcdhPackage =
                    wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                        TransportError::Backend(e.to_string())
                    })?;
                let targets = req.entries.iter().map(|e| e.ecdh_pk).collect::<Vec<_>>();

                let mut out = Vec::with_capacity(responders.len());
                let peers_guard = self
                    .peers
                    .lock()
                    .map_err(|_| TransportError::Backend("peer lock poisoned".to_string()))?;

                for peer in responders {
                    let Some(ctx) = peers_guard.get(&peer) else {
                        return Err(TransportError::PeerNotFound);
                    };
                    let pkg = create_ecdh_package(&req.members, &ctx.share, &targets)
                        .map_err(|e| TransportError::Backend(e.to_string()))?;
                    out.push(IncomingMessage {
                        peer: peer.clone(),
                        envelope: RpcEnvelope {
                            version: 1,
                            id: format!("{}-resp", msg.envelope.id),
                            sender: peer,
                            payload: RpcPayload::Ecdh(EcdhPackageWire::from(pkg)),
                        },
                    });
                }

                Ok(out)
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
        Err(TransportError::Backend("not used".to_string()))
    }
}

fn fixture(
    mode: ChaosMode,
    sign_timeout_ms: u64,
    ecdh_timeout_ms: u64,
) -> (BifrostNode<ChaosTransport, TestClock>, Vec<String>) {
    let (shares, pubkey_pkg) =
        frost::keys::generate_with_dealer(3, 3, frost::keys::IdentifierList::Default, OsRng)
            .expect("dealer");

    let mut material = Vec::new();
    for (id, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share).expect("key package");
        material.push((id, key_package));
    }
    material.sort_by_key(|(id, _)| id.serialize());

    let mut group_pk = [0u8; 33];
    group_pk.copy_from_slice(
        &pubkey_pkg
            .verifying_key()
            .serialize()
            .expect("serialize group key"),
    );

    let mut members = Vec::new();
    let mut share_packages = Vec::new();
    for (id, key) in &material {
        let mut member_pk = [0u8; 33];
        member_pk.copy_from_slice(
            &key.verifying_share()
                .serialize()
                .expect("serialize member key"),
        );
        members.push(MemberPackage {
            idx: id.serialize()[31] as u16,
            pubkey: member_pk,
        });

        let mut seckey = [0u8; 32];
        seckey.copy_from_slice(&key.signing_share().serialize());
        share_packages.push(SharePackage {
            idx: id.serialize()[31] as u16,
            seckey,
        });
    }

    let group = GroupPackage {
        group_pk,
        threshold: 3,
        members: members.clone(),
    };

    let local_share = share_packages[0].clone();
    let peer_shares = vec![share_packages[1].clone(), share_packages[2].clone()];

    let mut peer_map = HashMap::new();
    let mut peer_pubkeys = Vec::new();
    for share in peer_shares {
        let peer_pubkey = hex::encode(local_pubkey_from_share(&share).expect("peer pubkey"));
        peer_pubkeys.push(peer_pubkey.clone());
        peer_map.insert(
            peer_pubkey,
            PeerCtx {
                group: group.clone(),
                share,
                signing_nonces: HashMap::new(),
            },
        );
    }

    let transport = Arc::new(ChaosTransport::new(mode, peer_map));
    let node = BifrostNode::new(
        group,
        local_share,
        peer_pubkeys.clone(),
        transport,
        Arc::new(TestClock),
        Some(BifrostNodeOptions {
            sign_timeout_ms,
            ecdh_timeout_ms,
            nonce_pool: NoncePoolConfig {
                pool_size: 16,
                min_threshold: 1,
                critical_threshold: 0,
                replenish_count: 4,
            },
            ..Default::default()
        }),
    )
    .expect("node");

    block_on(node.connect()).expect("connect");
    for peer in &peer_pubkeys {
        block_on(node.ping(peer)).expect("seed nonces via ping");
    }

    (node, peer_pubkeys)
}

#[test]
fn fault_injection_sign_partial_quorum_times_out() {
    let (node, _peers) = fixture(ChaosMode::DropOne, 100, 100);
    let err = block_on(node.sign([1u8; 32])).expect_err("sign must fail with dropped peer");
    assert!(matches!(err, NodeError::Transport(_)));
    assert!(err.to_string().contains("timeout"));
}

#[test]
fn fault_injection_sign_delayed_peers_respect_timeout() {
    let (node, _peers) = fixture(ChaosMode::DelayMs(250), 50, 50);
    let err = block_on(node.sign([2u8; 32])).expect_err("sign must fail on delay > timeout");
    assert!(matches!(err, NodeError::Transport(_)));
    assert!(err.to_string().contains("timeout"));
}

#[test]
fn fault_injection_relay_churn_recovers_on_retry() {
    let (node, peers) = fixture(ChaosMode::ChurnFirstFailThenHealthy, 100, 100);

    let first = block_on(node.sign([3u8; 32]));
    assert!(first.is_err(), "first attempt should fail during churn");

    for peer in &peers {
        block_on(node.ping(peer)).expect("reseed nonces after failed attempt");
    }

    let second = block_on(node.sign([4u8; 32])).expect("second sign should recover");
    assert_eq!(second.len(), 64);
}

#[test]
fn fault_injection_ecdh_delayed_peers_can_still_succeed_within_timeout() {
    let (node, peers) = fixture(ChaosMode::DelayMs(10), 100, 100);
    let target =
        <[u8; 33]>::try_from(hex::decode(&peers[0]).expect("decode target")).expect("target");
    let secret = block_on(node.ecdh(target)).expect("ecdh must succeed");
    assert_ne!(secret, [0u8; 32]);
}
