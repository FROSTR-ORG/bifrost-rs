#![allow(clippy::manual_async_fn)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bifrost_codec::rpc::{RpcEnvelope, RpcPayload};
use bifrost_codec::wire::{PartialSigPackageWire, SignSessionPackageWire};
use bifrost_core::types::{
    DerivedPublicNonce, GroupPackage, MemberPackage, SharePackage, SignSessionTemplate,
};
use bifrost_core::{create_partial_sig_package, create_session_package, local_pubkey_from_share};
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

struct FrostPeerCtx {
    group: GroupPackage,
    share: SharePackage,
    signing_nonces: HashMap<[u8; 32], frost::round1::SigningNonces>,
}

struct MockTransport {
    frost_peer: Mutex<Option<FrostPeerCtx>>,
    tamper_signatures: bool,
    incoming_nonces: Vec<DerivedPublicNonce>,
    remote_group: GroupPackage,
}

impl Transport for MockTransport {
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
                RpcPayload::Ping(_) => Ok(IncomingMessage {
                    peer: msg.peer.clone(),
                    envelope: RpcEnvelope {
                        version: 1,
                        id: msg.envelope.id,
                        sender: msg.peer,
                        payload: RpcPayload::Ping(bifrost_codec::wire::PingPayloadWire {
                            version: 1,
                            nonces: Some(
                                self.incoming_nonces
                                    .iter()
                                    .cloned()
                                    .map(Into::into)
                                    .collect(),
                            ),
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
                }),
                RpcPayload::OnboardRequest(_) => Ok(IncomingMessage {
                    peer: msg.peer.clone(),
                    envelope: RpcEnvelope {
                        version: 1,
                        id: msg.envelope.id,
                        sender: msg.peer,
                        payload: RpcPayload::OnboardResponse(
                            bifrost_codec::wire::OnboardResponseWire {
                                group: self.remote_group.clone().into(),
                                nonces: self
                                    .incoming_nonces
                                    .iter()
                                    .cloned()
                                    .map(Into::into)
                                    .collect(),
                            },
                        ),
                    },
                }),
                _ => Err(TransportError::Backend(
                    "unsupported request payload".to_string(),
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
    ) -> impl std::future::Future<Output = TransportResult<Vec<IncomingMessage>>> + Send {
        async move {
            let peer = peers
                .first()
                .cloned()
                .ok_or_else(|| TransportError::Backend("missing peer".to_string()))?;
            match msg.envelope.payload {
                RpcPayload::Sign(wire) => {
                    let mut guard = self
                        .frost_peer
                        .lock()
                        .map_err(|_| TransportError::Backend("poisoned".to_string()))?;
                    let Some(ctx) = guard.as_mut() else {
                        return Err(TransportError::Backend("missing context".to_string()));
                    };
                    let session: bifrost_core::types::SignSessionPackage =
                        wire.try_into().map_err(|e: bifrost_codec::CodecError| {
                            TransportError::Backend(e.to_string())
                        })?;
                    let member_nonce = session
                        .nonces
                        .as_ref()
                        .and_then(|n| n.iter().find(|n| n.idx == ctx.share.idx))
                        .ok_or_else(|| TransportError::Backend("missing nonce".to_string()))?;
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
                    let mut pkg = create_partial_sig_package(
                        &ctx.group,
                        &session,
                        &ctx.share,
                        &signing_nonces,
                        local_pubkey_from_share(&ctx.share)
                            .map_err(|e| TransportError::Backend(e.to_string()))?,
                    )
                    .map_err(|e| TransportError::Backend(e.to_string()))?;
                    if self.tamper_signatures {
                        pkg.psigs[0].partial_sig[0] ^= 0x01;
                    }

                    Ok(vec![IncomingMessage {
                        peer: peer.clone(),
                        envelope: RpcEnvelope {
                            version: 1,
                            id: "sign-resp".to_string(),
                            sender: peer.clone(),
                            payload: RpcPayload::SignResponse(PartialSigPackageWire::from(pkg)),
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
        async move { Err(TransportError::Backend("not used".to_string())) }
    }
}

fn fixture(
    tamper_signatures: bool,
    nonce_count: usize,
) -> (BifrostNode<MockTransport, TestClock>, String) {
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

    let mut incoming_nonces = Vec::new();
    let mut peer_signing_nonces_map = HashMap::new();
    for _ in 0..nonce_count {
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

    let transport = Arc::new(MockTransport {
        frost_peer: Mutex::new(Some(FrostPeerCtx {
            group: group.clone(),
            share: SharePackage {
                idx: peer_idx,
                seckey: {
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&peer_key.signing_share().serialize());
                    s
                },
            },
            signing_nonces: peer_signing_nonces_map,
        })),
        tamper_signatures,
        incoming_nonces: incoming_nonces.clone(),
        remote_group: group.clone(),
    });

    let mut options = BifrostNodeOptions::default();
    options.nonce_pool.critical_threshold = 0;
    let peer_pubkey_hex = hex::encode(peer_member_pk);
    let node = BifrostNode::new(
        group,
        share,
        vec![peer_pubkey_hex.clone()],
        transport,
        Arc::new(TestClock),
        Some(options),
    )
    .expect("node");

    (node, peer_pubkey_hex)
}

#[test]
fn adversarial_rejects_tampered_signature_share() {
    let (node, peer_pubkey_hex) = fixture(true, 1);
    block_on(node.connect()).expect("connect");
    let _ = block_on(node.onboard(&peer_pubkey_hex)).expect("onboard");
    let err = block_on(node.sign([7u8; 32])).expect_err("must fail tampered share");
    match err {
        NodeError::Core(message) => assert!(message.to_lowercase().contains("frost")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn adversarial_nonce_exhaustion_fails_second_sign() {
    let (node, peer_pubkey_hex) = fixture(false, 1);
    block_on(node.connect()).expect("connect");
    let _ = block_on(node.onboard(&peer_pubkey_hex)).expect("onboard");
    let _ = block_on(node.sign([8u8; 32])).expect("first sign");
    let err = block_on(node.sign([9u8; 32])).expect_err("must fail with exhausted nonce");
    assert!(matches!(
        err,
        NodeError::NonceUnavailable | NodeError::InsufficientPeers
    ));
}

#[test]
fn adversarial_rejects_malformed_sign_session_shape() {
    let (node, peer_pubkey_hex) = fixture(false, 0);
    block_on(node.connect()).expect("connect");

    let template = SignSessionTemplate {
        members: vec![1, 2],
        hashes: vec![[1u8; 32], [2u8; 32]],
        content: None,
        kind: "message".to_string(),
        stamp: 1,
    };
    let session = create_session_package(node.group(), template).expect("session");
    let msg = IncomingMessage {
        peer: peer_pubkey_hex.clone(),
        envelope: RpcEnvelope {
            version: 1,
            id: "1700000000-2-1".to_string(),
            sender: peer_pubkey_hex,
            payload: RpcPayload::Sign(SignSessionPackageWire::from(session)),
        },
    };

    let err = block_on(node.handle_incoming(msg)).expect_err("must reject malformed session");
    assert!(matches!(err, NodeError::InvalidSignSession(_)));
}
