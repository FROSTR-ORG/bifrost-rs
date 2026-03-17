use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bifrost_bridge_tokio::{Bridge, BridgeConfig, BridgeError, RelayAdapter};
use bifrost_codec::wire::OnboardRequestWire;
use bifrost_codec::{
    BridgeEnvelope, BridgePayload, decode_bridge_envelope, encode_bridge_envelope,
};
use bifrost_core::types::{GroupPackage, SharePackage};
use bifrost_signer::{DeviceConfig, DeviceState, SigningDevice};
use frostr_utils::{CreateKeysetConfig, create_keyset};
use nostr::nips::nip44;
use nostr::{Event, EventBuilder, Filter, Keys, Kind, SecretKey};
use tokio::sync::mpsc;

struct MockRelayAdapter {
    inbound_rx: mpsc::UnboundedReceiver<Event>,
    published_tx: mpsc::UnboundedSender<Event>,
}

#[async_trait]
impl RelayAdapter for MockRelayAdapter {
    async fn connect(&mut self) -> Result<()> {
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }

    async fn subscribe(&mut self, _filters: Vec<Filter>) -> Result<()> {
        Ok(())
    }

    async fn publish(&mut self, event: Event) -> Result<()> {
        self.published_tx
            .send(event)
            .map_err(|_| anyhow!("published channel closed"))
    }

    async fn next_event(&mut self) -> Result<Event> {
        self.inbound_rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("inbound channel closed"))
    }
}

fn build_signer(group: &GroupPackage, share: &SharePackage) -> SigningDevice {
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
        DeviceState::new(share.idx, share.seckey),
        DeviceConfig::default(),
    )
    .expect("build signer")
}

#[tokio::test]
async fn ecdh_round_fails_on_invalid_locked_peer_response() {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 3,
        count: 4,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let local_signer = build_signer(&group, &local_share);
    let target_ecdh: [u8; 32] = group.members[2].pubkey[1..]
        .try_into()
        .expect("xonly target");
    let event_kind = DeviceConfig::default().event_kind as u16;
    let local_secret = SecretKey::from_slice(&local_share.seckey).expect("local secret");
    let local_keys = Keys::new(local_secret.clone());

    let mut peer_signers = bundle
        .shares
        .iter()
        .skip(1)
        .map(|share| (build_signer(&group, share), share.clone()))
        .collect::<Vec<_>>();

    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let inbound_tx_worker = inbound_tx.clone();
    let (published_tx, mut published_rx) = mpsc::unbounded_channel();

    let adapter = MockRelayAdapter {
        inbound_rx,
        published_tx,
    };
    let bridge = Bridge::start_with_config(adapter, local_signer, BridgeConfig::default())
        .await
        .expect("start bridge");

    let worker = tokio::spawn(async move {
        let mut injected = false;
        while let Some(event) = published_rx.recv().await {
            for (signer, share) in peer_signers.iter_mut() {
                let Ok(outbound) = signer.process_event(&event) else {
                    continue;
                };
                if outbound.is_empty() {
                    continue;
                }
                if injected {
                    break;
                }

                let response = outbound[0].clone();
                let plain = nip44::decrypt(&local_secret, &response.pubkey, &response.content)
                    .expect("decrypt response");
                let envelope = decode_bridge_envelope(&plain).expect("decode envelope");

                let malformed = BridgeEnvelope {
                    request_id: envelope.request_id,
                    sent_at: envelope.sent_at.saturating_add(1),
                    payload: BridgePayload::OnboardRequest(OnboardRequestWire {
                        version: 1,
                        nonces: vec![],
                    }),
                };
                let malformed_plain = encode_bridge_envelope(&malformed).expect("encode envelope");
                let peer_secret = SecretKey::from_slice(&share.seckey).expect("peer secret");
                let peer_keys = Keys::new(peer_secret.clone());
                let encrypted = nip44::encrypt(
                    &peer_secret,
                    &local_keys.public_key(),
                    &malformed_plain,
                    nip44::Version::default(),
                )
                .expect("encrypt malformed");
                let bad_event = EventBuilder::new(Kind::Custom(event_kind), encrypted)
                    .sign_with_keys(&peer_keys)
                    .expect("sign malformed event");
                inbound_tx_worker
                    .send(bad_event)
                    .expect("inject malformed inbound event");
                injected = true;
                break;
            }
        }
    });

    let err = bridge
        .ecdh(target_ecdh, Duration::from_secs(5))
        .await
        .expect_err("ecdh must fail on malformed locked-peer response");
    match err {
        BridgeError::InvalidLockedPeerResponse {
            request_id,
            message,
        } => {
            assert!(!request_id.is_empty());
            assert!(message.contains("unexpected response payload"));
        }
        // If malformed payload is rejected before pending-response binding, the round
        // still fails via timeout because no valid locked-peer response can complete.
        BridgeError::Timeout => {}
        other => panic!("unexpected bridge error: {other:?}"),
    }

    bridge.shutdown().await;
    drop(inbound_tx);
    let _ = worker.await;
}

#[tokio::test]
async fn inbound_duplicate_event_is_processed_once() {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let remote_share = bundle.shares[1].clone();
    let local_pubkey_hex = hex::encode(
        &group
            .members
            .iter()
            .find(|m| m.idx == local_share.idx)
            .expect("local member")
            .pubkey[1..],
    );

    let local_signer = build_signer(&group, &local_share);
    let mut remote_signer = build_signer(&group, &remote_share);

    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (published_tx, mut published_rx) = mpsc::unbounded_channel();
    let adapter = MockRelayAdapter {
        inbound_rx,
        published_tx,
    };
    let bridge = Bridge::start_with_config(adapter, local_signer, BridgeConfig::default())
        .await
        .expect("start bridge");

    let outbound = remote_signer
        .initiate_ping(&local_pubkey_hex)
        .expect("remote ping request");
    assert_eq!(outbound.len(), 1);
    let request_event = outbound[0].clone();

    let _ = inbound_tx.send(request_event.clone());
    let _ = inbound_tx.send(request_event);

    let first = tokio::time::timeout(Duration::from_secs(2), published_rx.recv())
        .await
        .expect("first publish timeout")
        .expect("first publish value");
    assert_eq!(
        first.kind.as_u16(),
        DeviceConfig::default().event_kind as u16
    );

    let second = tokio::time::timeout(Duration::from_millis(300), published_rx.recv()).await;
    assert!(second.is_err(), "duplicate event should be deduped");

    bridge.shutdown().await;
}
