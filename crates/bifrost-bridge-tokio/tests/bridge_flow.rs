use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bifrost_bridge_tokio::{Bridge, BridgeConfig, RelayAdapter};
use bifrost_core::types::{GroupPackage, SharePackage};
use bifrost_signer::{DeviceConfig, DeviceState, SigningDevice};
use frostr_utils::{CreateKeysetConfig, create_keyset};
use nostr::{Event, Filter};
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
async fn bridge_roundtrip_ping_onboard_sign_and_ecdh() {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let peer_pubkeys = group
        .members
        .iter()
        .filter(|member| member.idx != local_share.idx)
        .map(|member| hex::encode(&member.pubkey[1..]))
        .collect::<Vec<_>>();
    let target_member = group
        .members
        .iter()
        .find(|member| member.idx != local_share.idx)
        .expect("target member");
    let target_peer = hex::encode(&target_member.pubkey[1..]);
    let target_ecdh: [u8; 32] = target_member.pubkey[1..].try_into().expect("xonly target");

    let local_signer = build_signer(&group, &local_share);
    let mut peer_signers = bundle
        .shares
        .iter()
        .skip(1)
        .map(|share| build_signer(&group, share))
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
        while let Some(event) = published_rx.recv().await {
            for signer in peer_signers.iter_mut() {
                if let Ok(outbound) = signer.process_event(&event) {
                    if outbound.is_empty() {
                        continue;
                    }
                    for response in outbound {
                        let _ = inbound_tx_worker.send(response);
                    }
                    break;
                }
            }
        }
    });

    for peer in &peer_pubkeys {
        let ping = bridge
            .ping(peer.clone(), Duration::from_secs(5))
            .await
            .expect("ping");
        assert_eq!(ping.peer, *peer);
    }

    let onboard = bridge
        .onboard(target_peer.clone(), Duration::from_secs(5))
        .await
        .expect("onboard");
    assert_eq!(onboard.group_member_count, group.members.len());

    let sign = bridge
        .sign([0xAA; 32], Duration::from_secs(5))
        .await
        .expect("sign");
    assert_eq!(sign.signatures.len(), 1);

    let ecdh = bridge
        .ecdh(target_ecdh, Duration::from_secs(5))
        .await
        .expect("ecdh");
    assert_ne!(ecdh.shared_secret, [0u8; 32]);

    bridge.shutdown().await;
    drop(inbound_tx);
    let _ = worker.await;
}
