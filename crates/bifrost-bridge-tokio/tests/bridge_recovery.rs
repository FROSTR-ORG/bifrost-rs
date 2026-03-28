use std::collections::VecDeque;
use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bifrost_bridge_tokio::{Bridge, BridgeConfig, RelayAdapter};
use bifrost_core::types::{GroupPackage, SharePackage};
use bifrost_router::RequestPhase;
use bifrost_signer::{DeviceConfig, DeviceState, SigningDevice};
use frostr_utils::{CreateKeysetConfig, create_keyset};
use nostr::{Event, Filter};
use tokio::sync::mpsc;

enum ScriptedInbound {
    Error(&'static str),
}

struct ScriptedRelayAdapter {
    inbound_rx: mpsc::UnboundedReceiver<Event>,
    published_tx: mpsc::UnboundedSender<Event>,
    scripted: VecDeque<ScriptedInbound>,
}

#[async_trait]
impl RelayAdapter for ScriptedRelayAdapter {
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
        if let Some(next) = self.scripted.pop_front() {
            return match next {
                ScriptedInbound::Error(message) => Err(anyhow!(message)),
            };
        }
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
async fn bridge_recovers_from_repeated_next_event_failures_and_completes_rounds() {
    let bundle = create_keyset(CreateKeysetConfig {
        group_name: "Test Group".to_string(),
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let target_peer = hex::encode(&group.members[1].pubkey[1..]);
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

    let bridge = Bridge::start_with_config(
        ScriptedRelayAdapter {
            inbound_rx,
            published_tx,
            scripted: VecDeque::from([
                ScriptedInbound::Error("synthetic next_event failure 1"),
                ScriptedInbound::Error("synthetic next_event failure 2"),
                ScriptedInbound::Error("synthetic next_event failure 3"),
            ]),
        },
        local_signer,
        BridgeConfig {
            relay_backoff: Duration::from_millis(5),
            ..BridgeConfig::default()
        },
    )
    .await
    .expect("start bridge");

    let worker = tokio::spawn(async move {
        while let Some(event) = published_rx.recv().await {
            for signer in peer_signers.iter_mut() {
                let Ok(outbound) = signer.process_event(&event) else {
                    continue;
                };
                if outbound.is_empty() {
                    continue;
                }
                for response in outbound {
                    let _ = inbound_tx_worker.send(response);
                }
                break;
            }
        }
    });

    let status = bridge
        .runtime_status()
        .await
        .expect("runtime status during backoff");
    assert_eq!(status.metadata.member_idx, local_share.idx);
    assert_eq!(status.metadata.peers.len(), 2);
    assert!(!status.readiness.sign_ready);

    let readiness = bridge.readiness().await.expect("readiness during backoff");
    assert!(!readiness.sign_ready);
    let peers = bridge
        .peer_status()
        .await
        .expect("peer status during backoff");
    assert_eq!(peers.len(), 2);

    let ping = bridge
        .ping(target_peer.clone(), Duration::from_secs(5))
        .await
        .expect("ping after relay recovery");
    assert_eq!(
        bridge
            .request_phase(ping.request_id.clone())
            .await
            .expect("ping phase"),
        Some(RequestPhase::Completed)
    );

    let onboard = bridge
        .onboard(target_peer.clone(), Duration::from_secs(5))
        .await
        .expect("onboard after relay recovery");
    assert!(
        !onboard.nonces.is_empty(),
        "onboard should bootstrap nonces"
    );
    assert_eq!(
        bridge
            .request_phase(onboard.request_id.clone())
            .await
            .expect("onboard phase"),
        Some(RequestPhase::Completed)
    );

    let sign = bridge
        .sign([0x5Au8; 32], Duration::from_secs(5))
        .await
        .expect("sign after relay recovery");
    assert!(!sign.signatures.is_empty());
    assert_eq!(
        bridge
            .request_phase(sign.request_id.clone())
            .await
            .expect("sign phase"),
        Some(RequestPhase::Completed)
    );

    bridge.shutdown().await;
    drop(inbound_tx);
    let _ = worker.await;
}

#[tokio::test]
async fn bridge_runtime_queries_survive_closed_inbound_stream() {
    let bundle = create_keyset(CreateKeysetConfig {
        group_name: "Test Group".to_string(),
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let local_signer = build_signer(&group, &local_share);
    let (_inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (published_tx, _published_rx) = mpsc::unbounded_channel();

    let bridge = Bridge::start_with_config(
        ScriptedRelayAdapter {
            inbound_rx,
            published_tx,
            scripted: VecDeque::new(),
        },
        local_signer,
        BridgeConfig {
            relay_backoff: Duration::from_millis(5),
            ..BridgeConfig::default()
        },
    )
    .await
    .expect("start bridge");

    tokio::time::sleep(Duration::from_millis(20)).await;

    let runtime = bridge
        .runtime_status()
        .await
        .expect("runtime status with closed inbound stream");
    assert_eq!(runtime.metadata.member_idx, local_share.idx);
    assert_eq!(runtime.peers.len(), 2);

    let readiness = bridge
        .readiness()
        .await
        .expect("readiness with closed inbound stream");
    assert!(!readiness.sign_ready);

    let peers = bridge
        .peer_status()
        .await
        .expect("peer status with closed inbound stream");
    assert_eq!(peers.len(), 2);

    bridge.shutdown().await;
}
