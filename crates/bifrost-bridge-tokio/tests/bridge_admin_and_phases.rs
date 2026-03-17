use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bifrost_bridge_tokio::{Bridge, BridgeConfig, BridgeError, RelayAdapter};
use bifrost_core::types::{GroupPackage, SharePackage};
use bifrost_router::RequestPhase;
use bifrost_signer::{DeviceConfig, DeviceConfigPatch, DeviceState, SigningDevice};
use frostr_utils::{CreateKeysetConfig, create_keyset};
use nostr::{Event, Filter};
use tokio::sync::mpsc;

struct MockRelayAdapter {
    inbound_rx: mpsc::UnboundedReceiver<Event>,
    published_tx: mpsc::UnboundedSender<Event>,
    fail_publish: bool,
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
        if self.fail_publish {
            return Err(anyhow!("synthetic publish failure"));
        }
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
async fn runtime_metadata_and_update_config_roundtrip() {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let signer = build_signer(&group, &local_share);
    let (_inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (published_tx, _published_rx) = mpsc::unbounded_channel();

    let bridge = Bridge::start_with_config(
        MockRelayAdapter {
            inbound_rx,
            published_tx,
            fail_publish: false,
        },
        signer,
        BridgeConfig::default(),
    )
    .await
    .expect("start bridge");

    let metadata = bridge.runtime_metadata().await.expect("runtime metadata");
    assert_eq!(metadata.member_idx, local_share.idx);
    assert_eq!(metadata.peers.len(), group.members.len() - 1);

    bridge
        .update_config(DeviceConfigPatch {
            sign_timeout_secs: Some(41),
            ping_timeout_secs: Some(19),
            request_ttl_secs: Some(480),
            state_save_interval_secs: Some(9),
            peer_selection_strategy: None,
        })
        .await
        .expect("update config");
    let config = bridge.read_config().await.expect("read config");
    assert_eq!(config.sign_timeout_secs, 41);
    assert_eq!(config.ping_timeout_secs, 19);
    assert_eq!(config.request_ttl_secs, 480);
    assert_eq!(config.state_save_interval_secs, 9);

    bridge.shutdown().await;
}

#[tokio::test]
async fn request_phase_reaches_completed_for_successful_ping() {
    let bundle = create_keyset(CreateKeysetConfig {
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
        MockRelayAdapter {
            inbound_rx,
            published_tx,
            fail_publish: false,
        },
        local_signer,
        BridgeConfig::default(),
    )
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

    let ping = bridge
        .ping(target_peer, Duration::from_secs(5))
        .await
        .expect("ping");
    assert_eq!(
        bridge
            .request_phase(ping.request_id.clone())
            .await
            .expect("request phase"),
        Some(RequestPhase::Completed)
    );

    bridge.shutdown().await;
    drop(inbound_tx);
    let _ = worker.await;
}

#[tokio::test]
async fn request_phase_reaches_completed_for_successful_onboard_and_sign() {
    let bundle = create_keyset(CreateKeysetConfig {
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
        MockRelayAdapter {
            inbound_rx,
            published_tx,
            fail_publish: false,
        },
        local_signer,
        BridgeConfig::default(),
    )
    .await
    .expect("start bridge");

    let worker = tokio::spawn(async move {
        while let Some(event) = published_rx.recv().await {
            for signer in peer_signers.iter_mut() {
                if let Ok(outbound) = signer.process_event(&event) {
                    for response in outbound {
                        let _ = inbound_tx_worker.send(response);
                    }
                    break;
                }
            }
        }
    });

    let onboard = bridge
        .onboard(target_peer, Duration::from_secs(5))
        .await
        .expect("onboard");
    assert_eq!(
        bridge
            .request_phase(onboard.request_id.clone())
            .await
            .expect("onboard request phase"),
        Some(RequestPhase::Completed)
    );

    let sign = bridge
        .sign([0xAA; 32], Duration::from_secs(5))
        .await
        .expect("sign");
    assert_eq!(
        bridge
            .request_phase(sign.request_id.clone())
            .await
            .expect("sign request phase"),
        Some(RequestPhase::Completed)
    );

    bridge.shutdown().await;
    drop(inbound_tx);
    let _ = worker.await;
}

#[tokio::test]
async fn publish_failure_marks_request_failed() {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let target_peer = hex::encode(&group.members[1].pubkey[1..]);
    let (_inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (published_tx, _published_rx) = mpsc::unbounded_channel();

    let bridge = Bridge::start_with_config(
        MockRelayAdapter {
            inbound_rx,
            published_tx,
            fail_publish: true,
        },
        build_signer(&group, &local_share),
        BridgeConfig::default(),
    )
    .await
    .expect("start bridge");

    let err = bridge
        .ping(target_peer, Duration::from_secs(1))
        .await
        .expect_err("ping should fail on publish error");
    let request_id = match err {
        BridgeError::RoundFailed {
            request_id,
            code,
            message,
        } => {
            assert_eq!(code, "peer_rejected");
            assert!(message.contains("relay publish failed"));
            request_id
        }
        other => panic!("unexpected bridge error: {other:?}"),
    };
    assert_eq!(
        bridge
            .request_phase(request_id)
            .await
            .expect("request phase after failure"),
        Some(RequestPhase::Failed)
    );

    bridge.shutdown().await;
}

#[tokio::test]
async fn locked_peer_timeout_marks_request_failed() {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let target_peer = hex::encode(&group.members[1].pubkey[1..]);
    let peers = group
        .members
        .iter()
        .filter(|member| member.idx != local_share.idx)
        .map(|member| hex::encode(&member.pubkey[1..]))
        .collect::<Vec<_>>();
    let signer = SigningDevice::new(
        group,
        local_share.clone(),
        peers,
        DeviceState::new(local_share.idx, local_share.seckey),
        DeviceConfig {
            ping_timeout_secs: 1,
            ..DeviceConfig::default()
        },
    )
    .expect("build signer");
    let (_inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (published_tx, _published_rx) = mpsc::unbounded_channel();

    let bridge = Bridge::start_with_config(
        MockRelayAdapter {
            inbound_rx,
            published_tx,
            fail_publish: false,
        },
        signer,
        BridgeConfig {
            expire_tick: Duration::from_millis(50),
            ..BridgeConfig::default()
        },
    )
    .await
    .expect("start bridge");

    let err = bridge
        .ping(target_peer, Duration::from_secs(3))
        .await
        .expect_err("ping should expire");
    let request_id = match err {
        BridgeError::LockedPeerTimeout { request_id } => request_id,
        other => panic!("unexpected bridge error: {other:?}"),
    };
    assert_eq!(
        bridge
            .request_phase(request_id)
            .await
            .expect("request phase after timeout"),
        Some(RequestPhase::Failed)
    );

    bridge.shutdown().await;
}
