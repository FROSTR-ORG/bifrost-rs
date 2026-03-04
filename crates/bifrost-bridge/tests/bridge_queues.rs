use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bifrost_bridge::{Bridge, BridgeConfig, BridgeError, QueueOverflowPolicy, RelayAdapter};
use bifrost_core::types::{GroupPackage, SharePackage};
use bifrost_signer::{DeviceConfig, DeviceState, SigningDevice};
use frostr_utils::{CreateKeysetConfig, create_keyset};
use nostr::{Event, Filter};
use tokio::sync::mpsc;

struct NullRelayAdapter {
    inbound_rx: mpsc::UnboundedReceiver<Event>,
}

#[async_trait]
impl RelayAdapter for NullRelayAdapter {
    async fn connect(&mut self) -> Result<()> {
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }

    async fn subscribe(&mut self, _filters: Vec<Filter>) -> Result<()> {
        Ok(())
    }

    async fn publish(&mut self, _event: Event) -> Result<()> {
        Ok(())
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
        .map(|member| hex::encode(member.pubkey))
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
async fn outbound_queue_overflow_fails_round() {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 5,
        count: 6,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let target_ecdh = group.members[1].pubkey;
    let local_signer = build_signer(&group, &local_share);

    let (_inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let adapter = NullRelayAdapter { inbound_rx };

    let bridge = Bridge::start_with_config(
        adapter,
        local_signer,
        BridgeConfig {
            outbound_queue_capacity: 2,
            outbound_overflow_policy: QueueOverflowPolicy::Fail,
            ..BridgeConfig::default()
        },
    )
    .await
    .expect("start bridge");

    let err = bridge
        .ecdh(target_ecdh, Duration::from_secs(5))
        .await
        .expect_err("must fail when outbound queue overflows");

    match err {
        BridgeError::RoundFailed { code, message, .. } => {
            assert_eq!(code, "peer_rejected");
            assert!(message.contains("outbound queue overflow"));
        }
        other => panic!("unexpected bridge error: {other:?}"),
    }

    bridge.shutdown().await;
}
