use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use bifrost_app::onboarding::{
    BootstrapImportResult, BootstrapStateSnapshot, complete_onboarding_with_adapter,
    persist_validated_onboarding_state,
};
use bifrost_app::runtime::EncryptedFileStore;
use bifrost_bridge_tokio::RelayAdapter;
use bifrost_core::types::{GroupPackage, SharePackage};
use bifrost_signer::{DeviceConfig, DeviceState, DeviceStore, SigningDevice};
use frostr_utils::{BfOnboardPayload, CreateKeysetConfig, create_keyset};
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

fn temp_state_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bifrost-onboarding-{name}-{}-{nonce}.bin",
        std::process::id()
    ))
}

async fn complete_onboarding_fixture() -> (BootstrapImportResult, GroupPackage, SharePackage) {
    let bundle = create_keyset(CreateKeysetConfig {
        group_name: "Test Group".to_string(),
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let local_share = bundle.shares[0].clone();
    let inviter_share = bundle.shares[1].clone();
    let inviter_peer = group
        .members
        .iter()
        .find(|member| member.idx == inviter_share.idx)
        .expect("inviter member");

    let package = BfOnboardPayload {
        share_secret: hex::encode(local_share.seckey),
        relays: vec!["ws://mock-relay".to_string()],
        peer_pk: hex::encode(&inviter_peer.pubkey[1..]),
    };

    let mut inviter_signer = build_signer(&group, &inviter_share);
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let inbound_tx_worker = inbound_tx.clone();
    let (published_tx, mut published_rx) = mpsc::unbounded_channel();

    let adapter = MockRelayAdapter {
        inbound_rx,
        published_tx,
    };

    let worker = tokio::spawn(async move {
        while let Some(event) = published_rx.recv().await {
            let outbound = inviter_signer.process_event(&event).expect("process event");
            for response in outbound {
                let _ = inbound_tx_worker.send(response);
            }
        }
    });

    let completed =
        complete_onboarding_with_adapter(adapter, package, std::time::Duration::from_secs(5))
            .await
            .expect("complete onboarding");

    drop(inbound_tx);
    let _ = worker.await;
    (completed, group, local_share)
}

#[tokio::test]
async fn onboarding_runtime_recovers_group_from_peer_response() {
    let (completed, group, local_share) = complete_onboarding_fixture().await;

    assert_eq!(completed.group, group);
    assert_eq!(completed.share.idx, local_share.idx);
    assert_eq!(completed.group_member_count, group.members.len());
    assert!(!completed.bootstrap_nonces.is_empty());
}

#[tokio::test]
async fn onboarding_state_validation_rejects_corrupt_bootstrap_state_hex() {
    let (mut completed, _group, _local_share) = complete_onboarding_fixture().await;
    completed.bootstrap_state = BootstrapStateSnapshot {
        device_state_hex: "not-valid-hex".to_string(),
    };

    let state_path = temp_state_path("corrupt-bootstrap");
    let err = persist_validated_onboarding_state(&state_path, &completed)
        .expect_err("corrupt bootstrap state must fail");
    assert!(err.to_string().contains("decode bootstrap device state"));
    let _ = fs::remove_file(state_path);
}

#[tokio::test]
async fn onboarding_state_validation_persists_incoming_and_outgoing_nonce_usability() {
    let (completed, _group, local_share) = complete_onboarding_fixture().await;
    let state_path = temp_state_path("validated-bootstrap");
    let report = persist_validated_onboarding_state(&state_path, &completed)
        .expect("persist validated onboarding state");

    assert!(report.validation_passed);
    assert!(report.nonce_count > 0);
    assert!(report.persisted_incoming_available >= report.nonce_count);
    assert!(report.persisted_outgoing_available > 0);
    assert!(report.reloaded_incoming_available >= report.nonce_count);
    assert!(report.reloaded_outgoing_available >= report.persisted_outgoing_available);
    assert!(report.reloaded_can_sign);

    let store = EncryptedFileStore::new(state_path.clone(), local_share);
    let reloaded = store.load().expect("reload onboarding state");
    let peer_stats = reloaded.nonce_pool.peer_stats(report.inviter_member_idx);
    assert!(peer_stats.incoming_available >= report.nonce_count);
    assert!(peer_stats.outgoing_available >= report.persisted_outgoing_available);

    let _ = fs::remove_file(state_path);
}
