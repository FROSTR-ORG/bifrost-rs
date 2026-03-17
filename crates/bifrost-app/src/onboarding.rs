#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bifrost_bridge_tokio::{NostrSdkAdapter, RelayAdapter};
use bifrost_core::nonce::NoncePoolConfig;
use bifrost_core::types::{DerivedPublicNonce, GroupPackage, SharePackage};
use bifrost_signer::{
    DeviceConfig, DeviceState, DeviceStore, finalize_onboarding_bootstrap_seed,
    generate_onboarding_bootstrap_seed,
};
use frostr_utils::{
    BfOnboardPayload, build_onboard_request_event, decode_onboard_response_event,
    generate_opaque_request_id,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use nostr::Filter;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::runtime::{EncryptedFileStore, begin_run, complete_clean_run};

#[derive(Debug, Clone)]
pub struct BootstrapImportResult {
    pub request_id: String,
    pub group: GroupPackage,
    pub share: SharePackage,
    pub relays: Vec<String>,
    pub peer_pubkey: String,
    pub group_member_count: usize,
    pub bootstrap_nonces: Vec<DerivedPublicNonce>,
    pub bootstrap_state: BootstrapStateSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapStateSnapshot {
    pub device_state_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapValidationReport {
    pub request_id: String,
    pub peer_pubkey: String,
    pub inviter_member_idx: u16,
    pub nonce_count: usize,
    pub persisted_incoming_available: usize,
    pub persisted_outgoing_available: usize,
    pub reloaded_incoming_available: usize,
    pub reloaded_outgoing_available: usize,
    pub reloaded_can_sign: bool,
    pub validation_passed: bool,
}

pub async fn complete_onboarding_package(
    package: BfOnboardPayload,
    timeout: Duration,
) -> Result<BootstrapImportResult> {
    let relays = package.relays.clone();
    complete_onboarding_with_adapter(NostrSdkAdapter::new(relays), package, timeout).await
}

pub async fn complete_onboarding_with_adapter<A>(
    adapter: A,
    package: BfOnboardPayload,
    timeout: Duration,
) -> Result<BootstrapImportResult>
where
    A: RelayAdapter + 'static,
{
    let peer_pubkey = package.peer_pk.to_ascii_lowercase();
    info!(peer_pubkey = %peer_pubkey, relay_count = package.relays.len(), "onboarding bootstrap starting");
    let share_secret = decode_hex32(&package.share_secret)?;
    let local_pubkey = derive_member_pubkey(share_secret)?;
    let local_pubkey_hex = hex::encode(&local_pubkey[1..]);
    let request_id = generate_opaque_request_id();
    let event_kind = DeviceConfig::default().event_kind;
    let bootstrap_seed = generate_onboarding_bootstrap_seed(
        share_secret,
        NoncePoolConfig::default().pool_size,
    )
    .map_err(|e| anyhow!(e.to_string()))?;
    let filter = onboarding_filter(event_kind, &peer_pubkey, &local_pubkey_hex)?;
    let request_event =
        build_onboard_request_event(
            share_secret,
            &peer_pubkey,
            event_kind,
            &request_id,
            now_unix_secs(),
            &bootstrap_seed.request_nonces,
        )
        .map_err(|e| anyhow!(e.to_string()))?;

    let mut adapter = adapter;
    adapter.connect().await?;
    adapter.subscribe(vec![filter]).await?;
    adapter.publish(request_event).await?;

    let response = match await_onboard_response(
        &mut adapter,
        share_secret,
        &peer_pubkey,
        &local_pubkey_hex,
        &request_id,
        timeout,
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            let _ = adapter.disconnect().await;
            return Err(err);
        }
    };
    let _ = adapter.disconnect().await;

    validate_onboarding_result(&response.group, share_secret, &peer_pubkey)?;
    let local_member_idx = local_member_idx(&response.group, share_secret)?;
    let inviter_member_idx = inviter_member_idx(&response.group, &peer_pubkey)?;
    let share = SharePackage {
        idx: local_member_idx,
        seckey: share_secret,
    };
    if response.nonces.is_empty() {
        bail!("onboard response is missing bootstrap nonces for inviter peer {peer_pubkey}");
    }
    let state = finalize_onboarding_bootstrap_seed(
        bootstrap_seed.state,
        local_member_idx,
        inviter_member_idx,
        response.nonces.clone(),
    )
    .map_err(|e| anyhow!(e.to_string()))?;
    debug!(
        request_id = %request_id,
        peer_pubkey = %peer_pubkey,
        inviter_member_idx,
        onboard_response_nonce_count = response.nonces.len(),
        "onboarding bootstrap completed"
    );

    Ok(BootstrapImportResult {
        request_id,
        group_member_count: response.group.members.len(),
        group: response.group,
        share,
        relays: package.relays,
        peer_pubkey,
        bootstrap_nonces: response.nonces,
        bootstrap_state: BootstrapStateSnapshot {
            device_state_hex: encode_device_state_hex(&state)?,
        },
    })
}

pub fn inviter_member_idx(group: &GroupPackage, peer_pubkey: &str) -> Result<u16> {
    group
        .members
        .iter()
        .find(|member| hex::encode(&member.pubkey[1..]) == peer_pubkey)
        .map(|member| member.idx)
        .ok_or_else(|| anyhow!("onboarded group is missing inviter peer {peer_pubkey}"))
}

fn local_member_idx(group: &GroupPackage, share_seckey: [u8; 32]) -> Result<u16> {
    let expected_local = derive_member_pubkey(share_seckey)?;
    group
        .members
        .iter()
        .find(|member| member.pubkey == expected_local)
        .map(|member| member.idx)
        .ok_or_else(|| anyhow!("onboarded group is missing the local share pubkey"))
}

pub fn persist_validated_onboarding_state(
    state_path: &Path,
    completion: &BootstrapImportResult,
) -> Result<BootstrapValidationReport> {
    let inviter_member_idx = inviter_member_idx(&completion.group, &completion.peer_pubkey)?;
    let mut state = decode_device_state_hex(&completion.bootstrap_state.device_state_hex)?;
    state.pending_operations.clear();
    let run_id = begin_run(state_path).context("begin onboarding import run marker")?;
    let persisted = state.nonce_pool.peer_stats(inviter_member_idx);
    let store = EncryptedFileStore::new(state_path.to_path_buf(), completion.share.clone());
    store.save(&state).context("save onboarding state")?;
    complete_clean_run(state_path, &run_id, &state)
        .context("complete onboarding import run marker")?;
    let reloaded = store.load().context("reload onboarding state")?;
    let reloaded_stats = reloaded.nonce_pool.peer_stats(inviter_member_idx);
    let expected = completion.bootstrap_nonces.len();
    if expected == 0 {
        bail!(
            "onboarding state validation failed for peer {}: onboard response did not include bootstrap nonces",
            completion.peer_pubkey
        );
    }
    let report = BootstrapValidationReport {
        request_id: completion.request_id.clone(),
        peer_pubkey: completion.peer_pubkey.clone(),
        inviter_member_idx,
        nonce_count: expected,
        persisted_incoming_available: persisted.incoming_available,
        persisted_outgoing_available: persisted.outgoing_available,
        reloaded_incoming_available: reloaded_stats.incoming_available,
        reloaded_outgoing_available: reloaded_stats.outgoing_available,
        reloaded_can_sign: reloaded_stats.can_sign,
        validation_passed: reloaded_stats.incoming_available >= expected
            && reloaded_stats.outgoing_available >= persisted.outgoing_available,
    };
    debug!(
        request_id = %report.request_id,
        peer_pubkey = %report.peer_pubkey,
        inviter_member_idx = report.inviter_member_idx,
        nonce_count = report.nonce_count,
        persisted_incoming_available = report.persisted_incoming_available,
        persisted_outgoing_available = report.persisted_outgoing_available,
        reloaded_incoming_available = report.reloaded_incoming_available,
        reloaded_outgoing_available = report.reloaded_outgoing_available,
        reloaded_can_sign = report.reloaded_can_sign,
        validation_passed = report.validation_passed,
        "validated persisted onboarding state"
    );
    if !report.validation_passed {
        bail!(
            "onboarding state validation failed for peer {}: expected {} incoming nonces for member idx {}, found {} after reload",
            report.peer_pubkey,
            report.nonce_count,
            report.inviter_member_idx,
            report.reloaded_incoming_available
        );
    }
    if report.reloaded_outgoing_available < report.persisted_outgoing_available {
        bail!(
            "onboarding state validation failed for peer {}: expected at least {} outgoing nonces for member idx {}, found {} after reload",
            report.peer_pubkey,
            report.persisted_outgoing_available,
            report.inviter_member_idx,
            report.reloaded_outgoing_available
        );
    }
    Ok(report)
}

fn encode_device_state_hex(state: &DeviceState) -> Result<String> {
    let encoded = bincode::serialize(state).context("serialize bootstrap device state")?;
    Ok(hex::encode(encoded))
}

fn decode_device_state_hex(value: &str) -> Result<DeviceState> {
    let bytes = hex::decode(value).context("decode bootstrap device state hex")?;
    bincode::deserialize(&bytes).context("decode bootstrap device state bytes")
}

fn derive_member_pubkey(seckey: [u8; 32]) -> Result<[u8; 33]> {
    let secret = k256::SecretKey::from_slice(&seckey).context("invalid onboarding share seckey")?;
    let point = secret.public_key().to_encoded_point(true);
    let bytes = point.as_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn validate_onboarding_result(
    group: &GroupPackage,
    share_seckey: [u8; 32],
    peer_pubkey: &str,
) -> Result<()> {
    let expected_local = derive_member_pubkey(share_seckey)?;
    let Some(local_member) = group.members.iter().find(|member| member.pubkey == expected_local) else {
        bail!("onboard response group is missing the local share pubkey");
    };
    if local_member.pubkey != expected_local {
        bail!("onboard response local member pubkey does not match provided share");
    }
    if !group
        .members
        .iter()
        .any(|member| hex::encode(&member.pubkey[1..]) == peer_pubkey)
    {
        bail!(
            "onboard response group is missing inviter peer {}",
            peer_pubkey
        );
    }
    Ok(())
}

fn decode_hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("decode onboarding share secret")?;
    if bytes.len() != 32 {
        bail!("onboarding share secret must be 32-byte hex");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn now_unix_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        return (js_sys::Date::now() / 1000.0).floor() as u64;
    }

    #[cfg(not(target_arch = "wasm32"))]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn onboarding_filter(event_kind: u64, peer_pubkey: &str, local_pubkey: &str) -> Result<Filter> {
    serde_json::from_value(serde_json::json!({
        "kinds": [event_kind],
        "authors": [peer_pubkey],
        "#p": [local_pubkey],
    }))
    .context("invalid onboarding relay filter")
}

async fn await_onboard_response<A>(
    adapter: &mut A,
    share_seckey: [u8; 32],
    peer_pubkey: &str,
    local_pubkey: &str,
    request_id: &str,
    timeout: Duration,
) -> Result<bifrost_core::types::OnboardResponse>
where
    A: RelayAdapter + ?Sized,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for onboard response from {peer_pubkey}");
        }
        let event = tokio::time::timeout(remaining, adapter.next_event())
            .await
            .context("timed out waiting for onboard response")??;
        match decode_onboard_response_event(
            &event,
            share_seckey,
            peer_pubkey,
            local_pubkey,
            request_id,
        ) {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => continue,
            Err(err) => return Err(anyhow!("onboarding rejected by peer {}: {}", peer_pubkey, err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use bifrost_core::types::DerivedPublicNonce;
    use bifrost_signer::{DeviceConfig, SigningDevice};
    use frostr_utils::{CreateKeysetConfig, create_keyset};

    #[test]
    fn persist_validated_onboarding_state_preserves_inviter_nonces() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("keyset");
        let share = bundle
            .shares
            .iter()
            .find(|share| share.idx == 2)
            .cloned()
            .expect("bob share");
        let alice = bundle
            .group
            .members
            .iter()
            .find(|member| member.idx == 1)
            .expect("alice member");
        let mut state = DeviceState::new(share.idx, share.seckey);
        state.nonce_pool.store_incoming(
            1,
            vec![DerivedPublicNonce {
                code: [7u8; 32],
                binder_pn: [8u8; 33],
                hidden_pn: [9u8; 33],
            }],
        );
        state
            .nonce_pool
            .generate_for_peer(1, 4)
            .expect("bootstrap outgoing");
        let completion = BootstrapImportResult {
            request_id: "req-1".to_string(),
            group: bundle.group.clone(),
            share: share.clone(),
            relays: vec!["ws://127.0.0.1:8194".to_string()],
            peer_pubkey: hex::encode(&alice.pubkey[1..]),
            group_member_count: bundle.group.members.len(),
            bootstrap_nonces: vec![DerivedPublicNonce {
                code: [7u8; 32],
                binder_pn: [8u8; 33],
                hidden_pn: [9u8; 33],
            }],
            bootstrap_state: BootstrapStateSnapshot {
                device_state_hex: encode_device_state_hex(&state).expect("encode state"),
            },
        };
        let root = std::env::temp_dir().join(format!(
            "bifrost-onboarding-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&root).expect("create temp root");
        let state_path = root.join("signer-state.bin");

        let report =
            persist_validated_onboarding_state(&state_path, &completion).expect("validate");

        assert_eq!(report.inviter_member_idx, 1);
        assert_eq!(report.nonce_count, 1);
        assert_eq!(report.reloaded_incoming_available, 1);
        assert!(report.reloaded_outgoing_available >= 4);
        assert!(report.validation_passed);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stateless_onboard_request_event_roundtrips_with_signer() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("keyset");
        let local_share = bundle.shares[0].clone();
        let inviter_share = bundle.shares[1].clone();
        let inviter_pubkey = hex::encode(
            &bundle
                .group
                .members
                .iter()
                .find(|member| member.idx == inviter_share.idx)
                .expect("inviter member")
                .pubkey[1..],
        );
        let peers = bundle
            .group
            .members
            .iter()
            .filter(|member| member.idx != inviter_share.idx)
            .map(|member| hex::encode(&member.pubkey[1..]))
            .collect::<Vec<_>>();
        let mut inviter = SigningDevice::new(
            bundle.group.clone(),
            inviter_share,
            peers,
            DeviceState::new(2, bundle.shares[1].seckey),
            DeviceConfig::default(),
        )
        .expect("build inviter");
        let bootstrap_seed = generate_onboarding_bootstrap_seed(
            local_share.seckey,
            NoncePoolConfig::default().pool_size,
        )
        .expect("bootstrap seed");
        let event = build_onboard_request_event(
            local_share.seckey,
            &inviter_pubkey,
            DeviceConfig::default().event_kind,
            "request-1",
            now_unix_secs(),
            &bootstrap_seed.request_nonces,
        )
        .expect("build request");
        let outbound = inviter.process_event(&event).expect("process onboard request");
        assert_eq!(outbound.len(), 1);
    }
}
