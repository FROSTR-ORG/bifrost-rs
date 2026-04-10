use anyhow::{Context, Result};
use bifrost_codec::{parse_group_package, parse_share_package};
use bifrost_signer::{DeviceConfig, DeviceState, DeviceStore, SigningDevice};
use tracing::{info, warn};

use super::config::{AppConfig, ResolvedAppConfig};
use super::health::dirty_restart_reason;
use super::paths::expand_tilde;

pub fn resolve_config(config: &AppConfig) -> Result<ResolvedAppConfig> {
    let group_path = expand_tilde(&config.group_path);
    let share_path = expand_tilde(&config.share_path);

    let group_raw = std::fs::read_to_string(&group_path)
        .with_context(|| format!("read group package {group_path}"))?;
    let share_raw = std::fs::read_to_string(&share_path)
        .with_context(|| format!("read share package {share_path}"))?;

    let group = parse_group_package(&group_raw).context("parse group package")?;
    let share = parse_share_package(&share_raw).context("parse share package")?;

    Ok(ResolvedAppConfig {
        group,
        share,
        state_path: std::path::PathBuf::from(expand_tilde(&config.state_path)),
        relays: config.relays.clone(),
        peers: config.peers.clone(),
        manual_policy_overrides: config.manual_policy_overrides.clone(),
        options: config.options.clone(),
    })
}

pub fn load_share(path: &str) -> Result<bifrost_core::types::SharePackage> {
    let path = expand_tilde(path);
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read share file {path}"))?;
    parse_share_package(&raw).context("parse share package")
}

pub fn load_or_init_signer<S: DeviceStore>(config: &AppConfig, store: &S) -> Result<SigningDevice> {
    let resolved = resolve_config(config)?;
    load_or_init_signer_resolved(&resolved, store)
}

pub fn load_or_init_signer_resolved<S: DeviceStore>(
    config: &ResolvedAppConfig,
    store: &S,
) -> Result<SigningDevice> {
    let group = config.group.clone();
    let share = config.share.clone();
    let state_path = config.state_path.clone();
    let state = if store.exists() {
        let mut state = store.load().context("load state")?;
        if let Some(reason) = dirty_restart_reason(&state_path) {
            let occurrence = reason
                .counter()
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            warn!(
                ?reason,
                reason_code = reason.code(),
                event_id = reason.event_id(),
                occurrence,
                state_path = %state_path.display(),
                "dirty restart detected; discarding volatile state"
            );
            state.discard_volatile_for_dirty_restart(share.idx, share.seckey);
        } else {
            info!(
                state_path = %state_path.display(),
                "clean restart detected; preserving volatile state"
            );
        }
        state
    } else {
        DeviceState::new(share.idx, share.seckey)
    };

    let mut signer = SigningDevice::new(
        group,
        share.clone(),
        config.peers.clone(),
        state,
        DeviceConfig {
            sign_timeout_secs: config.options.sign_timeout_secs,
            ecdh_timeout_secs: config.options.ecdh_timeout_secs,
            ping_timeout_secs: config.options.ping_timeout_secs,
            onboard_timeout_secs: config.options.onboard_timeout_secs,
            request_ttl_secs: config.options.request_ttl_secs,
            max_future_skew_secs: config.options.max_future_skew_secs,
            request_cache_limit: config.options.request_cache_limit,
            ecdh_cache_capacity: config.options.ecdh_cache_capacity,
            ecdh_cache_ttl_secs: config.options.ecdh_cache_ttl_secs,
            sig_cache_capacity: config.options.sig_cache_capacity,
            sig_cache_ttl_secs: config.options.sig_cache_ttl_secs,
            state_save_interval_secs: config.options.state_save_interval_secs,
            event_kind: config.options.event_kind,
            peer_selection_strategy: config.options.peer_selection_strategy,
        },
    )?;

    for (peer, policy_override) in &config.manual_policy_overrides {
        signer.set_peer_policy_override(peer, policy_override.clone())?;
    }

    Ok(signer)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use bifrost_codec::package::{encode_group_package_json, encode_share_package_json};
    use bifrost_core::types::{PeerPolicyOverride, PolicyOverrideValue};
    use bifrost_signer::{
        CollectedResponse, DeviceState, DeviceStore, PendingOpContext, PendingOpType,
        PendingOperation,
    };
    use frostr_utils::{CreateKeysetConfig, create_keyset};

    use crate::runtime::{AppOptions, EncryptedFileStore};

    use super::*;

    fn temp_path(name: &str, suffix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bifrost-bootstrap-{name}-{}-{nonce}.{suffix}",
            std::process::id()
        ))
    }

    fn write_json(path: &PathBuf, value: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, value).expect("write file");
    }

    #[test]
    fn resolve_config_loads_packages_and_paths() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let group_path = temp_path("group", "json");
        let share_path = temp_path("share", "json");
        let state_path = temp_path("state", "bin");
        write_json(
            &group_path,
            &encode_group_package_json(&bundle.group).expect("encode group"),
        );
        write_json(
            &share_path,
            &encode_share_package_json(&bundle.shares[0]).expect("encode share"),
        );

        let config = AppConfig {
            group_path: group_path.display().to_string(),
            share_path: share_path.display().to_string(),
            state_path: state_path.display().to_string(),
            relays: vec!["ws://127.0.0.1:8194".to_string()],
            peers: Vec::new(),
            manual_policy_overrides: Default::default(),
            options: AppOptions::default(),
        };

        let resolved = resolve_config(&config).expect("resolve config");
        assert_eq!(resolved.group, bundle.group);
        assert_eq!(resolved.share, bundle.shares[0]);
        assert_eq!(resolved.state_path, state_path);

        let _ = fs::remove_file(group_path);
        let _ = fs::remove_file(share_path);
    }

    #[test]
    fn load_or_init_signer_resolved_reuses_saved_state_and_policy() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let group = bundle.group.clone();
        let share = bundle.shares[0].clone();
        let peer_pubkey = hex::encode(&group.members[1].pubkey[1..]);
        let resolved = ResolvedAppConfig {
            group,
            share: share.clone(),
            state_path: temp_path("state", "bin"),
            relays: vec!["ws://127.0.0.1:8194".to_string()],
            peers: vec![peer_pubkey.clone()],
            manual_policy_overrides: std::iter::once((
                peer_pubkey.clone(),
                PeerPolicyOverride {
                    request: bifrost_core::types::MethodPolicyOverride {
                        sign: PolicyOverrideValue::Deny,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ))
            .collect(),
            options: AppOptions::default(),
        };
        let store = EncryptedFileStore::new(resolved.state_path.clone(), share.clone());
        let mut state = DeviceState::new(share.idx, share.seckey);
        state.request_seq = 42;
        state.pending_operations.insert(
            "req-1".to_string(),
            PendingOperation {
                op_type: PendingOpType::Ping,
                request_id: "req-1".to_string(),
                started_at: 1,
                timeout_at: 2,
                target_peers: vec![peer_pubkey.clone()],
                threshold: 1,
                collected_responses: Vec::<CollectedResponse>::new(),
                context: PendingOpContext::PingRequest,
            },
        );
        store.save(&state).expect("save state");

        let signer = load_or_init_signer_resolved(&resolved, &store).expect("load signer");
        assert_eq!(signer.state().request_seq, 42);
        assert!(signer.state().pending_operations.is_empty());
        let peer_state = signer
            .peer_permission_states()
            .into_iter()
            .find(|entry| entry.pubkey == peer_pubkey)
            .expect("peer permission state");
        assert_eq!(
            peer_state.manual_override.request.sign,
            PolicyOverrideValue::Deny
        );

        let _ = fs::remove_file(&resolved.state_path);
    }
}
