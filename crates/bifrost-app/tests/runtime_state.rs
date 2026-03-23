use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bifrost_app::runtime::{
    AppConfig, AppOptions, DeviceLock, EncryptedFileStore, ResolvedAppConfig, begin_run,
    complete_clean_run, expand_tilde, inspect_state_health, load_config,
    load_or_init_signer_resolved, load_share, resolve_config,
};
use bifrost_codec::package::{encode_group_package_json, encode_share_package_json};
use bifrost_core::types::{PeerPolicyOverride, PolicyOverrideValue};
use bifrost_signer::{
    CollectedResponse, DeviceState, DeviceStore, PendingOpContext, PendingOpType, PendingOperation,
};
use frostr_utils::{CreateKeysetConfig, create_keyset};

fn home_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn temp_path(name: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bifrost-runtime-{name}-{}-{nonce}.{suffix}",
        std::process::id()
    ))
}

fn write_json(path: &PathBuf, value: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, value).expect("write file");
}

fn base_config() -> (
    ResolvedAppConfig,
    bifrost_core::types::GroupPackage,
    bifrost_core::types::SharePackage,
) {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let share = bundle.shares[0].clone();
    let peer_pubkey = hex::encode(&group.members[1].pubkey[1..]);
    let resolved = ResolvedAppConfig {
        group: group.clone(),
        share: share.clone(),
        state_path: temp_path("state", "bin"),
        relays: vec!["ws://127.0.0.1:8194".to_string()],
        peers: vec![peer_pubkey.clone()],
        manual_policy_overrides: std::iter::once((
            peer_pubkey,
            PeerPolicyOverride {
                request: bifrost_core::types::MethodPolicyOverride {
                    sign: PolicyOverrideValue::Deny,
                    ..Default::default()
                },
                ..Default::default()
            },
        ))
        .collect(),
        remote_policy_observations: Default::default(),
        options: AppOptions::default(),
    };
    (resolved, group, share)
}

#[test]
fn load_config_rejects_empty_relays() {
    let config_path = temp_path("config-empty-relays", "json");
    write_json(
        &config_path,
        &serde_json::json!({
            "group_path": "/tmp/group.json",
            "share_path": "/tmp/share.json",
            "state_path": "/tmp/state.bin",
            "relays": [],
            "peers": [],
            "options": {}
        })
        .to_string(),
    );

    let err = load_config(&config_path).expect_err("empty relays must fail");
    assert!(err.to_string().contains("config.relays must not be empty"));

    let _ = fs::remove_file(config_path);
}

#[test]
fn expand_tilde_uses_home_only_for_tilde_prefix() {
    let _guard = home_env_lock().lock().expect("lock HOME env");
    let home = temp_path("fake-home", "dir");
    fs::create_dir_all(&home).expect("create fake home");
    let previous_home = std::env::var_os("HOME");
    unsafe {
        std::env::set_var("HOME", &home);
    }

    let expanded = expand_tilde("~/nested/share.json");
    assert_eq!(
        expanded,
        home.join("nested/share.json").display().to_string()
    );
    assert_eq!(
        expand_tilde("/tmp/already-absolute"),
        "/tmp/already-absolute"
    );

    if let Some(value) = previous_home {
        unsafe {
            std::env::set_var("HOME", value);
        }
    } else {
        unsafe {
            std::env::remove_var("HOME");
        }
    }
    let _ = fs::remove_dir_all(home);
}

#[test]
fn resolve_config_loads_group_and_share_packages_from_disk() {
    let bundle = create_keyset(CreateKeysetConfig {
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
        remote_policy_observations: Default::default(),
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
fn load_share_supports_tilde_paths() {
    let _guard = home_env_lock().lock().expect("lock HOME env");
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let fake_home = temp_path("fake-home-share", "dir");
    let share_rel = "shares/member.json";
    let share_path = fake_home.join(share_rel);
    write_json(
        &share_path,
        &encode_share_package_json(&bundle.shares[1]).expect("encode share"),
    );

    let previous_home = std::env::var_os("HOME");
    unsafe {
        std::env::set_var("HOME", &fake_home);
    }

    let share = load_share(&format!("~/{}", share_rel)).expect("load share with tilde");
    assert_eq!(share, bundle.shares[1]);

    if let Some(value) = previous_home {
        unsafe {
            std::env::set_var("HOME", value);
        }
    } else {
        unsafe {
            std::env::remove_var("HOME");
        }
    }
    let _ = fs::remove_dir_all(fake_home);
}

#[test]
fn load_or_init_signer_discards_volatile_state_after_dirty_restart_and_applies_policy() {
    let (resolved, _group, share) = base_config();
    let store = EncryptedFileStore::new(resolved.state_path.clone(), share.clone());
    let now = 1_700_000_000;
    let peer = resolved.peers[0].clone();

    let mut state = DeviceState::new(share.idx, share.seckey);
    state.pending_operations.insert(
        "req-1".to_string(),
        PendingOperation {
            op_type: PendingOpType::Ping,
            request_id: "req-1".to_string(),
            started_at: now,
            timeout_at: now + 30,
            target_peers: vec![peer.clone()],
            threshold: 1,
            collected_responses: Vec::<CollectedResponse>::new(),
            context: PendingOpContext::PingRequest,
        },
    );
    store.save(&state).expect("save state");

    let signer = load_or_init_signer_resolved(&resolved, &store).expect("load signer");
    assert!(signer.state().pending_operations.is_empty());
    let peer_state = signer
        .peer_permission_states()
        .into_iter()
        .find(|entry| entry.pubkey == peer)
        .expect("peer permission state");
    assert_eq!(
        peer_state.manual_override.request.sign,
        PolicyOverrideValue::Deny
    );
    assert!(!peer_state.effective_policy.request.sign);

    let _ = fs::remove_file(resolved.state_path);
}

#[test]
fn encrypted_store_roundtrip_and_state_health_report_clean_run() {
    let (resolved, _group, share) = base_config();
    let store = EncryptedFileStore::new(resolved.state_path.clone(), share.clone());
    let mut state = DeviceState::new(share.idx, share.seckey);
    state.request_seq = 42;
    store.save(&state).expect("save state");

    let loaded = store.load().expect("load state");
    assert_eq!(loaded.request_seq, 42);

    let run_id = begin_run(&resolved.state_path).expect("begin run");
    complete_clean_run(&resolved.state_path, &run_id, &loaded).expect("complete run");
    let health = inspect_state_health(&resolved.state_path);
    assert!(health.clean);
    assert!(health.dirty_reason.is_none());
    assert_eq!(health.marker.as_ref().expect("marker").phase, "clean");
    assert!(health.state_hash.is_some());

    let _ = fs::remove_file(&resolved.state_path);
    let _ = fs::remove_file(resolved.state_path.with_extension("run.json"));
}

#[test]
fn device_lock_reports_holder_when_already_locked() {
    let state_path = temp_path("lock-state", "bin");
    let _first = DeviceLock::acquire_exclusive(&state_path).expect("first lock");

    let second = DeviceLock::acquire_exclusive(&state_path)
        .err()
        .expect("second lock must fail");
    assert!(
        second
            .to_string()
            .contains("device is locked by another process")
    );

    let _ = fs::remove_file(state_path.with_extension("lock"));
}

#[test]
fn shared_device_lock_is_compatible_with_shared_reader_and_blocks_exclusive_writer() {
    let state_path = temp_path("shared-lock-state", "bin");
    let shared_one = DeviceLock::acquire_shared(&state_path).expect("first shared lock");
    let shared_two = DeviceLock::acquire_shared(&state_path).expect("second shared lock");

    let exclusive = DeviceLock::acquire_exclusive(&state_path)
        .err()
        .expect("exclusive lock must fail while shared locks held");
    assert!(
        exclusive
            .to_string()
            .contains("device is locked by another process")
    );

    drop(shared_two);
    drop(shared_one);
    let _exclusive = DeviceLock::acquire_exclusive(&state_path).expect("exclusive after shared");

    let _ = fs::remove_file(state_path.with_extension("lock"));
}
