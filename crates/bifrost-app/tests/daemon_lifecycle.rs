#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bifrost_app::host::{
    ControlCommand, DaemonClient, DaemonTransportConfig, RuntimeDiagnosticsSnapshot,
    run_resolved_daemon,
};
use bifrost_app::runtime::{AppOptions, ResolvedAppConfig};
use bifrost_core::types::{GroupPackage, SharePackage};
use frostr_utils::{CreateKeysetConfig, create_keyset};
use tokio::time::sleep;

fn temp_path(name: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bifrost-daemon-{name}-{}-{nonce}.{suffix}",
        std::process::id()
    ))
}

fn resolved_config(
    group: GroupPackage,
    share: SharePackage,
    state_path: PathBuf,
) -> ResolvedAppConfig {
    ResolvedAppConfig {
        group,
        share,
        state_path,
        relays: vec!["ws://127.0.0.1:65535".to_string()],
        peers: vec![],
        manual_policy_overrides: Default::default(),
        options: AppOptions::default(),
    }
}

async fn wait_for_socket(socket_path: &Path) {
    for _ in 0..100 {
        if socket_path.exists() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("socket did not appear: {}", socket_path.display());
}

#[tokio::test]
async fn run_resolved_daemon_serves_status_diagnostics_and_shutdown() {
    let bundle = create_keyset(CreateKeysetConfig {
        group_name: "Test Group".to_string(),
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let config = resolved_config(
        bundle.group,
        bundle.shares[0].clone(),
        temp_path("state", "bin"),
    );
    let socket_path = temp_path("control", "sock");
    let token = "daemon-test-token".to_string();
    let transport = DaemonTransportConfig {
        socket_path: socket_path.clone(),
        token: token.clone(),
    };

    let daemon = tokio::spawn(run_resolved_daemon(config.clone(), transport));
    wait_for_socket(&socket_path).await;

    let client = DaemonClient::new(socket_path.clone(), token);
    let status = client
        .request_ok(ControlCommand::Status)
        .await
        .expect("status over daemon socket");
    assert!(status["device_id"].is_string());
    assert!(status["pending_ops"].is_number());
    assert!(status["known_peers"].is_number());

    let diagnostics_value = client
        .request_ok(ControlCommand::RuntimeDiagnostics)
        .await
        .expect("runtime diagnostics");
    let diagnostics: RuntimeDiagnosticsSnapshot =
        serde_json::from_value(diagnostics_value).expect("parse diagnostics");
    assert!(diagnostics.runtime_status.is_object());
    assert!(diagnostics.runtime_status["readiness"].is_object());

    client
        .request_ok(ControlCommand::Shutdown)
        .await
        .expect("shutdown daemon");
    daemon.await.expect("join daemon").expect("daemon exit");

    assert!(!socket_path.exists(), "daemon socket should be removed");
    let _ = fs::remove_file(&config.state_path);
}

#[tokio::test]
async fn daemon_control_admin_commands_roundtrip() {
    let bundle = create_keyset(CreateKeysetConfig {
        group_name: "Test Group".to_string(),
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let config = resolved_config(
        bundle.group,
        bundle.shares[0].clone(),
        temp_path("admin-state", "bin"),
    );
    let socket_path = temp_path("admin-control", "sock");
    let token = "daemon-admin-token".to_string();
    let transport = DaemonTransportConfig {
        socket_path: socket_path.clone(),
        token: token.clone(),
    };

    let daemon = tokio::spawn(run_resolved_daemon(config.clone(), transport));
    wait_for_socket(&socket_path).await;

    let client = DaemonClient::new(socket_path.clone(), token);
    let metadata = client
        .request_ok(ControlCommand::RuntimeMetadata)
        .await
        .expect("runtime metadata");
    assert!(metadata["member_idx"].is_number());
    assert!(metadata["peers"].is_array());

    client
        .request_ok(ControlCommand::UpdateConfig {
            config_patch_json: serde_json::json!({
                "sign_timeout_secs": 44,
                "ping_timeout_secs": 18
            })
            .to_string(),
        })
        .await
        .expect("update config");
    let updated = client
        .request_ok(ControlCommand::ReadConfig)
        .await
        .expect("read updated config");
    assert_eq!(updated["sign_timeout_secs"], 44);
    assert_eq!(updated["ping_timeout_secs"], 18);

    client
        .request_ok(ControlCommand::Shutdown)
        .await
        .expect("shutdown daemon");
    daemon.await.expect("join daemon").expect("daemon exit");

    assert!(!socket_path.exists(), "daemon socket should be removed");
    let _ = fs::remove_file(&config.state_path);
}

#[tokio::test]
async fn daemon_control_runtime_surfaces_roundtrip() {
    let bundle = create_keyset(CreateKeysetConfig {
        group_name: "Test Group".to_string(),
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let config = resolved_config(
        bundle.group,
        bundle.shares[0].clone(),
        temp_path("runtime-state", "bin"),
    );
    let socket_path = temp_path("runtime-control", "sock");
    let token = "daemon-runtime-token".to_string();
    let transport = DaemonTransportConfig {
        socket_path: socket_path.clone(),
        token: token.clone(),
    };

    let daemon = tokio::spawn(run_resolved_daemon(config.clone(), transport));
    wait_for_socket(&socket_path).await;

    let client = DaemonClient::new(socket_path.clone(), token);

    let peer_status = client
        .request_ok(ControlCommand::PeerStatus)
        .await
        .expect("peer status");
    assert!(peer_status.is_array());

    let readiness = client
        .request_ok(ControlCommand::Readiness)
        .await
        .expect("readiness");
    assert!(readiness["threshold"].is_number());
    assert!(readiness["restore_complete"].is_boolean());

    let runtime_status = client
        .request_ok(ControlCommand::RuntimeStatus)
        .await
        .expect("runtime status");
    assert!(runtime_status["status"].is_object());
    assert!(runtime_status["readiness"].is_object());
    assert!(runtime_status["peers"].is_array());
    assert!(runtime_status["peer_permission_states"].is_array());

    client
        .request_ok(ControlCommand::Shutdown)
        .await
        .expect("shutdown daemon");
    daemon.await.expect("join daemon").expect("daemon exit");

    assert!(!socket_path.exists(), "daemon socket should be removed");
    let _ = fs::remove_file(&config.state_path);
}
