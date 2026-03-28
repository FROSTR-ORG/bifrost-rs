#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bifrost_app::host::{ControlCommand, DaemonClient, DaemonTransportConfig, run_resolved_daemon};
use bifrost_app::runtime::{AppOptions, ResolvedAppConfig};
use frostr_utils::{CreateKeysetConfig, create_keyset};
use tokio::time::sleep;

fn temp_path(name: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bifrost-daemon-errors-{name}-{}-{nonce}.{suffix}",
        std::process::id()
    ))
}

fn resolved_config() -> ResolvedAppConfig {
    let bundle = create_keyset(CreateKeysetConfig {
        group_name: "Test Group".to_string(),
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    ResolvedAppConfig {
        group: bundle.group,
        share: bundle.shares[0].clone(),
        state_path: temp_path("state", "bin"),
        relays: vec!["ws://127.0.0.1:65535".to_string()],
        peers: vec![],
        manual_policy_overrides: Default::default(),
        options: AppOptions::default(),
    }
}

async fn wait_for_socket(socket_path: &PathBuf) {
    for _ in 0..100 {
        if socket_path.exists() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("socket did not appear: {}", socket_path.display());
}

#[tokio::test]
async fn daemon_control_maps_invalid_hex_and_unknown_peer_errors() {
    let config = resolved_config();
    let socket_path = temp_path("control", "sock");
    let token = "daemon-error-token".to_string();
    let transport = DaemonTransportConfig {
        socket_path: socket_path.clone(),
        token: token.clone(),
    };

    let daemon = tokio::spawn(run_resolved_daemon(config.clone(), transport));
    wait_for_socket(&socket_path).await;

    let client = DaemonClient::new(socket_path.clone(), token);

    let err = client
        .request_ok(ControlCommand::Sign {
            message_hex32: "abc".to_string(),
            timeout_secs: Some(1),
        })
        .await
        .expect_err("invalid sign hex must fail");
    let err = err.to_string();
    assert!(err.contains("invalid") || err.contains("hex"));

    let err = client
        .request_ok(ControlCommand::Ecdh {
            pubkey_hex32: "xyz".to_string(),
            timeout_secs: Some(1),
        })
        .await
        .expect_err("invalid ecdh hex must fail");
    let err = err.to_string();
    assert!(err.contains("invalid") || err.contains("hex"));

    let err = client
        .request_ok(ControlCommand::Ping {
            peer: "00".repeat(32),
            timeout_secs: Some(1),
        })
        .await
        .expect_err("unknown peer ping must fail");
    assert!(err.to_string().contains("unknown peer"));

    let err = client
        .request_ok(ControlCommand::Onboard {
            peer: "00".repeat(32),
            timeout_secs: Some(1),
        })
        .await
        .expect_err("unknown peer onboard must fail");
    let err = err.to_string();
    assert!(err.contains("unknown peer"));

    let err = client
        .request_ok(ControlCommand::SetPolicyOverride {
            peer: "00".repeat(32),
            policy_override_json: serde_json::json!({
                "request": {
                    "ping": "allow",
                    "onboard": "allow",
                    "sign": "allow",
                    "ecdh": "allow"
                },
                "respond": {
                    "ping": "allow",
                    "onboard": "allow",
                    "sign": "allow",
                    "ecdh": "allow"
                }
            })
            .to_string(),
        })
        .await
        .expect_err("unknown peer set policy override must fail");
    assert!(err.to_string().contains("unknown peer"));

    client
        .request_ok(ControlCommand::Shutdown)
        .await
        .expect("shutdown daemon");
    daemon.await.expect("join daemon").expect("daemon exit");

    assert!(!socket_path.exists(), "daemon socket should be removed");
    let _ = fs::remove_file(&config.state_path);
}
