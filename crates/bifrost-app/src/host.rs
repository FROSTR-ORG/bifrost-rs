#[cfg(test)]
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::runtime::{EncryptedFileStore, ResolvedAppConfig, load_config};
#[cfg(test)]
use anyhow::{Result, anyhow};
#[cfg(test)]
use bifrost_bridge_tokio::{Bridge, BridgeConfig};
#[cfg(test)]
use bifrost_signer::DeviceStatus;
#[cfg(test)]
use serde_json::json;
#[cfg(all(test, unix))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "host/client.rs"]
mod client;
#[path = "host/daemon.rs"]
mod daemon;
#[path = "host/handlers.rs"]
mod handlers;
#[path = "host/logging.rs"]
mod logging;
#[path = "host/protocol.rs"]
mod protocol;
#[path = "host/types.rs"]
mod types;

pub use client::DaemonClient;
pub use daemon::run_resolved_daemon;
pub use handlers::{execute_command, run_command};
pub use logging::{default_log_filter, init_tracing};
pub use protocol::{ControlCommand, ControlRequest, ControlResponse};
pub use types::{
    DaemonTransportConfig, EcdhPayload, HostCommand, HostCommandResult, LogOptions, OnboardPayload,
    PingPayload, ReadConfigPayload, ReadinessPayload, RuntimeDiagnosticsSnapshot,
    RuntimeMetadataPayload, RuntimeStatusPayload, ShutdownPayload, SignPayload, UpdatedPayload,
    WipedPayload,
};

#[cfg(test)]
pub(crate) use daemon::handle_control_stream;
#[cfg(test)]
pub(crate) use handlers::{decode_hex32, execute_control_command, print_host_result};
#[cfg(test)]
pub(crate) use protocol::next_request_id;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bifrost_codec::package::{encode_group_package_json, encode_share_package_json};
    use bifrost_core::types::{GroupPackage, PeerPolicy, SharePackage};
    use bifrost_signer::{
        DeviceConfig, DeviceState, PendingOpContext, PendingOpType, PendingOperation, SigningDevice,
    };
    use frostr_utils::{CreateKeysetConfig, create_keyset};
    use nostr::{Event, Filter};
    use std::fs;
    use tokio::sync::mpsc;

    use crate::runtime::{AppConfig, AppOptions, load_or_init_signer_resolved, resolve_config};

    struct MockRelayAdapter {
        inbound_rx: mpsc::UnboundedReceiver<Event>,
        published_tx: mpsc::UnboundedSender<Event>,
    }

    #[async_trait]
    impl bifrost_bridge_tokio::RelayAdapter for MockRelayAdapter {
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

    struct HostFixture {
        bridge: Bridge,
        store: EncryptedFileStore,
        config: ResolvedAppConfig,
    }

    struct HostConfigFixture {
        config_path: PathBuf,
        group_path: PathBuf,
        share_path: PathBuf,
        state_path: PathBuf,
    }

    fn temp_path(name: &str, suffix: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bifrost-host-{name}-{}-{nonce}.{suffix}",
            std::process::id()
        ))
    }

    fn build_signer(
        group: &GroupPackage,
        share: &SharePackage,
        mut state: DeviceState,
    ) -> SigningDevice {
        let peers = group
            .members
            .iter()
            .filter(|member| member.idx != share.idx)
            .map(|member| hex::encode(&member.pubkey[1..]))
            .collect::<Vec<_>>();
        state.pending_operations.clear();
        SigningDevice::new(
            group.clone(),
            share.clone(),
            peers,
            state,
            DeviceConfig::default(),
        )
        .expect("build signer")
    }

    async fn host_fixture_with_state(state: DeviceState) -> HostFixture {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let group = bundle.group.clone();
        let share = bundle.shares[0].clone();
        let signer = build_signer(&group, &share, state);
        let store_path = temp_path("state", "bin");
        let store = EncryptedFileStore::new(store_path.clone(), share.clone());
        let (_inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (published_tx, _published_rx) = mpsc::unbounded_channel();
        let bridge = Bridge::start_with_config(
            MockRelayAdapter {
                inbound_rx,
                published_tx,
            },
            signer,
            BridgeConfig::default(),
        )
        .await
        .expect("start bridge");
        let config = ResolvedAppConfig {
            group,
            share,
            state_path: store_path,
            relays: vec!["ws://127.0.0.1:8194".to_string()],
            peers: vec![],
            manual_policy_overrides: Default::default(),
            options: AppOptions::default(),
        };
        HostFixture {
            bridge,
            store,
            config,
        }
    }

    async fn host_fixture() -> HostFixture {
        host_fixture_with_state(DeviceState::new(1, [7u8; 32])).await
    }

    async fn host_live_fixture() -> (HostFixture, tokio::task::JoinHandle<()>) {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let group = bundle.group.clone();
        let share = bundle.shares[0].clone();
        let signer = build_signer(&group, &share, DeviceState::new(share.idx, share.seckey));
        let store_path = temp_path("live-state", "bin");
        let store = EncryptedFileStore::new(store_path.clone(), share.clone());
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let inbound_tx_worker = inbound_tx.clone();
        let (published_tx, mut published_rx) = mpsc::unbounded_channel();
        let mut peer_signers = bundle
            .shares
            .iter()
            .skip(1)
            .map(|member_share| {
                build_signer(
                    &group,
                    member_share,
                    DeviceState::new(member_share.idx, member_share.seckey),
                )
            })
            .collect::<Vec<_>>();
        let bridge = Bridge::start_with_config(
            MockRelayAdapter {
                inbound_rx,
                published_tx,
            },
            signer,
            BridgeConfig::default(),
        )
        .await
        .expect("start bridge");
        let config = ResolvedAppConfig {
            group,
            share,
            state_path: store_path,
            relays: vec!["ws://127.0.0.1:8194".to_string()],
            peers: bundle
                .group
                .members
                .iter()
                .filter(|member| member.idx != bundle.shares[0].idx)
                .map(|member| hex::encode(&member.pubkey[1..]))
                .collect(),
            manual_policy_overrides: Default::default(),
            options: AppOptions::default(),
        };
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
            drop(inbound_tx);
        });
        (
            HostFixture {
                bridge,
                store,
                config,
            },
            worker,
        )
    }

    fn write_string(path: &Path, value: String) {
        fs::write(path, value).expect("write file");
    }

    fn host_config_fixture() -> HostConfigFixture {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let group_path = temp_path("cfg-group", "json");
        let share_path = temp_path("cfg-share", "json");
        let state_path = temp_path("cfg-state", "bin");
        let config_path = temp_path("cfg", "json");

        write_string(
            &group_path,
            encode_group_package_json(&bundle.group).expect("encode group"),
        );
        write_string(
            &share_path,
            encode_share_package_json(&bundle.shares[0]).expect("encode share"),
        );
        write_string(
            &config_path,
            serde_json::to_string(&AppConfig {
                group_path: group_path.display().to_string(),
                share_path: share_path.display().to_string(),
                state_path: state_path.display().to_string(),
                relays: vec!["ws://127.0.0.1:65535".to_string()],
                peers: bundle
                    .group
                    .members
                    .iter()
                    .filter(|member| member.idx != bundle.shares[0].idx)
                    .map(|member| hex::encode(&member.pubkey[1..]))
                    .collect(),
                manual_policy_overrides: Default::default(),
                options: AppOptions::default(),
            })
            .expect("serialize config"),
        );

        HostConfigFixture {
            config_path,
            group_path,
            share_path,
            state_path,
        }
    }

    fn cleanup_host_config_fixture(fixture: HostConfigFixture) {
        let _ = fs::remove_file(fixture.config_path);
        let _ = fs::remove_file(fixture.group_path);
        let _ = fs::remove_file(fixture.share_path);
        let _ = fs::remove_file(&fixture.state_path);
        let _ = fs::remove_file(fixture.state_path.with_extension("run.json"));
        let _ = fs::remove_file(fixture.state_path.with_extension("lock"));
    }

    async fn socket_pair(_socket_path: &Path) -> (tokio::net::UnixStream, tokio::net::UnixStream) {
        tokio::net::UnixStream::pair().expect("create unix stream pair")
    }

    #[tokio::test]
    async fn runtime_diagnostics_exposes_runtime_status() {
        let fixture = host_fixture().await;

        let diagnostics = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-diag".to_string(),
                token: "token".to_string(),
                command: ControlCommand::RuntimeDiagnostics,
            },
        )
        .await
        .expect("runtime diagnostics");
        assert_eq!(diagnostics.0, "req-diag");
        assert!(diagnostics.1["runtime_status"].is_object());

        fixture.bridge.shutdown().await;
        let _ = std::fs::remove_file(&fixture.config.state_path);
    }

    #[tokio::test]
    async fn handle_control_stream_rejects_invalid_token_and_bad_json() {
        let fixture = host_fixture().await;
        let socket_path = temp_path("control", "sock");
        let (mut client, mut server) = socket_pair(&socket_path).await;
        let mut shutdown_tx = None;

        let worker = tokio::spawn(async move {
            handle_control_stream(
                &fixture.bridge,
                &fixture.store,
                &fixture.config,
                "expected-token",
                &mut server,
                &mut shutdown_tx,
            )
            .await
        });

        let invalid_request = serde_json::to_vec(&ControlRequest {
            request_id: "req-auth".to_string(),
            token: "wrong-token".to_string(),
            command: ControlCommand::Status,
        })
        .expect("serialize request");
        client
            .write_all(&invalid_request)
            .await
            .expect("write request");
        client.shutdown().await.expect("shutdown client");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response: ControlResponse =
            serde_json::from_slice(&response).expect("parse control response");
        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("invalid control token"));
        worker.await.expect("join worker").expect("handle control");

        let fixture = host_fixture().await;
        let socket_path = temp_path("control-bad", "sock");
        let (mut client, mut server) = socket_pair(&socket_path).await;
        let mut shutdown_tx = None;
        let worker = tokio::spawn(async move {
            handle_control_stream(
                &fixture.bridge,
                &fixture.store,
                &fixture.config,
                "expected-token",
                &mut server,
                &mut shutdown_tx,
            )
            .await
        });
        client
            .write_all(br#"{"request_id":"oops","token":"expected-token""#)
            .await
            .expect("write malformed request");
        client.shutdown().await.expect("shutdown client");
        let err = worker
            .await
            .expect("join worker")
            .expect_err("malformed json must fail");
        assert!(err.to_string().contains("invalid control request json"));
    }

    #[tokio::test]
    async fn handle_control_stream_returns_success_response_without_shutdown() {
        let fixture = host_fixture().await;
        let socket_path = temp_path("control-ok", "sock");
        let (mut client, mut server) = socket_pair(&socket_path).await;
        let mut shutdown_tx = None;

        let worker = tokio::spawn(async move {
            handle_control_stream(
                &fixture.bridge,
                &fixture.store,
                &fixture.config,
                "expected-token",
                &mut server,
                &mut shutdown_tx,
            )
            .await
        });

        let request = serde_json::to_vec(&ControlRequest {
            request_id: "req-status".to_string(),
            token: "expected-token".to_string(),
            command: ControlCommand::Status,
        })
        .expect("serialize request");
        client.write_all(&request).await.expect("write request");
        client.shutdown().await.expect("shutdown client");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response: ControlResponse =
            serde_json::from_slice(&response).expect("parse control response");
        assert!(response.ok);
        assert_eq!(response.request_id, "req-status");
        assert!(response.result.expect("control result")["device_id"].is_string());

        worker.await.expect("join worker").expect("handle control");
    }

    #[tokio::test]
    async fn wipe_state_clears_runtime_state_and_shutdown_requests_exit() {
        let mut state = DeviceState::new(1, [9u8; 32]);
        state.replay_cache.insert("req".to_string(), 1);
        state.peer_last_seen.insert("peer-a".to_string(), 42);
        state.pending_operations.insert(
            "pending-1".to_string(),
            PendingOperation {
                op_type: PendingOpType::Ping,
                request_id: "pending-1".to_string(),
                started_at: 1,
                timeout_at: 2,
                target_peers: vec!["peer-a".to_string()],
                threshold: 1,
                collected_responses: Vec::new(),
                context: PendingOpContext::PingRequest,
            },
        );
        let fixture = host_fixture_with_state(state).await;

        let wipe = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-wipe".to_string(),
                token: "token".to_string(),
                command: ControlCommand::WipeState,
            },
        )
        .await
        .expect("wipe state");
        assert_eq!(wipe.0, "req-wipe");
        assert_eq!(wipe.1["wiped"], true);

        let snapshot = fixture
            .bridge
            .snapshot_state()
            .await
            .expect("snapshot state after wipe");
        assert!(snapshot.pending_operations.is_empty());
        assert!(snapshot.peer_last_seen.is_empty());
        assert!(snapshot.replay_cache.is_empty());

        let shutdown = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-shutdown".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Shutdown,
            },
        )
        .await
        .expect("shutdown command");
        assert_eq!(shutdown.0, "req-shutdown");
        assert!(shutdown.2);

        fixture.bridge.shutdown().await;
        let _ = std::fs::remove_file(&fixture.config.state_path);
    }

    #[tokio::test]
    async fn execute_control_command_covers_admin_roundtrip_and_error_paths() {
        let fixture = host_fixture().await;

        let config = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-update-config".to_string(),
                token: "token".to_string(),
                command: ControlCommand::UpdateConfig {
                    config_patch_json: serde_json::json!({
                        "sign_timeout_secs": 55,
                        "ping_timeout_secs": 17
                    })
                    .to_string(),
                },
            },
        )
        .await
        .expect("update config");
        assert_eq!(config.1["updated"], true);

        let read_config = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-read-config".to_string(),
                token: "token".to_string(),
                command: ControlCommand::ReadConfig,
            },
        )
        .await
        .expect("read config");
        assert_eq!(read_config.1["sign_timeout_secs"], 55);
        assert_eq!(read_config.1["ping_timeout_secs"], 17);

        let peer_status = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-peer-status".to_string(),
                token: "token".to_string(),
                command: ControlCommand::PeerStatus,
            },
        )
        .await
        .expect("peer status");
        assert!(peer_status.1.is_array());

        let runtime_metadata = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-runtime-metadata".to_string(),
                token: "token".to_string(),
                command: ControlCommand::RuntimeMetadata,
            },
        )
        .await
        .expect("runtime metadata");
        assert_eq!(runtime_metadata.1["member_idx"], fixture.config.share.idx);
        assert_eq!(
            runtime_metadata.1["peers"]
                .as_array()
                .expect("metadata peers")
                .len(),
            2
        );

        let err = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-config-bad-json".to_string(),
                token: "token".to_string(),
                command: ControlCommand::UpdateConfig {
                    config_patch_json: "{".to_string(),
                },
            },
        )
        .await
        .expect_err("invalid config patch json must fail");
        assert_eq!(err.0, "req-config-bad-json");
        assert!(err.1.contains("invalid config patch json"));

        let err = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-sign-bad-hex".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Sign {
                    message_hex32: "abcd".to_string(),
                    timeout_secs: Some(1),
                },
            },
        )
        .await
        .expect_err("invalid sign hex must fail");
        assert_eq!(err.0, "req-sign-bad-hex");
        assert!(err.1.contains("invalid hex32") || err.1.contains("expected 32 bytes"));

        let err = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-policy-unknown-peer".to_string(),
                token: "token".to_string(),
                command: ControlCommand::SetPolicyOverride {
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
                },
            },
        )
        .await
        .expect_err("unknown policy peer must fail");
        assert_eq!(err.0, "req-policy-unknown-peer");
        assert!(err.1.contains("unknown peer"));

        let err = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-ecdh-bad-hex".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Ecdh {
                    pubkey_hex32: "abcd".to_string(),
                    timeout_secs: Some(1),
                },
            },
        )
        .await
        .expect_err("invalid ecdh hex must fail");
        assert_eq!(err.0, "req-ecdh-bad-hex");
        assert!(err.1.contains("invalid hex32") || err.1.contains("expected 32 bytes"));

        fixture.bridge.shutdown().await;
        let _ = std::fs::remove_file(&fixture.config.state_path);
    }

    #[tokio::test]
    async fn execute_control_command_round_trips_live_ping_onboard_sign_and_ecdh() {
        let (fixture, worker) = host_live_fixture().await;
        let peer_pubkeys = fixture.config.peers.clone();
        let target_peer = peer_pubkeys[0].clone();

        for peer in &peer_pubkeys {
            let ping = execute_control_command(
                &fixture.bridge,
                &fixture.config,
                ControlRequest {
                    request_id: format!("req-ping-{peer}"),
                    token: "token".to_string(),
                    command: ControlCommand::Ping {
                        peer: peer.clone(),
                        timeout_secs: Some(5),
                    },
                },
            )
            .await
            .expect("ping");
            assert_eq!(ping.1["peer"], *peer);
        }

        let onboard = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-onboard-live".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Onboard {
                    peer: target_peer.clone(),
                    timeout_secs: Some(5),
                },
            },
        )
        .await
        .expect("onboard");
        assert_eq!(
            onboard.1["group_member_count"]
                .as_u64()
                .expect("group member count"),
            fixture.config.group.members.len() as u64
        );

        let sign = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-sign-live".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Sign {
                    message_hex32: "aa".repeat(32),
                    timeout_secs: Some(5),
                },
            },
        )
        .await
        .expect("sign");
        assert_eq!(
            sign.1["signatures_hex"]
                .as_array()
                .expect("signatures")
                .len(),
            1
        );

        let ecdh = execute_control_command(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-ecdh-live".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Ecdh {
                    pubkey_hex32: target_peer,
                    timeout_secs: Some(5),
                },
            },
        )
        .await
        .expect("ecdh");
        assert_eq!(
            ecdh.1["shared_secret_hex32"]
                .as_str()
                .expect("shared secret")
                .len(),
            64
        );

        fixture.bridge.shutdown().await;
        let _ = worker.await;
        let _ = std::fs::remove_file(&fixture.config.state_path);
    }

    #[test]
    fn helper_functions_cover_log_filters_request_ids_and_hex_decode() {
        assert_eq!(
            default_log_filter(LogOptions {
                verbose: false,
                debug: false,
            }),
            "warn"
        );
        assert_eq!(
            default_log_filter(LogOptions {
                verbose: true,
                debug: false,
            }),
            "warn,bifrost_app=info,bifrost_bridge_tokio=info,bifrost_signer=info"
        );
        assert_eq!(
            default_log_filter(LogOptions {
                verbose: false,
                debug: true,
            }),
            "warn,bifrost_app=debug,bifrost_bridge_tokio=debug,bifrost_signer=debug"
        );

        let first = next_request_id();
        let second = next_request_id();
        assert_ne!(first, second);
        assert!(first.starts_with("req-"));
        assert!(second.starts_with("req-"));

        assert_eq!(
            decode_hex32(&"11".repeat(32)).expect("valid hex"),
            [0x11; 32]
        );
        assert!(decode_hex32("zz").is_err());
        assert!(decode_hex32(&"22".repeat(31)).is_err());

        let policy = PeerPolicy::from_send_receive(false, true);
        assert_eq!(policy, PeerPolicy::from_send_receive(false, true));
    }

    #[tokio::test]
    async fn execute_command_offline_admin_paths_round_trip_from_config_file() {
        let fixture = host_config_fixture();
        let log = LogOptions {
            verbose: false,
            debug: false,
        };

        let status = execute_command(&fixture.config_path, HostCommand::Status, log)
            .await
            .expect("status");
        match status {
            HostCommandResult::Status { status } => {
                assert_eq!(status.known_peers, 2);
            }
            other => panic!("unexpected status result: {other:?}"),
        }

        let policy_json = serde_json::json!({
            "request": {
                "ping": "allow",
                "onboard": "allow",
                "sign": "deny",
                "ecdh": "allow"
            },
            "respond": {
                "ping": "allow",
                "onboard": "allow",
                "sign": "allow",
                "ecdh": "allow"
            }
        })
        .to_string();
        let peer = {
            let config = load_config(&fixture.config_path).expect("load config");
            config.peers[0].clone()
        };
        let updated = execute_command(
            &fixture.config_path,
            HostCommand::SetPolicyOverride {
                peer: peer.clone(),
                policy_json,
            },
            log,
        )
        .await
        .expect("set policy");
        match updated {
            HostCommandResult::PolicyUpdated { peer: updated_peer } => {
                assert_eq!(updated_peer, peer);
            }
            other => panic!("unexpected policy update result: {other:?}"),
        }

        let config = load_config(&fixture.config_path).expect("reload config");
        let resolved = resolve_config(&config).expect("resolve config");
        let store = EncryptedFileStore::new(resolved.state_path.clone(), resolved.share.clone());
        let signer = load_or_init_signer_resolved(&resolved, &store).expect("load signer");
        let peer_policy = signer
            .peer_permission_states()
            .into_iter()
            .find(|entry| entry.pubkey == peer)
            .expect("peer policy entry");
        assert_eq!(peer_policy.pubkey, peer);
        assert!(peer_policy.effective_policy.respond.sign);

        let health = execute_command(&fixture.config_path, HostCommand::StateHealth, log)
            .await
            .expect("state health");
        match health {
            HostCommandResult::StateHealth { report } => {
                assert_eq!(report["state_exists"], true);
                assert_eq!(report["clean"], true);
            }
            other => panic!("unexpected state health result: {other:?}"),
        }

        cleanup_host_config_fixture(fixture);
    }

    #[tokio::test]
    async fn execute_command_offline_admin_paths_report_expected_errors() {
        let fixture = host_config_fixture();
        let log = LogOptions {
            verbose: false,
            debug: false,
        };

        let err = execute_command(
            &fixture.config_path,
            HostCommand::SetPolicyOverride {
                peer: {
                    let config = load_config(&fixture.config_path).expect("load config");
                    config.peers[0].clone()
                },
                policy_json: "{".to_string(),
            },
            log,
        )
        .await
        .expect_err("invalid policy override json must fail");
        assert!(err.to_string().contains("invalid policy override json"));

        cleanup_host_config_fixture(fixture);
    }

    #[test]
    fn print_host_result_handles_all_non_network_variants() {
        assert!(
            print_host_result(&HostCommandResult::StateHealth {
                report: json!({"clean": true}),
            })
            .is_ok()
        );
        assert!(
            print_host_result(&HostCommandResult::PolicyUpdated {
                peer: "peer-a".to_string(),
            })
            .is_ok()
        );
        assert!(
            print_host_result(&HostCommandResult::Ping {
                request_id: "req-1".to_string(),
                peer: "peer-a".to_string(),
            })
            .is_ok()
        );
        assert!(
            print_host_result(&HostCommandResult::Onboard {
                request_id: "req-2".to_string(),
                group_member_count: 3,
            })
            .is_ok()
        );
        assert!(
            print_host_result(&HostCommandResult::Ecdh {
                request_id: "req-3".to_string(),
                shared_secret_hex32: "22".repeat(32),
            })
            .is_ok()
        );
        assert!(
            print_host_result(&HostCommandResult::Status {
                status: DeviceStatus {
                    device_id: "device".to_string(),
                    pending_ops: 0,
                    last_active: 0,
                    known_peers: 2,
                    request_seq: 1,
                },
            })
            .is_ok()
        );
        assert!(print_host_result(&HostCommandResult::Listen).is_ok());

        let err = print_host_result(&HostCommandResult::Sign {
            request_id: "req-empty".to_string(),
            signatures_hex: vec![],
        })
        .expect_err("empty signatures must fail");
        assert!(err.to_string().contains("empty signature set"));
    }
}
