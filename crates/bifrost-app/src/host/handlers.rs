use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bifrost_bridge_tokio::{Bridge, NostrSdkAdapter};
use bifrost_core::types::PeerPolicyOverride;
use bifrost_signer::{DeviceStore, PersistenceHint};
use serde_json::json;
use tracing::info;

use crate::runtime::{
    DeviceLock, EncryptedFileStore, begin_run, complete_clean_run, inspect_state_health,
    load_config, load_or_init_signer_resolved, resolve_config,
};

#[path = "handlers/admin.rs"]
mod admin;
#[path = "handlers/network_ops.rs"]
mod network_ops;
#[path = "handlers/runtime_reads.rs"]
mod runtime_reads;

use super::protocol::{ControlCommand, ControlRequest};
use super::types::{
    ControlResultPayload, HostCommand, HostCommandResult, LogOptions, bridge_config,
};

pub async fn run_command(config_path: &Path, command: HostCommand, log: LogOptions) -> Result<()> {
    let result = execute_command(config_path, command, log).await?;
    print_host_result(&result)?;
    Ok(())
}

pub async fn execute_command(
    config_path: &Path,
    command: HostCommand,
    log: LogOptions,
) -> Result<HostCommandResult> {
    let config = load_config(config_path)?;
    let resolved = resolve_config(&config)?;
    info!(
        config_path = %config_path.display(),
        command = ?command,
        verbose = log.verbose,
        debug = log.debug,
        "host command starting"
    );

    let state_path = resolved.state_path.clone();
    let store = EncryptedFileStore::new(state_path.clone(), resolved.share.clone());

    match &command {
        HostCommand::Status => {
            let _lock = DeviceLock::acquire_shared(&state_path)?;
            let signer = load_or_init_signer_resolved(&resolved, &store)?;
            return Ok(HostCommandResult::Status {
                status: signer.status(),
            });
        }
        HostCommand::SetPolicyOverride { peer, policy_json } => {
            let _lock = DeviceLock::acquire_exclusive(&state_path)?;
            let mut signer = load_or_init_signer_resolved(&resolved, &store)?;
            let run_id = begin_run(&state_path)?;
            let policy: PeerPolicyOverride =
                serde_json::from_str(policy_json).context("invalid policy override json")?;
            signer.set_peer_policy_override(peer, policy)?;
            store.save(signer.state())?;
            complete_clean_run(&state_path, &run_id, signer.state())?;
            return Ok(HostCommandResult::PolicyUpdated { peer: peer.clone() });
        }
        HostCommand::ClearPeerPolicyOverrides => {
            let _lock = DeviceLock::acquire_exclusive(&state_path)?;
            let mut signer = load_or_init_signer_resolved(&resolved, &store)?;
            let run_id = begin_run(&state_path)?;
            signer.clear_peer_policy_overrides();
            store.save(signer.state())?;
            complete_clean_run(&state_path, &run_id, signer.state())?;
            return Ok(HostCommandResult::PolicyUpdated {
                peer: "*".to_string(),
            });
        }
        HostCommand::StateHealth => {
            let report = inspect_state_health(&state_path);
            return Ok(HostCommandResult::StateHealth {
                report: serde_json::to_value(report)?,
            });
        }
        _ => {}
    }

    let _lock = DeviceLock::acquire_exclusive(&state_path)?;
    let signer = load_or_init_signer_resolved(&resolved, &store)?;
    let run_id = begin_run(&state_path)?;

    let adapter = NostrSdkAdapter::new(resolved.relays.clone());
    let bridge = Bridge::start_with_config(adapter, signer, bridge_config(&resolved)).await?;

    let command_result = match command {
        HostCommand::Sign { message_hex32 } => {
            let message = decode_hex32(&message_hex32)?;
            let result = bridge
                .sign(
                    message,
                    Duration::from_secs(resolved.options.sign_timeout_secs),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            let signatures_hex = result
                .signatures
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>();
            if signatures_hex.is_empty() {
                return Err(anyhow!("empty signature set"));
            }
            HostCommandResult::Sign {
                request_id: result.request_id,
                signatures_hex,
            }
        }
        HostCommand::Ecdh { pubkey_hex32 } => {
            let pubkey = decode_hex32(&pubkey_hex32)?;
            let result = bridge
                .ecdh(
                    pubkey,
                    Duration::from_secs(resolved.options.ecdh_timeout_secs),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            HostCommandResult::Ecdh {
                request_id: result.request_id,
                shared_secret_hex32: hex::encode(result.shared_secret),
            }
        }
        HostCommand::Ping { peer } => {
            let result = bridge
                .ping(
                    peer,
                    Duration::from_secs(resolved.options.ping_timeout_secs),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            HostCommandResult::Ping {
                request_id: result.request_id,
                peer: result.peer,
            }
        }
        HostCommand::Onboard { peer } => {
            let result = bridge
                .onboard(
                    peer,
                    Duration::from_secs(resolved.options.onboard_timeout_secs),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            HostCommandResult::Onboard {
                request_id: result.request_id,
                group_member_count: result.group_member_count,
            }
        }
        HostCommand::Listen {
            control_socket,
            control_token,
        } => {
            #[cfg(not(unix))]
            {
                if control_socket.is_some() || control_token.is_some() {
                    return Err(anyhow!(
                        "--control-socket is supported only on unix targets"
                    ));
                }
            }

            #[cfg(unix)]
            let mut control_listener = if let Some(path) = control_socket.clone() {
                if control_token.is_none() {
                    return Err(anyhow!(
                        "--control-token is required when --control-socket is provided"
                    ));
                }
                if path.exists() {
                    let _ = std::fs::remove_file(&path);
                }
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Some((tokio::net::UnixListener::bind(&path)?, path))
            } else {
                None
            };

            let mut save_tick = tokio::time::interval(Duration::from_secs(
                resolved.options.state_save_interval_secs,
            ));
            #[cfg(unix)]
            loop {
                tokio::select! {
                    _ = save_tick.tick() => {
                        persist_if_needed(&bridge, &store).await?;
                    }
                    _ = tokio::signal::ctrl_c() => {
                        break;
                    }
                    accept = async {
                        use std::future::pending;
                        match &control_listener {
                            Some((listener, _)) => Some(listener.accept().await),
                            None => pending::<Option<std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)>>>().await,
                        }
                    } => {
                        if let Some(Ok((mut stream, _))) = accept {
                            let token = control_token.as_deref().unwrap_or_default();
                            let mut no_shutdown = None;
                            let response = super::daemon::handle_control_stream(&bridge, &store, &resolved, token, &mut stream, &mut no_shutdown).await;
                            if let Err(err) = response {
                                let _ = tokio::io::AsyncWriteExt::write_all(
                                    &mut stream,
                                    serde_json::to_string(&super::protocol::ControlResponse{
                                        request_id: "unknown".to_string(),
                                        ok: false,
                                        result: None,
                                        error: Some(err.to_string()),
                                    }).unwrap_or_else(|_| "{\"request_id\":\"unknown\",\"ok\":false,\"result\":null,\"error\":\"control error\"}".to_string()).as_bytes()
                                ).await;
                            }
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            loop {
                tokio::select! {
                    _ = save_tick.tick() => {
                        persist_if_needed(&bridge, &store).await?;
                    }
                    _ = tokio::signal::ctrl_c() => {
                        break;
                    }
                }
            }

            #[cfg(unix)]
            if let Some((_, path)) = control_listener.take() {
                let _ = std::fs::remove_file(path);
            }
            HostCommandResult::Listen
        }
        HostCommand::Status
        | HostCommand::StateHealth
        | HostCommand::SetPolicyOverride { .. }
        | HostCommand::ClearPeerPolicyOverrides => unreachable!(),
    };

    let state = bridge
        .snapshot_state()
        .await
        .map_err(|e| anyhow!(e.to_string()))?;
    store.save(&state)?;
    bridge.shutdown().await;
    complete_clean_run(&state_path, &run_id, &state)?;
    Ok(command_result)
}

pub(crate) fn print_host_result(result: &HostCommandResult) -> Result<()> {
    match result {
        HostCommandResult::Sign { signatures_hex, .. } => {
            if let Some(first) = signatures_hex.first() {
                println!("{first}");
            } else {
                return Err(anyhow!("empty signature set"));
            }
        }
        HostCommandResult::Ecdh {
            shared_secret_hex32,
            ..
        } => println!("{shared_secret_hex32}"),
        HostCommandResult::Ping { request_id, peer } => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "request_id": request_id,
                "peer": peer,
            }))?
        ),
        HostCommandResult::Onboard {
            request_id,
            group_member_count,
        } => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "request_id": request_id,
                "group_member_count": group_member_count,
            }))?
        ),
        HostCommandResult::Status { status } => {
            println!("{}", serde_json::to_string_pretty(status)?)
        }
        HostCommandResult::StateHealth { report } => {
            println!("{}", serde_json::to_string_pretty(report)?)
        }
        HostCommandResult::PolicyUpdated { peer } => println!("updated policy for {peer}"),
        HostCommandResult::Listen => {}
    }
    Ok(())
}

pub(crate) async fn persist_if_needed(bridge: &Bridge, store: &EncryptedFileStore) -> Result<()> {
    let hint = bridge
        .take_persistence_hint()
        .await
        .map_err(|e| anyhow!(e.to_string()))?;
    if !matches!(hint, PersistenceHint::None) {
        let state = bridge
            .snapshot_state()
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        store.save(&state)?;
    }
    Ok(())
}

pub(crate) fn decode_hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("invalid hex32")?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) async fn execute_control_payload(
    bridge: &Bridge,
    config: &crate::runtime::ResolvedAppConfig,
    request: ControlRequest,
) -> std::result::Result<(String, ControlResultPayload, bool), (String, String)> {
    let request_id = request.request_id.clone();
    let command = request.command;
    let run: std::result::Result<(ControlResultPayload, bool), anyhow::Error> = match command {
        command @ (ControlCommand::Status
        | ControlCommand::SetPolicyOverride { .. }
        | ControlCommand::ClearPeerPolicyOverrides
        | ControlCommand::ReadConfig
        | ControlCommand::UpdateConfig { .. }
        | ControlCommand::WipeState
        | ControlCommand::Shutdown) => admin::execute_admin_command(bridge, command).await,
        command @ (ControlCommand::PeerStatus
        | ControlCommand::Readiness
        | ControlCommand::RuntimeStatus
        | ControlCommand::RuntimeDiagnostics
        | ControlCommand::RuntimeMetadata) => {
            runtime_reads::execute_runtime_read(bridge, command).await
        }
        command => network_ops::execute_network_command(bridge, config, command).await,
    };

    match run {
        Ok((v, should_shutdown)) => Ok((request_id, v, should_shutdown)),
        Err(e) => Err((request_id, e.to_string())),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn execute_control_command(
    bridge: &Bridge,
    config: &crate::runtime::ResolvedAppConfig,
    request: ControlRequest,
) -> std::result::Result<(String, serde_json::Value, bool), (String, String)> {
    execute_control_payload(bridge, config, request).await.map(
        |(request_id, payload, should_shutdown)| {
            (request_id, payload.into_value(), should_shutdown)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_bridge_tokio::{Bridge, BridgeConfig};
    use bifrost_core::types::{MethodPolicyOverride, PeerPolicyOverride, PolicyOverrideValue};
    use bifrost_signer::{
        DeviceState, DeviceStore, RuntimeMetadata, RuntimeReadiness, RuntimeStatusSummary,
    };
    use frostr_utils::{CreateKeysetConfig, create_keyset};
    use tokio::sync::mpsc;

    use crate::host::types::{
        PeerStatusPayload, ReadConfigPayload, ReadinessPayload, RuntimeDiagnosticsPayload,
        RuntimeMetadataPayload, RuntimeStatusPayload, StatusPayload,
    };
    use crate::runtime::{AppOptions, EncryptedFileStore, ResolvedAppConfig};

    struct MockRelayAdapter {
        inbound_rx: mpsc::UnboundedReceiver<nostr::Event>,
        published_tx: mpsc::UnboundedSender<nostr::Event>,
    }

    #[async_trait::async_trait]
    impl bifrost_bridge_tokio::RelayAdapter for MockRelayAdapter {
        async fn connect(&mut self) -> Result<()> {
            Ok(())
        }

        async fn disconnect(&mut self) -> Result<()> {
            Ok(())
        }

        async fn subscribe(&mut self, _filters: Vec<nostr::Filter>) -> Result<()> {
            Ok(())
        }

        async fn publish(&mut self, event: nostr::Event) -> Result<()> {
            self.published_tx
                .send(event)
                .map_err(|_| anyhow!("published channel closed"))
        }

        async fn next_event(&mut self) -> Result<nostr::Event> {
            self.inbound_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("inbound channel closed"))
        }
    }

    struct HandlerFixture {
        bridge: Bridge,
        store: EncryptedFileStore,
        config: ResolvedAppConfig,
    }

    fn temp_path(name: &str, suffix: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bifrost-handlers-{name}-{}-{nonce}.{suffix}",
            std::process::id()
        ))
    }

    async fn handler_fixture() -> HandlerFixture {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let group = bundle.group.clone();
        let share = bundle.shares[0].clone();
        let peers = group
            .members
            .iter()
            .filter(|member| member.idx != share.idx)
            .map(|member| hex::encode(&member.pubkey[1..]))
            .collect::<Vec<_>>();
        let signer = bifrost_signer::SigningDevice::new(
            group.clone(),
            share.clone(),
            peers.clone(),
            DeviceState::new(share.idx, share.seckey),
            bifrost_signer::DeviceConfig::default(),
        )
        .expect("build signer");
        let (_inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (published_tx, _published_rx) = mpsc::unbounded_channel();
        let state_path = temp_path("state", "bin");
        let store = EncryptedFileStore::new(state_path.clone(), share.clone());
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
        HandlerFixture {
            bridge,
            store,
            config: ResolvedAppConfig {
                group,
                share,
                state_path,
                relays: vec!["ws://127.0.0.1:8194".to_string()],
                peers,
                manual_policy_overrides: std::iter::once((
                    "peer-override".to_string(),
                    PeerPolicyOverride {
                        request: MethodPolicyOverride {
                            sign: PolicyOverrideValue::Deny,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                ))
                .collect(),
                options: AppOptions::default(),
            },
        }
    }

    #[tokio::test]
    async fn execute_control_payload_returns_typed_runtime_read_surfaces() {
        let fixture = handler_fixture().await;

        let status = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-status".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Status,
            },
        )
        .await
        .expect("status");
        assert!(matches!(status.1, ControlResultPayload::Status(_)));
        let status_value = status.1.into_value();
        let decoded: StatusPayload = serde_json::from_value(status_value).expect("decode status");
        assert!(!decoded.0.device_id.is_empty());

        let readiness = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-readiness".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Readiness,
            },
        )
        .await
        .expect("readiness");
        let decoded: ReadinessPayload =
            serde_json::from_value(readiness.1.into_value()).expect("decode readiness");
        let _: RuntimeReadiness = decoded.0;

        let runtime_status = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-runtime-status".to_string(),
                token: "token".to_string(),
                command: ControlCommand::RuntimeStatus,
            },
        )
        .await
        .expect("runtime status");
        let decoded: RuntimeStatusPayload =
            serde_json::from_value(runtime_status.1.into_value()).expect("decode runtime status");
        let _: RuntimeStatusSummary = decoded.0;

        let diagnostics = execute_control_payload(
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
        let diagnostics_value = diagnostics.1.into_value();
        assert!(diagnostics_value["runtime_status"].is_object());
        let decoded: RuntimeDiagnosticsPayload =
            serde_json::from_value(diagnostics_value).expect("decode diagnostics");
        let _: RuntimeStatusSummary = decoded.runtime_status.0;

        let metadata = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-meta".to_string(),
                token: "token".to_string(),
                command: ControlCommand::RuntimeMetadata,
            },
        )
        .await
        .expect("runtime metadata");
        let decoded: RuntimeMetadataPayload =
            serde_json::from_value(metadata.1.into_value()).expect("decode runtime metadata");
        let _: RuntimeMetadata = decoded.0;

        let peer_status = execute_control_payload(
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
        let decoded: PeerStatusPayload =
            serde_json::from_value(peer_status.1.into_value()).expect("decode peer status");
        assert_eq!(decoded.0.len(), fixture.config.peers.len());

        let read_config = execute_control_payload(
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
        let decoded: ReadConfigPayload =
            serde_json::from_value(read_config.1.into_value()).expect("decode read config");
        assert_eq!(
            decoded.0.request_ttl_secs,
            fixture.config.options.request_ttl_secs
        );

        fixture.bridge.shutdown().await;
        let _ = std::fs::remove_file(&fixture.config.state_path);
    }

    #[tokio::test]
    async fn execute_control_payload_maps_common_errors_and_admin_results() {
        let fixture = handler_fixture().await;

        let invalid_hex = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-invalid-hex".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Sign {
                    message_hex32: "zz".to_string(),
                    timeout_secs: None,
                },
            },
        )
        .await
        .expect_err("invalid hex must fail");
        assert_eq!(invalid_hex.0, "req-invalid-hex");
        assert!(invalid_hex.1.contains("invalid hex32"));

        let unknown_peer = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-unknown-peer".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Ping {
                    peer: "deadbeef".to_string(),
                    timeout_secs: Some(1),
                },
            },
        )
        .await
        .expect_err("unknown peer must fail");
        assert_eq!(unknown_peer.0, "req-unknown-peer");
        assert!(unknown_peer.1.contains("unknown peer"));

        let bad_patch = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-bad-patch".to_string(),
                token: "token".to_string(),
                command: ControlCommand::UpdateConfig {
                    config_patch_json: "{".to_string(),
                },
            },
        )
        .await
        .expect_err("invalid patch must fail");
        assert_eq!(bad_patch.0, "req-bad-patch");
        assert!(bad_patch.1.contains("invalid config patch json"));

        let updated = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-clear-overrides".to_string(),
                token: "token".to_string(),
                command: ControlCommand::ClearPeerPolicyOverrides,
            },
        )
        .await
        .expect("clear overrides");
        assert_eq!(updated.0, "req-clear-overrides");
        assert_eq!(
            updated.1.into_value(),
            serde_json::json!({ "updated": true })
        );

        let wiped = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-wipe".to_string(),
                token: "token".to_string(),
                command: ControlCommand::WipeState,
            },
        )
        .await
        .expect("wipe");
        assert_eq!(wiped.1.into_value(), serde_json::json!({ "wiped": true }));

        let shutdown = execute_control_payload(
            &fixture.bridge,
            &fixture.config,
            ControlRequest {
                request_id: "req-shutdown".to_string(),
                token: "token".to_string(),
                command: ControlCommand::Shutdown,
            },
        )
        .await
        .expect("shutdown payload");
        assert!(shutdown.2);
        assert_eq!(
            shutdown.1.into_value(),
            serde_json::json!({ "shutdown": true })
        );

        fixture.bridge.shutdown().await;
        let _ = std::fs::remove_file(&fixture.config.state_path);
    }

    #[tokio::test]
    async fn persist_if_needed_only_saves_when_bridge_requests_persistence() {
        let fixture = handler_fixture().await;

        persist_if_needed(&fixture.bridge, &fixture.store)
            .await
            .expect("persist without hint");
        assert!(!fixture.store.exists());

        fixture.bridge.wipe_state().await.expect("wipe state");
        persist_if_needed(&fixture.bridge, &fixture.store)
            .await
            .expect("persist after wipe");
        assert!(fixture.store.exists());
        let persisted = fixture.store.load().expect("load persisted state");
        assert!(persisted.pending_operations.is_empty());
        assert!(persisted.peer_last_seen.is_empty());
        assert!(persisted.replay_cache.is_empty());

        fixture.bridge.shutdown().await;
        let _ = std::fs::remove_file(&fixture.config.state_path);
    }
}
