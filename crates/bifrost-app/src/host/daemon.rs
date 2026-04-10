use anyhow::{Context, Result, anyhow};
use bifrost_bridge_tokio::{Bridge, NostrSdkAdapter};
use bifrost_signer::DeviceStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

use crate::runtime::{
    DeviceLock, EncryptedFileStore, ResolvedAppConfig, begin_run, complete_clean_run,
    load_or_init_signer_resolved,
};

use super::handlers::{execute_control_payload, persist_if_needed};
use super::protocol::{ControlRequest, ControlResponse};
use super::types::{DaemonTransportConfig, bridge_config};

#[cfg(unix)]
pub async fn run_resolved_daemon(
    config: ResolvedAppConfig,
    transport: DaemonTransportConfig,
) -> Result<()> {
    let state_path = config.state_path.clone();
    let _lock = DeviceLock::acquire_exclusive(&state_path)?;
    let signer = load_or_init_signer_resolved(
        &config,
        &EncryptedFileStore::new(state_path.clone(), config.share.clone()),
    )?;
    let run_id = begin_run(&state_path)?;
    let store = EncryptedFileStore::new(state_path.clone(), config.share.clone());
    let bridge = Bridge::start_with_config(
        NostrSdkAdapter::new(config.relays.clone()),
        signer,
        bridge_config(&config),
    )
    .await?;

    if transport.socket_path.exists() {
        let _ = std::fs::remove_file(&transport.socket_path);
    }
    if let Some(parent) = transport.socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = tokio::net::UnixListener::bind(&transport.socket_path)?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let mut shutdown_tx = Some(shutdown_tx);
    let mut save_tick = tokio::time::interval(std::time::Duration::from_secs(
        config.options.state_save_interval_secs,
    ));

    loop {
        tokio::select! {
            _ = save_tick.tick() => {
                persist_if_needed(&bridge, &store).await?;
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = &mut shutdown_rx => {
                break;
            }
            accept = listener.accept() => {
                let (mut stream, _) = accept?;
                let response = handle_control_stream(
                    &bridge,
                    &store,
                    &config,
                    &transport.token,
                    &mut stream,
                    &mut shutdown_tx,
                ).await;
                if let Err(err) = response {
                    let _ = stream.write_all(
                        serde_json::to_string(&ControlResponse{
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

    let state = bridge
        .snapshot_state()
        .await
        .map_err(|e| anyhow!(e.to_string()))?;
    store.save(&state)?;
    bridge.shutdown().await;
    complete_clean_run(&state_path, &run_id, &state)?;
    let _ = std::fs::remove_file(&transport.socket_path);
    Ok(())
}

#[cfg(unix)]
pub(crate) async fn handle_control_stream(
    bridge: &Bridge,
    store: &EncryptedFileStore,
    config: &ResolvedAppConfig,
    expected_token: &str,
    stream: &mut tokio::net::UnixStream,
    shutdown_tx: &mut Option<oneshot::Sender<()>>,
) -> Result<()> {
    let mut request_bytes = Vec::new();
    stream.read_to_end(&mut request_bytes).await?;
    let request: ControlRequest =
        serde_json::from_slice(&request_bytes).context("invalid control request json")?;

    let response = if request.token != expected_token {
        ControlResponse {
            request_id: request.request_id,
            ok: false,
            result: None,
            error: Some("invalid control token".to_string()),
        }
    } else {
        match execute_control_payload(bridge, config, request).await {
            Ok((request_id, result, should_shutdown)) => {
                persist_if_needed(bridge, store).await?;
                if should_shutdown && let Some(tx) = shutdown_tx.take() {
                    let _ = tx.send(());
                }
                ControlResponse {
                    request_id,
                    ok: true,
                    result: Some(result.into_value()),
                    error: None,
                }
            }
            Err((request_id, err)) => ControlResponse {
                request_id,
                ok: false,
                result: None,
                error: Some(err),
            },
        }
    };

    stream
        .write_all(serde_json::to_string(&response)?.as_bytes())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_bridge_tokio::BridgeConfig;
    use bifrost_signer::{DeviceConfig, DeviceState, SigningDevice};
    use frostr_utils::{CreateKeysetConfig, create_keyset};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{mpsc, oneshot};

    use crate::host::protocol::ControlCommand;
    use crate::runtime::AppOptions;

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

    struct DaemonFixture {
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
            "bifrost-daemon-{name}-{}-{nonce}.{suffix}",
            std::process::id()
        ))
    }

    async fn daemon_fixture() -> DaemonFixture {
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
        let signer = SigningDevice::new(
            group.clone(),
            share.clone(),
            peers.clone(),
            DeviceState::new(share.idx, share.seckey),
            DeviceConfig::default(),
        )
        .expect("build signer");
        let state_path = temp_path("state", "bin");
        let store = EncryptedFileStore::new(state_path.clone(), share.clone());
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
            state_path,
            relays: vec!["ws://127.0.0.1:8194".to_string()],
            peers,
            manual_policy_overrides: Default::default(),
            options: AppOptions::default(),
        };
        DaemonFixture {
            bridge,
            store,
            config,
        }
    }

    async fn socket_pair() -> (tokio::net::UnixStream, tokio::net::UnixStream) {
        tokio::net::UnixStream::pair().expect("create unix stream pair")
    }

    #[tokio::test]
    async fn handle_control_stream_maps_success_and_token_errors_to_wire_envelope() {
        let fixture = daemon_fixture().await;
        let (mut client, mut server) = socket_pair().await;
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
        .expect("serialize");
        client.write_all(&request).await.expect("write request");
        client.shutdown().await.expect("shutdown client");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response: ControlResponse = serde_json::from_slice(&response).expect("parse response");
        assert!(response.ok);
        assert_eq!(response.request_id, "req-status");
        assert!(response.result.expect("result")["device_id"].is_string());
        worker.await.expect("join worker").expect("handle control");

        let fixture = daemon_fixture().await;
        let (mut client, mut server) = socket_pair().await;
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
        .expect("serialize invalid request");
        client
            .write_all(&invalid_request)
            .await
            .expect("write invalid request");
        client.shutdown().await.expect("shutdown client");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read invalid-token response");
        let response: ControlResponse =
            serde_json::from_slice(&response).expect("parse invalid-token response");
        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("invalid control token"));
        worker.await.expect("join worker").expect("handle control");
    }

    #[tokio::test]
    async fn handle_control_stream_rejects_malformed_json() {
        let fixture = daemon_fixture().await;
        let (mut client, mut server) = socket_pair().await;
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
    async fn handle_control_stream_triggers_shutdown_only_for_shutdown_command() {
        let fixture = daemon_fixture().await;
        let (mut client, mut server) = socket_pair().await;
        let (tx, rx) = oneshot::channel();
        let mut shutdown_tx = Some(tx);
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
            request_id: "req-shutdown".to_string(),
            token: "expected-token".to_string(),
            command: ControlCommand::Shutdown,
        })
        .expect("serialize shutdown request");
        client.write_all(&request).await.expect("write request");
        client.shutdown().await.expect("shutdown client");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response: ControlResponse = serde_json::from_slice(&response).expect("parse response");
        assert!(response.ok);
        assert_eq!(response.result.expect("result")["shutdown"], true);
        worker.await.expect("join worker").expect("handle shutdown");
        rx.await.expect("receive shutdown signal");

        let fixture = daemon_fixture().await;
        let (mut client, mut server) = socket_pair().await;
        let (tx, mut rx) = oneshot::channel();
        let mut shutdown_tx = Some(tx);
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
        .expect("serialize status request");
        client.write_all(&request).await.expect("write request");
        client.shutdown().await.expect("shutdown client");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response: ControlResponse = serde_json::from_slice(&response).expect("parse response");
        assert!(response.ok);
        worker.await.expect("join worker").expect("handle status");
        assert!(rx.try_recv().is_err());
    }
}
