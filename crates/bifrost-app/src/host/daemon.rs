use anyhow::{Result, anyhow};
use bifrost_bridge_tokio::{Bridge, NostrSdkAdapter};
use bifrost_core::secret::{DaemonToken, Passphrase};
use bifrost_signer::DeviceStore;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

use crate::runtime::{
    DeviceLock, EncryptedFileStore, ResolvedAppConfig, begin_run, complete_clean_run,
    load_or_init_signer_resolved,
};

use super::handlers::{execute_control_payload, persist_if_needed};
use super::protocol::{ControlRequest, ControlResponse};
use super::types::{DaemonTransportConfig, bridge_config};
use super::unlock::UnlockSession;

/// Failure modes for [`read_passphrase_from_stdin`].
///
/// The variants intentionally do not echo the line that was read, so
/// passphrase prefixes cannot leak into error output.
#[derive(Debug, Error)]
pub enum DaemonStartupError {
    /// stdin closed before a newline-terminated passphrase arrived.
    #[error("daemon stdin closed before passphrase was sent")]
    PassphraseStdinClosed,

    /// stdin returned an OS error before a passphrase could be read.
    #[error("daemon stdin read failed: {0}")]
    PassphraseStdinIo(#[from] std::io::Error),
}

/// Read a single newline-terminated line from `stdin` and wrap it in a
/// [`Passphrase`].
///
/// C.5: every daemon-spawn path (`bifrost_app::start_profile_daemon_with_passphrase`
/// and the consuming host's daemon argv handler) now pipes the passphrase
/// over stdin instead of via `IGLOO_SHELL_PROFILE_PASSPHRASE`. This helper
/// is the canonical receiver-side reader.
///
/// The trailing newline is stripped before wrapping. The `String` buffer
/// is consumed into `Passphrase::new`, so its bytes are zeroized on drop.
/// If the spawning parent closes stdin without ever sending a passphrase,
/// or sends bytes without a terminating newline before EOF and the line is
/// empty, the function returns [`DaemonStartupError::PassphraseStdinClosed`]
/// — the daemon must not hang on a half-closed pipe.
pub fn read_passphrase_from_stdin() -> Result<Passphrase, DaemonStartupError> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line)?;
    if read == 0 {
        return Err(DaemonStartupError::PassphraseStdinClosed);
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(Passphrase::new(line))
}

#[cfg(unix)]
pub async fn run_resolved_daemon(
    config: ResolvedAppConfig,
    transport: DaemonTransportConfig,
) -> Result<()> {
    run_resolved_daemon_with_session(config, transport, None).await
}

/// Variant of [`run_resolved_daemon`] that holds a [`UnlockSession`] for the
/// daemon process's lifetime.
///
/// Bucket C C.6: the session caches the [`bifrost_core::secret::FileStoreKey`]
/// derived from the operator passphrase at startup, so any subsequent
/// profile-envelope re-decrypts (e.g. for Wipe / Rotate flows) skip the
/// Argon2id KDF. The session is dropped (zeroized) when this function
/// returns.
///
/// The session is held but not actively consumed inside the existing daemon
/// hot paths (Sign / Ecdh / Status) — those operate on the already-loaded
/// share material. Callers wiring follow-on rekey / rotate flows into the
/// control loop should hand them a `&UnlockSession` reference to keep the
/// KDF off the hot path.
#[cfg(unix)]
pub async fn run_resolved_daemon_with_session(
    config: ResolvedAppConfig,
    transport: DaemonTransportConfig,
    unlock_session: Option<UnlockSession>,
) -> Result<()> {
    // C.4: harden file-creation permissions for the entire daemon lifetime.
    // We deliberately discard the previous umask — the daemon should not
    // inherit a relaxed umask from its caller, and any file it writes
    // (state, control socket, logs) should default to user-only access.
    //
    // SAFETY: `libc::umask` is an FFI call that mutates a single
    // process-global value with no other side effects. It is async-signal
    // safe and safe to call from any thread context.
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }

    // C.6: bind the session for the daemon's lifetime. Held without further
    // use today — the existing Sign / Ecdh / Status hot paths operate on the
    // already-loaded share material. Follow-on PRs that thread Wipe /
    // Rotate / rekey flows through here should accept this binding so the
    // cached FileStoreKey skips the ~400-600 ms Argon2id derivation.
    let _unlock_session = unlock_session;

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
    // C.4: tighten the control socket to 0o600 immediately after bind so it
    // is never connectable by other users on the host, even momentarily.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &transport.socket_path,
            std::fs::Permissions::from_mode(0o600),
        )?;
    }
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
    expected_token: &DaemonToken,
    stream: &mut tokio::net::UnixStream,
    shutdown_tx: &mut Option<oneshot::Sender<()>>,
) -> Result<()> {
    let mut request_bytes = Vec::new();
    stream.read_to_end(&mut request_bytes).await?;
    let request = ControlRequest::decode_wire(&request_bytes)?;

    // Constant-time comparison via `DaemonToken`'s `PartialEq` (subtle).
    let response = if &request.token != expected_token {
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

    fn token_with_byte(b: u8) -> DaemonToken {
        DaemonToken::from_hex(&hex::encode([b; 32])).expect("test token hex")
    }

    fn expected_token() -> DaemonToken {
        token_with_byte(0xAB)
    }

    fn wrong_token() -> DaemonToken {
        token_with_byte(0x07)
    }

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
            DeviceState::new(share.idx, *share.seckey.expose_bytes()),
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
        let token = expected_token();
        let worker = tokio::spawn(async move {
            handle_control_stream(
                &fixture.bridge,
                &fixture.store,
                &fixture.config,
                &token,
                &mut server,
                &mut shutdown_tx,
            )
            .await
        });

        let request = ControlRequest {
            request_id: "req-status".to_string(),
            token: expected_token(),
            command: ControlCommand::Status,
        }
        .encode_wire()
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
        let token = expected_token();
        let worker = tokio::spawn(async move {
            handle_control_stream(
                &fixture.bridge,
                &fixture.store,
                &fixture.config,
                &token,
                &mut server,
                &mut shutdown_tx,
            )
            .await
        });
        let invalid_request = ControlRequest {
            request_id: "req-auth".to_string(),
            token: wrong_token(),
            command: ControlCommand::Status,
        }
        .encode_wire()
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
        let token = expected_token();
        let worker = tokio::spawn(async move {
            handle_control_stream(
                &fixture.bridge,
                &fixture.store,
                &fixture.config,
                &token,
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
        let token = expected_token();
        let worker = tokio::spawn(async move {
            handle_control_stream(
                &fixture.bridge,
                &fixture.store,
                &fixture.config,
                &token,
                &mut server,
                &mut shutdown_tx,
            )
            .await
        });

        let request = ControlRequest {
            request_id: "req-shutdown".to_string(),
            token: expected_token(),
            command: ControlCommand::Shutdown,
        }
        .encode_wire()
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
        let token = expected_token();
        let worker = tokio::spawn(async move {
            handle_control_stream(
                &fixture.bridge,
                &fixture.store,
                &fixture.config,
                &token,
                &mut server,
                &mut shutdown_tx,
            )
            .await
        });
        let request = ControlRequest {
            request_id: "req-status".to_string(),
            token: expected_token(),
            command: ControlCommand::Status,
        }
        .encode_wire()
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
