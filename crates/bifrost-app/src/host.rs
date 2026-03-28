use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bifrost_bridge_tokio::{Bridge, BridgeConfig, NostrSdkAdapter};
use bifrost_core::types::PeerPolicyOverride;
use bifrost_signer::{DeviceConfigPatch, DeviceStatus, DeviceStore, PersistenceHint};
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::sync::oneshot;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::runtime::{
    DeviceLock, EncryptedFileStore, ResolvedAppConfig, begin_run, complete_clean_run,
    inspect_state_health, load_config, load_or_init_signer_resolved, resolve_config,
};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy)]
pub struct LogOptions {
    pub verbose: bool,
    pub debug: bool,
}

#[derive(Debug, Clone)]
pub enum HostCommand {
    Sign {
        message_hex32: String,
    },
    Ecdh {
        pubkey_hex32: String,
    },
    Ping {
        peer: String,
    },
    Onboard {
        peer: String,
    },
    Listen {
        control_socket: Option<PathBuf>,
        control_token: Option<String>,
    },
    Status,
    StateHealth,
    SetPolicyOverride {
        peer: String,
        policy_json: String,
    },
    ClearPeerPolicyOverrides,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlRequest {
    pub request_id: String,
    pub token: String,
    #[serde(flatten)]
    pub command: ControlCommand,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlCommand {
    Status,
    SetPolicyOverride {
        peer: String,
        policy_override_json: String,
    },
    ClearPeerPolicyOverrides,
    Ping {
        peer: String,
        timeout_secs: Option<u64>,
    },
    Onboard {
        peer: String,
        timeout_secs: Option<u64>,
    },
    Sign {
        message_hex32: String,
        timeout_secs: Option<u64>,
    },
    Ecdh {
        pubkey_hex32: String,
        timeout_secs: Option<u64>,
    },
    ReadConfig,
    UpdateConfig {
        config_patch_json: String,
    },
    PeerStatus,
    Readiness,
    RuntimeStatus,
    RuntimeMetadata,
    RuntimeDiagnostics,
    WipeState,
    Shutdown,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlResponse {
    pub request_id: String,
    pub ok: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeDiagnosticsSnapshot {
    pub runtime_status: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct DaemonTransportConfig {
    pub socket_path: PathBuf,
    pub token: String,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct DaemonClient {
    socket_path: PathBuf,
    token: String,
}

#[cfg(unix)]
impl DaemonClient {
    pub fn new(socket_path: PathBuf, token: String) -> Self {
        Self { socket_path, token }
    }

    pub async fn request(&self, command: ControlCommand) -> Result<ControlResponse> {
        let request = ControlRequest {
            request_id: next_request_id(),
            token: self.token.clone(),
            command,
        };

        let mut stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| format!("connect {}", self.socket_path.display()))?;
        stream
            .write_all(serde_json::to_vec(&request)?.as_slice())
            .await?;
        stream.shutdown().await?;

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await?;
        let response: ControlResponse =
            serde_json::from_slice(&response_bytes).context("invalid control response json")?;
        Ok(response)
    }

    pub async fn request_ok(&self, command: ControlCommand) -> Result<serde_json::Value> {
        let response = self.request(command).await?;
        if response.ok {
            Ok(response.result.unwrap_or_else(|| json!({})))
        } else {
            Err(anyhow!(
                response
                    .error
                    .unwrap_or_else(|| "daemon request failed".to_string())
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostCommandResult {
    Sign {
        request_id: String,
        signatures_hex: Vec<String>,
    },
    Ecdh {
        request_id: String,
        shared_secret_hex32: String,
    },
    Ping {
        request_id: String,
        peer: String,
    },
    Onboard {
        request_id: String,
        group_member_count: usize,
    },
    Status {
        status: DeviceStatus,
    },
    StateHealth {
        report: serde_json::Value,
    },
    PolicyUpdated {
        peer: String,
    },
    Listen,
}

pub fn init_tracing(log: LogOptions) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_log_filter(log)));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_env_filter(filter)
        .try_init();
}

pub fn default_log_filter(log: LogOptions) -> &'static str {
    if log.debug {
        "warn,bifrost_app=debug,bifrost_bridge_tokio=debug,bifrost_signer=debug"
    } else if log.verbose {
        "warn,bifrost_app=info,bifrost_bridge_tokio=info,bifrost_signer=info"
    } else {
        "warn"
    }
}

fn next_request_id() -> String {
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("req-{counter}")
}

fn bridge_config(config: &ResolvedAppConfig) -> BridgeConfig {
    BridgeConfig {
        expire_tick: Duration::from_millis(config.options.router_expire_tick_ms),
        relay_backoff: Duration::from_millis(config.options.router_relay_backoff_ms),
        command_queue_capacity: config.options.router_command_queue_capacity,
        inbound_queue_capacity: config.options.router_inbound_queue_capacity,
        outbound_queue_capacity: config.options.router_outbound_queue_capacity,
        command_overflow_policy: config.options.router_command_overflow_policy.into(),
        inbound_overflow_policy: config.options.router_inbound_overflow_policy.into(),
        outbound_overflow_policy: config.options.router_outbound_overflow_policy.into(),
        inbound_dedupe_cache_limit: config.options.router_inbound_dedupe_cache_limit,
    }
}

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
    let mut save_tick =
        tokio::time::interval(Duration::from_secs(config.options.state_save_interval_secs));

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
                            let response = handle_control_stream(&bridge, &store, &resolved, token, &mut stream, &mut no_shutdown).await;
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

fn print_host_result(result: &HostCommandResult) -> Result<()> {
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

async fn persist_if_needed(bridge: &Bridge, store: &EncryptedFileStore) -> Result<()> {
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

fn decode_hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("invalid hex32")?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(unix)]
async fn handle_control_stream(
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
        match execute_control_command(bridge, config, request).await {
            Ok((request_id, result, should_shutdown)) => {
                persist_if_needed(bridge, store).await?;
                if should_shutdown && let Some(tx) = shutdown_tx.take() {
                    let _ = tx.send(());
                }
                ControlResponse {
                    request_id,
                    ok: true,
                    result: Some(result),
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

#[cfg(unix)]
async fn execute_control_command(
    bridge: &Bridge,
    config: &ResolvedAppConfig,
    request: ControlRequest,
) -> std::result::Result<(String, serde_json::Value, bool), (String, String)> {
    let request_id = request.request_id.clone();
    let run: std::result::Result<(serde_json::Value, bool), anyhow::Error> = async {
        match request.command {
            ControlCommand::Status => {
                let status = bridge.status().await.map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!(status), false))
            }
            ControlCommand::SetPolicyOverride {
                peer,
                policy_override_json,
            } => {
                let policy: PeerPolicyOverride = serde_json::from_str(&policy_override_json)
                    .context("invalid policy override json")?;
                bridge
                    .set_policy_override(peer, policy)
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!({"updated": true}), false))
            }
            ControlCommand::ClearPeerPolicyOverrides => {
                bridge
                    .clear_policy_overrides()
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!({"updated": true}), false))
            }
            ControlCommand::Ping { peer, timeout_secs } => {
                let result = bridge
                    .ping(
                        peer,
                        Duration::from_secs(
                            timeout_secs.unwrap_or(config.options.ping_timeout_secs),
                        ),
                    )
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!({
                    "request_id": result.request_id,
                    "peer": result.peer,
                }), false))
            }
            ControlCommand::Onboard { peer, timeout_secs } => {
                let result = bridge
                    .onboard(
                        peer,
                        Duration::from_secs(
                            timeout_secs.unwrap_or(config.options.onboard_timeout_secs),
                        ),
                    )
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!({
                    "request_id": result.request_id,
                    "group_member_count": result.group_member_count,
                }), false))
            }
            ControlCommand::Sign {
                message_hex32,
                timeout_secs,
            } => {
                let message = decode_hex32(&message_hex32)?;
                let result = bridge
                    .sign(
                        message,
                        Duration::from_secs(
                            timeout_secs.unwrap_or(config.options.sign_timeout_secs),
                        ),
                    )
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!({
                    "request_id": result.request_id,
                    "signatures_hex": result.signatures.iter().map(hex::encode).collect::<Vec<_>>(),
                }), false))
            }
            ControlCommand::Ecdh {
                pubkey_hex32,
                timeout_secs,
            } => {
                let pubkey = decode_hex32(&pubkey_hex32)?;
                let result = bridge
                    .ecdh(
                        pubkey,
                        Duration::from_secs(
                            timeout_secs.unwrap_or(config.options.ecdh_timeout_secs),
                        ),
                    )
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!({
                    "request_id": result.request_id,
                    "shared_secret_hex32": hex::encode(result.shared_secret),
                }), false))
            }
            ControlCommand::ReadConfig => {
                let config = bridge
                    .read_config()
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!(config), false))
            }
            ControlCommand::UpdateConfig { config_patch_json } => {
                let patch: DeviceConfigPatch = serde_json::from_str(&config_patch_json)
                    .context("invalid config patch json")?;
                bridge
                    .update_config(patch)
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!({"updated": true}), false))
            }
            ControlCommand::PeerStatus => {
                let status = bridge
                    .peer_status()
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!(status), false))
            }
            ControlCommand::Readiness => {
                let readiness = bridge
                    .readiness()
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!(readiness), false))
            }
            ControlCommand::RuntimeStatus => {
                let status = bridge
                    .runtime_status()
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!(status), false))
            }
            ControlCommand::RuntimeDiagnostics => {
                let status = bridge
                    .runtime_status()
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((
                    json!(RuntimeDiagnosticsSnapshot {
                        runtime_status: json!(status),
                    }),
                    false,
                ))
            }
            ControlCommand::RuntimeMetadata => {
                let metadata = bridge
                    .runtime_metadata()
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!(metadata), false))
            }
            ControlCommand::WipeState => {
                bridge
                    .wipe_state()
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok((json!({"wiped": true}), false))
            }
            ControlCommand::Shutdown => {
                Ok((json!({"shutdown": true}), true))
            }
        }
    }
    .await;

    match run {
        Ok((v, should_shutdown)) => Ok((request_id, v, should_shutdown)),
        Err(e) => Err((request_id, e.to_string())),
    }
}

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
