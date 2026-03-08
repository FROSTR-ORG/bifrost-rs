use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bifrost_app::runtime::{
    DeviceLock, EncryptedFileStore, begin_run, complete_clean_run, inspect_state_health,
    load_config, load_or_init_signer, load_share,
};
use bifrost_bridge_tokio::{Bridge, BridgeConfig, NostrSdkAdapter};
use bifrost_core::types::PeerPolicy;
use bifrost_signer::{DeviceStore, PersistenceHint};
use clap::{Parser, Subcommand};
use frostr_utils::encode_invite_token;
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "bifrost")]
struct Cli {
    #[arg(long, global = true, conflicts_with = "debug")]
    verbose: bool,
    #[arg(long, global = true)]
    debug: bool,
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
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
        #[arg(long)]
        challenge_hex32: Option<String>,
    },
    Invite {
        #[command(subcommand)]
        command: InviteCommands,
    },
    Listen {
        #[arg(long)]
        control_socket: Option<PathBuf>,
        #[arg(long)]
        control_token: Option<String>,
    },
    Status,
    Policies,
    StateHealth,
    SetPolicy {
        peer: String,
        policy_json: String,
    },
}

#[derive(Debug, Subcommand)]
enum InviteCommands {
    Create {
        #[arg(long = "relay")]
        relay_overrides: Vec<String>,
        #[arg(long, default_value_t = 3600)]
        expires_in_secs: u64,
        #[arg(long)]
        label: Option<String>,
    },
    ShowPending,
    Revoke {
        challenge_hex32: String,
    },
}

#[derive(Debug, Deserialize)]
struct ControlRequest {
    request_id: String,
    token: String,
    #[serde(flatten)]
    command: ControlCommand,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum ControlCommand {
    Status,
    Policies,
    SetPolicy {
        peer: String,
        send: bool,
        receive: bool,
    },
    Ping {
        peer: String,
        timeout_secs: Option<u64>,
    },
    Onboard {
        peer: String,
        timeout_secs: Option<u64>,
        challenge_hex32: Option<String>,
    },
    Sign {
        message_hex32: String,
        timeout_secs: Option<u64>,
    },
    Ecdh {
        pubkey_hex32: String,
        timeout_secs: Option<u64>,
    },
}

#[derive(Debug, Serialize)]
struct ControlResponse {
    request_id: String,
    ok: bool,
    result: Option<serde_json::Value>,
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli);
    let config = load_config(&cli.config)?;
    info!(
        config_path = %cli.config.display(),
        command = ?cli.command,
        verbose = cli.verbose,
        debug = cli.debug,
        "bifrost command starting"
    );

    let share = load_share(&config.share_path)?;
    let state_path = PathBuf::from(bifrost_app::runtime::expand_tilde(&config.state_path));
    let store = EncryptedFileStore::new(state_path.clone(), share);

    match &cli.command {
        Commands::Status => {
            let _lock = DeviceLock::acquire_shared(&state_path)?;
            let signer = load_or_init_signer(&config, &store)?;
            let status = signer.status();
            println!("{}", serde_json::to_string_pretty(&status)?);
            return Ok(());
        }
        Commands::Policies => {
            let _lock = DeviceLock::acquire_shared(&state_path)?;
            let signer = load_or_init_signer(&config, &store)?;
            println!("{}", serde_json::to_string_pretty(signer.policies())?);
            return Ok(());
        }
        Commands::SetPolicy { peer, policy_json } => {
            let _lock = DeviceLock::acquire_exclusive(&state_path)?;
            let mut signer = load_or_init_signer(&config, &store)?;
            let run_id = begin_run(&state_path)?;
            let policy: PeerPolicy =
                serde_json::from_str(&policy_json).context("invalid policy json")?;
            signer.set_peer_policy(&peer, policy)?;
            store.save(signer.state())?;
            complete_clean_run(&state_path, &run_id, signer.state())?;
            println!("updated policy for {peer}");
            return Ok(());
        }
        Commands::Invite {
            command:
                InviteCommands::Create {
                    relay_overrides,
                    expires_in_secs,
                    label,
                },
        } => {
            let _lock = DeviceLock::acquire_exclusive(&state_path)?;
            let mut signer = load_or_init_signer(&config, &store)?;
            let run_id = begin_run(&state_path)?;
            let relays = if relay_overrides.is_empty() {
                config.relays.clone()
            } else {
                relay_overrides.clone()
            };
            let token = signer.create_invite(relays, *expires_in_secs, label.clone())?;
            store.save(signer.state())?;
            complete_clean_run(&state_path, &run_id, signer.state())?;
            println!("{}", encode_invite_token(&token)?);
            return Ok(());
        }
        Commands::Invite {
            command: InviteCommands::ShowPending,
        } => {
            let _lock = DeviceLock::acquire_shared(&state_path)?;
            let signer = load_or_init_signer(&config, &store)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&signer.pending_invites())?
            );
            return Ok(());
        }
        Commands::Invite {
            command: InviteCommands::Revoke { challenge_hex32 },
        } => {
            let _lock = DeviceLock::acquire_exclusive(&state_path)?;
            let mut signer = load_or_init_signer(&config, &store)?;
            let run_id = begin_run(&state_path)?;
            if !signer.revoke_pending_invite(challenge_hex32) {
                return Err(anyhow!("unknown invite challenge"));
            }
            store.save(signer.state())?;
            complete_clean_run(&state_path, &run_id, signer.state())?;
            println!("revoked invite {challenge_hex32}");
            return Ok(());
        }
        Commands::StateHealth => {
            let report = inspect_state_health(&state_path);
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        _ => {}
    }

    let _lock = DeviceLock::acquire_exclusive(&state_path)?;
    let signer = load_or_init_signer(&config, &store)?;
    let run_id = begin_run(&state_path)?;

    let adapter = NostrSdkAdapter::new(config.relays.clone());
    let bridge = Bridge::start_with_config(
        adapter,
        signer,
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
        },
    )
    .await?;

    match cli.command {
        Commands::Sign { message_hex32 } => {
            let message = decode_hex32(&message_hex32)?;
            let result = bridge
                .sign(
                    message,
                    Duration::from_secs(config.options.sign_timeout_secs),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            if let Some(first) = result.signatures.first() {
                println!("{}", hex::encode(first));
            } else {
                return Err(anyhow!("empty signature set"));
            }
        }
        Commands::Ecdh { pubkey_hex32 } => {
            let pubkey = decode_hex32(&pubkey_hex32)?;
            let result = bridge
                .ecdh(
                    pubkey,
                    Duration::from_secs(config.options.ecdh_timeout_secs),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            println!("{}", hex::encode(result.shared_secret));
        }
        Commands::Ping { peer } => {
            let result = bridge
                .ping(peer, Duration::from_secs(config.options.ping_timeout_secs))
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            println!("{result:?}");
        }
        Commands::Onboard {
            peer,
            challenge_hex32,
        } => {
            let challenge = challenge_hex32
                .as_deref()
                .map(decode_hex32)
                .transpose()?;
            let result = bridge
                .onboard(
                    peer,
                    challenge,
                    Duration::from_secs(config.options.onboard_timeout_secs),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            println!("{result:?}");
        }
        Commands::Listen {
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
                Some((UnixListener::bind(&path)?, path))
            } else {
                None
            };

            let mut save_tick =
                tokio::time::interval(Duration::from_secs(config.options.state_save_interval_secs));
            #[cfg(unix)]
            loop {
                tokio::select! {
                    _ = save_tick.tick() => {
                        let hint = bridge.take_persistence_hint().await.map_err(|e| anyhow!(e.to_string()))?;
                        if !matches!(hint, PersistenceHint::None) {
                            let state = bridge.snapshot_state().await.map_err(|e| anyhow!(e.to_string()))?;
                            store.save(&state)?;
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        break;
                    }
                    accept = async {
                        use std::future::pending;
                        match &control_listener {
                            Some((listener, _)) => Some(listener.accept().await),
                            None => pending::<Option<std::io::Result<(UnixStream, tokio::net::unix::SocketAddr)>>>().await,
                        }
                    } => {
                        if let Some(Ok((mut stream, _))) = accept {
                            let token = control_token.as_deref().unwrap_or_default();
                            let response = handle_control_stream(
                                &bridge,
                                &store,
                                &config,
                                token,
                                &mut stream
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
            }
            #[cfg(not(unix))]
            loop {
                tokio::select! {
                    _ = save_tick.tick() => {
                        let hint = bridge.take_persistence_hint().await.map_err(|e| anyhow!(e.to_string()))?;
                        if !matches!(hint, PersistenceHint::None) {
                            let state = bridge.snapshot_state().await.map_err(|e| anyhow!(e.to_string()))?;
                            store.save(&state)?;
                        }
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
        }
        Commands::Status
        | Commands::Policies
        | Commands::StateHealth
        | Commands::SetPolicy { .. }
        | Commands::Invite { .. } => unreachable!(),
    }

    let state = bridge
        .snapshot_state()
        .await
        .map_err(|e| anyhow!(e.to_string()))?;
    store.save(&state)?;
    bridge.shutdown().await;
    complete_clean_run(&state_path, &run_id, &state)?;
    Ok(())
}

fn init_tracing(cli: &Cli) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(default_log_filter(cli))
    });
    let _ = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_env_filter(filter)
        .try_init();
}

fn default_log_filter(cli: &Cli) -> &'static str {
    if cli.debug {
        "warn,bifrost_app=debug,bifrost_bridge_tokio=debug,bifrost_signer=debug"
    } else if cli.verbose {
        "warn,bifrost_app=info,bifrost_bridge_tokio=info,bifrost_signer=info"
    } else {
        "warn"
    }
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
    config: &bifrost_app::runtime::AppConfig,
    expected_token: &str,
    stream: &mut UnixStream,
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
            Ok((request_id, result)) => {
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
    config: &bifrost_app::runtime::AppConfig,
    request: ControlRequest,
) -> std::result::Result<(String, serde_json::Value), (String, String)> {
    let request_id = request.request_id.clone();
    let run: std::result::Result<serde_json::Value, anyhow::Error> = async {
        match request.command {
            ControlCommand::Status => {
                let status = bridge.status().await.map_err(|e| anyhow!(e.to_string()))?;
                Ok(json!(status))
            }
            ControlCommand::Policies => {
                let policies = bridge
                    .policies()
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok(json!(policies))
            }
            ControlCommand::SetPolicy {
                peer,
                send,
                receive,
            } => {
                let request = bifrost_core::types::MethodPolicy {
                    echo: send,
                    ping: send,
                    onboard: send,
                    sign: send,
                    ecdh: send,
                };
                let respond = bifrost_core::types::MethodPolicy {
                    echo: receive,
                    ping: receive,
                    onboard: receive,
                    sign: receive,
                    ecdh: receive,
                };
                bridge
                    .set_policy(
                        peer,
                        PeerPolicy {
                            block_all: !send && !receive,
                            request,
                            respond,
                        },
                    )
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok(json!({"updated": true}))
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
                Ok(json!({
                    "request_id": result.request_id,
                    "peer": result.peer,
                }))
            }
            ControlCommand::Onboard {
                peer,
                timeout_secs,
                challenge_hex32,
            } => {
                let challenge = challenge_hex32
                    .as_deref()
                    .map(decode_hex32)
                    .transpose()?;
                let result = bridge
                    .onboard(
                        peer,
                        challenge,
                        Duration::from_secs(
                            timeout_secs.unwrap_or(config.options.onboard_timeout_secs),
                        ),
                    )
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                Ok(json!({
                    "request_id": result.request_id,
                    "group_member_count": result.group_member_count,
                }))
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
                Ok(json!({
                    "request_id": result.request_id,
                    "signatures_hex": result.signatures.iter().map(hex::encode).collect::<Vec<_>>(),
                }))
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
                Ok(json!({
                    "request_id": result.request_id,
                    "shared_secret_hex32": hex::encode(result.shared_secret),
                }))
            }
        }
    }
    .await;

    match run {
        Ok(v) => Ok((request_id, v)),
        Err(e) => Err((request_id, e.to_string())),
    }
}
