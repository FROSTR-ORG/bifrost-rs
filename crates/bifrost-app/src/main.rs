use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bifrost_app::runtime::{
    DeviceLock, EncryptedFileStore, NostrSdkAdapter, load_config, load_or_init_signer, load_share,
};
use bifrost_bridge::{Bridge, BridgeConfig};
use bifrost_core::types::PeerPolicy;
use bifrost_signer::DeviceStore;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "bifrost")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Sign { message_hex32: String },
    Ecdh { pubkey_hex33: String },
    Ping { peer: String },
    Onboard { peer: String },
    Listen,
    Status,
    Policies,
    SetPolicy { peer: String, policy_json: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    let share = load_share(&config.share_path)?;
    let state_path = PathBuf::from(bifrost_app::runtime::expand_tilde(&config.state_path));
    let store = EncryptedFileStore::new(state_path.clone(), share);

    match cli.command {
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
            let policy: PeerPolicy =
                serde_json::from_str(&policy_json).context("invalid policy json")?;
            signer.set_peer_policy(&peer, policy)?;
            store.save(signer.state())?;
            println!("updated policy for {peer}");
            return Ok(());
        }
        _ => {}
    }

    let _lock = DeviceLock::acquire_exclusive(&state_path)?;
    let signer = load_or_init_signer(&config, &store)?;

    let adapter = NostrSdkAdapter::new(config.relays.clone());
    let bridge = Bridge::start_with_config(
        adapter,
        signer,
        BridgeConfig {
            expire_tick: Duration::from_millis(config.options.bridge_expire_tick_ms),
            relay_backoff: Duration::from_millis(config.options.bridge_relay_backoff_ms),
            command_queue_capacity: config.options.bridge_command_queue_capacity,
            inbound_queue_capacity: config.options.bridge_inbound_queue_capacity,
            outbound_queue_capacity: config.options.bridge_outbound_queue_capacity,
            command_overflow_policy: config.options.bridge_command_overflow_policy.into(),
            inbound_overflow_policy: config.options.bridge_inbound_overflow_policy.into(),
            outbound_overflow_policy: config.options.bridge_outbound_overflow_policy.into(),
            inbound_dedupe_cache_limit: config.options.bridge_inbound_dedupe_cache_limit,
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
        Commands::Ecdh { pubkey_hex33 } => {
            let pubkey = decode_hex33(&pubkey_hex33)?;
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
        Commands::Onboard { peer } => {
            let result = bridge
                .onboard(
                    peer,
                    Duration::from_secs(config.options.onboard_timeout_secs),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            println!("{result:?}");
        }
        Commands::Listen => {
            let mut save_tick =
                tokio::time::interval(Duration::from_secs(config.options.state_save_interval_secs));
            loop {
                tokio::select! {
                    _ = save_tick.tick() => {
                        let state = bridge.snapshot_state().await.map_err(|e| anyhow!(e.to_string()))?;
                        store.save(&state)?;
                    }
                    _ = tokio::signal::ctrl_c() => {
                        let state = bridge.snapshot_state().await.map_err(|e| anyhow!(e.to_string()))?;
                        store.save(&state)?;
                        break;
                    }
                }
            }
        }
        Commands::Status | Commands::Policies | Commands::SetPolicy { .. } => unreachable!(),
    }

    let state = bridge
        .snapshot_state()
        .await
        .map_err(|e| anyhow!(e.to_string()))?;
    store.save(&state)?;
    bridge.shutdown().await;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,bifrost_bridge=info,bifrost_app=info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
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

fn decode_hex33(value: &str) -> Result<[u8; 33]> {
    let bytes = hex::decode(value).context("invalid hex33")?;
    if bytes.len() != 33 {
        return Err(anyhow!("expected 33 bytes"));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes);
    Ok(out)
}
