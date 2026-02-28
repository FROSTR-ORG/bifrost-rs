use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
use bifrost_core::local_pubkey_from_share;
use frostr_utils::{CreateKeysetConfig, create_keyset};
use serde::Serialize;

const DEFAULT_NAMES: [&str; 8] = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
];

#[derive(Debug, Clone, Serialize)]
struct DaemonConfig {
    socket_path: String,
    group_path: String,
    share_path: String,
    peers: Vec<DaemonPeerConfig>,
    relays: Vec<String>,
    options: Option<serde_json::Value>,
    transport: DaemonTransportConfig,
    auth: DaemonAuthConfig,
}

#[derive(Debug, Clone, Serialize)]
struct DaemonPeerConfig {
    pubkey: String,
    policy: PeerPolicyConfig,
}

#[derive(Debug, Clone, Serialize)]
struct PeerPolicyConfig {
    block_all: bool,
    request: MethodPolicyConfig,
    respond: MethodPolicyConfig,
}

#[derive(Debug, Clone, Serialize)]
struct MethodPolicyConfig {
    echo: bool,
    ping: bool,
    onboard: bool,
    sign: bool,
    ecdh: bool,
}

#[derive(Debug, Clone, Serialize)]
struct DaemonTransportConfig {
    rpc_kind: u64,
    max_retries: u32,
    backoff_initial_ms: u64,
    backoff_max_ms: u64,
    sender_pubkey33: String,
    sender_seckey32_hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct DaemonAuthConfig {
    token: Option<String>,
    allow_unauthenticated_read: bool,
    insecure_no_auth: bool,
}

pub fn run_keygen_command(args: &[String]) -> Result<()> {
    let out_dir = arg_value(args, "--out-dir").unwrap_or_else(|| "dev/data".to_string());
    let threshold = arg_value(args, "--threshold")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(2);
    let count = arg_value(args, "--count")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(3);
    let relay = arg_value(args, "--relay").unwrap_or_else(|| "ws://127.0.0.1:8194".to_string());
    let socket_dir = arg_value(args, "--socket-dir").unwrap_or_else(|| "/tmp".to_string());

    if threshold < 2 {
        return Err(anyhow!("threshold must be >= 2"));
    }
    if count < threshold {
        return Err(anyhow!("count must be >= threshold"));
    }
    if count as usize > DEFAULT_NAMES.len() {
        return Err(anyhow!("count exceeds built-in member names"));
    }

    let out_path = PathBuf::from(out_dir);
    fs::create_dir_all(&out_path).with_context(|| format!("create {}", out_path.display()))?;

    let bundle = create_keyset(CreateKeysetConfig { threshold, count })
        .map_err(|e| anyhow!("create keyset: {e}"))?;
    let group = bundle.group;
    let share_packages = bundle.shares;
    let members = group.members.clone();

    write_json(
        &out_path.join("group.json"),
        &GroupPackageWire::from(group.clone()),
    )?;

    let selected_names = DEFAULT_NAMES[..count as usize].to_vec();
    for (i, share) in share_packages.iter().enumerate() {
        let name = selected_names
            .get(i)
            .ok_or_else(|| anyhow!("missing name for member index {i}"))?;
        let path = out_path.join(format!("share-{name}.json"));
        write_json(&path, &SharePackageWire::from(share.clone()))?;
    }

    for (i, share) in share_packages.iter().enumerate() {
        let name = selected_names
            .get(i)
            .ok_or_else(|| anyhow!("missing name for member index {i}"))?;
        let peers = members
            .iter()
            .filter(|m| m.idx != share.idx)
            .map(|m| DaemonPeerConfig {
                pubkey: hex::encode(m.pubkey),
                policy: PeerPolicyConfig {
                    block_all: false,
                    request: MethodPolicyConfig {
                        echo: true,
                        ping: true,
                        onboard: true,
                        sign: true,
                        ecdh: true,
                    },
                    respond: MethodPolicyConfig {
                        echo: true,
                        ping: true,
                        onboard: true,
                        sign: true,
                        ecdh: true,
                    },
                },
            })
            .collect::<Vec<_>>();

        let daemon_cfg = DaemonConfig {
            socket_path: format!("{socket_dir}/bifrostd-{name}.sock"),
            group_path: out_path.join("group.json").display().to_string(),
            share_path: out_path
                .join(format!("share-{name}.json"))
                .display()
                .to_string(),
            peers,
            relays: vec![relay.clone()],
            options: None,
            transport: DaemonTransportConfig {
                rpc_kind: 20_000,
                max_retries: 3,
                backoff_initial_ms: 250,
                backoff_max_ms: 5_000,
                sender_pubkey33: hex::encode(
                    local_pubkey_from_share(share).context("derive local transport pubkey")?,
                ),
                sender_seckey32_hex: hex::encode(share.seckey),
            },
            auth: DaemonAuthConfig {
                token: None,
                allow_unauthenticated_read: false,
                insecure_no_auth: true,
            },
        };

        write_json(&out_path.join(format!("daemon-{name}.json")), &daemon_cfg)?;
    }

    println!("devnet material generated in {}", out_path.display());
    println!("members: {}", selected_names.join(", "));
    println!("threshold: {threshold}-of-{count}");
    println!("relay: {relay}");
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let raw = serde_json::to_string_pretty(value).context("serialize json")?;
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == key {
            return args.get(i + 1).cloned();
        }
    }
    None
}

pub fn print_keygen_usage() {
    eprintln!(
        "bifrost-devtools keygen [--out-dir DIR] [--threshold N] [--count N] [--relay URL] [--socket-dir DIR]"
    );
}
