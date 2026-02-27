use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
use bifrost_core::local_pubkey_from_share;
use bifrost_core::types::{GroupPackage, MemberPackage, SharePackage};
use frost_secp256k1_tr_unofficial as frost;
use rand_core::OsRng;
use serde::Serialize;

const DEFAULT_NAMES: [&str; 8] = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
];

#[derive(Debug, Clone, Serialize)]
struct DaemonConfig {
    socket_path: String,
    group_path: String,
    share_path: String,
    peers: Vec<String>,
    relays: Vec<String>,
    options: Option<serde_json::Value>,
    transport: DaemonTransportConfig,
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

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    match cmd {
        "keygen" => run_keygen(&args[1..]),
        _ => {
            print_usage();
            Ok(())
        }
    }
}

fn run_keygen(args: &[String]) -> Result<()> {
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

    let (shares, pubkey_pkg) = frost::keys::generate_with_dealer(
        count,
        threshold,
        frost::keys::IdentifierList::Default,
        OsRng,
    )
    .context("generate_with_dealer")?;

    let mut material = Vec::new();
    for (id, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share).context("key package")?;
        material.push((id, key_package));
    }
    material.sort_by_key(|(id, _)| id.serialize());

    let mut group_pk = [0u8; 33];
    group_pk.copy_from_slice(&pubkey_pkg.verifying_key().serialize().context("group pk")?);

    let mut members = Vec::new();
    let mut share_packages = Vec::new();

    for (id, key) in material {
        let id_ser = id.serialize();
        let idx = id_ser[31] as u16;

        let mut member_pk = [0u8; 33];
        member_pk.copy_from_slice(&key.verifying_share().serialize().context("member pk")?);

        let mut seckey = [0u8; 32];
        seckey.copy_from_slice(&key.signing_share().serialize());

        members.push(MemberPackage {
            idx,
            pubkey: member_pk,
        });
        share_packages.push(SharePackage { idx, seckey });
    }

    members.sort_by_key(|m| m.idx);
    share_packages.sort_by_key(|s| s.idx);

    let group = GroupPackage {
        group_pk,
        threshold,
        members: members.clone(),
    };

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
            .map(|m| hex::encode(m.pubkey))
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

fn print_usage() {
    eprintln!(
        "bifrost-devnet keygen [--out-dir DIR] [--threshold N] [--count N] [--relay URL] [--socket-dir DIR]"
    );
}
