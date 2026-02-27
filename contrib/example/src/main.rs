use std::sync::Arc;

use bifrost_core::types::{GroupPackage, MemberPackage, SharePackage};
use bifrost_node::{BifrostNode, BifrostNodeOptions};
use bifrost_transport::Clock;
use bifrost_transport_ws::{WebSocketTransport, WsNostrConfig, WsTransportConfig};
use frost_secp256k1_tr_unofficial as frost;
use rand_core::OsRng;

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let relay = std::env::var("RELAY_URL").unwrap_or_else(|_| "wss://relay.damus.io".to_string());
    let run_network = std::env::var("RUN_NETWORK").ok().as_deref() == Some("1");

    let (shares, pubkey_pkg) =
        frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, OsRng)?;
    let mut material = Vec::new();
    for (id, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        material.push((id, key_package));
    }
    material.sort_by_key(|(id, _)| id.serialize());
    let (local_id, local_key) = material.remove(0);
    let (peer_id, peer_key) = material.remove(0);

    let mut group_pk = [0u8; 33];
    group_pk.copy_from_slice(&pubkey_pkg.verifying_key().serialize()?);

    let mut local_member_pk = [0u8; 33];
    local_member_pk.copy_from_slice(&local_key.verifying_share().serialize()?);
    let mut peer_member_pk = [0u8; 33];
    peer_member_pk.copy_from_slice(&peer_key.verifying_share().serialize()?);

    let local_idx = local_id.serialize()[31] as u16;
    let peer_idx = peer_id.serialize()[31] as u16;

    let group = GroupPackage {
        group_pk,
        threshold: 2,
        members: vec![
            MemberPackage {
                idx: local_idx,
                pubkey: local_member_pk,
            },
            MemberPackage {
                idx: peer_idx,
                pubkey: peer_member_pk,
            },
        ],
    };

    let mut local_seckey = [0u8; 32];
    local_seckey.copy_from_slice(&local_key.signing_share().serialize());
    let share = SharePackage {
        idx: local_idx,
        seckey: local_seckey,
    };

    let ws = Arc::new(WebSocketTransport::with_config(
        vec![relay.clone()],
        WsTransportConfig {
            max_retries: 2,
            backoff_initial_ms: 250,
            backoff_max_ms: 2_000,
            rpc_kind: 20_000,
        },
        WsNostrConfig {
            sender_pubkey33: hex::encode(local_member_pk),
            sender_seckey32: local_seckey,
            peer_pubkeys33: vec![hex::encode(peer_member_pk)],
        },
    ));

    let mut options = BifrostNodeOptions::default();
    options.nonce_pool.critical_threshold = 0;
    let node = BifrostNode::new(
        group,
        share,
        vec![hex::encode(peer_member_pk)],
        ws,
        Arc::new(SystemClock),
        Some(options),
    )?;

    println!("node initialized for relay: {relay}");
    println!("local idx: {local_idx}, peer idx: {peer_idx}");
    println!("run network connect: {run_network}");

    if run_network {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            node.connect().await?;
            node.close().await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        println!("network connect/close complete");
    } else {
        println!("dry-run mode: set RUN_NETWORK=1 to connect against RELAY_URL");
    }

    Ok(())
}
