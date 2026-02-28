use std::path::PathBuf;

use anyhow::{Result, anyhow};
use bifrost_rpc::{BifrostRpcRequest, DaemonClient, PeerPolicyView};

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    let mut socket = PathBuf::from("/tmp/bifrostd.sock");
    let mut json_output = false;
    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--socket" => {
                let path = args
                    .get(idx + 1)
                    .ok_or_else(|| anyhow!("missing socket value"))?;
                socket = PathBuf::from(path);
                idx += 2;
            }
            "--json" => {
                json_output = true;
                idx += 1;
            }
            _ => break,
        }
    }

    let command = args
        .get(idx)
        .ok_or_else(|| anyhow!("missing command"))?
        .clone();
    let tail = &args[(idx + 1)..];

    let req = match command.as_str() {
        "negotiate" => {
            let client_name = tail
                .first()
                .cloned()
                .unwrap_or_else(|| "bifrost-cli".to_string());
            let client_version = tail.get(1).and_then(|v| v.parse::<u16>().ok()).unwrap_or(1);
            BifrostRpcRequest::Negotiate {
                client_name,
                client_version,
            }
        }
        "health" => BifrostRpcRequest::Health,
        "status" => BifrostRpcRequest::Status,
        "events" => {
            let limit = tail
                .first()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(20);
            BifrostRpcRequest::Events { limit }
        }
        "echo" => {
            if tail.len() < 2 {
                return Err(anyhow!("usage: echo <peer> <message>"));
            }
            BifrostRpcRequest::Echo {
                peer: tail[0].clone(),
                message: tail[1..].join(" "),
            }
        }
        "ping" => {
            let peer = tail.first().ok_or_else(|| anyhow!("usage: ping <peer>"))?;
            BifrostRpcRequest::Ping { peer: peer.clone() }
        }
        "onboard" => {
            let peer = tail
                .first()
                .ok_or_else(|| anyhow!("usage: onboard <peer>"))?;
            BifrostRpcRequest::Onboard { peer: peer.clone() }
        }
        "sign" => {
            let message32_hex = tail
                .first()
                .ok_or_else(|| anyhow!("usage: sign <32-byte-hex>"))?;
            BifrostRpcRequest::Sign {
                message32_hex: message32_hex.clone(),
            }
        }
        "ecdh" => {
            let pubkey33_hex = tail
                .first()
                .ok_or_else(|| anyhow!("usage: ecdh <33-byte-hex>"))?;
            BifrostRpcRequest::Ecdh {
                pubkey33_hex: pubkey33_hex.clone(),
            }
        }
        "policy" => {
            let sub = tail
                .first()
                .ok_or_else(|| anyhow!("usage: policy <list|get|set|refresh> ..."))?;
            match sub.as_str() {
                "list" => BifrostRpcRequest::GetPeerPolicies,
                "get" => {
                    let peer = tail
                        .get(1)
                        .ok_or_else(|| anyhow!("usage: policy get <peer>"))?;
                    BifrostRpcRequest::GetPeerPolicy { peer: peer.clone() }
                }
                "refresh" => {
                    let peer = tail
                        .get(1)
                        .ok_or_else(|| anyhow!("usage: policy refresh <peer>"))?;
                    BifrostRpcRequest::RefreshPeerPolicy { peer: peer.clone() }
                }
                "set" => {
                    let peer = tail
                        .get(1)
                        .ok_or_else(|| anyhow!("usage: policy set <peer> <json-policy>"))?;
                    let raw = tail
                        .get(2)
                        .ok_or_else(|| anyhow!("usage: policy set <peer> <json-policy>"))?;
                    let policy: PeerPolicyView = serde_json::from_str(raw)
                        .map_err(|e| anyhow!("invalid policy json: {e}"))?;
                    BifrostRpcRequest::SetPeerPolicy {
                        peer: peer.clone(),
                        policy,
                    }
                }
                _ => return Err(anyhow!("usage: policy <list|get|set|refresh> ...")),
            }
        }
        "shutdown" => BifrostRpcRequest::Shutdown,
        _ => return Err(anyhow!("unknown command: {command}")),
    };

    let client = DaemonClient::new(socket);
    match client.call(req).await {
        Ok(data) => {
            if json_output {
                println!("{}", serde_json::to_string(&data)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&data)?);
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_usage() {
    eprintln!(
        "bifrost-cli [--socket PATH] [--json] <command> [args]\n\ncommands:\n  negotiate [client_name] [client_version]\n  health\n  status\n  events [limit]\n  echo <peer> <message>\n  ping <peer>\n  onboard <peer>\n  sign <32-byte-hex>\n  ecdh <33-byte-hex>\n  policy list\n  policy get <peer>\n  policy set <peer> <json-policy>\n  policy refresh <peer>\n  shutdown"
    );
}
