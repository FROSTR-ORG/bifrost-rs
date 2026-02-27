use std::path::PathBuf;

use anyhow::{Result, anyhow};
use bifrost_rpc::{
    BifrostRpcRequest, BifrostRpcResponse, next_request_id, request, send_request_to,
};

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
        "shutdown" => BifrostRpcRequest::Shutdown,
        _ => return Err(anyhow!("unknown command: {command}")),
    };

    let resp = send_request_to(&socket, request(next_request_id(), req)).await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    match resp.response {
        BifrostRpcResponse::Ok(data) => println!("{}", serde_json::to_string_pretty(&data)?),
        BifrostRpcResponse::Err { code, message } => {
            eprintln!("rpc error ({code}): {message}");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_usage() {
    eprintln!(
        "bifrost-cli [--socket PATH] [--json] <command> [args]\n\ncommands:\n  health\n  status\n  events [limit]\n  echo <peer> <message>\n  ping <peer>\n  onboard <peer>\n  sign <32-byte-hex>\n  ecdh <33-byte-hex>\n  shutdown"
    );
}
