mod keygen;
mod relay;

use std::env;

use anyhow::{Context, Result};
use keygen::{print_keygen_usage, run_keygen_command};
use relay::NostrRelay;

#[tokio::main]
async fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        return Ok(());
    };

    match cmd {
        "keygen" => run_keygen_command(&args[1..]),
        "relay" => run_relay_command(&args[1..]).await,
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => {
            print_usage();
            Ok(())
        }
    }
}

async fn run_relay_command(args: &[String]) -> Result<()> {
    let mut port: u16 = 8194;
    let mut idx = 0usize;
    while idx < args.len() {
        let arg = &args[idx];
        if arg == "--port" || arg == "-p" {
            let value = args.get(idx + 1).context("missing value for --port")?;
            port = value.parse::<u16>().context("invalid port")?;
            idx += 2;
            continue;
        }
        if let Ok(parsed) = arg.parse::<u16>() {
            port = parsed;
        }
        idx += 1;
    }

    let purge_secs = env::var("BIFROST_RELAY_PURGE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());

    let relay = NostrRelay::new("127.0.0.1", port, purge_secs);
    println!("bifrost-devtools relay listening on ws://127.0.0.1:{port}");
    relay.start().await
}

fn print_usage() {
    eprintln!(
        "bifrost-devtools <command> [args]\n\ncommands:\n  keygen [--out-dir DIR] [--threshold N] [--count N] [--relay URL] [--socket-dir DIR]\n  relay [--port N|N]"
    );
    print_keygen_usage();
}
