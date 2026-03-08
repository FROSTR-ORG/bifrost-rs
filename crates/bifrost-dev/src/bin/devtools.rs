#[path = "devtools/e2e.rs"]
mod e2e;
#[path = "devtools/invite.rs"]
mod invite;
#[path = "devtools/keygen.rs"]
mod keygen;
#[path = "devtools/relay.rs"]
mod relay;

use std::env;

use anyhow::{Context, Result};
use e2e::{print_e2e_usage, run_e2e_full_command, run_e2e_node_command};
use invite::{print_invite_usage, run_invite_command};
use keygen::{print_keygen_usage, run_keygen_command};
use relay::NostrRelay;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy)]
struct LogFlags {
    verbose: bool,
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let (flags, args) = parse_global_flags(env::args().skip(1).collect::<Vec<_>>());
    init_tracing(flags);
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        return Ok(());
    };
    info!(command = cmd, verbose = flags.verbose, debug = flags.debug, "bifrost-devtools starting");

    match cmd {
        "keygen" => run_keygen_command(&args[1..]),
        "invite" => run_invite_command(&args[1..]),
        "e2e-node" => run_e2e_node_command(&args[1..]),
        "e2e-full" => run_e2e_full_command(&args[1..]),
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
    let mut host = env::var("BIFROST_RELAY_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let mut idx = 0usize;
    while idx < args.len() {
        let arg = &args[idx];
        if arg == "--host" || arg == "-H" {
            let value = args.get(idx + 1).context("missing value for --host")?;
            host = value.clone();
            idx += 2;
            continue;
        }
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

    let relay = NostrRelay::new(&host, port, purge_secs);
    info!(relay_host = %host, relay_url = %format!("ws://{host}:{port}"), "bifrost-devtools relay listening");
    println!("bifrost-devtools relay listening on ws://{host}:{port}");
    relay.start().await
}

fn parse_global_flags(args: Vec<String>) -> (LogFlags, Vec<String>) {
    let mut filtered = Vec::with_capacity(args.len());
    let mut verbose = false;
    let mut debug = false;

    for arg in args {
        match arg.as_str() {
            "--verbose" if !debug => verbose = true,
            "--debug" => {
                debug = true;
                verbose = false;
            }
            _ => filtered.push(arg),
        }
    }

    (LogFlags { verbose, debug }, filtered)
}

fn init_tracing(flags: LogFlags) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_log_filter(flags)));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_env_filter(filter)
        .try_init();
}

fn default_log_filter(flags: LogFlags) -> &'static str {
    if flags.debug {
        "warn,bifrost_app=debug,bifrost_bridge_tokio=debug,bifrost_signer=debug,bifrost_dev=debug"
    } else if flags.verbose {
        "warn,bifrost_app=info,bifrost_bridge_tokio=info,bifrost_signer=info,bifrost_dev=info"
    } else {
        "warn"
    }
}

fn print_usage() {
    eprintln!(
        "bifrost-devtools [--verbose|--debug] <command> [args]\n\ncommands:\n  keygen [--out-dir DIR] [--threshold N] [--count N] [--relay URL]\n  e2e-node [--out-dir DIR] [--relay URL]\n  e2e-full [--out-dir DIR] [--relay URL] [--threshold N] [--count N] [--sign-iterations N] [--ecdh-iterations N] [--seed N]\n  relay [--host HOST] [--port N|N]"
    );
    print_invite_usage();
    print_keygen_usage();
    print_e2e_usage();
}
