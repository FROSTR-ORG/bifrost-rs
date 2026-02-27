use std::env;

use anyhow::{Context, Result};
use bifrost_relay_dev::NostrRelay;

#[tokio::main]
async fn main() -> Result<()> {
    let mut port: u16 = 8194;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--port" || arg == "-p" {
            let value = args.next().context("missing value for --port")?;
            port = value.parse::<u16>().context("invalid port")?;
            continue;
        }
        if let Ok(parsed) = arg.parse::<u16>() {
            port = parsed;
        }
    }

    let purge_secs = env::var("BIFROST_RELAY_PURGE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());

    let relay = NostrRelay::new("127.0.0.1", port, purge_secs);
    println!("bifrost-relay-dev listening on ws://127.0.0.1:{port}");
    relay.start().await
}
