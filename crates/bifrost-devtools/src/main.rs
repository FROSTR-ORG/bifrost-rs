mod e2e;
mod keygen;
mod relay;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "bifrost-devtools")]
#[command(about = "Developer relay, keygen, and e2e tooling for Bifrost")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Relay {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Keygen {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    E2eNode {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    E2eFull {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Commands::Relay { args } => relay::run_relay_command(&args).await,
        Commands::Keygen { args } => keygen::run_keygen_command(&args),
        Commands::E2eNode { args } => e2e::run_e2e_node_command(&args),
        Commands::E2eFull { args } => e2e::run_e2e_full_command(&args),
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_supported_subcommands_and_args() {
        let cli = Cli::try_parse_from(["bifrost-devtools", "relay", "--port", "9000"])
            .expect("parse relay");
        assert!(matches!(cli.command, Commands::Relay { args } if args == vec!["--port", "9000"]));

        let cli = Cli::try_parse_from(["bifrost-devtools", "keygen", "--count", "4"])
            .expect("parse keygen");
        assert!(matches!(cli.command, Commands::Keygen { args } if args == vec!["--count", "4"]));

        let cli = Cli::try_parse_from([
            "bifrost-devtools",
            "e2e-node",
            "--relay",
            "ws://127.0.0.1:9999",
        ])
        .expect("parse e2e-node");
        assert!(
            matches!(cli.command, Commands::E2eNode { args } if args == vec!["--relay", "ws://127.0.0.1:9999"])
        );

        let cli = Cli::try_parse_from(["bifrost-devtools", "e2e-full", "--count", "9"])
            .expect("parse e2e-full");
        assert!(matches!(cli.command, Commands::E2eFull { args } if args == vec!["--count", "9"]));
    }

    #[test]
    fn init_tracing_is_idempotent_for_tests() {
        init_tracing();
        init_tracing();
    }
}
