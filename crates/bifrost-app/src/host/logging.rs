use tracing_subscriber::EnvFilter;

use super::types::LogOptions;

pub fn init_tracing(log: LogOptions) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_log_filter(log)));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_env_filter(filter)
        .try_init();
}

pub fn default_log_filter(log: LogOptions) -> &'static str {
    if log.debug {
        "warn,bifrost_app=debug,bifrost_bridge_tokio=debug,bifrost_signer=debug"
    } else if log.verbose {
        "warn,bifrost_app=info,bifrost_bridge_tokio=info,bifrost_signer=info"
    } else {
        "warn"
    }
}
