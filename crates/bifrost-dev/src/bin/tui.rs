use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, anyhow};
use bifrost_app::runtime::{
    EncryptedFileStore, begin_run, complete_clean_run, load_config, load_or_init_signer,
    load_share,
};
use bifrost_bridge_tokio::{Bridge, BridgeConfig, NostrSdkAdapter};
use bifrost_core::types::PeerPolicy;
use bifrost_signer::DeviceStore;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, Paragraph};

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args()
        .skip(1)
        .find_map(|arg| arg.strip_prefix("--config=").map(ToString::to_string))
        .unwrap_or_else(|| "config/bifrost.json".to_string());

    let config = load_config(Path::new(&config_path))?;
    let share = load_share(&config.share_path)?;
    let state_path = PathBuf::from(bifrost_app::runtime::expand_tilde(&config.state_path));
    let run_id = begin_run(&state_path)?;
    let store = EncryptedFileStore::new(state_path.clone(), share);
    let signer = load_or_init_signer(&config, &store)?;

    let bridge = Bridge::start_with_config(
        NostrSdkAdapter::new(config.relays.clone()),
        signer,
        BridgeConfig {
            expire_tick: Duration::from_millis(config.options.router_expire_tick_ms),
            relay_backoff: Duration::from_millis(config.options.router_relay_backoff_ms),
            command_queue_capacity: config.options.router_command_queue_capacity,
            inbound_queue_capacity: config.options.router_inbound_queue_capacity,
            outbound_queue_capacity: config.options.router_outbound_queue_capacity,
            command_overflow_policy: config.options.router_command_overflow_policy.into(),
            inbound_overflow_policy: config.options.router_inbound_overflow_policy.into(),
            outbound_overflow_policy: config.options.router_outbound_overflow_policy.into(),
            inbound_dedupe_cache_limit: config.options.router_inbound_dedupe_cache_limit,
        },
    )
    .await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut running = true;
    while running {
        let status = bridge.status().await.map_err(|e| anyhow!(e.to_string()))?;
        let policies = bridge
            .policies()
            .await
            .map_err(|e| anyhow!(e.to_string()))?;

        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(5), Constraint::Min(5)])
                .split(frame.area());

            let header = Paragraph::new(format!(
                "device: {}\npending: {}\nknown peers: {}\nrequest_seq: {}",
                status.device_id, status.pending_ops, status.known_peers, status.request_seq
            ))
            .block(Block::default().title("Status").borders(Borders::ALL));
            frame.render_widget(header, chunks[0]);

            let policy_lines = format_policies(&policies);
            let body = Paragraph::new(policy_lines).block(
                Block::default()
                    .title("Policies (q to quit)")
                    .borders(Borders::ALL),
            );
            frame.render_widget(body, chunks[1]);
        })?;

        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
            && key.code == KeyCode::Char('q')
        {
            running = false;
        }
    }

    let state = bridge
        .snapshot_state()
        .await
        .map_err(|e| anyhow!(e.to_string()))?;
    store.save(&state)?;
    complete_clean_run(&state_path, &run_id, &state)?;
    bridge.shutdown().await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn format_policies(policies: &std::collections::HashMap<String, PeerPolicy>) -> String {
    policies
        .iter()
        .map(|(peer, policy)| format!("{peer} => block_all={}", policy.block_all))
        .collect::<Vec<_>>()
        .join("\n")
}
