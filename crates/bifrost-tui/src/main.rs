use std::collections::VecDeque;
use std::fs;
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use bifrost_rpc::{
    BifrostRpcRequest, BifrostRpcResponse, DaemonStatus, PeerView, next_request_id, request,
    send_request_to,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::{execute, terminal};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

const MAX_MESSAGES: usize = 5_000;
const REFRESH_EVERY: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct App {
    alias: String,
    socket: PathBuf,
    input: String,
    messages: VecDeque<String>,
    status_lines: Vec<String>,
    event_lines: Vec<String>,
    peers: Vec<PeerView>,
    quit: bool,
    last_refresh: Instant,
}

impl App {
    fn new(socket: PathBuf) -> Self {
        let mut messages = VecDeque::new();
        messages.push_back("welcome: type 'help' for commands".to_string());
        Self {
            alias: alias_from_socket(&socket),
            socket,
            input: String::new(),
            messages,
            status_lines: vec!["loading status...".to_string()],
            event_lines: Vec::new(),
            peers: Vec::new(),
            quit: false,
            last_refresh: Instant::now() - REFRESH_EVERY,
        }
    }

    fn push_message(&mut self, msg: impl Into<String>) {
        self.messages.push_back(msg.into());
        while self.messages.len() > MAX_MESSAGES {
            self.messages.pop_front();
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let socket = socket_arg().unwrap_or_else(|| PathBuf::from("/tmp/bifrostd.sock"));
    if let Some(script_path) = script_arg() {
        return run_script_mode(socket, script_path).await;
    }
    let mut app = App::new(socket);

    init_terminal()?;
    let mut terminal = make_terminal()?;

    let run_result = run_app(&mut terminal, &mut app).await;

    restore_terminal()?;
    run_result
}

async fn run_script_mode(socket: PathBuf, script_path: PathBuf) -> Result<()> {
    let mut app = App::new(socket);
    refresh_panels(&mut app).await;
    let content = fs::read_to_string(&script_path)?;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let before = app.messages.len();
        execute_command(&mut app, line).await;
        let new_lines = app.messages.iter().skip(before).cloned().collect::<Vec<_>>();
        for msg in new_lines {
            println!("{msg}");
        }
    }
    Ok(())
}

async fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    refresh_panels(app).await;

    loop {
        terminal.draw(|f| render(f, app))?;
        if app.quit {
            break;
        }

        if app.last_refresh.elapsed() >= REFRESH_EVERY {
            refresh_panels(app).await;
        }

        if event::poll(Duration::from_millis(120))? {
            let ev = event::read()?;
            if let Event::Key(key) = ev {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                        app.quit = true;
                    }
                    KeyCode::Esc => app.quit = true,
                    KeyCode::Char(ch) => app.input.push(ch),
                    KeyCode::Backspace => {
                        app.input.pop();
                    }
                    KeyCode::Enter => {
                        let cmd = app.input.trim().to_string();
                        app.input.clear();
                        if !cmd.is_empty() {
                            execute_command(app, &cmd).await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

async fn execute_command(app: &mut App, cmd: &str) {
    app.push_message(format!("> {cmd}"));

    let parts = cmd.split_whitespace().collect::<Vec<_>>();
    let Some(op) = parts.first().copied() else {
        return;
    };

    match op {
        "quit" | "exit" => app.quit = true,
        "clear" => app.messages.clear(),
        "help" => app.push_message(
            "commands: help, status, events [n], health, ping <peer>, echo <peer> <msg>, sign <hex32>, ecdh <hex33>, onboard <peer>, clear, quit  (peer selector: alice|bob|carol|index|pubkey-prefix)",
        ),
        "status" => {
            rpc_and_log(app, BifrostRpcRequest::Status, Some("status")).await;
            refresh_panels(app).await;
        }
        "events" => {
            let limit = parts
                .get(1)
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(20);
            rpc_and_log(app, BifrostRpcRequest::Events { limit }, Some("events")).await;
            refresh_panels(app).await;
        }
        "health" => rpc_and_log(app, BifrostRpcRequest::Health, None).await,
        "ping" => {
            if let Some(peer) = parts.get(1) {
                let resolved = match resolve_peer_selector(&app.peers, peer) {
                    Ok(v) => v,
                    Err(err) => {
                        app.push_message(err);
                        return;
                    }
                };
                rpc_and_log(
                    app,
                    BifrostRpcRequest::Ping {
                        peer: resolved,
                    },
                    None,
                )
                .await;
                refresh_panels(app).await;
            } else {
                app.push_message("usage: ping <peer>");
            }
        }
        "onboard" => {
            if let Some(peer) = parts.get(1) {
                let resolved = match resolve_peer_selector(&app.peers, peer) {
                    Ok(v) => v,
                    Err(err) => {
                        app.push_message(err);
                        return;
                    }
                };
                rpc_and_log(
                    app,
                    BifrostRpcRequest::Onboard {
                        peer: resolved,
                    },
                    None,
                )
                .await;
                refresh_panels(app).await;
            } else {
                app.push_message("usage: onboard <peer>");
            }
        }
        "echo" => {
            if parts.len() >= 3 {
                let resolved = match resolve_peer_selector(&app.peers, parts[1]) {
                    Ok(v) => v,
                    Err(err) => {
                        app.push_message(err);
                        return;
                    }
                };
                rpc_and_log(
                    app,
                    BifrostRpcRequest::Echo {
                        peer: resolved,
                        message: parts[2..].join(" "),
                    },
                    None,
                )
                .await;
                refresh_panels(app).await;
            } else {
                app.push_message("usage: echo <peer> <message>");
            }
        }
        "sign" => {
            if let Some(hex) = parts.get(1) {
                rpc_and_log(
                    app,
                    BifrostRpcRequest::Sign {
                        message32_hex: (*hex).to_string(),
                    },
                    None,
                )
                .await;
            } else {
                app.push_message("usage: sign <32-byte-hex>");
            }
        }
        "ecdh" => {
            if let Some(hex) = parts.get(1) {
                rpc_and_log(
                    app,
                    BifrostRpcRequest::Ecdh {
                        pubkey33_hex: (*hex).to_string(),
                    },
                    None,
                )
                .await;
            } else {
                app.push_message("usage: ecdh <33-byte-hex>");
            }
        }
        _ => app.push_message("unknown command (type 'help')"),
    }
}

async fn rpc_and_log(app: &mut App, req: BifrostRpcRequest, panel_hint: Option<&str>) {
    let id = next_request_id();
    match send_request_to(&app.socket, request(id, req)).await {
        Ok(resp) => match resp.response {
            BifrostRpcResponse::Ok(data) => {
                if let Ok(pretty) = serde_json::to_string_pretty(&data) {
                    for line in pretty.lines() {
                        app.push_message(line.to_string());
                    }
                    if panel_hint == Some("status") {
                        if let Some(status) = decode_status(&data) {
                            app.peers = status.peers.clone();
                            app.status_lines = format_status_lines(&status);
                        } else {
                            app.status_lines = pretty.lines().map(ToString::to_string).collect();
                        }
                    }
                    if panel_hint == Some("events") {
                        merge_events_into_output(app, extract_events(&data));
                    }
                }
            }
            BifrostRpcResponse::Err { code, message } => {
                app.push_message(format!("rpc error ({code}): {message}"));
            }
        },
        Err(err) => app.push_message(format!("rpc transport error: {err}")),
    }
}

async fn refresh_panels(app: &mut App) {
    app.last_refresh = Instant::now();

    if let Ok(resp) = send_request_to(
        &app.socket,
        request(next_request_id(), BifrostRpcRequest::Status),
    )
    .await
    {
        if let BifrostRpcResponse::Ok(data) = resp.response {
            if let Some(status) = decode_status(&data) {
                app.peers = status.peers.clone();
                app.status_lines = format_status_lines(&status);
            } else if let Ok(pretty) = serde_json::to_string_pretty(&data) {
                app.status_lines = pretty.lines().map(ToString::to_string).collect();
            }
        }
    }

    if let Ok(resp) = send_request_to(
        &app.socket,
        request(next_request_id(), BifrostRpcRequest::Events { limit: 30 }),
    )
    .await
    {
        if let BifrostRpcResponse::Ok(data) = resp.response {
            merge_events_into_output(app, extract_events(&data));
        }
    }
}

fn extract_events(data: &serde_json::Value) -> Vec<String> {
    let Some(arr) = data.get("events").and_then(|v| v.as_array()) else {
        return vec!["(no events)".to_string()];
    };
    if arr.is_empty() {
        return vec!["(no events)".to_string()];
    }
    arr.iter()
        .filter_map(|v| v.as_str().map(ToString::to_string))
        .collect()
}

fn decode_status(data: &serde_json::Value) -> Option<DaemonStatus> {
    serde_json::from_value(data.clone()).ok()
}

fn short_pubkey(value: &str) -> String {
    if value.len() <= 18 {
        return value.to_string();
    }
    format!("{}...{}", &value[..10], &value[value.len() - 6..])
}

fn format_status_lines(status: &DaemonStatus) -> Vec<String> {
    let pool_max = status.nonce_pool_size.max(1);
    let mut lines = Vec::new();

    for (idx, peer) in status.peers.iter().enumerate() {
        let alias = alias_for_member_idx(peer.member_idx);
        let theirs_bar = progress_bar(peer.nonce_incoming_available, pool_max, 10);
        let ours_bar = progress_bar(peer.nonce_outgoing_available, pool_max, 10);
        lines.push(format!(
            "{} ({}) m{} {} {} policy:{}{} sign:{} send:{}",
            idx + 1,
            alias,
            peer.member_idx,
            short_pubkey(&peer.pubkey),
            peer.status,
            if peer.nonce_can_sign { "yes" } else { "no" },
            if peer.nonce_should_send { "yes" } else { "no" },
            if peer.send { "S" } else { "-" },
            if peer.recv { "R" } else { "-" },
        ));
        lines.push(format!(
            "  theirs [{}] {}/{} | ours [{}] {}/{} | spent {}",
            theirs_bar,
            peer.nonce_incoming_available,
            pool_max,
            ours_bar,
            peer.nonce_outgoing_available,
            pool_max,
            peer.nonce_outgoing_spent
        ));
    }

    lines
}

fn alias_for_member_idx(member_idx: u16) -> &'static str {
    match member_idx {
        1 => "alice",
        2 => "bob",
        3 => "carol",
        4 => "dave",
        _ => "peer",
    }
}

fn progress_bar(current: usize, max: usize, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let clamped_max = max.max(1);
    let clamped_current = current.min(clamped_max);
    let filled = clamped_current.saturating_mul(width) / clamped_max;
    let mut out = String::with_capacity(width);
    for i in 0..width {
        out.push(if i < filled { '#' } else { '-' });
    }
    out
}

fn resolve_peer_selector(
    peers: &[PeerView],
    selector: &str,
) -> std::result::Result<String, String> {
    if peers.is_empty() {
        return Ok(selector.to_string());
    }

    if peers.iter().any(|p| p.pubkey == selector) {
        return Ok(selector.to_string());
    }

    if let Ok(one_based) = selector.parse::<usize>() {
        if one_based >= 1 && one_based <= peers.len() {
            return Ok(peers[one_based - 1].pubkey.clone());
        }
        return Err(format!(
            "peer index out of range: {one_based} (1..={})",
            peers.len()
        ));
    }

    let normalized = selector.to_ascii_lowercase();
    if let Some((_, peer)) = peers
        .iter()
        .enumerate()
        .find(|(_, p)| alias_for_member_idx(p.member_idx) == normalized)
    {
        return Ok(peer.pubkey.clone());
    }

    let prefixed = peers
        .iter()
        .filter(|p| p.pubkey.starts_with(selector))
        .collect::<Vec<_>>();
    if prefixed.len() == 1 {
        return Ok(prefixed[0].pubkey.clone());
    }
    if prefixed.len() > 1 {
        return Err(format!(
            "ambiguous peer selector '{}': {} matches",
            selector,
            prefixed.len()
        ));
    }

    Err(format!("unknown peer selector: {selector}"))
}

fn alias_from_socket(socket: &PathBuf) -> String {
    let lower = socket.display().to_string().to_ascii_lowercase();
    if lower.contains("alice") {
        return "alice".to_string();
    }
    if lower.contains("bob") {
        return "bob".to_string();
    }
    if lower.contains("carol") {
        return "carol".to_string();
    }
    if lower.contains("dave") {
        return "dave".to_string();
    }
    "node".to_string()
}

fn merge_events_into_output(app: &mut App, next_events: Vec<String>) {
    if next_events.is_empty() {
        return;
    }
    for ev in &next_events {
        if !app.event_lines.iter().any(|prev| prev == ev) {
            app.push_message(format!("event: {ev}"));
        }
    }
    app.event_lines = next_events;
}

fn tail_lines(lines: &[String], max_rows: usize) -> Vec<String> {
    if max_rows == 0 || lines.is_empty() {
        return Vec::new();
    }
    let take = max_rows.min(lines.len());
    lines[lines.len() - take..].to_vec()
}

fn render(frame: &mut Frame<'_>, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " BIFROST TUI ",
            Style::default().fg(Color::Black).bg(Color::Cyan),
        ),
        Span::raw("  "),
        Span::styled(
            format!("alias: {}", app.alias),
            Style::default().fg(Color::LightYellow),
        ),
        Span::raw("  "),
        Span::styled(
            format!("sock: {}", app.socket.display()),
            Style::default().fg(Color::Gray),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, root[0]);

    let status_visible_rows = root[1].height.saturating_sub(2) as usize;
    let status_items = tail_lines(&app.status_lines, status_visible_rows)
        .iter()
        .map(|line| ListItem::new(line.clone()))
        .collect::<Vec<_>>();
    let status = List::new(status_items).block(
        Block::default()
            .title(Span::styled(
                "Peers",
                Style::default()
                    .fg(Color::LightBlue)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(status, root[1]);

    let output_visible_rows = root[2].height.saturating_sub(2) as usize;
    let output_snapshot = app.messages.iter().cloned().collect::<Vec<_>>();
    let output_lines = tail_lines(&output_snapshot, output_visible_rows)
        .iter()
        .map(|m| ListItem::new(m.clone()))
        .collect::<Vec<_>>();
    let output = List::new(output_lines).block(
        Block::default()
            .title(Span::styled(
                "Output",
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(output, root[2]);

    let input = Paragraph::new(app.input.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .title(Span::styled(
                    "Command",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(input, root[3]);
}

fn init_terminal() -> Result<()> {
    enable_raw_mode()?;
    execute!(io::stdout(), terminal::EnterAlternateScreen)?;
    Ok(())
}

fn restore_terminal() -> Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), terminal::LeaveAlternateScreen)?;
    Ok(())
}

fn make_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn socket_arg() -> Option<PathBuf> {
    let args = std::env::args().collect::<Vec<_>>();
    for idx in 0..args.len() {
        if args[idx] == "--socket" {
            return args.get(idx + 1).map(PathBuf::from);
        }
    }
    None
}

fn script_arg() -> Option<PathBuf> {
    let args = std::env::args().collect::<Vec<_>>();
    for idx in 0..args.len() {
        if args[idx] == "--script" {
            return args.get(idx + 1).map(PathBuf::from);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(pubkey: &str, member_idx: u16) -> PeerView {
        PeerView {
            pubkey: pubkey.to_string(),
            status: "online".to_string(),
            send: true,
            recv: true,
            updated: 0,
            member_idx,
            nonce_incoming_available: 1,
            nonce_outgoing_available: 2,
            nonce_outgoing_spent: 0,
            nonce_can_sign: true,
            nonce_should_send: false,
        }
    }

    #[test]
    fn resolve_peer_selector_supports_index_alias_and_prefix() {
        let peers = vec![
            peer(
                "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                2,
            ),
            peer(
                "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                3,
            ),
        ];
        assert_eq!(
            resolve_peer_selector(&peers, "1").expect("index"),
            peers[0].pubkey
        );
        assert_eq!(
            resolve_peer_selector(&peers, "carol").expect("alias"),
            peers[1].pubkey
        );
        assert_eq!(
            resolve_peer_selector(&peers, "02aaaa").expect("prefix"),
            peers[0].pubkey
        );
    }

    #[test]
    fn format_status_lines_includes_nonce_columns() {
        let status = DaemonStatus {
            ready: true,
            share_idx: 1,
            nonce_pool_size: 100,
            nonce_pool_min_threshold: 20,
            nonce_pool_critical_threshold: 5,
            peers: vec![peer(
                "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                2,
            )],
        };
        let lines = format_status_lines(&status);
        assert!(lines.iter().any(|l| l.contains("theirs [")));
        assert!(lines.iter().any(|l| l.contains("ours [")));
        assert!(lines.iter().any(|l| l.contains("spent")));
        assert!(lines.iter().any(|l| l.contains("(bob)")));
    }
}
