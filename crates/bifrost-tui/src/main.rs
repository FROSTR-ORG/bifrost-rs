use std::collections::VecDeque;
use std::fs;
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use bifrost_core::{decode_hex32, message_sighash};
use bifrost_rpc::{BifrostRpcRequest, DaemonClient, DaemonStatus, PeerPolicyView, PeerView};
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
    client: DaemonClient,
    input: String,
    messages: VecDeque<String>,
    status_lines: Vec<String>,
    event_lines: Vec<String>,
    peers: Vec<PeerView>,
    active_peer: Option<String>,
    active_peer_label: Option<String>,
    quit: bool,
    last_refresh: Instant,
}

impl App {
    fn new(socket: PathBuf) -> Self {
        let mut messages = VecDeque::new();
        messages.push_back("welcome: type 'help' for commands".to_string());
        Self {
            alias: alias_from_socket(&socket),
            client: DaemonClient::new(socket),
            input: String::new(),
            messages,
            status_lines: vec!["loading status...".to_string()],
            event_lines: Vec::new(),
            peers: Vec::new(),
            active_peer: None,
            active_peer_label: None,
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

#[derive(Clone, Copy)]
struct Theme {
    header_bg: Color,
    header_fg: Color,
    header_label: Color,
    dim: Color,
    panel_status: Color,
    panel_output: Color,
    panel_input: Color,
    output_command: Color,
    output_event: Color,
    output_error: Color,
    output_success: Color,
    output_info: Color,
}

fn high_contrast_theme() -> Theme {
    Theme {
        header_bg: Color::LightBlue,
        header_fg: Color::Black,
        header_label: Color::LightYellow,
        dim: Color::Gray,
        panel_status: Color::LightCyan,
        panel_output: Color::LightGreen,
        panel_input: Color::LightYellow,
        output_command: Color::Yellow,
        output_event: Color::LightBlue,
        output_error: Color::Red,
        output_success: Color::LightGreen,
        output_info: Color::LightCyan,
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
        let new_lines = app
            .messages
            .iter()
            .skip(before)
            .cloned()
            .collect::<Vec<_>>();
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
            "commands: help, status, events [n], health, use <peer>, ping <peer>, onboard <peer>, echo <peer> <msg> | echo <msg>, sign <text> | sign hex:<hex32> | sign 0x<hex32>, ecdh <peer>, policy list|get <peer>|set <peer> <json>|refresh <peer>, clear, quit  (peer selector: alice|bob|carol|index|pubkey-prefix)",
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
        "use" => {
            if let Some(selector) = parts.get(1) {
                match resolve_peer_selector(&app.peers, selector) {
                    Ok(resolved) => {
                        set_active_peer(app, resolved, (*selector).to_string());
                    }
                    Err(err) => app.push_message(err),
                }
            } else {
                app.push_message("usage: use <peer>");
            }
        }
        "ping" => {
            if let Some(selector) = parts.get(1) {
                let resolved = match resolve_peer_selector(&app.peers, selector) {
                    Ok(v) => v,
                    Err(err) => {
                        app.push_message(err);
                        return;
                    }
                };
                set_active_peer(app, resolved.clone(), (*selector).to_string());
                rpc_and_log(app, BifrostRpcRequest::Ping { peer: resolved }, None).await;
                refresh_panels(app).await;
            } else {
                app.push_message("usage: ping <peer>");
            }
        }
        "onboard" => {
            if let Some(selector) = parts.get(1) {
                let resolved = match resolve_peer_selector(&app.peers, selector) {
                    Ok(v) => v,
                    Err(err) => {
                        app.push_message(err);
                        return;
                    }
                };
                set_active_peer(app, resolved.clone(), (*selector).to_string());
                rpc_and_log(app, BifrostRpcRequest::Onboard { peer: resolved }, None).await;
                refresh_panels(app).await;
            } else {
                app.push_message("usage: onboard <peer>");
            }
        }
        "echo" => {
            let args = parts.get(1..).unwrap_or(&[]);
            match resolve_echo_target_and_message(&app.peers, app.active_peer.as_deref(), args) {
                Ok((peer, message, explicit_selector)) => {
                    if explicit_selector {
                        set_active_peer(app, peer.clone(), args[0].to_string());
                    }
                    rpc_and_log(app, BifrostRpcRequest::Echo { peer, message }, None).await;
                    refresh_panels(app).await;
                }
                Err(err) => app.push_message(err),
            }
        }
        "sign" => {
            let args = parts.get(1..).unwrap_or(&[]);
            match parse_sign_digest(args) {
                Ok((digest, explain)) => {
                    app.push_message(explain);
                    rpc_and_log(
                        app,
                        BifrostRpcRequest::Sign {
                            message32_hex: hex::encode(digest),
                        },
                        None,
                    )
                    .await;
                }
                Err(err) => app.push_message(err),
            }
        }
        "ecdh" => {
            if let Some(selector) = parts.get(1) {
                let resolved = match resolve_peer_selector(&app.peers, selector) {
                    Ok(v) => v,
                    Err(err) => {
                        app.push_message(err);
                        return;
                    }
                };
                set_active_peer(app, resolved.clone(), (*selector).to_string());
                rpc_and_log(
                    app,
                    BifrostRpcRequest::Ecdh {
                        pubkey33_hex: resolved,
                    },
                    None,
                )
                .await;
            } else {
                app.push_message("usage: ecdh <peer>");
            }
        }
        "policy" => {
            let sub = parts.get(1).copied().unwrap_or("");
            match sub {
                "list" => rpc_and_log(app, BifrostRpcRequest::GetPeerPolicies, None).await,
                "get" => {
                    if let Some(selector) = parts.get(2) {
                        let resolved = match resolve_peer_selector(&app.peers, selector) {
                            Ok(v) => v,
                            Err(err) => {
                                app.push_message(err);
                                return;
                            }
                        };
                        rpc_and_log(app, BifrostRpcRequest::GetPeerPolicy { peer: resolved }, None)
                            .await;
                    } else {
                        app.push_message("usage: policy get <peer>");
                    }
                }
                "refresh" => {
                    if let Some(selector) = parts.get(2) {
                        let resolved = match resolve_peer_selector(&app.peers, selector) {
                            Ok(v) => v,
                            Err(err) => {
                                app.push_message(err);
                                return;
                            }
                        };
                        rpc_and_log(
                            app,
                            BifrostRpcRequest::RefreshPeerPolicy { peer: resolved },
                            None,
                        )
                        .await;
                    } else {
                        app.push_message("usage: policy refresh <peer>");
                    }
                }
                "set" => {
                    if parts.len() >= 4 {
                        let resolved = match resolve_peer_selector(&app.peers, parts[2]) {
                            Ok(v) => v,
                            Err(err) => {
                                app.push_message(err);
                                return;
                            }
                        };
                        let raw = parts[3..].join(" ");
                        let policy: PeerPolicyView = match serde_json::from_str(&raw) {
                            Ok(v) => v,
                            Err(err) => {
                                app.push_message(format!("invalid policy json: {err}"));
                                return;
                            }
                        };
                        rpc_and_log(
                            app,
                            BifrostRpcRequest::SetPeerPolicy {
                                peer: resolved,
                                policy,
                            },
                            None,
                        )
                        .await;
                    } else {
                        app.push_message("usage: policy set <peer> <json-policy>");
                    }
                }
                _ => app.push_message("usage: policy <list|get|set|refresh> ..."),
            }
        }
        _ => app.push_message("unknown command (type 'help')"),
    }
}

fn parse_sign_digest(args: &[&str]) -> std::result::Result<([u8; 32], String), String> {
    let Some(first) = args.first() else {
        return Err(
            "usage: sign <text> | sign hex:<32-byte-hex> | sign 0x<32-byte-hex>".to_string(),
        );
    };

    if let Some(value) = first.strip_prefix("hex:") {
        let digest = decode_hex32(value).map_err(|_| "invalid sign digest hex".to_string())?;
        return Ok((
            digest,
            format!("sign: using explicit digest {}", hex::encode(digest)),
        ));
    }

    if let Some(value) = first.strip_prefix("0x") {
        let digest = decode_hex32(value).map_err(|_| "invalid sign digest hex".to_string())?;
        return Ok((
            digest,
            format!("sign: using explicit digest {}", hex::encode(digest)),
        ));
    }

    let text = args.join(" ");
    if text.is_empty() {
        return Err(
            "usage: sign <text> | sign hex:<32-byte-hex> | sign 0x<32-byte-hex>".to_string(),
        );
    }

    let digest = message_sighash(text.as_bytes());
    Ok((
        digest,
        format!(
            "sign: sha256(utf8)={} (text='{}')",
            hex::encode(digest),
            text
        ),
    ))
}

fn resolve_echo_target_and_message(
    peers: &[PeerView],
    active_peer: Option<&str>,
    args: &[&str],
) -> std::result::Result<(String, String, bool), String> {
    if args.is_empty() {
        return Err(
            "usage: echo <peer> <message> | echo <message> (requires 'use <peer>')".to_string(),
        );
    }

    if args.len() >= 2
        && let Ok(peer) = resolve_peer_selector(peers, args[0])
    {
        return Ok((peer, args[1..].join(" "), true));
    }

    let Some(active) = active_peer else {
        return Err(
            "echo target is not set; use 'use <peer>' first or run 'echo <peer> <message>'"
                .to_string(),
        );
    };

    Ok((active.to_string(), args.join(" "), false))
}

fn set_active_peer(app: &mut App, peer: String, label: String) {
    app.active_peer = Some(peer.clone());
    app.active_peer_label = Some(label.clone());
    app.push_message(format!("active peer: {} ({})", label, short_pubkey(&peer)));
}

async fn rpc_and_log(app: &mut App, req: BifrostRpcRequest, panel_hint: Option<&str>) {
    match app.client.call(req).await {
        Ok(data) => {
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
        Err(err) => app.push_message(format!("error: {err}")),
    }
}

async fn refresh_panels(app: &mut App) {
    app.last_refresh = Instant::now();

    if let Ok(status) = app.client.status().await {
        app.peers = status.peers.clone();
        app.status_lines = format_status_lines(&status);
    }

    if let Ok(data) = app.client.events(30).await {
        merge_events_into_output(app, extract_events(&data));
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
            "{} ({}) m{} {} {} block:{} req(sign/ecdh):{}/{} resp(sign/ecdh):{}/{} nonce:{}",
            idx + 1,
            alias,
            peer.member_idx,
            short_pubkey(&peer.pubkey),
            peer.status,
            if peer.block_all { "yes" } else { "no" },
            if peer.request.sign { "Y" } else { "N" },
            if peer.request.ecdh { "Y" } else { "N" },
            if peer.respond.sign { "Y" } else { "N" },
            if peer.respond.ecdh { "Y" } else { "N" },
            if peer.nonce_can_sign {
                "ready"
            } else {
                "empty"
            },
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

fn alias_from_socket(socket: &std::path::Path) -> String {
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
    let theme = high_contrast_theme();
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());
    let middle = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(root[1]);

    let active_peer = app
        .active_peer
        .as_ref()
        .map(|peer| {
            format!(
                "target: {} ({})",
                app.active_peer_label.as_deref().unwrap_or("peer"),
                short_pubkey(peer)
            )
        })
        .unwrap_or_else(|| "target: (unset; use <peer>)".to_string());

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " BIFROST TUI ",
            Style::default().fg(theme.header_fg).bg(theme.header_bg),
        ),
        Span::raw("  "),
        Span::styled(
            format!("alias: {}", app.alias),
            Style::default()
                .fg(theme.header_label)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(active_peer, Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        Span::styled(
            "hint: sign hello | ecdh bob | echo hello",
            Style::default().fg(theme.dim),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, root[0]);

    let status_visible_rows = middle[0].height.saturating_sub(2) as usize;
    let status_items = tail_lines(&app.status_lines, status_visible_rows)
        .iter()
        .map(|line| {
            ListItem::new(Line::styled(
                line.clone(),
                Style::default().fg(Color::White),
            ))
        })
        .collect::<Vec<_>>();
    let status = List::new(status_items).block(
        Block::default()
            .title(Span::styled(
                "Peers",
                Style::default()
                    .fg(theme.panel_status)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(status, middle[0]);

    let output_visible_rows = middle[1].height.saturating_sub(2) as usize;
    let output_snapshot = app.messages.iter().cloned().collect::<Vec<_>>();
    let output_lines = tail_lines(&output_snapshot, output_visible_rows)
        .iter()
        .map(|m| ListItem::new(Line::styled(m.clone(), style_output_line(m, theme))))
        .collect::<Vec<_>>();
    let output = List::new(output_lines).block(
        Block::default()
            .title(Span::styled(
                "Output",
                Style::default()
                    .fg(theme.panel_output)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(output, middle[1]);

    let input = Paragraph::new(app.input.as_str())
        .style(Style::default().fg(theme.panel_input))
        .block(
            Block::default()
                .title(Span::styled(
                    format!("Command  sock: {}", app.client.socket().display()),
                    Style::default()
                        .fg(theme.panel_input)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(input, root[2]);
}

fn style_output_line(line: &str, theme: Theme) -> Style {
    if line.starts_with('>') {
        return Style::default().fg(theme.output_command);
    }
    if line.starts_with("event:") {
        return Style::default().fg(theme.output_event);
    }
    if line.starts_with("usage:") || line.starts_with("error:") || line.starts_with("unknown") {
        return Style::default().fg(theme.output_error);
    }
    if line.contains("\"ok\": true")
        || line.contains("\"signature\"")
        || line.contains("\"shared_secret\"")
        || line.starts_with("active peer:")
    {
        return Style::default().fg(theme.output_success);
    }
    if line.starts_with("sign:") {
        return Style::default().fg(theme.output_info);
    }
    Style::default().fg(Color::White)
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
            block_all: false,
            request: bifrost_rpc::MethodPolicyView {
                echo: true,
                ping: true,
                onboard: true,
                sign: true,
                ecdh: true,
            },
            respond: bifrost_rpc::MethodPolicyView {
                echo: true,
                ping: true,
                onboard: true,
                sign: true,
                ecdh: true,
            },
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

    #[test]
    fn parse_sign_digest_supports_text_and_hex_modes() {
        let (text_digest, _) = parse_sign_digest(&["hello"]).expect("text");
        let (hex_digest, _) = parse_sign_digest(&[
            "hex:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        ])
        .expect("hex");
        let (ox_digest, _) = parse_sign_digest(&[
            "0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        ])
        .expect("0x");
        assert_eq!(text_digest, hex_digest);
        assert_eq!(ox_digest, hex_digest);
    }

    #[test]
    fn resolve_echo_target_prefers_explicit_selector_and_falls_back_to_active() {
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

        let explicit =
            resolve_echo_target_and_message(&peers, None, &["bob", "hello"]).expect("explicit");
        assert_eq!(explicit.0, peers[0].pubkey);
        assert_eq!(explicit.1, "hello");
        assert!(explicit.2);

        let fallback =
            resolve_echo_target_and_message(&peers, Some(&peers[1].pubkey), &["hello", "team"])
                .expect("fallback");
        assert_eq!(fallback.0, peers[1].pubkey);
        assert_eq!(fallback.1, "hello team");
        assert!(!fallback.2);
    }

    #[test]
    fn resolve_echo_target_requires_active_peer_for_shorthand() {
        let err = resolve_echo_target_and_message(&[], None, &["hello"]).expect_err("no active");
        assert!(err.contains("use <peer>"));
    }
}
