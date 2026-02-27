use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bifrost_codec::wire::{OnboardResponseWire, PingPayloadWire};
use bifrost_codec::{parse_group_package, parse_share_package};
use bifrost_core::local_pubkey_from_share;
use bifrost_node::{BifrostNode, BifrostNodeOptions, NodeEvent, PeerStatus};
use bifrost_rpc::{
    BifrostRpcRequest, BifrostRpcResponse, DaemonStatus, PeerView, RpcRequestEnvelope,
    RpcResponseEnvelope,
};
use bifrost_transport::Clock;
use bifrost_transport_ws::{WebSocketTransport, WsNostrConfig, WsTransportConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonConfig {
    socket_path: String,
    group_path: String,
    share_path: String,
    peers: Vec<String>,
    relays: Vec<String>,
    #[serde(default)]
    options: Option<BifrostNodeOptions>,
    #[serde(default)]
    transport: DaemonTransportConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonTransportConfig {
    #[serde(default = "default_rpc_kind")]
    rpc_kind: u64,
    #[serde(default = "default_max_retries")]
    max_retries: u32,
    #[serde(default = "default_backoff_initial_ms")]
    backoff_initial_ms: u64,
    #[serde(default = "default_backoff_max_ms")]
    backoff_max_ms: u64,
    #[serde(default)]
    sender_pubkey33: Option<String>,
    #[serde(default)]
    sender_seckey32_hex: Option<String>,
}

impl Default for DaemonTransportConfig {
    fn default() -> Self {
        Self {
            rpc_kind: default_rpc_kind(),
            max_retries: default_max_retries(),
            backoff_initial_ms: default_backoff_initial_ms(),
            backoff_max_ms: default_backoff_max_ms(),
            sender_pubkey33: None,
            sender_seckey32_hex: None,
        }
    }
}

fn default_rpc_kind() -> u64 {
    20_000
}

fn default_max_retries() -> u32 {
    3
}

fn default_backoff_initial_ms() -> u64 {
    250
}

fn default_backoff_max_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone)]
struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[derive(Clone)]
struct DaemonState {
    node: Arc<BifrostNode<WebSocketTransport, SystemClock>>,
    events: Arc<Mutex<VecDeque<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = arg_value("--config").unwrap_or_else(|| "config/daemon.json".to_string());
    let cfg = load_config(Path::new(&config_path)).await?;

    let group_raw = tokio::fs::read_to_string(&cfg.group_path)
        .await
        .with_context(|| format!("read group package {}", cfg.group_path))?;
    let share_raw = tokio::fs::read_to_string(&cfg.share_path)
        .await
        .with_context(|| format!("read share package {}", cfg.share_path))?;

    let group = parse_group_package(&group_raw).context("parse group package")?;
    let share = parse_share_package(&share_raw).context("parse share package")?;

    let derived_sender_pubkey33 =
        hex::encode(local_pubkey_from_share(&share).context("derive local pubkey")?);
    let sender_pubkey33 = cfg
        .transport
        .sender_pubkey33
        .clone()
        .unwrap_or_else(|| derived_sender_pubkey33.clone());
    let sender_seckey32 = if let Some(raw) = cfg.transport.sender_seckey32_hex.as_ref() {
        parse_hex32(raw).context("parse transport.sender_seckey32_hex")?
    } else {
        share.seckey
    };
    if sender_pubkey33 != derived_sender_pubkey33 {
        return Err(anyhow!(
            "transport.sender_pubkey33 does not match share public key"
        ));
    }

    let nostr_cfg = WsNostrConfig {
        sender_pubkey33,
        sender_seckey32,
        peer_pubkeys33: cfg.peers.clone(),
    };
    let transport = Arc::new(WebSocketTransport::with_config(
        cfg.relays.clone(),
        WsTransportConfig {
            max_retries: cfg.transport.max_retries,
            backoff_initial_ms: cfg.transport.backoff_initial_ms,
            backoff_max_ms: cfg.transport.backoff_max_ms,
            rpc_kind: cfg.transport.rpc_kind,
        },
        nostr_cfg,
    ));
    let node = Arc::new(BifrostNode::new(
        group,
        share,
        cfg.peers.clone(),
        transport,
        Arc::new(SystemClock),
        cfg.options,
    )?);

    node.connect().await.context("node connect")?;

    let events = Arc::new(Mutex::new(VecDeque::<String>::with_capacity(512)));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let state = DaemonState {
        node: node.clone(),
        events: events.clone(),
        stop: stop.clone(),
    };

    spawn_event_collector(node.clone(), events.clone(), stop.clone());
    spawn_inbound_processor(node.clone(), stop.clone());

    if Path::new(&cfg.socket_path).exists() {
        let _ = tokio::fs::remove_file(&cfg.socket_path).await;
    }

    let listener = UnixListener::bind(&cfg.socket_path)
        .with_context(|| format!("bind unix socket {}", cfg.socket_path))?;
    println!("bifrostd listening on {}", cfg.socket_path);

    loop {
        let (stream, _) = listener.accept().await.context("accept rpc client")?;
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(state_clone, stream).await {
                tracing::debug!("rpc client handler ended: {err}");
            }
        });

        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
    }

    let _ = node.close().await;
    let _ = tokio::fs::remove_file(&cfg.socket_path).await;
    Ok(())
}

fn spawn_event_collector(
    node: Arc<BifrostNode<WebSocketTransport, SystemClock>>,
    events: Arc<Mutex<VecDeque<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut rx = node.subscribe_events();
    tokio::spawn(async move {
        loop {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let recv = rx.recv().await;
            let ev = match recv {
                Ok(v) => v,
                Err(_) => break,
            };
            let label = match ev {
                NodeEvent::Ready => "ready".to_string(),
                NodeEvent::Closed => "closed".to_string(),
                NodeEvent::Message(m) => format!("message:{m}"),
                NodeEvent::Bounced(m) => format!("bounced:{m}"),
                NodeEvent::Info(m) => format!("info:{m}"),
                NodeEvent::Error(m) => format!("error:{m}"),
            };
            let mut guard = events.lock().await;
            if guard.len() >= 1024 {
                guard.pop_front();
            }
            guard.push_back(label);
        }
    });
}

fn spawn_inbound_processor(
    node: Arc<BifrostNode<WebSocketTransport, SystemClock>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::spawn(async move {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = node.process_next_incoming().await;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    });
}

async fn load_config(path: &Path) -> Result<DaemonConfig> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read daemon config {}", path.display()))?;
    let cfg: DaemonConfig = serde_json::from_str(&raw).context("parse daemon config")?;
    if cfg.relays.is_empty() {
        return Err(anyhow!("daemon config must include at least one relay"));
    }
    if cfg.peers.is_empty() {
        return Err(anyhow!("daemon config must include at least one peer"));
    }
    Ok(cfg)
}

async fn handle_client(state: DaemonState, stream: UnixStream) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.context("read rpc line")?;
        if n == 0 {
            break;
        }

        let req: RpcRequestEnvelope = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(err) => {
                let resp = RpcResponseEnvelope {
                    id: 0,
                    response: BifrostRpcResponse::Err {
                        code: 400,
                        message: format!("invalid request: {err}"),
                    },
                };
                write_response(&mut write_half, &resp).await?;
                continue;
            }
        };

        let resp = execute_request(&state, req).await;
        write_response(&mut write_half, &resp).await?;
    }

    Ok(())
}

async fn execute_request(state: &DaemonState, req: RpcRequestEnvelope) -> RpcResponseEnvelope {
    let id = req.id;
    let result: Result<serde_json::Value, anyhow::Error> = async {
        match req.request {
            BifrostRpcRequest::Health => Ok(json!({"ok": true})),
            BifrostRpcRequest::Status => {
                let nonce_cfg = state.node.nonce_pool_config();
                let peers = state
                    .node
                    .peers()
                    .iter()
                    .map(|p| {
                        let nonce = state.node.peer_nonce_health(&p.pubkey).ok();
                        PeerView {
                            member_idx: nonce.as_ref().map(|v| v.member_idx).unwrap_or(0),
                            pubkey: p.pubkey.clone(),
                            status: match p.status {
                                PeerStatus::Online => "online".to_string(),
                                PeerStatus::Offline => "offline".to_string(),
                            },
                            send: p.policy.send,
                            recv: p.policy.recv,
                            updated: p.updated,
                            nonce_incoming_available: nonce
                                .as_ref()
                                .map(|v| v.incoming_available)
                                .unwrap_or(0),
                            nonce_outgoing_available: nonce
                                .as_ref()
                                .map(|v| v.outgoing_available)
                                .unwrap_or(0),
                            nonce_outgoing_spent: nonce
                                .as_ref()
                                .map(|v| v.outgoing_spent)
                                .unwrap_or(0),
                            nonce_can_sign: nonce.as_ref().map(|v| v.can_sign).unwrap_or(false),
                            nonce_should_send: nonce
                                .as_ref()
                                .map(|v| v.should_send_nonces)
                                .unwrap_or(true),
                        }
                    })
                    .collect::<Vec<_>>();
                let status = DaemonStatus {
                    ready: state.node.is_ready(),
                    share_idx: state.node.share_idx(),
                    nonce_pool_size: nonce_cfg.pool_size,
                    nonce_pool_min_threshold: nonce_cfg.min_threshold,
                    nonce_pool_critical_threshold: nonce_cfg.critical_threshold,
                    peers,
                };
                Ok(serde_json::to_value(status)?)
            }
            BifrostRpcRequest::Events { limit } => {
                let guard = state.events.lock().await;
                let take = limit.min(guard.len());
                let values = guard.iter().rev().take(take).cloned().collect::<Vec<_>>();
                Ok(json!({ "events": values }))
            }
            BifrostRpcRequest::Echo { peer, message } => {
                let out = state.node.echo(&peer, &message).await?;
                Ok(json!({ "echo": out }))
            }
            BifrostRpcRequest::Ping { peer } => {
                let out = state.node.ping(&peer).await?;
                Ok(serde_json::to_value(PingPayloadWire::from(out))?)
            }
            BifrostRpcRequest::Onboard { peer } => {
                let out = state.node.onboard(&peer).await?;
                Ok(serde_json::to_value(OnboardResponseWire::from(out))?)
            }
            BifrostRpcRequest::Sign { message32_hex } => {
                let bytes = parse_fixed_hex::<32>(&message32_hex)?;
                let sig = state.node.sign(bytes).await?;
                Ok(json!({ "signature": hex::encode(sig) }))
            }
            BifrostRpcRequest::Ecdh { pubkey33_hex } => {
                let bytes = parse_fixed_hex::<33>(&pubkey33_hex)?;
                let key = state.node.ecdh(bytes).await?;
                Ok(json!({ "shared_secret": hex::encode(key) }))
            }
            BifrostRpcRequest::Shutdown => {
                state.stop.store(true, std::sync::atomic::Ordering::Relaxed);
                Ok(json!({ "shutting_down": true }))
            }
        }
    }
    .await;

    match result {
        Ok(data) => RpcResponseEnvelope {
            id,
            response: BifrostRpcResponse::Ok(data),
        },
        Err(err) => RpcResponseEnvelope {
            id,
            response: BifrostRpcResponse::Err {
                code: 500,
                message: err.to_string(),
            },
        },
    }
}

async fn write_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    resp: &RpcResponseEnvelope,
) -> Result<()> {
    let raw = serde_json::to_string(resp).context("encode rpc response")?;
    writer
        .write_all(raw.as_bytes())
        .await
        .context("write rpc")?;
    writer.write_all(b"\n").await.context("write rpc newline")?;
    writer.flush().await.context("flush rpc")?;
    Ok(())
}

fn parse_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid hex input: {value}"))?;
    if bytes.len() != N {
        return Err(anyhow!("expected {N} bytes but got {}", bytes.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn arg_value(flag: &str) -> Option<String> {
    let args = std::env::args().collect::<Vec<_>>();
    for idx in 0..args.len() {
        if args[idx] == flag {
            return args.get(idx + 1).cloned();
        }
    }
    None
}

fn parse_hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid hex input: {value}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes but got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
