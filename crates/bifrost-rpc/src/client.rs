use std::path::Path;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::types::{BifrostRpcRequest, RPC_VERSION, RpcRequestEnvelope, RpcResponseEnvelope};

pub async fn send_request_to(
    socket_path: &Path,
    req: RpcRequestEnvelope,
) -> Result<RpcResponseEnvelope> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect socket {}", socket_path.display()))?;
    send_request(stream, req).await
}

pub async fn send_request(
    stream: UnixStream,
    req: RpcRequestEnvelope,
) -> Result<RpcResponseEnvelope> {
    let raw = serde_json::to_string(&req).context("encode request")?;

    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(raw.as_bytes())
        .await
        .context("write request")?;
    write_half.write_all(b"\n").await.context("write newline")?;
    write_half.flush().await.context("flush request")?;

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await.context("read response")?;
    if n == 0 {
        return Err(anyhow!("daemon closed socket without response"));
    }
    let resp: RpcResponseEnvelope = serde_json::from_str(line.trim()).context("decode response")?;
    Ok(resp)
}

pub fn next_request_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    now as u64
}

pub fn request(id: u64, request: BifrostRpcRequest) -> RpcRequestEnvelope {
    let auth_token = std::env::var("BIFROST_RPC_TOKEN")
        .ok()
        .filter(|v| !v.is_empty());
    RpcRequestEnvelope {
        id,
        rpc_version: RPC_VERSION,
        auth_token,
        request,
    }
}
