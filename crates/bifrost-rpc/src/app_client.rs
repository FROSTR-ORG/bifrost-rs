use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

use crate::client::{next_request_id, request, send_request_to};
use crate::types::PeerPolicyView;
use crate::types::{BifrostRpcRequest, BifrostRpcResponse, DaemonStatus};

#[derive(Debug, Clone)]
pub struct DaemonClient {
    socket: PathBuf,
}

impl DaemonClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub async fn call(&self, req: BifrostRpcRequest) -> Result<serde_json::Value> {
        let resp = send_request_to(&self.socket, request(next_request_id(), req)).await?;
        match resp.response {
            BifrostRpcResponse::Ok(data) => Ok(data),
            BifrostRpcResponse::Err { code, message } => {
                Err(anyhow!("rpc error ({code}): {message}"))
            }
        }
    }

    pub async fn negotiate(
        &self,
        client_name: String,
        client_version: u16,
    ) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Negotiate {
            client_name,
            client_version,
        })
        .await
    }

    pub async fn health(&self) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Health).await
    }

    pub async fn status(&self) -> Result<DaemonStatus> {
        let value = self.call(BifrostRpcRequest::Status).await?;
        serde_json::from_value(value).map_err(|e| anyhow!("decode daemon status: {e}"))
    }

    pub async fn status_value(&self) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Status).await
    }

    pub async fn events(&self, limit: usize) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Events { limit }).await
    }

    pub async fn ping(&self, peer: String) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Ping { peer }).await
    }

    pub async fn echo(&self, peer: String, message: String) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Echo { peer, message }).await
    }

    pub async fn onboard(&self, peer: String) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Onboard { peer }).await
    }

    pub async fn sign(&self, message32_hex: String) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Sign { message32_hex }).await
    }

    pub async fn ecdh(&self, pubkey33_hex: String) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Ecdh { pubkey33_hex }).await
    }

    pub async fn get_peer_policies(&self) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::GetPeerPolicies).await
    }

    pub async fn get_peer_policy(&self, peer: String) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::GetPeerPolicy { peer }).await
    }

    pub async fn set_peer_policy(
        &self,
        peer: String,
        policy: PeerPolicyView,
    ) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::SetPeerPolicy { peer, policy })
            .await
    }

    pub async fn refresh_peer_policy(&self, peer: String) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::RefreshPeerPolicy { peer })
            .await
    }

    pub async fn shutdown(&self) -> Result<serde_json::Value> {
        self.call(BifrostRpcRequest::Shutdown).await
    }
}
