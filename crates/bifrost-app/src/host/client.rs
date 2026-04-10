use anyhow::{Context, Result, anyhow};
use bifrost_core::types::PeerPolicyOverride;
use bifrost_signer::{
    DeviceConfig, DeviceStatus, PeerStatus, RuntimeMetadata, RuntimeReadiness, RuntimeStatusSummary,
};
use serde::de::DeserializeOwned;
use serde_json::json;

use super::protocol::{ControlCommand, ControlRequest, ControlResponse, next_request_id};
use super::types::{
    DaemonTransportConfig, EcdhPayload, OnboardPayload, PingPayload, RuntimeDiagnosticsSnapshot,
    ShutdownPayload, SignPayload, UpdatedPayload, WipedPayload,
};

#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct DaemonClient {
    socket_path: std::path::PathBuf,
    token: String,
}

#[cfg(unix)]
impl DaemonClient {
    pub fn new(socket_path: std::path::PathBuf, token: String) -> Self {
        Self { socket_path, token }
    }

    pub async fn request(&self, command: ControlCommand) -> Result<ControlResponse> {
        let request = ControlRequest {
            request_id: next_request_id(),
            token: self.token.clone(),
            command,
        };

        let mut stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| format!("connect {}", self.socket_path.display()))?;
        stream
            .write_all(serde_json::to_vec(&request)?.as_slice())
            .await?;
        stream.shutdown().await?;

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await?;
        let response: ControlResponse =
            serde_json::from_slice(&response_bytes).context("invalid control response json")?;
        Ok(response)
    }

    pub async fn request_ok(&self, command: ControlCommand) -> Result<serde_json::Value> {
        let response = self.request(command).await?;
        if response.ok {
            Ok(response.result.unwrap_or_else(|| json!({})))
        } else {
            Err(anyhow!(
                response
                    .error
                    .unwrap_or_else(|| "daemon request failed".to_string())
            ))
        }
    }

    pub async fn request_ok_typed<T: DeserializeOwned>(
        &self,
        command: ControlCommand,
    ) -> Result<T> {
        let value = self.request_ok(command).await?;
        serde_json::from_value(value).context("invalid typed daemon result")
    }

    pub async fn runtime_status(&self) -> Result<RuntimeStatusSummary> {
        self.request_ok_typed(ControlCommand::RuntimeStatus).await
    }

    pub async fn runtime_diagnostics(&self) -> Result<RuntimeDiagnosticsSnapshot> {
        self.request_ok_typed(ControlCommand::RuntimeDiagnostics)
            .await
    }

    pub async fn runtime_metadata(&self) -> Result<RuntimeMetadata> {
        self.request_ok_typed(ControlCommand::RuntimeMetadata).await
    }

    pub async fn readiness(&self) -> Result<RuntimeReadiness> {
        self.request_ok_typed(ControlCommand::Readiness).await
    }

    pub async fn peer_status(&self) -> Result<Vec<PeerStatus>> {
        self.request_ok_typed(ControlCommand::PeerStatus).await
    }

    pub async fn read_config(&self) -> Result<DeviceConfig> {
        self.request_ok_typed(ControlCommand::ReadConfig).await
    }

    pub async fn status(&self) -> Result<DeviceStatus> {
        self.request_ok_typed(ControlCommand::Status).await
    }

    pub async fn sign(
        &self,
        message_hex32: String,
        timeout_secs: Option<u64>,
    ) -> Result<SignPayload> {
        self.request_ok_typed(ControlCommand::Sign {
            message_hex32,
            timeout_secs,
        })
        .await
    }

    pub async fn ecdh(
        &self,
        pubkey_hex32: String,
        timeout_secs: Option<u64>,
    ) -> Result<EcdhPayload> {
        self.request_ok_typed(ControlCommand::Ecdh {
            pubkey_hex32,
            timeout_secs,
        })
        .await
    }

    pub async fn ping(&self, peer: String, timeout_secs: Option<u64>) -> Result<PingPayload> {
        self.request_ok_typed(ControlCommand::Ping { peer, timeout_secs })
            .await
    }

    pub async fn onboard(&self, peer: String, timeout_secs: Option<u64>) -> Result<OnboardPayload> {
        self.request_ok_typed(ControlCommand::Onboard { peer, timeout_secs })
            .await
    }

    pub async fn set_policy_override(
        &self,
        peer: String,
        policy_override: &PeerPolicyOverride,
    ) -> Result<UpdatedPayload> {
        self.request_ok_typed(ControlCommand::SetPolicyOverride {
            peer,
            policy_override_json: serde_json::to_string(policy_override)
                .context("serialize policy override")?,
        })
        .await
    }

    pub async fn clear_peer_policy_overrides(&self) -> Result<UpdatedPayload> {
        self.request_ok_typed(ControlCommand::ClearPeerPolicyOverrides)
            .await
    }

    pub async fn update_config(&self, config_patch_json: String) -> Result<UpdatedPayload> {
        self.request_ok_typed(ControlCommand::UpdateConfig { config_patch_json })
            .await
    }

    pub async fn wipe_state(&self) -> Result<WipedPayload> {
        self.request_ok_typed(ControlCommand::WipeState).await
    }

    pub async fn shutdown(&self) -> Result<ShutdownPayload> {
        self.request_ok_typed(ControlCommand::Shutdown).await
    }
}

#[allow(dead_code)]
fn _assert_transport_type(_transport: &DaemonTransportConfig) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::path::PathBuf;

    #[cfg(unix)]
    use tokio::net::UnixListener;

    #[cfg(unix)]
    fn test_socket_path(name: &str) -> PathBuf {
        let unique = format!(
            "bifrost-app-client-{}-{}-{}.sock",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should advance")
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    #[cfg(unix)]
    async fn with_fake_daemon<F, Fut>(name: &str, handle: F) -> Result<DaemonClient>
    where
        F: FnOnce(ControlRequest) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ControlResponse> + Send + 'static,
    {
        let socket_path = test_socket_path(name);
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept should succeed");
            let mut request_bytes = Vec::new();
            stream
                .read_to_end(&mut request_bytes)
                .await
                .expect("read should succeed");
            let request: ControlRequest =
                serde_json::from_slice(&request_bytes).expect("request should parse");
            let response = handle(request).await;
            stream
                .write_all(&serde_json::to_vec(&response).expect("response should serialize"))
                .await
                .expect("write should succeed");
        });
        Ok(DaemonClient::new(socket_path, "test-token".to_string()))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn status_uses_status_command_and_decodes_payload() -> Result<()> {
        let client = with_fake_daemon("status", |request| async move {
            assert_eq!(request.token, "test-token");
            assert!(matches!(request.command, ControlCommand::Status));
            ControlResponse {
                request_id: request.request_id,
                ok: true,
                result: Some(json!({
                    "device_id": "device-1",
                    "pending_ops": 2,
                    "last_active": 1700000000u64,
                    "known_peers": 3,
                    "request_seq": 11
                })),
                error: None,
            }
        })
        .await?;

        let result = client.status().await?;
        assert_eq!(result.device_id, "device-1");
        assert_eq!(result.pending_ops, 2);
        assert_eq!(result.request_seq, 11);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn update_config_uses_update_config_command() -> Result<()> {
        let client = with_fake_daemon("update-config", |request| async move {
            match request.command {
                ControlCommand::UpdateConfig { config_patch_json } => {
                    assert_eq!(config_patch_json, r#"{"auto_start":true}"#);
                }
                other => panic!("unexpected command: {other:?}"),
            }
            ControlResponse {
                request_id: request.request_id,
                ok: true,
                result: Some(json!({ "updated": true })),
                error: None,
            }
        })
        .await?;

        let result = client
            .update_config(r#"{"auto_start":true}"#.to_string())
            .await?;
        assert!(result.updated);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn clear_peer_policy_overrides_uses_clear_command() -> Result<()> {
        let client = with_fake_daemon("clear-policy", |request| async move {
            assert!(matches!(
                request.command,
                ControlCommand::ClearPeerPolicyOverrides
            ));
            ControlResponse {
                request_id: request.request_id,
                ok: true,
                result: Some(json!({ "updated": true })),
                error: None,
            }
        })
        .await?;

        let result = client.clear_peer_policy_overrides().await?;
        assert!(result.updated);
        Ok(())
    }
}
