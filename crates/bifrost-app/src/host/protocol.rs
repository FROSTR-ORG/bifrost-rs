use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use bifrost_core::secret::DaemonToken;
use serde::{Deserialize, Serialize};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

/// In-memory control request handled by the daemon and client.
///
/// The token is held as a [`DaemonToken`] (zeroize-on-drop, constant-time
/// compare). The wire form uses a hex string — see [`ControlRequestWire`]
/// and the [`ControlRequest::encode_wire`] / [`ControlRequest::decode_wire`]
/// helpers for the boundary conversion. This mirrors the
/// `SharePackage` / `SharePackageWire` split from Bucket A.
#[derive(Debug)]
pub struct ControlRequest {
    pub request_id: String,
    pub token: DaemonToken,
    pub command: ControlCommand,
}

impl ControlRequest {
    /// Serialize this request to its on-wire JSON encoding.
    ///
    /// The token is encoded as a 64-character lowercase hex string. The
    /// returned `Vec<u8>` is owned plaintext containing the token — callers
    /// should write it to the control socket promptly and not retain copies.
    pub fn encode_wire(&self) -> Result<Vec<u8>> {
        let wire = ControlRequestWire {
            request_id: self.request_id.clone(),
            token: self.token.to_hex(),
            command: self.command.clone(),
        };
        serde_json::to_vec(&wire).context("serialize control request")
    }

    /// Decode a wire-form JSON request into the in-memory `ControlRequest`.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self> {
        let wire: ControlRequestWire =
            serde_json::from_slice(bytes).context("invalid control request json")?;
        let token = DaemonToken::from_hex(&wire.token).context("invalid control request token")?;
        Ok(Self {
            request_id: wire.request_id,
            token,
            command: wire.command,
        })
    }
}

/// Wire-only representation of a [`ControlRequest`] — `token` is the
/// canonical lowercase 64-character hex form of a [`DaemonToken`]. Only the
/// transport boundary should touch this type; in-process callers should use
/// [`ControlRequest`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlRequestWire {
    pub request_id: String,
    pub token: String,
    #[serde(flatten)]
    pub command: ControlCommand,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlCommand {
    Status,
    SetPolicyOverride {
        peer: String,
        policy_override_json: String,
    },
    ClearPeerPolicyOverrides,
    ResolveApproval {
        // The control request is `#[serde(flatten)]`ed onto a wrapper that
        // already has its own `request_id`; rename the wire key so the two don't
        // collide (the Rust field stays `request_id` for the bridge call).
        #[serde(rename = "approval_request_id")]
        request_id: String,
        approved: bool,
    },
    Ping {
        peer: String,
        timeout_secs: Option<u64>,
    },
    Onboard {
        peer: String,
        timeout_secs: Option<u64>,
    },
    Sign {
        message_hex32: String,
        timeout_secs: Option<u64>,
    },
    Ecdh {
        pubkey_hex32: String,
        timeout_secs: Option<u64>,
    },
    ReadConfig,
    UpdateConfig {
        config_patch_json: String,
    },
    PeerStatus,
    Readiness,
    RuntimeStatus,
    RuntimeMetadata,
    RuntimeDiagnostics,
    WipeState,
    Shutdown,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlResponse {
    pub request_id: String,
    pub ok: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

pub(crate) fn next_request_id() -> String {
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("req-{counter}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_with_byte(b: u8) -> DaemonToken {
        DaemonToken::from_hex(&hex::encode([b; 32])).expect("test token hex")
    }

    #[test]
    fn control_request_wire_round_trip_preserves_fields() {
        let request = ControlRequest {
            request_id: "req-roundtrip".to_string(),
            token: token_with_byte(0x42),
            command: ControlCommand::Status,
        };
        let bytes = request.encode_wire().expect("encode wire");
        let decoded = ControlRequest::decode_wire(&bytes).expect("decode wire");
        assert_eq!(decoded.request_id, "req-roundtrip");
        assert_eq!(decoded.token, token_with_byte(0x42));
        assert!(matches!(decoded.command, ControlCommand::Status));
    }

    #[test]
    fn resolve_approval_wire_round_trip_keeps_both_request_ids() {
        // ResolveApproval carries its own request_id; the wrapper flattens the
        // command, so the wire key is renamed (approval_request_id) to avoid
        // colliding with the wrapper's request_id. Guard that collision.
        let request = ControlRequest {
            request_id: "wrapper-id".to_string(),
            token: token_with_byte(0x11),
            command: ControlCommand::ResolveApproval {
                request_id: "parked-id".to_string(),
                approved: true,
            },
        };
        let bytes = request.encode_wire().expect("encode wire");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");
        assert_eq!(value["request_id"], "wrapper-id");
        assert_eq!(value["approval_request_id"], "parked-id");

        let decoded = ControlRequest::decode_wire(&bytes).expect("decode wire");
        assert_eq!(decoded.request_id, "wrapper-id");
        match decoded.command {
            ControlCommand::ResolveApproval {
                request_id,
                approved,
            } => {
                assert_eq!(request_id, "parked-id");
                assert!(approved);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn control_request_wire_token_is_hex_encoded() {
        let request = ControlRequest {
            request_id: "req".to_string(),
            token: token_with_byte(0xCD),
            command: ControlCommand::Status,
        };
        let bytes = request.encode_wire().expect("encode wire");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");
        let token = value["token"].as_str().expect("token string");
        assert_eq!(token, "cd".repeat(32));
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn control_request_wire_rejects_non_hex_token() {
        // Construct an invalid wire form by hand and confirm decode rejects it.
        let bad = br#"{"request_id":"req-bad","token":"not-hex-not-hex","command":"status"}"#;
        let err = ControlRequest::decode_wire(bad).expect_err("non-hex token must fail");
        assert!(err.to_string().contains("invalid control request token"));
    }
}
