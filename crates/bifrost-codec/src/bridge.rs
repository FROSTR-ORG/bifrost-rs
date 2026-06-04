use serde::{Deserialize, Serialize};

use crate::error::{CodecError, CodecResult};
use crate::wire::{
    EcdhPackageWire, OnboardRequestWire, OnboardResponseWire, PartialSigPackageWire, PeerErrorWire,
    PingPayloadWire, SignSessionPackageWire,
};

/// Hard ceiling on the raw JSON size of any bridge envelope we will
/// attempt to parse. Enforced by [`decode_bridge_envelope`] before any
/// `serde_json` work runs, so oversized inputs cannot force us to
/// allocate past the input buffer.
///
/// Chosen to generously fit any legitimate envelope (a batched sign
/// request with a full nonce bundle sits well under 20 KiB) while
/// cutting off authenticated-DoS attempts from any group peer.
pub const MAX_BRIDGE_ENVELOPE_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum BridgePayload {
    PingRequest(PingPayloadWire),
    PingResponse(PingPayloadWire),
    OnboardRequest(OnboardRequestWire),
    OnboardResponse(OnboardResponseWire),
    SignRequest(SignSessionPackageWire),
    SignResponse(PartialSigPackageWire),
    EcdhRequest(EcdhPackageWire),
    EcdhResponse(EcdhPackageWire),
    Error(PeerErrorWire),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeEnvelope {
    pub request_id: String,
    pub sent_at: u64,
    pub payload: BridgePayload,
}

pub fn encode_bridge_envelope(msg: &BridgeEnvelope) -> CodecResult<String> {
    Ok(serde_json::to_string(msg)?)
}

pub fn decode_bridge_envelope(raw: &str) -> CodecResult<BridgeEnvelope> {
    if raw.len() > MAX_BRIDGE_ENVELOPE_BYTES {
        return Err(CodecError::EnvelopeTooLarge);
    }
    let envelope: BridgeEnvelope = serde_json::from_str(raw)?;
    validate_bridge_envelope(&envelope)?;
    Ok(envelope)
}

/// Per-field string cap for identifier/label fields (`kind`,
/// `group_name`, `code`, `message`).
const MAX_IDENTIFIER_FIELD_BYTES: usize = 1024;

/// Per-field string cap for the hex `content` field carried in sign
/// sessions. 32 KiB covers any realistic event payload while staying
/// well under the envelope ceiling.
const MAX_CONTENT_FIELD_BYTES: usize = 32 * 1024;

fn check_identifier(field: &'static str, value: &str) -> CodecResult<()> {
    if value.len() > MAX_IDENTIFIER_FIELD_BYTES {
        return Err(CodecError::FieldTooLarge {
            field,
            limit: MAX_IDENTIFIER_FIELD_BYTES,
        });
    }
    Ok(())
}

fn check_content(field: &'static str, value: &str) -> CodecResult<()> {
    if value.len() > MAX_CONTENT_FIELD_BYTES {
        return Err(CodecError::FieldTooLarge {
            field,
            limit: MAX_CONTENT_FIELD_BYTES,
        });
    }
    Ok(())
}

fn validate_bridge_envelope(envelope: &BridgeEnvelope) -> CodecResult<()> {
    if envelope.request_id.is_empty() {
        return Err(CodecError::InvalidPayload("request_id must not be empty"));
    }
    if envelope.request_id.len() > 256 {
        return Err(CodecError::InvalidPayload("request_id exceeds max length"));
    }
    validate_payload_field_bounds(&envelope.payload)?;
    Ok(())
}

fn validate_payload_field_bounds(payload: &BridgePayload) -> CodecResult<()> {
    match payload {
        BridgePayload::Error(err) => {
            check_identifier("code", &err.code)?;
            check_identifier("message", &err.message)?;
        }
        BridgePayload::SignRequest(session) => {
            check_identifier("kind", &session.kind)?;
            if let Some(content) = session.content.as_ref() {
                check_content("content", content)?;
            }
        }
        BridgePayload::OnboardResponse(response) => {
            check_identifier("group_name", &response.group.group_name)?;
        }
        BridgePayload::PingRequest(_)
        | BridgePayload::PingResponse(_)
        | BridgePayload::OnboardRequest(_)
        | BridgePayload::SignResponse(_)
        | BridgePayload::EcdhRequest(_)
        | BridgePayload::EcdhResponse(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_envelope_roundtrip() {
        let envelope = BridgeEnvelope {
            request_id: "req-1".to_string(),
            sent_at: 1700000000,
            payload: BridgePayload::Error(PeerErrorWire {
                code: "ERR".to_string(),
                message: "boom".to_string(),
            }),
        };
        let encoded = encode_bridge_envelope(&envelope).expect("encode");
        let decoded = decode_bridge_envelope(&encoded).expect("decode");
        assert_eq!(decoded.request_id, "req-1");
        assert!(matches!(decoded.payload, BridgePayload::Error(_)));
    }

    #[test]
    fn bridge_envelope_rejects_empty_request_id() {
        let envelope = BridgeEnvelope {
            request_id: String::new(),
            sent_at: 1700000000,
            payload: BridgePayload::Error(PeerErrorWire {
                code: "ERR".to_string(),
                message: "boom".to_string(),
            }),
        };
        let err = decode_bridge_envelope(&encode_bridge_envelope(&envelope).expect("encode"))
            .expect_err("must reject empty request_id");
        assert!(matches!(
            err,
            CodecError::InvalidPayload("request_id must not be empty")
        ));
    }

    #[test]
    fn bridge_envelope_rejects_oversized_request_id() {
        let envelope = BridgeEnvelope {
            request_id: "r".repeat(257),
            sent_at: 1700000000,
            payload: BridgePayload::Error(PeerErrorWire {
                code: "ERR".to_string(),
                message: "boom".to_string(),
            }),
        };
        let err = decode_bridge_envelope(&encode_bridge_envelope(&envelope).expect("encode"))
            .expect_err("must reject oversized request_id");
        assert!(matches!(
            err,
            CodecError::InvalidPayload("request_id exceeds max length")
        ));
    }
}
