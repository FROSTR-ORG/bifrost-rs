use serde::{Deserialize, Serialize};

use crate::error::{CodecError, CodecResult};
use crate::wire::{
    EcdhPackageWire, OnboardRequestWire, OnboardResponseWire, PartialSigPackageWire, PeerErrorWire,
    PingPayloadWire, SignSessionPackageWire,
};

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
    let envelope: BridgeEnvelope = serde_json::from_str(raw)?;
    validate_bridge_envelope(&envelope)?;
    Ok(envelope)
}

fn validate_bridge_envelope(envelope: &BridgeEnvelope) -> CodecResult<()> {
    if envelope.request_id.is_empty() {
        return Err(CodecError::InvalidPayload("request_id must not be empty"));
    }
    if envelope.request_id.len() > 256 {
        return Err(CodecError::InvalidPayload("request_id exceeds max length"));
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
}
