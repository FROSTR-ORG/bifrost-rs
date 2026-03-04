use serde::{Deserialize, Serialize};

use crate::error::{CodecError, CodecResult};
use crate::wire::{
    EcdhPackageWire, OnboardRequestWire, OnboardResponseWire, PartialSigPackageWire, PeerErrorWire,
    PingPayloadWire, SignSessionPackageWire,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum BridgePayloadV1 {
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
pub struct BridgeEnvelopeV1 {
    pub version: u16,
    pub request_id: String,
    pub sent_at: u64,
    pub payload: BridgePayloadV1,
}

pub fn encode_bridge_envelope(msg: &BridgeEnvelopeV1) -> CodecResult<String> {
    Ok(serde_json::to_string(msg)?)
}

pub fn decode_bridge_envelope(raw: &str) -> CodecResult<BridgeEnvelopeV1> {
    let envelope: BridgeEnvelopeV1 = serde_json::from_str(raw)?;
    validate_bridge_envelope(&envelope)?;
    Ok(envelope)
}

fn validate_bridge_envelope(envelope: &BridgeEnvelopeV1) -> CodecResult<()> {
    if envelope.version != 1 {
        return Err(CodecError::InvalidPayload(
            "unsupported bridge envelope version",
        ));
    }
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
        let envelope = BridgeEnvelopeV1 {
            version: 1,
            request_id: "req-1".to_string(),
            sent_at: 1700000000,
            payload: BridgePayloadV1::Error(PeerErrorWire {
                code: "ERR".to_string(),
                message: "boom".to_string(),
            }),
        };
        let encoded = encode_bridge_envelope(&envelope).expect("encode");
        let decoded = decode_bridge_envelope(&encoded).expect("decode");
        assert_eq!(decoded.request_id, "req-1");
        assert!(matches!(decoded.payload, BridgePayloadV1::Error(_)));
    }

    #[test]
    fn bridge_envelope_rejects_invalid_version() {
        let envelope = BridgeEnvelopeV1 {
            version: 2,
            request_id: "req-1".to_string(),
            sent_at: 1700000000,
            payload: BridgePayloadV1::Error(PeerErrorWire {
                code: "ERR".to_string(),
                message: "boom".to_string(),
            }),
        };
        let err = decode_bridge_envelope(&encode_bridge_envelope(&envelope).expect("encode"))
            .expect_err("must reject unsupported version");
        assert!(matches!(err, CodecError::InvalidPayload(_)));
    }
}
