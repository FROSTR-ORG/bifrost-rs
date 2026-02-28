use serde::{Deserialize, Serialize};

use crate::error::{CodecError, CodecResult};
use crate::wire::{
    EcdhPackageWire, OnboardRequestWire, OnboardResponseWire, PartialSigPackageWire, PeerErrorWire,
    PingPayloadWire, SignSessionPackageWire,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcMethod {
    Ping,
    Echo,
    Sign,
    Ecdh,
    Onboard,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "data")]
pub enum RpcPayload {
    Ping(PingPayloadWire),
    Echo(String),
    Sign(SignSessionPackageWire),
    SignResponse(PartialSigPackageWire),
    Ecdh(EcdhPackageWire),
    OnboardRequest(OnboardRequestWire),
    OnboardResponse(OnboardResponseWire),
    Error(PeerErrorWire),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcEnvelope {
    pub version: u16,
    pub id: String,
    pub sender: String,
    pub payload: RpcPayload,
}

pub fn encode_envelope(msg: &RpcEnvelope) -> CodecResult<String> {
    Ok(serde_json::to_string(msg)?)
}

pub fn decode_envelope(msg: &str) -> CodecResult<RpcEnvelope> {
    let envelope: RpcEnvelope = serde_json::from_str(msg)?;
    validate_envelope(&envelope)?;
    Ok(envelope)
}

fn validate_envelope(envelope: &RpcEnvelope) -> CodecResult<()> {
    if envelope.id.is_empty() {
        return Err(CodecError::InvalidPayload("envelope id must not be empty"));
    }
    if envelope.sender.is_empty() {
        return Err(CodecError::InvalidPayload(
            "envelope sender must not be empty",
        ));
    }
    if envelope.id.len() > 256 {
        return Err(CodecError::InvalidPayload("envelope id exceeds max length"));
    }
    if envelope.sender.len() > 256 {
        return Err(CodecError::InvalidPayload(
            "envelope sender exceeds max length",
        ));
    }
    match &envelope.payload {
        RpcPayload::Echo(value) if value.len() > 8192 => {
            return Err(CodecError::InvalidPayload(
                "echo payload exceeds max length",
            ));
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let env = RpcEnvelope {
            version: 1,
            id: "abc".to_string(),
            sender: "peer1".to_string(),
            payload: RpcPayload::Echo("hello".to_string()),
        };

        let encoded = encode_envelope(&env).expect("encode");
        let decoded = decode_envelope(&encoded).expect("decode");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.id, "abc");
        assert_eq!(decoded.sender, "peer1");
        assert!(matches!(decoded.payload, RpcPayload::Echo(_)));
    }

    #[test]
    fn decode_envelope_rejects_empty_id() {
        let raw = encode_envelope(&RpcEnvelope {
            version: 1,
            id: String::new(),
            sender: "peer1".to_string(),
            payload: RpcPayload::Echo("ok".to_string()),
        })
        .expect("encode");
        let err = decode_envelope(&raw).expect_err("must reject empty id");
        assert!(matches!(err, CodecError::InvalidPayload(_)));
    }

    #[test]
    fn decode_envelope_rejects_oversized_echo() {
        let raw = encode_envelope(&RpcEnvelope {
            version: 1,
            id: "abc".to_string(),
            sender: "peer1".to_string(),
            payload: RpcPayload::Echo("x".repeat(8200)),
        })
        .expect("encode");
        let err = decode_envelope(&raw).expect_err("must reject oversized echo");
        assert!(matches!(err, CodecError::InvalidPayload(_)));
    }
}
