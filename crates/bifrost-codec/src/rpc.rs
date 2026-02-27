use serde::{Deserialize, Serialize};

use crate::error::CodecResult;
use crate::wire::{
    EcdhPackageWire, OnboardRequestWire, OnboardResponseWire, PartialSigPackageWire,
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
    Ok(serde_json::from_str(msg)?)
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
}
