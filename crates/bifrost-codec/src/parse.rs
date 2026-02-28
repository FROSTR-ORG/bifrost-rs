use bifrost_core::types::{
    EcdhPackage, GroupPackage, OnboardRequest, OnboardResponse, PartialSigPackage, PeerError,
    PingPayload, SharePackage, SignSessionPackage,
};

use crate::error::{CodecError, CodecResult};
use crate::rpc::{RpcEnvelope, RpcPayload};
use crate::wire::{GroupPackageWire, SharePackageWire};

pub fn parse_ping(envelope: &RpcEnvelope) -> CodecResult<PingPayload> {
    let RpcPayload::Ping(wire) = &envelope.payload else {
        return Err(CodecError::InvalidPayload("expected ping payload"));
    };
    wire.clone().try_into()
}

pub fn parse_session(envelope: &RpcEnvelope) -> CodecResult<SignSessionPackage> {
    let RpcPayload::Sign(wire) = &envelope.payload else {
        return Err(CodecError::InvalidPayload("expected sign payload"));
    };
    wire.clone().try_into()
}

pub fn parse_psig(envelope: &RpcEnvelope) -> CodecResult<PartialSigPackage> {
    let RpcPayload::SignResponse(wire) = &envelope.payload else {
        return Err(CodecError::InvalidPayload("expected sign response payload"));
    };
    wire.clone().try_into()
}

pub fn parse_ecdh(envelope: &RpcEnvelope) -> CodecResult<EcdhPackage> {
    let RpcPayload::Ecdh(wire) = &envelope.payload else {
        return Err(CodecError::InvalidPayload("expected ecdh payload"));
    };
    wire.clone().try_into()
}

pub fn parse_onboard_request(envelope: &RpcEnvelope) -> CodecResult<OnboardRequest> {
    let RpcPayload::OnboardRequest(wire) = &envelope.payload else {
        return Err(CodecError::InvalidPayload(
            "expected onboard request payload",
        ));
    };
    wire.clone().try_into()
}

pub fn parse_onboard_response(envelope: &RpcEnvelope) -> CodecResult<OnboardResponse> {
    let RpcPayload::OnboardResponse(wire) = &envelope.payload else {
        return Err(CodecError::InvalidPayload(
            "expected onboard response payload",
        ));
    };
    wire.clone().try_into()
}

pub fn parse_error(envelope: &RpcEnvelope) -> CodecResult<PeerError> {
    let RpcPayload::Error(wire) = &envelope.payload else {
        return Err(CodecError::InvalidPayload("expected error payload"));
    };
    Ok(wire.clone().into())
}

pub fn parse_group_package(raw: &str) -> CodecResult<GroupPackage> {
    let wire: GroupPackageWire = serde_json::from_str(raw)?;
    wire.try_into()
}

pub fn parse_share_package(raw: &str) -> CodecResult<SharePackage> {
    let wire: SharePackageWire = serde_json::from_str(raw)?;
    wire.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        EcdhEntryWire, EcdhPackageWire, OnboardRequestWire, OnboardResponseWire,
        PartialSigEntryWire, PartialSigPackageWire, PingPayloadWire,
    };

    fn base_envelope(payload: RpcPayload) -> RpcEnvelope {
        RpcEnvelope {
            version: 1,
            id: "id-1".to_string(),
            sender: "peer-1".to_string(),
            payload,
        }
    }

    #[test]
    fn parse_session_rejects_wrong_payload_kind() {
        let envelope = base_envelope(RpcPayload::Echo("hello".to_string()));
        let err = parse_session(&envelope).expect_err("must reject wrong payload kind");
        assert!(matches!(err, CodecError::InvalidPayload(_)));
    }

    #[test]
    fn parse_ecdh_and_psig_roundtrip() {
        let ecdh_envelope = base_envelope(RpcPayload::Ecdh(EcdhPackageWire {
            idx: 1,
            members: vec![1, 2],
            entries: vec![EcdhEntryWire {
                ecdh_pk: hex::encode([1u8; 33]),
                keyshare: hex::encode([2u8; 33]),
            }],
        }));
        let ecdh = parse_ecdh(&ecdh_envelope).expect("ecdh parse");
        assert_eq!(ecdh.members, vec![1, 2]);
        assert_eq!(ecdh.entries.len(), 1);

        let psig_envelope = base_envelope(RpcPayload::SignResponse(PartialSigPackageWire {
            idx: 1,
            sid: hex::encode([3u8; 32]),
            pubkey: hex::encode([4u8; 33]),
            psigs: vec![PartialSigEntryWire {
                hash_index: 0,
                sighash: hex::encode([5u8; 32]),
                partial_sig: hex::encode([6u8; 32]),
            }],
            nonce_code: None,
            replenish: None,
        }));
        let psig = parse_psig(&psig_envelope).expect("psig parse");
        assert_eq!(psig.idx, 1);
        assert_eq!(psig.psigs.len(), 1);
    }

    #[test]
    fn parse_group_and_share_package_json() {
        let group_json = r#"{
            "group_pk":"020202020202020202020202020202020202020202020202020202020202020202",
            "threshold":2,
            "members":[
                {"idx":1,"pubkey":"030303030303030303030303030303030303030303030303030303030303030303"},
                {"idx":2,"pubkey":"040404040404040404040404040404040404040404040404040404040404040404"}
            ]
        }"#;
        let group = parse_group_package(group_json).expect("group parse");
        assert_eq!(group.threshold, 2);
        assert_eq!(group.members.len(), 2);

        let share_json = r#"{
            "idx":1,
            "seckey":"0101010101010101010101010101010101010101010101010101010101010101"
        }"#;
        let share = parse_share_package(share_json).expect("share parse");
        assert_eq!(share.idx, 1);
        assert_eq!(share.seckey, [1u8; 32]);
    }

    #[test]
    fn parse_ping_and_onboard_payloads() {
        let ping_envelope = base_envelope(RpcPayload::Ping(PingPayloadWire {
            version: 1,
            nonces: None,
            policy_profile: None,
        }));
        let ping = parse_ping(&ping_envelope).expect("ping parse");
        assert_eq!(ping.version, 1);
        assert!(ping.nonces.is_none());

        let onboard_req_envelope = base_envelope(RpcPayload::OnboardRequest(OnboardRequestWire {
            idx: 2,
            share_pk: hex::encode([8u8; 33]),
        }));
        let onboard_req = parse_onboard_request(&onboard_req_envelope).expect("onboard req parse");
        assert_eq!(onboard_req.idx, 2);

        let onboard_res_envelope =
            base_envelope(RpcPayload::OnboardResponse(OnboardResponseWire {
                group: crate::wire::GroupPackageWire {
                    group_pk: hex::encode([9u8; 33]),
                    threshold: 2,
                    members: vec![crate::wire::MemberPackageWire {
                        idx: 2,
                        pubkey: hex::encode([8u8; 33]),
                    }],
                },
                nonces: vec![],
            }));
        let onboard_res = parse_onboard_response(&onboard_res_envelope).expect("onboard res parse");
        assert_eq!(onboard_res.group.threshold, 2);
        let err = parse_onboard_response(&base_envelope(RpcPayload::Echo("x".to_string())))
            .expect_err("must reject wrong payload kind");
        assert!(matches!(err, CodecError::InvalidPayload(_)));
    }
}
