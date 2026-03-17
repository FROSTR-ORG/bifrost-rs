use bifrost_core::types::{GroupPackage, SharePackage};
use bifrost_signer::{CompletedOperation, DeviceConfig, DeviceState, SignerInput, SigningDevice};
use frostr_utils::{CreateKeysetConfig, create_keyset};

fn build_signer(group: &GroupPackage, share: &SharePackage) -> SigningDevice {
    let peers = group
        .members
        .iter()
        .filter(|member| member.idx != share.idx)
        .map(|member| hex::encode(&member.pubkey[1..]))
        .collect::<Vec<_>>();
    SigningDevice::new(
        group.clone(),
        share.clone(),
        peers,
        DeviceState::new(share.idx, share.seckey),
        DeviceConfig::default(),
    )
    .expect("build signer")
}

#[test]
fn onboarded_signer_can_respond_to_sign_request_after_nonce_advertisement() {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let inviter_share = bundle.shares[0].clone();
    let requester_share = bundle.shares[1].clone();
    let inviter_pubkey = hex::encode(
        &group
            .members
            .iter()
            .find(|member| member.idx == inviter_share.idx)
            .expect("inviter member")
            .pubkey[1..],
    );

    let mut inviter = build_signer(&group, &inviter_share);
    let mut requester = build_signer(&group, &requester_share);

    let onboard_request = requester
        .apply(SignerInput::BeginOnboard {
            peer: inviter_pubkey.clone(),
        })
        .expect("begin onboard")
        .outbound;
    assert_eq!(onboard_request.len(), 1);
    let onboard_response = inviter
        .process_event(&onboard_request[0])
        .expect("process onboard request");
    assert_eq!(onboard_response.len(), 1);

    let effects = requester
        .apply(SignerInput::ProcessEvent {
            event: onboard_response[0].clone(),
        })
        .expect("process onboard response");
    assert!(effects.completions.iter().any(|completion| {
        matches!(
            completion,
            CompletedOperation::Onboard { nonces, .. } if !nonces.is_empty()
        )
    }));

    let ping_request = requester
        .apply(SignerInput::BeginPing {
            peer: inviter_pubkey,
        })
        .expect("requester begins ping")
        .outbound;
    assert_eq!(ping_request.len(), 1);
    let ping_response = inviter
        .process_event(&ping_request[0])
        .expect("inviter processes ping");
    assert_eq!(ping_response.len(), 1);

    let sign_request = inviter
        .initiate_sign([0xAB; 32])
        .expect("inviter initiates sign after requester ping");
    assert_eq!(sign_request.len(), 1);
    let sign_response = requester
        .process_event(&sign_request[0])
        .expect("requester responds to sign");
    assert!(!sign_response.is_empty());
}

#[test]
fn onboarded_signer_can_initiate_sign_with_inviter_bootstrap_nonces() {
    let bundle = create_keyset(CreateKeysetConfig {
        threshold: 2,
        count: 3,
    })
    .expect("create keyset");
    let group = bundle.group.clone();
    let inviter_share = bundle.shares[0].clone();
    let requester_share = bundle.shares[1].clone();
    let inviter_pubkey = hex::encode(
        &group
            .members
            .iter()
            .find(|member| member.idx == inviter_share.idx)
            .expect("inviter member")
            .pubkey[1..],
    );

    let mut inviter = build_signer(&group, &inviter_share);
    let mut requester = build_signer(&group, &requester_share);

    let onboard_request = requester
        .apply(SignerInput::BeginOnboard {
            peer: inviter_pubkey.clone(),
        })
        .expect("begin onboard")
        .outbound;
    let onboard_response = inviter
        .process_event(&onboard_request[0])
        .expect("process onboard request");
    requester
        .apply(SignerInput::ProcessEvent {
            event: onboard_response[0].clone(),
        })
        .expect("process onboard response");

    let outbound = requester
        .initiate_sign([0xCD; 32])
        .expect("requester initiates sign after onboarding");
    assert_eq!(outbound.len(), 1);
    let request_id = requester.latest_request_id().expect("latest request id");
    assert!(
        requester
            .state()
            .pending_operations
            .contains_key(&request_id),
        "sign request should create a pending operation"
    );
}
