use crate::{PolicyOverrideEntry, PolicyOverridesDocument, ProfilePreview};
use anyhow::{Context, Result, anyhow, bail};
use bifrost_codec::wire::GroupPackageWire;
use bifrost_core::types::{
    GroupPackage, PeerPolicy, PeerPolicyOverride, PolicyOverrideValue, SharePackage,
};
use frostr_utils::{
    BfManualPeerPolicyOverride, BfProfileDevice, BfProfilePayload, core_peer_policy_override_to_bf,
    derive_profile_id_from_share_secret,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;

pub fn group_from_payload(payload: &BfProfilePayload) -> Result<GroupPackage> {
    payload
        .group_package
        .clone()
        .try_into()
        .map_err(|error: bifrost_codec::CodecError| anyhow!("invalid group package: {error}"))
}

pub fn share_from_payload(
    group: &GroupPackage,
    payload: &BfProfilePayload,
) -> Result<SharePackage> {
    let share_secret = hex::decode(&payload.device.share_secret)?;
    let seckey: [u8; 32] = share_secret
        .try_into()
        .map_err(|_| anyhow!("invalid share secret"))?;
    let share_public_key = hex::encode(
        k256::SecretKey::from_slice(&seckey)
            .map_err(|error| anyhow!("invalid share secret: {error}"))?
            .public_key()
            .to_sec1_bytes(),
    );
    let xonly = share_public_key
        .strip_prefix("02")
        .or_else(|| share_public_key.strip_prefix("03"))
        .unwrap_or(&share_public_key)
        .to_string();
    let member = group
        .members
        .iter()
        .find(|member| hex::encode(&member.pubkey[1..]) == xonly)
        .ok_or_else(|| anyhow!("share secret does not match any member in the recovered group"))?;
    Ok(SharePackage {
        idx: member.idx,
        seckey,
    })
}

pub fn rotation_payload_from_share(
    group: &GroupPackage,
    share: &SharePackage,
    label: String,
    relays: Vec<String>,
) -> Result<BfProfilePayload> {
    let share_secret = hex::encode(share.seckey);
    let local_pubkey = derive_member_pubkey_hex(share.seckey)?;
    Ok(BfProfilePayload {
        profile_id: derive_profile_id_for_share_secret(&share_secret)?,
        version: 1,
        device: BfProfileDevice {
            name: label,
            share_secret,
            manual_peer_policy_overrides: group
                .members
                .iter()
                .map(|member| hex::encode(&member.pubkey[1..]))
                .filter(|pubkey| pubkey != &local_pubkey)
                .map(|pubkey| BfManualPeerPolicyOverride {
                    pubkey,
                    policy: core_peer_policy_override_to_bf(&PeerPolicyOverride::from_peer_policy(
                        &PeerPolicy::default(),
                    )),
                })
                .collect(),
            relays,
        },
        group_package: GroupPackageWire::from(group.clone()),
    })
}

pub fn preview_from_profile_payload(
    payload: &BfProfilePayload,
    label: Option<String>,
    source: &'static str,
) -> Result<ProfilePreview> {
    let share_public_key = derive_member_pubkey_hex(hex_to_bytes32(&payload.device.share_secret)?)?;
    Ok(ProfilePreview {
        profile_id: payload.profile_id.clone(),
        label: label.unwrap_or_else(|| payload.device.name.clone()),
        share_public_key,
        group_public_key: payload.group_package.group_pk.clone(),
        threshold: payload.group_package.threshold as usize,
        total_count: payload.group_package.members.len(),
        relays: payload.device.relays.clone(),
        peer_pubkey: None,
        source,
    })
}

pub fn build_policy_overrides_value(
    policies: &[BfManualPeerPolicyOverride],
) -> Result<serde_json::Value> {
    serde_json::to_value(PolicyOverridesDocument {
        default_override: None,
        peer_overrides: policies
            .iter()
            .map(|policy| PolicyOverrideEntry {
                pubkey: policy.pubkey.clone(),
                policy_override: PeerPolicyOverride {
                    request: bifrost_core::types::MethodPolicyOverride {
                        echo: map_policy_value(policy.policy.request.echo),
                        ping: map_policy_value(policy.policy.request.ping),
                        onboard: map_policy_value(policy.policy.request.onboard),
                        sign: map_policy_value(policy.policy.request.sign),
                        ecdh: map_policy_value(policy.policy.request.ecdh),
                    },
                    respond: bifrost_core::types::MethodPolicyOverride {
                        echo: map_policy_value(policy.policy.respond.echo),
                        ping: map_policy_value(policy.policy.respond.ping),
                        onboard: map_policy_value(policy.policy.respond.onboard),
                        sign: map_policy_value(policy.policy.respond.sign),
                        ecdh: map_policy_value(policy.policy.respond.ecdh),
                    },
                },
            })
            .collect(),
    })
    .context("serialize policy overrides")
}

pub fn derive_member_pubkey_hex(seckey: [u8; 32]) -> Result<String> {
    let secret = k256::SecretKey::from_slice(&seckey).context("invalid share seckey")?;
    let point = secret.public_key().to_encoded_point(true);
    Ok(hex::encode(&point.as_bytes()[1..]))
}

pub fn derive_profile_id_for_share_secret(share_secret_hex: &str) -> Result<String> {
    derive_profile_id_from_share_secret(share_secret_hex).context("derive profile id")
}

pub fn hex_to_bytes32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("decode hex32 {value}"))?;
    if bytes.len() != 32 {
        bail!("expected 32-byte hex value");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn find_member_index_for_share_secret(group: &GroupPackage, share_secret: &str) -> Result<u16> {
    let local_pubkey = derive_member_pubkey_hex(hex_to_bytes32(share_secret)?)?;
    group
        .members
        .iter()
        .find(|member| hex::encode(&member.pubkey[1..]) == local_pubkey)
        .map(|member| member.idx)
        .ok_or_else(|| anyhow!("share secret does not match any group member"))
}

fn map_policy_value(value: frostr_utils::BfPolicyOverrideValue) -> PolicyOverrideValue {
    match value {
        frostr_utils::BfPolicyOverrideValue::Unset => PolicyOverrideValue::Unset,
        frostr_utils::BfPolicyOverrideValue::Allow => PolicyOverrideValue::Allow,
        frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frostr_utils::{CreateKeysetConfig, create_keyset};

    fn sample_payload() -> BfProfilePayload {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Managed Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[1].clone();
        BfProfilePayload {
            profile_id: derive_profile_id_for_share_secret(&hex::encode(share.seckey))
                .expect("derive profile id"),
            version: 1,
            device: BfProfileDevice {
                name: "Managed Device".to_string(),
                share_secret: hex::encode(share.seckey),
                manual_peer_policy_overrides: Vec::new(),
                relays: vec!["wss://relay.example.test".to_string()],
            },
            group_package: GroupPackageWire::from(bundle.group),
        }
    }

    #[test]
    fn preview_from_profile_payload_derives_share_key() {
        let payload = sample_payload();
        let preview = preview_from_profile_payload(&payload, None, "bfprofile").expect("preview");
        assert_eq!(preview.profile_id, payload.profile_id);
        assert_eq!(preview.label, "Managed Device");
        assert_eq!(preview.source, "bfprofile");
        assert_eq!(preview.relays, vec!["wss://relay.example.test"]);
    }

    #[test]
    fn group_and_share_round_trip_from_profile_payload() {
        let payload = sample_payload();
        let group = group_from_payload(&payload).expect("group");
        let share = share_from_payload(&group, &payload).expect("share");
        assert_eq!(
            find_member_index_for_share_secret(&group, &payload.device.share_secret)
                .expect("member index"),
            share.idx
        );
    }
}
