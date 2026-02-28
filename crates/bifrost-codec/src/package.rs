use bifrost_core::types::{GroupPackage, SharePackage};

use crate::error::CodecResult;
use crate::wire::{GroupPackageWire, SharePackageWire};

pub fn encode_group_package_json(group: &GroupPackage) -> CodecResult<String> {
    serde_json::to_string_pretty(&GroupPackageWire::from(group.clone())).map_err(Into::into)
}

pub fn decode_group_package_json(raw: &str) -> CodecResult<GroupPackage> {
    let wire: GroupPackageWire = serde_json::from_str(raw)?;
    wire.try_into()
}

pub fn encode_share_package_json(share: &SharePackage) -> CodecResult<String> {
    serde_json::to_string_pretty(&SharePackageWire::from(share.clone())).map_err(Into::into)
}

pub fn decode_share_package_json(raw: &str) -> CodecResult<SharePackage> {
    let wire: SharePackageWire = serde_json::from_str(raw)?;
    wire.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_package_roundtrip_json() {
        let group = GroupPackage {
            group_pk: [9u8; 33],
            threshold: 2,
            members: vec![
                bifrost_core::types::MemberPackage {
                    idx: 1,
                    pubkey: [2u8; 33],
                },
                bifrost_core::types::MemberPackage {
                    idx: 2,
                    pubkey: [3u8; 33],
                },
            ],
        };
        let raw = encode_group_package_json(&group).expect("encode");
        let decoded = decode_group_package_json(&raw).expect("decode");
        assert_eq!(decoded.threshold, 2);
        assert_eq!(decoded.members.len(), 2);
    }
}
