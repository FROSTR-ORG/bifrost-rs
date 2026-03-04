use bifrost_core::types::{GroupPackage, SharePackage};

use crate::error::CodecResult;
use crate::wire::{GroupPackageWire, SharePackageWire};

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
}
