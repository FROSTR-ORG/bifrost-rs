use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::types::{Bytes32, GroupPackage};

pub fn get_group_id(group: &GroupPackage) -> CoreResult<Bytes32> {
    if group.threshold == 0 {
        return Err(CoreError::InvalidThreshold);
    }
    if group.members.is_empty() {
        return Err(CoreError::EmptyMembers);
    }

    let mut hasher = Sha256::new();
    hasher.update(group.group_pk);
    hasher.update((group.threshold as u32).to_le_bytes());

    let mut members = group.members.clone();
    members.sort_by_key(|m| m.idx);
    for member in members {
        hasher.update(member.pubkey);
    }

    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GroupPackage, MemberPackage};

    #[test]
    fn group_id_is_deterministic() {
        let group = GroupPackage {
            group_pk: [2; 33],
            threshold: 2,
            members: vec![
                MemberPackage {
                    idx: 2,
                    pubkey: [3; 33],
                },
                MemberPackage {
                    idx: 1,
                    pubkey: [4; 33],
                },
            ],
        };

        let a = get_group_id(&group).expect("group id");
        let b = get_group_id(&group).expect("group id");
        assert_eq!(a, b);
    }
}
