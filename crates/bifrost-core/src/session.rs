use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::error::{CoreError, CoreResult};
use crate::group::get_group_id;
use crate::types::{Bytes32, GroupPackage, SignSessionPackage, SignSessionTemplate};

pub fn create_session_package(
    group: &GroupPackage,
    template: SignSessionTemplate,
) -> CoreResult<SignSessionPackage> {
    let members = canonicalize_and_validate_members(group, &template.members)?;
    if template.hashes.is_empty() {
        return Err(CoreError::EmptySessionHashes);
    }

    let gid = get_group_id(group)?;
    let sid = get_session_id(
        gid,
        &SignSessionTemplate {
            members: members.clone(),
            hashes: template.hashes.clone(),
            content: template.content.clone(),
            kind: template.kind.clone(),
            stamp: template.stamp,
        },
    )?;

    Ok(SignSessionPackage {
        gid,
        sid,
        members,
        hashes: template.hashes,
        content: template.content,
        kind: template.kind,
        stamp: template.stamp,
        nonces: None,
    })
}

pub fn verify_session_package(
    group: &GroupPackage,
    session: &SignSessionPackage,
) -> CoreResult<()> {
    let gid = get_group_id(group)?;
    if gid != session.gid {
        return Err(CoreError::SessionGroupIdMismatch);
    }

    let members = canonicalize_and_validate_members(group, &session.members)?;
    if session.members != members {
        return Err(CoreError::SessionIdMismatch);
    }

    let template = SignSessionTemplate {
        members,
        hashes: session.hashes.clone(),
        content: session.content.clone(),
        kind: session.kind.clone(),
        stamp: session.stamp,
    };
    let sid = get_session_id(gid, &template)?;

    if sid != session.sid {
        return Err(CoreError::SessionIdMismatch);
    }

    Ok(())
}

pub fn get_session_id(group_id: Bytes32, template: &SignSessionTemplate) -> CoreResult<Bytes32> {
    validate_canonical_members(&template.members)?;
    if template.hashes.is_empty() {
        return Err(CoreError::EmptySessionHashes);
    }

    let mut hasher = Sha256::new();
    hasher.update(group_id);

    for idx in &template.members {
        hasher.update((*idx as u32).to_le_bytes());
    }

    for sighash in &template.hashes {
        hasher.update(sighash);
    }

    match &template.content {
        Some(content) if !content.is_empty() => hasher.update(content),
        _ => hasher.update([0u8]),
    }

    hasher.update(template.kind.as_bytes());
    hasher.update(template.stamp.to_le_bytes());

    Ok(hasher.finalize().into())
}

fn canonicalize_and_validate_members(
    group: &GroupPackage,
    members: &[u16],
) -> CoreResult<Vec<u16>> {
    if members.is_empty() {
        return Err(CoreError::EmptySessionMembers);
    }
    if members.len() < group.threshold as usize {
        return Err(CoreError::InvalidThreshold);
    }

    let group_members: HashSet<u16> = group.members.iter().map(|m| m.idx).collect();
    let mut canonical = members.to_vec();
    canonical.sort_unstable();
    validate_canonical_members(&canonical)?;
    if !canonical.iter().all(|m| group_members.contains(m)) {
        return Err(CoreError::MissingMember);
    }

    Ok(canonical)
}

fn validate_canonical_members(members: &[u16]) -> CoreResult<()> {
    if members.is_empty() {
        return Err(CoreError::EmptySessionMembers);
    }
    for pair in members.windows(2) {
        if pair[0] == pair[1] {
            return Err(CoreError::DuplicateSessionMember);
        }
        if pair[0] > pair[1] {
            return Err(CoreError::SessionIdMismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GroupPackage, MemberPackage};

    fn sample_group() -> GroupPackage {
        GroupPackage {
            group_name: "Test Group".to_string(),
            group_pk: [7; 32],
            threshold: 2,
            members: vec![
                MemberPackage {
                    idx: 1,
                    pubkey: [2; 33],
                },
                MemberPackage {
                    idx: 2,
                    pubkey: [3; 33],
                },
            ],
        }
    }

    #[test]
    fn session_id_is_deterministic() {
        let group = sample_group();
        let template = SignSessionTemplate {
            members: vec![2, 1],
            hashes: vec![[9; 32]],
            content: Some(b"hello".to_vec()),
            kind: "message".to_string(),
            stamp: 100,
        };

        let pkg_a = create_session_package(&group, template.clone()).expect("session package");
        let pkg_b = create_session_package(&group, template).expect("session package");
        assert_eq!(pkg_a.sid, pkg_b.sid);
    }

    #[test]
    fn verify_session_passes_for_valid_package() {
        let group = sample_group();
        let template = SignSessionTemplate {
            members: vec![1, 2],
            hashes: vec![[10; 32]],
            content: None,
            kind: "message".to_string(),
            stamp: 42,
        };

        let pkg = create_session_package(&group, template).expect("session package");
        verify_session_package(&group, &pkg).expect("verify package");
    }

    #[test]
    fn create_session_rejects_duplicate_members() {
        let group = sample_group();
        let template = SignSessionTemplate {
            members: vec![1, 1],
            hashes: vec![[10; 32]],
            content: None,
            kind: "message".to_string(),
            stamp: 42,
        };
        let err = create_session_package(&group, template).expect_err("must reject duplicates");
        assert!(matches!(err, CoreError::DuplicateSessionMember));
    }

    #[test]
    fn verify_session_rejects_non_canonical_members() {
        let group = sample_group();
        let template = SignSessionTemplate {
            members: vec![1, 2],
            hashes: vec![[10; 32]],
            content: None,
            kind: "message".to_string(),
            stamp: 42,
        };
        let mut pkg = create_session_package(&group, template).expect("session package");
        pkg.members = vec![2, 1];
        let err = verify_session_package(&group, &pkg).expect_err("must reject non-canonical");
        assert!(matches!(err, CoreError::SessionIdMismatch));
    }

    #[test]
    fn create_session_rejects_empty_hashes() {
        let group = sample_group();
        let template = SignSessionTemplate {
            members: vec![1, 2],
            hashes: vec![],
            content: None,
            kind: "message".to_string(),
            stamp: 7,
        };

        let err = create_session_package(&group, template).expect_err("must reject empty hash set");
        assert!(matches!(err, CoreError::EmptySessionHashes));
    }
}
