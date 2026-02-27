use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::group::get_group_id;
use crate::types::{Bytes32, GroupPackage, SignSessionPackage, SignSessionTemplate};

pub fn create_session_package(
    group: &GroupPackage,
    template: SignSessionTemplate,
) -> CoreResult<SignSessionPackage> {
    if template.members.is_empty() {
        return Err(CoreError::EmptySessionMembers);
    }
    if template.hashes.is_empty() {
        return Err(CoreError::EmptySessionHashes);
    }
    if template.hashes.iter().any(Vec::is_empty) {
        return Err(CoreError::EmptySessionHashes);
    }

    let gid = get_group_id(group)?;
    let sid = get_session_id(gid, &template)?;

    Ok(SignSessionPackage {
        gid,
        sid,
        members: template.members,
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

    let template = SignSessionTemplate {
        members: session.members.clone(),
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
    if template.members.is_empty() {
        return Err(CoreError::EmptySessionMembers);
    }
    if template.hashes.is_empty() {
        return Err(CoreError::EmptySessionHashes);
    }
    if template.hashes.iter().any(Vec::is_empty) {
        return Err(CoreError::EmptySessionHashes);
    }

    let mut hasher = Sha256::new();
    hasher.update(group_id);

    let mut members = template.members.clone();
    members.sort_unstable();
    for idx in members {
        hasher.update((idx as u32).to_le_bytes());
    }

    for vec in &template.hashes {
        for sighash in vec {
            hasher.update(sighash);
        }
    }

    match &template.content {
        Some(content) if !content.is_empty() => hasher.update(content),
        _ => hasher.update([0u8]),
    }

    hasher.update(template.kind.as_bytes());
    hasher.update(template.stamp.to_le_bytes());

    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GroupPackage, MemberPackage};

    fn sample_group() -> GroupPackage {
        GroupPackage {
            group_pk: [7; 33],
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
            hashes: vec![vec![[9; 32]]],
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
            hashes: vec![vec![[10; 32]]],
            content: None,
            kind: "message".to_string(),
            stamp: 42,
        };

        let pkg = create_session_package(&group, template).expect("session package");
        verify_session_package(&group, &pkg).expect("verify package");
    }

    #[test]
    fn create_session_rejects_empty_inner_hashes() {
        let group = sample_group();
        let template = SignSessionTemplate {
            members: vec![1, 2],
            hashes: vec![vec![]],
            content: None,
            kind: "message".to_string(),
            stamp: 7,
        };

        let err = create_session_package(&group, template).expect_err("must reject empty hash set");
        assert!(matches!(err, CoreError::EmptySessionHashes));
    }
}
