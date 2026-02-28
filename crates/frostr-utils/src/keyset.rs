use std::time::{SystemTime, UNIX_EPOCH};

use bifrost_core::get_group_id;
use bifrost_core::types::{GroupPackage, MemberPackage, SharePackage};
use frost_secp256k1_tr_unofficial as frost;
use rand_core::OsRng;

use crate::errors::{FrostUtilsError, FrostUtilsResult};
use crate::types::{CreateKeysetConfig, KeysetBundle, RotateKeysetRequest, RotateKeysetResult};
use crate::verify::verify_keyset;

pub fn create_keyset(config: CreateKeysetConfig) -> FrostUtilsResult<KeysetBundle> {
    if config.threshold < 2 {
        return Err(FrostUtilsError::InvalidInput(
            "threshold must be >= 2".to_string(),
        ));
    }
    if config.count < config.threshold {
        return Err(FrostUtilsError::InvalidInput(
            "count must be >= threshold".to_string(),
        ));
    }

    let (shares, pubkey_pkg) = frost::keys::generate_with_dealer(
        config.count,
        config.threshold,
        frost::keys::IdentifierList::Default,
        OsRng,
    )
    .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?;

    let mut material = Vec::new();
    for (id, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)
            .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?;
        material.push((id, key_package));
    }
    material.sort_by_key(|(id, _)| id.serialize());

    let mut group_pk = [0u8; 33];
    group_pk.copy_from_slice(
        &pubkey_pkg
            .verifying_key()
            .serialize()
            .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?,
    );

    let mut members = Vec::new();
    let mut share_packages = Vec::new();

    for (id, key) in material {
        let id_ser = id.serialize();
        let idx = id_ser[31] as u16;

        let mut member_pk = [0u8; 33];
        member_pk.copy_from_slice(
            &key.verifying_share()
                .serialize()
                .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?,
        );

        let mut seckey = [0u8; 32];
        seckey.copy_from_slice(&key.signing_share().serialize());

        members.push(MemberPackage {
            idx,
            pubkey: member_pk,
        });
        share_packages.push(SharePackage { idx, seckey });
    }

    members.sort_by_key(|m| m.idx);
    share_packages.sort_by_key(|s| s.idx);

    let bundle = KeysetBundle {
        group: GroupPackage {
            group_pk,
            threshold: config.threshold,
            members,
        },
        shares: share_packages,
    };

    verify_keyset(&bundle)?;
    Ok(bundle)
}

pub fn rotate_keyset_dealer(
    current_group: &GroupPackage,
    req: RotateKeysetRequest,
) -> FrostUtilsResult<RotateKeysetResult> {
    let _issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| FrostUtilsError::InvalidInput(e.to_string()))?
        .as_secs();

    let previous_group_id = get_group_id(current_group)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

    let next = create_keyset(CreateKeysetConfig {
        threshold: req.threshold,
        count: req.count,
    })?;

    Ok(RotateKeysetResult {
        previous_group_id,
        next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CreateKeysetConfig;

    #[test]
    fn create_keyset_builds_valid_bundle() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");
        assert_eq!(bundle.group.members.len(), 3);
        assert_eq!(bundle.shares.len(), 3);
    }

    #[test]
    fn rotate_keyset_returns_new_group() {
        let current = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");
        let rotated = rotate_keyset_dealer(
            &current.group,
            RotateKeysetRequest {
                threshold: 2,
                count: 3,
            },
        )
        .expect("rotate");

        assert_eq!(rotated.next.group.members.len(), 3);
        assert_ne!(rotated.next.group.group_pk, current.group.group_pk);
    }
}
