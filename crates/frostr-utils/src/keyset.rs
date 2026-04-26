use bifrost_core::get_group_id;
use bifrost_core::types::{Bytes32, GroupPackage, MemberPackage, SharePackage};
use frost_secp256k1_tr_unofficial as frost;
use frost_secp256k1_tr_unofficial::keys::EvenY;
use rand_core::OsRng;

use crate::errors::{FrostUtilsError, FrostUtilsResult};
use crate::recovery::recover_key;
use crate::types::{
    CreateKeysetConfig, CreateKeysetFromSigningKeyConfig, KeysetBundle, RecoverKeyInput,
    RotateKeysetRequest, RotateKeysetResult,
};
use crate::verify::verify_keyset;

pub fn create_keyset(config: CreateKeysetConfig) -> FrostUtilsResult<KeysetBundle> {
    validate_keyset_shape(config.threshold, config.count)?;

    let (shares, public_key_package) = frost::keys::generate_with_dealer(
        config.count,
        config.threshold,
        frost::keys::IdentifierList::Default,
        OsRng,
    )
    .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?;

    build_keyset_bundle(
        config.group_name,
        config.threshold,
        shares,
        public_key_package,
    )
}

pub fn normalize_signing_key_even_y(signing_key32: Bytes32) -> FrostUtilsResult<Bytes32> {
    let signing_key = frost::SigningKey::deserialize(&signing_key32)
        .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?
        .into_even_y(None);
    signing_key_to_bytes(signing_key)
}

pub fn create_keyset_from_signing_key(
    config: CreateKeysetFromSigningKeyConfig,
) -> FrostUtilsResult<KeysetBundle> {
    validate_keyset_shape(config.threshold, config.count)?;
    split_signing_key(
        config.group_name,
        config.threshold,
        config.count,
        config.signing_key32,
    )
}

pub fn rotate_keyset_dealer(
    current_group: &GroupPackage,
    req: RotateKeysetRequest,
) -> FrostUtilsResult<RotateKeysetResult> {
    validate_keyset_shape(req.threshold, req.count)?;

    let previous_group_id = get_group_id(current_group)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

    let recovered = recover_key(&RecoverKeyInput {
        group: current_group.clone(),
        shares: req.shares,
    })?;

    let next = split_signing_key(
        current_group.group_name.clone(),
        req.threshold,
        req.count,
        recovered.signing_key32,
    )?;

    if next.group.group_pk != current_group.group_pk {
        return Err(FrostUtilsError::VerificationFailed(
            "rotation changed group public key".to_string(),
        ));
    }

    let next_group_id = get_group_id(&next.group)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

    Ok(RotateKeysetResult {
        previous_group_id,
        next_group_id,
        next,
    })
}

fn validate_keyset_shape(threshold: u16, count: u16) -> FrostUtilsResult<()> {
    if threshold < 2 {
        return Err(FrostUtilsError::InvalidInput(
            "threshold must be >= 2".to_string(),
        ));
    }
    if count < threshold {
        return Err(FrostUtilsError::InvalidInput(
            "count must be >= threshold".to_string(),
        ));
    }
    Ok(())
}

fn split_signing_key(
    group_name: String,
    threshold: u16,
    count: u16,
    signing_key32: Bytes32,
) -> FrostUtilsResult<KeysetBundle> {
    let signing_key = frost::SigningKey::deserialize(&signing_key32)
        .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?
        .into_even_y(None);

    let (shares, public_key_package) = frost::keys::split(
        &signing_key,
        count,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut OsRng,
    )
    .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?;

    build_keyset_bundle(group_name, threshold, shares, public_key_package)
}

fn signing_key_to_bytes(signing_key: frost::SigningKey) -> FrostUtilsResult<Bytes32> {
    let serialized = signing_key.serialize();
    if serialized.len() != 32 {
        return Err(FrostUtilsError::Crypto(
            "serialized signing key is not 32 bytes".to_string(),
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&serialized);
    Ok(bytes)
}

fn build_keyset_bundle(
    group_name: String,
    threshold: u16,
    shares: std::collections::BTreeMap<frost::Identifier, frost::keys::SecretShare>,
    public_key_package: frost::keys::PublicKeyPackage,
) -> FrostUtilsResult<KeysetBundle> {
    let public_key_package = public_key_package.into_even_y(None);

    let mut material = Vec::new();
    for (id, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)
            .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?
            .into_even_y(None);
        material.push((id, key_package));
    }
    material.sort_by_key(|(id, _)| id.serialize());

    let mut group_pk = [0u8; 32];
    group_pk.copy_from_slice(
        &public_key_package
            .verifying_key()
            .serialize()
            .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?[1..],
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
            group_name,
            group_pk,
            threshold,
            members,
        },
        shares: share_packages,
    };

    verify_keyset(&bundle)?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CreateKeysetConfig, CreateKeysetFromSigningKeyConfig};
    use crate::{recover_key, verify_share};

    #[test]
    fn create_keyset_builds_valid_bundle() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create");
        assert_eq!(bundle.group.members.len(), 3);
        assert_eq!(bundle.shares.len(), 3);
    }

    #[test]
    fn create_keyset_from_signing_key_recovers_the_normalized_key() {
        let generated = nostr::SecretKey::generate();
        let signing_key32 = generated.to_secret_bytes();
        let expected = normalize_signing_key_even_y(signing_key32).expect("normalize");
        let bundle = create_keyset_from_signing_key(CreateKeysetFromSigningKeyConfig {
            group_name: "Known Key Group".to_string(),
            threshold: 2,
            count: 3,
            signing_key32,
        })
        .expect("create from signing key");

        let recovered = recover_key(&RecoverKeyInput {
            group: bundle.group,
            shares: bundle.shares[..2].to_vec(),
        })
        .expect("recover");

        assert_eq!(recovered.signing_key32, expected);
    }

    #[test]
    fn create_keyset_from_signing_key_rejects_invalid_shapes_and_keys() {
        let signing_key32 = nostr::SecretKey::generate().to_secret_bytes();
        assert!(
            create_keyset_from_signing_key(CreateKeysetFromSigningKeyConfig {
                group_name: "Bad Shape".to_string(),
                threshold: 1,
                count: 2,
                signing_key32,
            })
            .is_err()
        );
        assert!(
            create_keyset_from_signing_key(CreateKeysetFromSigningKeyConfig {
                group_name: "Zero Key".to_string(),
                threshold: 2,
                count: 2,
                signing_key32: [0u8; 32],
            })
            .is_err()
        );
    }

    #[test]
    fn rotate_keyset_preserves_group_public_key() {
        let current = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create");

        let rotated = rotate_keyset_dealer(
            &current.group,
            RotateKeysetRequest {
                shares: current.shares[..2].to_vec(),
                threshold: 2,
                count: 3,
            },
        )
        .expect("rotate");

        assert_eq!(rotated.next.group.group_pk, current.group.group_pk);
        assert_ne!(rotated.next_group_id, rotated.previous_group_id);
        assert_eq!(rotated.next.group.members.len(), 3);
        assert_ne!(rotated.next.shares, current.shares);
    }

    #[test]
    fn rotate_keyset_allows_threshold_and_count_change() {
        let current = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create");

        let rotated = rotate_keyset_dealer(
            &current.group,
            RotateKeysetRequest {
                shares: current.shares[..2].to_vec(),
                threshold: 3,
                count: 5,
            },
        )
        .expect("rotate");

        assert_eq!(rotated.next.group.group_pk, current.group.group_pk);
        assert_eq!(rotated.next.group.threshold, 3);
        assert_eq!(rotated.next.group.members.len(), 5);
        assert_eq!(rotated.next.shares.len(), 5);
    }

    #[test]
    fn rotated_group_rejects_old_shares() {
        let current = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create");

        let rotated = rotate_keyset_dealer(
            &current.group,
            RotateKeysetRequest {
                shares: current.shares[..2].to_vec(),
                threshold: 2,
                count: 3,
            },
        )
        .expect("rotate");

        assert!(verify_share(&current.shares[0], &rotated.next.group).is_err());
        assert!(verify_share(&rotated.next.shares[0], &rotated.next.group).is_ok());
    }

    #[test]
    fn rotated_shares_recover_same_signing_key() {
        let current = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create");

        let original = recover_key(&RecoverKeyInput {
            group: current.group.clone(),
            shares: current.shares[..2].to_vec(),
        })
        .expect("recover original");

        let rotated = rotate_keyset_dealer(
            &current.group,
            RotateKeysetRequest {
                shares: current.shares[..2].to_vec(),
                threshold: 2,
                count: 4,
            },
        )
        .expect("rotate");

        let recovered = recover_key(&RecoverKeyInput {
            group: rotated.next.group.clone(),
            shares: rotated.next.shares[..2].to_vec(),
        })
        .expect("recover rotated");

        assert_eq!(recovered.signing_key32, original.signing_key32);
    }
}
