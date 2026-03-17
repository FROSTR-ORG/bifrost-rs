use std::collections::{BTreeMap, BTreeSet};

use bifrost_core::types::{GroupPackage, SharePackage};
use frost_secp256k1_tr_unofficial as frost;

use crate::errors::{FrostUtilsError, FrostUtilsResult};
use crate::types::{KeysetBundle, KeysetVerificationReport};

pub fn verify_group_config(group: &GroupPackage) -> FrostUtilsResult<()> {
    if group.threshold < 2 {
        return Err(FrostUtilsError::VerificationFailed(
            "threshold must be >= 2".to_string(),
        ));
    }
    if group.members.is_empty() {
        return Err(FrostUtilsError::VerificationFailed(
            "members must not be empty".to_string(),
        ));
    }
    if group.threshold as usize > group.members.len() {
        return Err(FrostUtilsError::VerificationFailed(
            "threshold cannot exceed member count".to_string(),
        ));
    }

    let mut seen = BTreeSet::new();
    for member in &group.members {
        if member.idx == 0 {
            return Err(FrostUtilsError::VerificationFailed(
                "member idx must be non-zero".to_string(),
            ));
        }
        if !seen.insert(member.idx) {
            return Err(FrostUtilsError::VerificationFailed(
                "duplicate member idx".to_string(),
            ));
        }
        frost::keys::VerifyingShare::deserialize(&member.pubkey)
            .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;
    }

    let group_pk = pubkey32_to_even_compressed(group.group_pk);
    frost::VerifyingKey::deserialize(&group_pk)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

    Ok(())
}

pub fn verify_share(share: &SharePackage, group: &GroupPackage) -> FrostUtilsResult<()> {
    let identifier = frost::Identifier::try_from(share.idx)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;
    let signing_share = frost::keys::SigningShare::deserialize(&share.seckey)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

    let member = group
        .members
        .iter()
        .find(|m| m.idx == share.idx)
        .ok_or_else(|| {
            FrostUtilsError::VerificationFailed("share idx missing in group".to_string())
        })?;

    let expected_share = frost::keys::VerifyingShare::deserialize(&member.pubkey)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;
    let derived_share = frost::keys::VerifyingShare::from(signing_share);

    let expected = expected_share
        .serialize()
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;
    let derived = derived_share
        .serialize()
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

    if expected != derived {
        return Err(FrostUtilsError::VerificationFailed(
            "share does not match member verifying share".to_string(),
        ));
    }

    let group_key = frost::VerifyingKey::deserialize(&pubkey32_to_even_compressed(group.group_pk))
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

    let key_package = frost::keys::KeyPackage::new(
        identifier,
        signing_share,
        expected_share,
        group_key,
        group.threshold,
    );

    let mut shares = BTreeMap::new();
    for m in &group.members {
        let id = frost::Identifier::try_from(m.idx)
            .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;
        let vs = frost::keys::VerifyingShare::deserialize(&m.pubkey)
            .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;
        shares.insert(id, vs);
    }

    let public = frost::keys::PublicKeyPackage::new(shares, group_key);

    let key_v = key_package
        .verifying_key()
        .serialize()
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;
    let pub_v = public
        .verifying_key()
        .serialize()
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

    if key_v != pub_v {
        return Err(FrostUtilsError::VerificationFailed(
            "share/group verifying key mismatch".to_string(),
        ));
    }

    Ok(())
}

pub fn verify_keyset(bundle: &KeysetBundle) -> FrostUtilsResult<KeysetVerificationReport> {
    verify_group_config(&bundle.group)?;
    if bundle.shares.len() != bundle.group.members.len() {
        return Err(FrostUtilsError::VerificationFailed(
            "share count must equal member count".to_string(),
        ));
    }

    for share in &bundle.shares {
        verify_share(share, &bundle.group)?;
    }

    Ok(KeysetVerificationReport {
        member_count: bundle.group.members.len(),
        threshold: bundle.group.threshold,
        verified_shares: bundle.shares.len(),
    })
}

fn pubkey32_to_even_compressed(pubkey: [u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x02;
    out[1..].copy_from_slice(&pubkey);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyset::create_keyset;
    use crate::types::CreateKeysetConfig;

    #[test]
    fn verify_keyset_accepts_valid_bundle() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");
        let report = verify_keyset(&bundle).expect("verify");
        assert_eq!(report.verified_shares, 3);
    }

    #[test]
    fn verify_share_rejects_tamper() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");
        let mut tampered = bundle.shares[0].clone();
        tampered.seckey[0] ^= 0x01;
        assert!(verify_share(&tampered, &bundle.group).is_err());
    }

    #[test]
    fn verify_group_config_rejects_invalid_threshold_and_duplicates() {
        let mut bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");

        bundle.group.threshold = 4;
        assert!(verify_group_config(&bundle.group).is_err());

        let mut bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");
        bundle.group.members[1].idx = bundle.group.members[0].idx;
        assert!(verify_group_config(&bundle.group).is_err());
    }

    #[test]
    fn verify_keyset_rejects_share_count_mismatch_and_missing_share_member() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");
        let short_bundle = crate::types::KeysetBundle {
            group: bundle.group.clone(),
            shares: bundle.shares[..2].to_vec(),
        };
        assert!(verify_keyset(&short_bundle).is_err());

        let mut tampered_share = bundle.shares[0].clone();
        tampered_share.idx = 99;
        assert!(verify_share(&tampered_share, &bundle.group).is_err());
    }
}
