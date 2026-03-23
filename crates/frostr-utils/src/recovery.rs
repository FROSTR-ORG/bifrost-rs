use bifrost_core::types::Bytes32;
use frost_secp256k1_tr_unofficial as frost;
use frost_secp256k1_tr_unofficial::keys::EvenY;

use crate::errors::{FrostUtilsError, FrostUtilsResult};
use crate::types::{RecoverKeyInput, RecoveredKeyMaterial};

pub fn recover_key(input: &RecoverKeyInput) -> FrostUtilsResult<RecoveredKeyMaterial> {
    if input.shares.len() < input.group.threshold as usize {
        return Err(FrostUtilsError::InvalidInput(
            "insufficient shares for threshold".to_string(),
        ));
    }

    let group_key =
        frost::VerifyingKey::deserialize(&pubkey32_to_even_compressed(input.group.group_pk))
            .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

    let mut key_packages = Vec::new();
    for share in input.shares.iter().take(input.group.threshold as usize) {
        let id = frost::Identifier::try_from(share.idx)
            .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;
        let signing_share = frost::keys::SigningShare::deserialize(&share.seckey)
            .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

        let member = input
            .group
            .members
            .iter()
            .find(|m| m.idx == share.idx)
            .ok_or_else(|| {
                FrostUtilsError::VerificationFailed("share idx missing in group".to_string())
            })?;
        let verifying_share = frost::keys::VerifyingShare::deserialize(&member.pubkey)
            .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))?;

        let kp = frost::keys::KeyPackage::new(
            id,
            signing_share,
            verifying_share,
            group_key,
            input.group.threshold,
        );
        key_packages.push(kp);
    }

    let signing_key = frost::keys::reconstruct(&key_packages)
        .map_err(|e| FrostUtilsError::Crypto(e.to_string()))?;
    let signing_key = signing_key.into_even_y(None);

    let derived_group_pk = verifying_key_to_group_pk(frost::VerifyingKey::from(&signing_key));
    if derived_group_pk != input.group.group_pk {
        return Err(FrostUtilsError::VerificationFailed(
            "recovered signing key does not match group public key".to_string(),
        ));
    }

    let bytes = signing_key.serialize();
    if bytes.len() != 32 {
        return Err(FrostUtilsError::Crypto(
            "unexpected recovered key size".to_string(),
        ));
    }

    let mut signing_key32 = Bytes32::default();
    signing_key32.copy_from_slice(&bytes);

    Ok(RecoveredKeyMaterial { signing_key32 })
}

fn pubkey32_to_even_compressed(pubkey: [u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x02;
    out[1..].copy_from_slice(&pubkey);
    out
}

fn verifying_key_to_group_pk(verifying_key: frost::VerifyingKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(
        &verifying_key
            .serialize()
            .expect("secp256k1-tr verifying key serialization should succeed")[1..],
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyset::create_keyset;
    use crate::types::CreateKeysetConfig;

    #[test]
    fn recover_key_with_threshold_shares() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");

        let input = RecoverKeyInput {
            group: bundle.group,
            shares: bundle.shares.into_iter().take(2).collect(),
        };
        let recovered = recover_key(&input).expect("recover");
        assert_ne!(recovered.signing_key32, [0u8; 32]);
    }

    #[test]
    fn recover_key_rejects_group_public_key_mismatch() {
        let first = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");
        let second = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");

        let mismatched = RecoverKeyInput {
            group: second.group,
            shares: first.shares[..2].to_vec(),
        };

        assert!(recover_key(&mismatched).is_err());
    }

    #[test]
    fn recover_key_rejects_insufficient_or_unknown_shares() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create");

        let insufficient = RecoverKeyInput {
            group: bundle.group.clone(),
            shares: vec![bundle.shares[0].clone()],
        };
        assert!(recover_key(&insufficient).is_err());

        let mut unknown_share = bundle.shares[0].clone();
        unknown_share.idx = 99;
        let invalid = RecoverKeyInput {
            group: bundle.group,
            shares: vec![unknown_share, bundle.shares[1].clone()],
        };
        assert!(recover_key(&invalid).is_err());
    }
}
