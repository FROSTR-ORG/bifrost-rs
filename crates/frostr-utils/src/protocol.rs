use bifrost_core::types::{
    Bytes32, EcdhPackage, GroupPackage, PartialSigPackage, SharePackage, SignSessionPackage,
    SignatureEntry,
};
use bifrost_core::{
    combine_ecdh_packages, combine_signatures, create_ecdh_package, create_partial_sig_package,
    local_pubkey_from_share, verify_partial_sig_package, verify_session_package,
};
use frost_secp256k1_tr_unofficial as frost;

use crate::errors::{FrostUtilsError, FrostUtilsResult};

pub fn validate_sign_session(
    group: &GroupPackage,
    session: &SignSessionPackage,
) -> FrostUtilsResult<()> {
    verify_session_package(group, session)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))
}

pub fn sign_create_partial(
    group: &GroupPackage,
    session: &SignSessionPackage,
    share: &SharePackage,
    signing_nonces: &[frost::round1::SigningNonces],
    signer_pubkey32: Option<Bytes32>,
) -> FrostUtilsResult<PartialSigPackage> {
    let pubkey = if let Some(v) = signer_pubkey32 {
        v
    } else {
        local_pubkey_from_share(share).map_err(|e| FrostUtilsError::Crypto(e.to_string()))?
    };

    create_partial_sig_package(group, session, share, signing_nonces, pubkey)
        .map_err(|e| FrostUtilsError::Crypto(e.to_string()))
}

pub fn sign_verify_partial(
    group: &GroupPackage,
    session: &SignSessionPackage,
    partial: &PartialSigPackage,
) -> FrostUtilsResult<()> {
    verify_partial_sig_package(group, session, partial)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))
}

pub fn sign_finalize(
    group: &GroupPackage,
    session: &SignSessionPackage,
    partials: &[PartialSigPackage],
) -> FrostUtilsResult<Vec<SignatureEntry>> {
    combine_signatures(group, session, partials).map_err(|e| FrostUtilsError::Crypto(e.to_string()))
}

pub fn ecdh_create_from_share(
    members: &[u16],
    share: &SharePackage,
    targets: &[Bytes32],
) -> FrostUtilsResult<EcdhPackage> {
    create_ecdh_package(members, share, targets).map_err(|e| FrostUtilsError::Crypto(e.to_string()))
}

pub fn ecdh_finalize(pkgs: &[EcdhPackage], target: Bytes32) -> FrostUtilsResult<Bytes32> {
    combine_ecdh_packages(pkgs, target).map_err(|e| FrostUtilsError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use bifrost_core::nonce::NoncePool;
    use bifrost_core::nonce::NoncePoolConfig;
    use bifrost_core::types::{
        IndexedPublicNonceCommitment, MemberNonceCommitmentSet, SignSessionTemplate,
    };
    use bifrost_core::{create_session_package, local_pubkey_from_share};

    use super::*;
    use crate::keyset::create_keyset;
    use crate::types::CreateKeysetConfig;

    fn two_member_session_fixture() -> (
        GroupPackage,
        SharePackage,
        SharePackage,
        SignSessionPackage,
        Vec<frost::round1::SigningNonces>,
        Vec<frost::round1::SigningNonces>,
    ) {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("bundle");

        let share_a = bundle.shares[0].clone();
        let share_b = bundle.shares[1].clone();

        let mut pool_a = NoncePool::new(share_a.idx, share_a.seckey, NoncePoolConfig::default());
        pool_a.init_peer(share_b.idx);
        let nonce_a = pool_a
            .generate_for_peer(share_b.idx, 1)
            .expect("nonce a")
            .remove(0);
        let nonces_a = pool_a
            .take_outgoing_signing_nonces_many(share_b.idx, &[nonce_a.code])
            .expect("nonces a");

        let mut pool_b = NoncePool::new(share_b.idx, share_b.seckey, NoncePoolConfig::default());
        pool_b.init_peer(share_a.idx);
        let nonce_b = pool_b
            .generate_for_peer(share_a.idx, 1)
            .expect("nonce b")
            .remove(0);
        let nonces_b = pool_b
            .take_outgoing_signing_nonces_many(share_a.idx, &[nonce_b.code])
            .expect("nonces b");

        let mut members = vec![share_a.idx, share_b.idx];
        members.sort_unstable();
        let mut nonces = vec![
            MemberNonceCommitmentSet {
                idx: share_a.idx,
                entries: vec![IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: nonce_a.binder_pn,
                    hidden_pn: nonce_a.hidden_pn,
                    code: nonce_a.code,
                }],
            },
            MemberNonceCommitmentSet {
                idx: share_b.idx,
                entries: vec![IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: nonce_b.binder_pn,
                    hidden_pn: nonce_b.hidden_pn,
                    code: nonce_b.code,
                }],
            },
        ];
        nonces.sort_by_key(|m| m.idx);

        let mut session = create_session_package(
            &bundle.group,
            SignSessionTemplate {
                members,
                hashes: vec![[7u8; 32]],
                content: None,
                kind: "message".to_string(),
                stamp: 1,
            },
        )
        .expect("session");
        session.nonces = Some(nonces);

        (bundle.group, share_a, share_b, session, nonces_a, nonces_b)
    }

    #[test]
    fn stateless_sign_flow_roundtrip() {
        let (group, share_a, share_b, session, nonces_a, nonces_b) = two_member_session_fixture();
        validate_sign_session(&group, &session).expect("session valid");

        let partial_a =
            sign_create_partial(&group, &session, &share_a, &nonces_a, None).expect("partial a");
        let partial_b =
            sign_create_partial(&group, &session, &share_b, &nonces_b, None).expect("partial b");

        sign_verify_partial(&group, &session, &partial_a).expect("verify a");
        sign_verify_partial(&group, &session, &partial_b).expect("verify b");

        let sigs = sign_finalize(&group, &session, &[partial_a, partial_b]).expect("finalize");
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn stateless_ecdh_flow_roundtrip() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("bundle");

        let share_a = bundle.shares[0].clone();
        let share_b = bundle.shares[1].clone();
        let target = local_pubkey_from_share(&bundle.shares[2]).expect("target");
        let mut members = vec![share_a.idx, share_b.idx];
        members.sort_unstable();

        let pkg_a = ecdh_create_from_share(&members, &share_a, &[target]).expect("pkg a");
        let pkg_b = ecdh_create_from_share(&members, &share_b, &[target]).expect("pkg b");

        let secret_ab = ecdh_finalize(&[pkg_a.clone(), pkg_b.clone()], target).expect("combine");
        let secret_ba = ecdh_finalize(&[pkg_b, pkg_a], target).expect("combine");
        assert_eq!(secret_ab, secret_ba);
    }
}
