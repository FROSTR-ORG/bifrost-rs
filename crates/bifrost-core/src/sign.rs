use std::collections::BTreeMap;

use frost_secp256k1_tr_unofficial as frost;

use crate::error::{CoreError, CoreResult};
use crate::types::{
    GroupPackage, PartialSigEntry, PartialSigPackage, SharePackage, SignSessionPackage,
    SignatureEntry,
};

pub fn create_partial_sig_package(
    group: &GroupPackage,
    session: &SignSessionPackage,
    share: &SharePackage,
    signing_nonces: &[frost::round1::SigningNonces],
    pubkey: [u8; 33],
) -> CoreResult<PartialSigPackage> {
    if session.hashes.is_empty() {
        return Err(CoreError::EmptySessionHashes);
    }
    if signing_nonces.len() != session.hashes.len() {
        return Err(CoreError::BatchItemCountMismatch);
    }

    let key_package = build_key_package(group, share)?;
    let commitments = build_commitments_by_index(session)?;

    let mut psigs = Vec::with_capacity(session.hashes.len());
    for (hash_index, sighash) in session.hashes.iter().enumerate() {
        let signing_package = frost::SigningPackage::new(
            commitments
                .get(hash_index)
                .ok_or(CoreError::MissingHashIndexContribution)?
                .clone(),
            sighash,
        );
        let signature_share = frost::round2::sign(
            &signing_package,
            signing_nonces
                .get(hash_index)
                .ok_or(CoreError::MissingHashIndexContribution)?,
            &key_package,
        )
        .map_err(|e| CoreError::Frost(e.to_string()))?;

        let share_bytes = signature_share.serialize();
        if share_bytes.len() != 32 {
            return Err(CoreError::InvalidScalar);
        }

        let mut partial_sig = [0u8; 32];
        partial_sig.copy_from_slice(&share_bytes);

        psigs.push(PartialSigEntry {
            hash_index: hash_index as u16,
            sighash: *sighash,
            partial_sig,
        });
    }

    Ok(PartialSigPackage {
        idx: share.idx,
        sid: session.sid,
        pubkey,
        psigs,
        nonce_code: None,
        replenish: None,
    })
}

pub fn create_partial_sig_packages_batch(
    group: &GroupPackage,
    sessions: &[SignSessionPackage],
    share: &SharePackage,
    signing_nonces: &[Vec<frost::round1::SigningNonces>],
    pubkey: [u8; 33],
) -> CoreResult<Vec<PartialSigPackage>> {
    if sessions.is_empty() {
        return Err(CoreError::EmptySessionHashes);
    }
    if sessions.len() != signing_nonces.len() {
        return Err(CoreError::BatchItemCountMismatch);
    }

    let mut out = Vec::with_capacity(sessions.len());
    for (session, nonces) in sessions.iter().zip(signing_nonces.iter()) {
        out.push(create_partial_sig_package(
            group, session, share, nonces, pubkey,
        )?);
    }

    Ok(out)
}

pub fn verify_partial_sig_package(
    group: &GroupPackage,
    session: &SignSessionPackage,
    pkg: &PartialSigPackage,
) -> CoreResult<()> {
    if pkg.sid != session.sid {
        return Err(CoreError::SessionIdMismatch);
    }
    if pkg.psigs.len() != session.hashes.len() {
        return Err(CoreError::EmptySessionHashes);
    }

    let identifier =
        frost::Identifier::try_from(pkg.idx).map_err(|e| CoreError::Frost(e.to_string()))?;
    let public_key_package = build_public_key_package(group)?;
    let verifying_share = public_key_package
        .verifying_shares()
        .get(&identifier)
        .ok_or(CoreError::MissingMember)?;
    let commitments = build_commitments_by_index(session)?;

    let mut seen = std::collections::HashSet::new();
    for psig in &pkg.psigs {
        let idx = psig.hash_index as usize;
        if idx >= session.hashes.len() {
            return Err(CoreError::HashIndexOutOfRange);
        }
        if !seen.insert(idx) {
            return Err(CoreError::HashIndexDuplicate);
        }
        if session.hashes[idx] != psig.sighash {
            return Err(CoreError::SessionHashMismatch);
        }
        let signing_package = frost::SigningPackage::new(
            commitments
                .get(idx)
                .ok_or(CoreError::MissingHashIndexContribution)?
                .clone(),
            &psig.sighash,
        );
        let signature_share = frost::round2::SignatureShare::deserialize(&psig.partial_sig)
            .map_err(|e| CoreError::Frost(e.to_string()))?;

        frost::verify_signature_share(
            identifier,
            verifying_share,
            &signature_share,
            &signing_package,
            public_key_package.verifying_key(),
        )
        .map_err(|e| CoreError::Frost(e.to_string()))?;
    }

    Ok(())
}

pub fn combine_signatures(
    group: &GroupPackage,
    session: &SignSessionPackage,
    pkgs: &[PartialSigPackage],
) -> CoreResult<Vec<SignatureEntry>> {
    if pkgs.len() < group.threshold as usize {
        return Err(CoreError::InvalidThreshold);
    }

    let public_key_package = build_public_key_package(group)?;
    let commitments = build_commitments_by_index(session)?;

    let mut out = Vec::with_capacity(session.hashes.len());
    for (hash_index, sighash) in session.hashes.iter().enumerate() {
        let signing_package = frost::SigningPackage::new(
            commitments
                .get(hash_index)
                .ok_or(CoreError::MissingHashIndexContribution)?
                .clone(),
            sighash,
        );
        let mut signature_shares = BTreeMap::new();

        for pkg in pkgs {
            let identifier = frost::Identifier::try_from(pkg.idx)
                .map_err(|e| CoreError::Frost(e.to_string()))?;
            let entry = pkg
                .psigs
                .iter()
                .find(|e| e.hash_index as usize == hash_index)
                .ok_or(CoreError::MissingHashIndexContribution)?;
            if entry.sighash != *sighash {
                return Err(CoreError::SessionHashMismatch);
            }
            let signature_share = frost::round2::SignatureShare::deserialize(&entry.partial_sig)
                .map_err(|e| CoreError::Frost(e.to_string()))?;
            signature_shares.insert(identifier, signature_share);
        }

        let signature = frost::aggregate(&signing_package, &signature_shares, &public_key_package)
            .map_err(|e| CoreError::Frost(e.to_string()))?;

        public_key_package
            .verifying_key()
            .verify(sighash, &signature)
            .map_err(|e| CoreError::Frost(e.to_string()))?;

        let serialized = signature
            .serialize()
            .map_err(|e| CoreError::Frost(e.to_string()))?;
        if serialized.len() != 64 {
            return Err(CoreError::InvalidScalar);
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&serialized);

        out.push(SignatureEntry {
            sighash: *sighash,
            pubkey: group.group_pk,
            signature: sig,
        });
    }

    Ok(out)
}

pub fn combine_signatures_batch(
    group: &GroupPackage,
    sessions: &[SignSessionPackage],
    pkgs_by_session: &[Vec<PartialSigPackage>],
) -> CoreResult<Vec<SignatureEntry>> {
    if sessions.is_empty() {
        return Err(CoreError::EmptySessionHashes);
    }
    if sessions.len() != pkgs_by_session.len() {
        return Err(CoreError::BatchItemCountMismatch);
    }

    let mut out = Vec::with_capacity(sessions.len());
    for (session, pkgs) in sessions.iter().zip(pkgs_by_session.iter()) {
        out.extend(combine_signatures(group, session, pkgs)?);
    }

    Ok(out)
}

fn build_commitments_by_index(
    session: &SignSessionPackage,
) -> CoreResult<Vec<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>>> {
    let nonces = session.nonces.as_ref().ok_or(CoreError::MissingNonces)?;
    let hash_len = session.hashes.len();
    let mut commitments = vec![BTreeMap::new(); hash_len];

    for member_nonce_set in nonces {
        let identifier = frost::Identifier::try_from(member_nonce_set.idx)
            .map_err(|e| CoreError::Frost(e.to_string()))?;
        if member_nonce_set.entries.len() != hash_len {
            return Err(CoreError::MissingHashIndexContribution);
        }
        for entry in &member_nonce_set.entries {
            let idx = entry.hash_index as usize;
            if idx >= hash_len {
                return Err(CoreError::HashIndexOutOfRange);
            }
            let hiding = frost::round1::NonceCommitment::deserialize(&entry.hidden_pn)
                .map_err(|e| CoreError::Frost(e.to_string()))?;
            let binding = frost::round1::NonceCommitment::deserialize(&entry.binder_pn)
                .map_err(|e| CoreError::Frost(e.to_string()))?;
            if commitments[idx]
                .insert(
                    identifier,
                    frost::round1::SigningCommitments::new(hiding, binding),
                )
                .is_some()
            {
                return Err(CoreError::HashIndexDuplicate);
            }
        }
    }

    Ok(commitments)
}

fn build_public_key_package(group: &GroupPackage) -> CoreResult<frost::keys::PublicKeyPackage> {
    let verifying_key = frost::VerifyingKey::deserialize(&group.group_pk)
        .map_err(|e| CoreError::Frost(e.to_string()))?;

    let mut verifying_shares = BTreeMap::new();
    for member in &group.members {
        let identifier =
            frost::Identifier::try_from(member.idx).map_err(|e| CoreError::Frost(e.to_string()))?;
        let share = frost::keys::VerifyingShare::deserialize(&member.pubkey)
            .map_err(|e| CoreError::Frost(e.to_string()))?;
        verifying_shares.insert(identifier, share);
    }

    Ok(frost::keys::PublicKeyPackage::new(
        verifying_shares,
        verifying_key,
    ))
}

fn build_key_package(
    group: &GroupPackage,
    share: &SharePackage,
) -> CoreResult<frost::keys::KeyPackage> {
    let identifier =
        frost::Identifier::try_from(share.idx).map_err(|e| CoreError::Frost(e.to_string()))?;
    let signing_share = frost::keys::SigningShare::deserialize(&share.seckey)
        .map_err(|e| CoreError::Frost(e.to_string()))?;

    let member = group
        .members
        .iter()
        .find(|m| m.idx == share.idx)
        .ok_or(CoreError::MissingMember)?;

    let verifying_share = frost::keys::VerifyingShare::deserialize(&member.pubkey)
        .map_err(|e| CoreError::Frost(e.to_string()))?;
    let verifying_key = frost::VerifyingKey::deserialize(&group.group_pk)
        .map_err(|e| CoreError::Frost(e.to_string()))?;

    Ok(frost::keys::KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        verifying_key,
        group.threshold,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn two_member_fixture() -> (GroupPackage, Vec<SharePackage>) {
        let (shares, group_pub) =
            frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, OsRng)
                .expect("dealer");

        let mut members = Vec::new();
        let mut share_packages = Vec::new();
        for (id, secret_share) in shares {
            let key_package = frost::keys::KeyPackage::try_from(secret_share).expect("key package");
            let mut member_pk = [0u8; 33];
            member_pk.copy_from_slice(
                &key_package
                    .verifying_share()
                    .serialize()
                    .expect("serialize verifying share"),
            );
            members.push(crate::types::MemberPackage {
                idx: id.serialize()[31] as u16,
                pubkey: member_pk,
            });

            let mut seckey = [0u8; 32];
            seckey.copy_from_slice(&key_package.signing_share().serialize());
            share_packages.push(SharePackage {
                idx: id.serialize()[31] as u16,
                seckey,
            });
        }
        members.sort_by_key(|m| m.idx);
        share_packages.sort_by_key(|s| s.idx);

        let mut group_pk = [0u8; 33];
        group_pk.copy_from_slice(
            &group_pub
                .verifying_key()
                .serialize()
                .expect("serialize group key"),
        );

        (
            GroupPackage {
                group_pk,
                threshold: 2,
                members,
            },
            share_packages,
        )
    }

    fn sign_fixture() -> (GroupPackage, SignSessionPackage, Vec<PartialSigPackage>) {
        let (shares, group_pub) =
            frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, OsRng)
                .expect("dealer");

        let mut members = Vec::new();
        let mut share_packages = Vec::new();
        for (id, secret_share) in shares {
            let kp = frost::keys::KeyPackage::try_from(secret_share).expect("key package");
            let vk_bytes = kp
                .verifying_share()
                .serialize()
                .expect("serialize verifying share");
            let mut member_pk = [0u8; 33];
            member_pk.copy_from_slice(&vk_bytes);
            members.push(crate::types::MemberPackage {
                idx: id.serialize()[31] as u16,
                pubkey: member_pk,
            });

            let sk_bytes = kp.signing_share().serialize();
            let mut seckey = [0u8; 32];
            seckey.copy_from_slice(&sk_bytes);
            share_packages.push(SharePackage {
                idx: id.serialize()[31] as u16,
                seckey,
            });
        }
        members.sort_by_key(|m| m.idx);
        share_packages.sort_by_key(|s| s.idx);

        let group_key = group_pub
            .verifying_key()
            .serialize()
            .expect("serialize group key");
        let mut group_pk = [0u8; 33];
        group_pk.copy_from_slice(&group_key);

        let group = GroupPackage {
            group_pk,
            threshold: 2,
            members,
        };

        let mut nonces = Vec::new();
        let mut local_nonces = Vec::new();
        for share in &share_packages {
            let signing_share = frost::keys::SigningShare::deserialize(&share.seckey)
                .expect("signing share deserialize");
            let (n, c) = frost::round1::commit(&signing_share, &mut OsRng);
            nonces.push(crate::types::MemberNonceCommitmentSet {
                idx: share.idx,
                entries: vec![crate::types::IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: c
                        .binding()
                        .serialize()
                        .expect("serialize commitment")
                        .try_into()
                        .expect("len"),
                    hidden_pn: c
                        .hiding()
                        .serialize()
                        .expect("serialize commitment")
                        .try_into()
                        .expect("len"),
                    code: [1u8; 32],
                }],
            });
            local_nonces.push(n);
        }

        let session = SignSessionPackage {
            gid: [1; 32],
            sid: [2; 32],
            members: share_packages.iter().map(|s| s.idx).collect(),
            hashes: vec![[7; 32]],
            content: None,
            kind: "message".to_string(),
            stamp: 1,
            nonces: Some(nonces),
        };

        let mut pkgs = Vec::new();
        for (idx, share) in share_packages.iter().enumerate() {
            let member = group
                .members
                .iter()
                .find(|m| m.idx == share.idx)
                .expect("member");
            let nonce_ser = local_nonces[idx].serialize().expect("serialize nonces");
            let parsed_nonces =
                frost::round1::SigningNonces::deserialize(&nonce_ser).expect("deserialize nonces");
            let key_pkg = build_key_package(&group, share).expect("build key package");
            let commitments = build_commitments_by_index(&session).expect("commitments");
            let sp = frost::SigningPackage::new(commitments[0].clone(), &[7; 32]);
            let sig_share = frost::round2::sign(&sp, &parsed_nonces, &key_pkg).expect("sign share");

            let mut ps = [0u8; 32];
            ps.copy_from_slice(&sig_share.serialize());

            pkgs.push(PartialSigPackage {
                idx: share.idx,
                sid: session.sid,
                pubkey: member.pubkey,
                psigs: vec![PartialSigEntry {
                    hash_index: 0,
                    sighash: [7; 32],
                    partial_sig: ps,
                }],
                nonce_code: None,
                replenish: None,
            });
        }

        (group, session, pkgs)
    }

    #[test]
    fn combine_signatures_is_deterministic() {
        let (group, session, pkgs) = sign_fixture();

        let one = combine_signatures(&group, &session, &pkgs).expect("combine");
        let two = combine_signatures(&group, &session, &pkgs).expect("combine");
        assert_eq!(one, two);
    }

    #[test]
    fn verify_partial_sig_rejects_tampered_signature_share() {
        let (group, session, mut pkgs) = sign_fixture();
        let mut pkg = pkgs.remove(0);
        pkg.psigs[0].partial_sig[0] ^= 0x01;

        let err = verify_partial_sig_package(&group, &session, &pkg).expect_err("must reject");
        assert!(matches!(err, CoreError::Frost(_)));
    }

    #[test]
    fn verify_partial_sig_rejects_unknown_member_idx() {
        let (group, session, mut pkgs) = sign_fixture();
        let mut pkg = pkgs.remove(0);
        pkg.idx = 999;

        let err = verify_partial_sig_package(&group, &session, &pkg).expect_err("must reject");
        assert!(matches!(err, CoreError::MissingMember));
    }

    #[test]
    fn create_partial_sig_packages_batch_rejects_nonce_count_mismatch() {
        let (group, shares) = two_member_fixture();
        let share = &shares[0];
        let signing_share =
            frost::keys::SigningShare::deserialize(&share.seckey).expect("signing share");
        let (nonce_a, commitments_a) = frost::round1::commit(&signing_share, &mut OsRng);
        let (nonce_b, _) = frost::round1::commit(&signing_share, &mut OsRng);

        let session = SignSessionPackage {
            gid: [1; 32],
            sid: [2; 32],
            members: shares.iter().map(|s| s.idx).collect(),
            hashes: vec![[7; 32]],
            content: None,
            kind: "message".to_string(),
            stamp: 1,
            nonces: Some(vec![crate::types::MemberNonceCommitmentSet {
                idx: share.idx,
                entries: vec![crate::types::IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: commitments_a
                        .binding()
                        .serialize()
                        .expect("serialize")
                        .try_into()
                        .expect("len"),
                    hidden_pn: commitments_a
                        .hiding()
                        .serialize()
                        .expect("serialize")
                        .try_into()
                        .expect("len"),
                    code: [3u8; 32],
                }],
            }]),
        };

        let err = create_partial_sig_packages_batch(
            &group,
            &[session],
            share,
            &[vec![nonce_a], vec![nonce_b]],
            group
                .members
                .iter()
                .find(|m| m.idx == share.idx)
                .expect("member")
                .pubkey,
        )
        .expect_err("must reject mismatch");
        assert!(matches!(err, CoreError::BatchItemCountMismatch));
    }

    #[test]
    fn combine_signatures_batch_signs_multiple_sessions() {
        let (group, shares) = two_member_fixture();

        let mut sessions = Vec::new();
        let mut local_nonces_by_share: Vec<Vec<Vec<u8>>> = vec![Vec::new(); shares.len()];
        for idx in 0..3u8 {
            let mut member_nonces = Vec::with_capacity(shares.len());
            for (share_idx, share) in shares.iter().enumerate() {
                let signing_share =
                    frost::keys::SigningShare::deserialize(&share.seckey).expect("signing share");
                let (nonces, commitments) = frost::round1::commit(&signing_share, &mut OsRng);
                local_nonces_by_share[share_idx]
                    .push(nonces.serialize().expect("serialize signing nonces"));
                member_nonces.push(crate::types::MemberNonceCommitmentSet {
                    idx: share.idx,
                    entries: vec![crate::types::IndexedPublicNonceCommitment {
                        hash_index: 0,
                        binder_pn: commitments
                            .binding()
                            .serialize()
                            .expect("serialize")
                            .try_into()
                            .expect("len"),
                        hidden_pn: commitments
                            .hiding()
                            .serialize()
                            .expect("serialize")
                            .try_into()
                            .expect("len"),
                        code: [idx; 32],
                    }],
                });
            }

            sessions.push(SignSessionPackage {
                gid: [1; 32],
                sid: [10 + idx; 32],
                members: shares.iter().map(|s| s.idx).collect(),
                hashes: vec![[20 + idx; 32]],
                content: None,
                kind: "message".to_string(),
                stamp: 100 + idx as u32,
                nonces: Some(member_nonces),
            });
        }

        let mut pkgs_per_share = Vec::with_capacity(shares.len());
        for (share_idx, share) in shares.iter().enumerate() {
            let pubkey = group
                .members
                .iter()
                .find(|m| m.idx == share.idx)
                .expect("member")
                .pubkey;
            let pkgs = create_partial_sig_packages_batch(
                &group,
                &sessions,
                share,
                &local_nonces_by_share[share_idx]
                    .iter()
                    .map(|n| {
                        vec![
                            frost::round1::SigningNonces::deserialize(n)
                                .expect("deserialize signing nonces"),
                        ]
                    })
                    .collect::<Vec<_>>(),
                pubkey,
            )
            .expect("create batch");
            pkgs_per_share.push(pkgs);
        }

        let mut pkgs_by_session: Vec<Vec<PartialSigPackage>> = vec![Vec::new(); sessions.len()];
        for pkgs in pkgs_per_share {
            for (session_idx, pkg) in pkgs.into_iter().enumerate() {
                pkgs_by_session[session_idx].push(pkg);
            }
        }
        let sigs =
            combine_signatures_batch(&group, &sessions, &pkgs_by_session).expect("combine batch");
        assert_eq!(sigs.len(), 3);
    }
}
