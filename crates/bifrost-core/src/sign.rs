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
    signing_nonces: &frost::round1::SigningNonces,
    pubkey: [u8; 33],
) -> CoreResult<PartialSigPackage> {
    if session.hashes.is_empty() {
        return Err(CoreError::EmptySessionHashes);
    }
    if session.hashes.len() != 1 || session.hashes[0].len() != 1 {
        return Err(CoreError::UnsupportedBatchSigning);
    }

    let key_package = build_key_package(group, share)?;
    let commitments = build_commitments_map(session)?;

    let mut psigs = Vec::with_capacity(session.hashes.len());
    for vec in &session.hashes {
        let Some(sighash) = vec.first() else {
            return Err(CoreError::EmptySessionHashes);
        };

        let signing_package = frost::SigningPackage::new(commitments.clone(), sighash);
        let signature_share = frost::round2::sign(&signing_package, signing_nonces, &key_package)
            .map_err(|e| CoreError::Frost(e.to_string()))?;
        let share_bytes = signature_share.serialize();
        if share_bytes.len() != 32 {
            return Err(CoreError::InvalidScalar);
        }

        let mut partial_sig = [0u8; 32];
        partial_sig.copy_from_slice(&share_bytes);

        psigs.push(PartialSigEntry {
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
    let commitments = build_commitments_map(session)?;

    for psig in &pkg.psigs {
        let signing_package = frost::SigningPackage::new(commitments.clone(), &psig.sighash);
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
    let commitments = build_commitments_map(session)?;

    let mut out = Vec::with_capacity(session.hashes.len());
    for vec in &session.hashes {
        let Some(sighash) = vec.first() else {
            return Err(CoreError::EmptySessionHashes);
        };

        let signing_package = frost::SigningPackage::new(commitments.clone(), sighash);
        let mut signature_shares = BTreeMap::new();

        for pkg in pkgs {
            let identifier = frost::Identifier::try_from(pkg.idx)
                .map_err(|e| CoreError::Frost(e.to_string()))?;
            let entry = pkg
                .psigs
                .iter()
                .find(|e| e.sighash == *sighash)
                .ok_or(CoreError::EmptySessionHashes)?;
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

fn build_commitments_map(
    session: &SignSessionPackage,
) -> CoreResult<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>> {
    let nonces = session.nonces.as_ref().ok_or(CoreError::MissingNonces)?;
    let mut commitments = BTreeMap::new();

    for nonce in nonces {
        let identifier =
            frost::Identifier::try_from(nonce.idx).map_err(|e| CoreError::Frost(e.to_string()))?;
        let hiding = frost::round1::NonceCommitment::deserialize(&nonce.hidden_pn)
            .map_err(|e| CoreError::Frost(e.to_string()))?;
        let binding = frost::round1::NonceCommitment::deserialize(&nonce.binder_pn)
            .map_err(|e| CoreError::Frost(e.to_string()))?;
        commitments.insert(
            identifier,
            frost::round1::SigningCommitments::new(hiding, binding),
        );
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

    #[test]
    fn combine_signatures_is_deterministic() {
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
            nonces.push(crate::types::MemberPublicNonce {
                idx: share.idx,
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
            });
            local_nonces.push(n);
        }

        let session = SignSessionPackage {
            gid: [1; 32],
            sid: [2; 32],
            members: vec![1, 2],
            hashes: vec![vec![[7; 32]]],
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
            let commitments = build_commitments_map(&session).expect("commitments");
            let sp = frost::SigningPackage::new(commitments, &[7; 32]);
            let sig_share = frost::round2::sign(&sp, &parsed_nonces, &key_pkg).expect("sign share");

            let mut ps = [0u8; 32];
            ps.copy_from_slice(&sig_share.serialize());

            pkgs.push(PartialSigPackage {
                idx: share.idx,
                sid: session.sid,
                pubkey: member.pubkey,
                psigs: vec![PartialSigEntry {
                    sighash: [7; 32],
                    partial_sig: ps,
                }],
                nonce_code: None,
                replenish: None,
            });
        }

        let one = combine_signatures(&group, &session, &pkgs).expect("combine");
        let two = combine_signatures(&group, &session, &pkgs).expect("combine");
        assert_eq!(one, two);
    }
}
