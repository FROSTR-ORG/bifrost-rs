//! FROST threshold-sign verify-roundtrip coverage (R3 / Bucket I, PR-I1).
//!
//! The in-crate `sign.rs` unit tests cover combine-determinism and partial-sig
//! tamper rejection, but only for a single 2-of-2 shape. This integration suite
//! exercises the full `keygen -> commit -> partial-sign -> aggregate -> verify`
//! path across several threshold shapes through the crate's public API.
//!
//! These are *verify-roundtrip* tests, not pinned known-answer vectors: keygen
//! and nonce generation in `bifrost-core` are seeded from `OsRng` with no
//! deterministic seam, so an aggregated signature cannot be pinned to a fixed
//! hex constant. Instead we assert that a freshly aggregated signature verifies
//! under the group key. `combine_signatures` already calls
//! `verifying_key().verify(...)` internally (sign.rs) and errors on failure, and
//! we additionally re-verify the returned 64-byte signature independently here
//! so the round-trip is asserted at the test boundary, not just inside the SUT.

use bifrost_core::secret::SharePrivateKey;
use bifrost_core::{
    GroupPackage, IndexedPublicNonceCommitment, MemberNonceCommitmentSet, MemberPackage,
    PartialSigPackage, SharePackage, SignSessionPackage, combine_signatures,
    create_partial_sig_package,
};
use frost_secp256k1_tr_unofficial::{self as frost, keys::EvenY};
use rand_core::OsRng;

/// x-only 32-byte group key -> 0x02-prefixed compressed point, matching the
/// (private) `pubkey32_to_even_compressed` helper in sign.rs.
fn even_compressed(pubkey32: &[u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x02;
    out[1..].copy_from_slice(pubkey32);
    out
}

/// Generate a `min`-of-`max` keyset and return the `GroupPackage` (with all
/// `max` members) plus one `SharePackage` per member, sorted by index.
fn generate_keyset(min: u16, max: u16) -> (GroupPackage, Vec<SharePackage>) {
    // frost's generate_with_dealer takes (max_signers, min_signers): total
    // membership first, then the signing threshold.
    let (shares, group_pub) =
        frost::keys::generate_with_dealer(max, min, frost::keys::IdentifierList::Default, OsRng)
            .expect("dealer keygen");
    let group_pub = group_pub.into_even_y(None);

    let mut members = Vec::new();
    let mut share_packages = Vec::new();
    for (id, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)
            .expect("key package")
            .into_even_y(None);

        let mut member_pk = [0u8; 33];
        member_pk.copy_from_slice(
            &key_package
                .verifying_share()
                .serialize()
                .expect("serialize verifying share"),
        );
        members.push(MemberPackage {
            idx: id.serialize()[31] as u16,
            pubkey: member_pk,
        });

        let mut seckey = [0u8; 32];
        seckey.copy_from_slice(&key_package.signing_share().serialize());
        share_packages.push(SharePackage {
            idx: id.serialize()[31] as u16,
            seckey: SharePrivateKey::new(seckey),
        });
    }
    members.sort_by_key(|m| m.idx);
    share_packages.sort_by_key(|s| s.idx);

    let mut group_pk = [0u8; 32];
    group_pk.copy_from_slice(
        &group_pub
            .verifying_key()
            .serialize()
            .expect("serialize group key")[1..],
    );

    (
        GroupPackage {
            group_name: "RoundtripGroup".to_string(),
            group_pk,
            threshold: min,
            members,
        },
        share_packages,
    )
}

/// Drive a full threshold-sign for `message` using the first `min` members as
/// signers, returning the aggregated 64-byte signature. Returns `Err` if any
/// stage (including the internal aggregate-verify) fails.
fn sign_and_aggregate(min: u16, max: u16, message: [u8; 32]) -> Result<[u8; 64], String> {
    let (group, shares) = generate_keyset(min, max);
    let signers = &shares[..min as usize];

    // Round 1: each signer commits a fresh nonce pair.
    let mut signer_nonces: Vec<frost::round1::SigningNonces> = Vec::with_capacity(signers.len());
    let mut nonce_sets: Vec<MemberNonceCommitmentSet> = Vec::with_capacity(signers.len());
    for share in signers {
        let signing_share = frost::keys::SigningShare::deserialize(share.seckey.expose_bytes())
            .map_err(|e| e.to_string())?;
        let (nonces, commitments) = frost::round1::commit(&signing_share, &mut OsRng);

        let binder_pn: [u8; 33] = commitments
            .binding()
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "binder length".to_string())?;
        let hidden_pn: [u8; 33] = commitments
            .hiding()
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "hiding length".to_string())?;

        nonce_sets.push(MemberNonceCommitmentSet {
            idx: share.idx,
            entries: vec![IndexedPublicNonceCommitment {
                hash_index: 0,
                binder_pn,
                hidden_pn,
                code: [0u8; 32],
            }],
        });
        signer_nonces.push(nonces);
    }

    let session = SignSessionPackage {
        gid: [0u8; 32],
        sid: [1u8; 32],
        members: signers.iter().map(|s| s.idx).collect(),
        hashes: vec![message],
        content: None,
        kind: "message".to_string(),
        stamp: 1,
        nonces: Some(nonce_sets),
    };

    // Round 2: each signer produces its partial signature package.
    let mut pkgs: Vec<PartialSigPackage> = Vec::with_capacity(signers.len());
    for (i, share) in signers.iter().enumerate() {
        let member = group
            .members
            .iter()
            .find(|m| m.idx == share.idx)
            .ok_or_else(|| "missing member".to_string())?;
        let pubkey: [u8; 32] = member.pubkey[1..]
            .try_into()
            .map_err(|_| "xonly pubkey".to_string())?;
        let pkg = create_partial_sig_package(
            &group,
            &session,
            share,
            std::slice::from_ref(&signer_nonces[i]),
            pubkey,
        )
        .map_err(|e| format!("{e:?}"))?;
        pkgs.push(pkg);
    }

    // Aggregate (internally verifies under the group key, errors on failure).
    let sigs = combine_signatures(&group, &session, &pkgs).map_err(|e| format!("{e:?}"))?;
    assert_eq!(sigs.len(), 1, "one hash -> one signature");
    let entry = &sigs[0];
    assert_eq!(entry.sighash, message, "signature is bound to the message");
    assert_eq!(
        entry.pubkey, group.group_pk,
        "signature carries the group pk"
    );

    // Independently re-verify at the test boundary so the round-trip is asserted
    // here, not only inside combine_signatures.
    let verifying_key = frost::VerifyingKey::deserialize(&even_compressed(&group.group_pk))
        .map_err(|e| e.to_string())?;
    let signature = frost::Signature::deserialize(&entry.signature).map_err(|e| e.to_string())?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|e| format!("independent verify failed: {e}"))?;

    Ok(entry.signature)
}

#[test]
fn threshold_sign_verifies_for_2_of_3() {
    let sig = sign_and_aggregate(2, 3, [0x11u8; 32]).expect("2-of-3 roundtrip");
    assert_ne!(sig, [0u8; 64], "signature must be non-trivial");
}

#[test]
fn threshold_sign_verifies_for_3_of_5() {
    let sig = sign_and_aggregate(3, 5, [0x22u8; 32]).expect("3-of-5 roundtrip");
    assert_ne!(sig, [0u8; 64]);
}

#[test]
fn threshold_sign_verifies_for_2_of_2() {
    sign_and_aggregate(2, 2, [0x33u8; 32]).expect("2-of-2 roundtrip");
}

/// A different message under the same shape produces a different signature
/// (sanity that the message is actually bound) and still verifies.
#[test]
fn distinct_messages_produce_distinct_signatures() {
    let a = sign_and_aggregate(2, 3, [0xAAu8; 32]).expect("message a");
    let b = sign_and_aggregate(2, 3, [0xBBu8; 32]).expect("message b");
    assert_ne!(a, b, "different messages must not collide");
}

/// Deterministic sweep over several threshold shapes and messages, standing in
/// for a property test without adding a proptest dependency to this offline-first
/// workspace. Every (min, max, message) combination must sign and verify.
#[test]
fn threshold_sign_roundtrip_sweep() {
    let shapes: &[(u16, u16)] = &[(2, 2), (2, 3), (3, 3), (3, 4), (3, 5), (2, 5), (4, 5)];
    for &(min, max) in shapes {
        // A handful of structurally different messages per shape.
        for seed in 0u8..4 {
            let mut message = [0u8; 32];
            for (i, b) in message.iter_mut().enumerate() {
                *b = seed
                    .wrapping_add(i as u8)
                    .wrapping_mul(7)
                    .wrapping_add(min as u8);
            }
            sign_and_aggregate(min, max, message)
                .unwrap_or_else(|e| panic!("{min}-of-{max} seed {seed} failed: {e}"));
        }
    }
}
