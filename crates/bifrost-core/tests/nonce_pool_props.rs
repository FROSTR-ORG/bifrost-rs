//! NoncePool invariants (R3 / Bucket I, PR-I1).
//!
//! The in-crate `nonce.rs` unit tests cover generate/consume, FIFO ordering,
//! peer stats, and single-use at the *claim* layer (`take_outgoing_signing_nonces`).
//! This suite adds the higher-value security invariants that were untested:
//!
//! - generation never emits a duplicate public nonce across many peers/calls
//!   (nonce reuse breaks Schnorr threshold signing);
//! - `remap_peer_indexes` is total and *merges* colliding target indexes rather
//!   than erroring (it returns `()`), which the draft plan mis-modelled as a
//!   fallible collision rejection;
//! - an empty pool round-trips through serde_json.
//!
//! These are deterministic loop/sweep tests rather than proptest cases: this is
//! an offline-first workspace and `proptest` is not vendored, so adding it would
//! require a network fetch and a lockfile churn unjustified for test-only code.

use std::collections::{HashMap, HashSet};

use bifrost_core::nonce::NoncePoolConfig;
use bifrost_core::{NoncePool, NoncePoolSecret};
use frost_secp256k1_tr_unofficial::{self as frost};
use rand_core::OsRng;

/// A valid FROST signing share, the seed `generate_for_peer` deserializes. The
/// raw bytes must be a valid scalar, so we derive one from a real dealer keygen
/// rather than using arbitrary bytes.
fn valid_nonce_secret() -> NoncePoolSecret {
    let (shares, _) =
        frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, OsRng)
            .expect("dealer keygen");
    let (_, secret_share) = shares.into_iter().next().expect("at least one share");
    let key_package = frost::keys::KeyPackage::try_from(secret_share).expect("key package");
    let mut seckey = [0u8; 32];
    seckey.copy_from_slice(&key_package.signing_share().serialize());
    NoncePoolSecret::new(seckey)
}

#[test]
fn generated_public_nonces_are_never_reused() {
    let seckey = valid_nonce_secret();
    let config = NoncePoolConfig {
        pool_size: 256,
        ..NoncePoolConfig::default()
    };
    let mut pool = NoncePool::new(1, config);

    // Distinct public commitments (binder, hidden) and codes must be globally
    // unique across every peer and every generate call.
    let mut commitments: HashSet<([u8; 33], [u8; 33])> = HashSet::new();
    let mut codes: HashSet<[u8; 32]> = HashSet::new();
    let mut total = 0usize;

    for peer in 2u16..=6 {
        pool.init_peer(peer);
        // Two separate calls per peer to exercise the incremental top-up path.
        for _ in 0..2 {
            let generated = pool
                .generate_for_peer(peer, 30, &seckey)
                .expect("generate nonces");
            for nonce in &generated {
                assert!(
                    commitments.insert((nonce.binder_pn, nonce.hidden_pn)),
                    "public nonce commitment reused across generations"
                );
                assert!(
                    codes.insert(nonce.code),
                    "nonce code reused across generations"
                );
                total += 1;
            }
        }
    }

    assert_eq!(commitments.len(), total, "every commitment was unique");
    assert_eq!(codes.len(), total, "every code was unique");
    assert!(total >= 250, "sanity: generated a meaningful volume");
}

#[test]
fn remap_preserves_codes_under_a_simple_relabel() {
    let seckey = valid_nonce_secret();
    let mut pool = NoncePool::new(1, NoncePoolConfig::default());
    pool.init_peer(2);
    pool.generate_for_peer(2, 5, &seckey).expect("generate");

    let before = pool.outgoing_public_nonce_codes(2);
    assert!(!before.is_empty());

    // Relabel peer 2 -> 7 (and keep our own index).
    let mut index_map = HashMap::new();
    index_map.insert(2u16, 7u16);
    pool.remap_peer_indexes(1, &index_map);

    assert!(
        pool.outgoing_public_nonce_codes(2).is_empty(),
        "old index no longer holds nonces"
    );
    assert_eq!(
        pool.outgoing_public_nonce_codes(7),
        before,
        "codes moved intact to the new index"
    );
}

#[test]
fn remap_merges_colliding_target_indexes() {
    let seckey = valid_nonce_secret();
    let mut pool = NoncePool::new(1, NoncePoolConfig::default());
    pool.init_peer(2);
    pool.init_peer(3);
    pool.generate_for_peer(2, 4, &seckey)
        .expect("generate peer 2");
    pool.generate_for_peer(3, 6, &seckey)
        .expect("generate peer 3");

    let codes_2 = pool.outgoing_public_nonce_codes(2);
    let codes_3 = pool.outgoing_public_nonce_codes(3);
    assert_eq!(codes_2.len(), 4);
    assert_eq!(codes_3.len(), 6);

    // Both 2 and 3 collapse onto target index 5. remap_peer_indexes is
    // infallible and MERGES rather than rejecting the collision.
    let mut index_map = HashMap::new();
    index_map.insert(2u16, 5u16);
    index_map.insert(3u16, 5u16);
    pool.remap_peer_indexes(1, &index_map);

    let merged = pool.outgoing_public_nonce_codes(5);
    assert_eq!(
        merged.len(),
        codes_2.len() + codes_3.len(),
        "merged index holds the union of both sources"
    );
    let mut expected: Vec<[u8; 32]> = codes_2.into_iter().chain(codes_3).collect();
    expected.sort_unstable();
    assert_eq!(merged, expected, "all source codes survive the merge");

    assert!(pool.outgoing_public_nonce_codes(2).is_empty());
    assert!(pool.outgoing_public_nonce_codes(3).is_empty());
}

#[test]
fn empty_pool_round_trips_through_serde_json() {
    // Only an *empty* pool is exercised: a populated NoncePool nests
    // HashMap<[u8;32], _> maps, and serde_json cannot encode non-string map
    // keys, so populated state crosses persistence boundaries via a DTO rather
    // than direct serde_json. NoncePool is not PartialEq, so we compare by
    // re-serialized form.
    let pool = NoncePool::new(3, NoncePoolConfig::default());
    let json = serde_json::to_string(&pool).expect("serialize empty pool");
    let decoded: NoncePool = serde_json::from_str(&json).expect("deserialize empty pool");
    let reencoded = serde_json::to_string(&decoded).expect("re-serialize");
    assert_eq!(
        json, reencoded,
        "empty-pool state survives a serde_json round-trip"
    );
}
