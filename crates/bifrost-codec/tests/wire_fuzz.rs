//! Structure-aware fuzz of the wire decoders (R3 / Bucket I, PR-I2).
//!
//! `envelope_bounds.rs` pins the envelope size/field caps and `wire.rs` has
//! per-decoder boundary unit tests, but neither throws broad random input at the
//! 17 `TryFrom<*Wire>` decoders. This suite generates thousands of randomized
//! (and frequently malformed) wire structs and asserts every decoder returns
//! `Ok`/`Err` without panicking, overflowing, or unbounded-allocating.
//!
//! It is a deterministic seeded-PRNG sweep rather than a `proptest`/`cargo-fuzz`
//! harness: this workspace builds offline and neither tool is vendored, so a
//! fixed splitmix64 generator gives reproducible coverage with no new dependency.
//! A failure is reproducible from the constant `SEED`.

use bifrost_codec::bridge::{MAX_BRIDGE_ENVELOPE_BYTES, decode_bridge_envelope};
use bifrost_codec::wire::{
    DerivedPublicNonceWire, EcdhEntryWire, EcdhPackageWire, GroupPackageWire,
    IndexedPublicNonceCommitmentWire, MemberNonceCommitmentSetWire, MemberPackageWire,
    MemberPublicNonceWire, MethodPolicyWire, OnboardRequestWire, OnboardResponseWire,
    PartialSigEntryWire, PartialSigPackageWire, PeerScopedPolicyProfileWire, PingPayloadWire,
    SharePackageWire, SignSessionPackageWire,
};
use bifrost_core::types::{
    DerivedPublicNonce, EcdhEntry, EcdhPackage, GroupPackage, IndexedPublicNonceCommitment,
    MemberNonceCommitmentSet, MemberPackage, MemberPublicNonce, MethodPolicy, OnboardRequest,
    OnboardResponse, PartialSigEntry, PartialSigPackage, PeerScopedPolicyProfile, PingPayload,
    SharePackage, SignSessionPackage,
};

const SEED: u64 = 0x5EED_1CE4_B0BA_F00D;
const ROUNDS: usize = 400;

/// Deterministic splitmix64 PRNG — reproducible, no external dependency.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn u16(&mut self) -> u16 {
        self.next_u64() as u16
    }
    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

/// A hex-ish string for a field whose decoder expects `good_len` bytes. Mixes
/// correct-length hex, off-by-one lengths, non-hex junk, empty, and oversized
/// inputs so both the success and every rejection branch are exercised.
fn field(rng: &mut Rng, good_len: usize) -> String {
    match rng.below(6) {
        0 => String::new(),
        1 => hex::encode(rng.bytes(good_len)),
        2 => hex::encode(rng.bytes(good_len + 1)),
        3 => hex::encode(rng.bytes(good_len.saturating_sub(1))),
        4 => "zz".repeat(1 + rng.below(4) as usize),
        _ => "ab".repeat(1 + rng.below(3000) as usize),
    }
}

/// A list length: mostly small, sometimes empty, occasionally over any plausible
/// cap (to hit the "exceeds max size" rejection branches).
fn list_len(rng: &mut Rng) -> usize {
    match rng.below(12) {
        0 => 0,
        11 => 1001,
        n => n as usize,
    }
}

fn rand_u16_vec(rng: &mut Rng) -> Vec<u16> {
    (0..list_len(rng)).map(|_| rng.u16()).collect()
}

/// A free-form identifier string: usually short, occasionally empty or past the
/// 1 KiB identifier cap.
fn rand_ident(rng: &mut Rng) -> String {
    match rng.below(8) {
        0 => String::new(),
        7 => "k".repeat(1025),
        _ => "message".to_string(),
    }
}

fn gen_member(rng: &mut Rng) -> MemberPackageWire {
    MemberPackageWire {
        idx: rng.u16(),
        pubkey: field(rng, 33),
    }
}

fn gen_group(rng: &mut Rng) -> GroupPackageWire {
    GroupPackageWire {
        group_name: rand_ident(rng),
        group_pk: field(rng, 32),
        threshold: rng.u16(),
        members: (0..list_len(rng).min(8)).map(|_| gen_member(rng)).collect(),
    }
}

fn gen_nonce(rng: &mut Rng) -> DerivedPublicNonceWire {
    DerivedPublicNonceWire {
        binder_pn: field(rng, 33),
        hidden_pn: field(rng, 33),
        code: field(rng, 32),
    }
}

fn gen_indexed_commitment(rng: &mut Rng) -> IndexedPublicNonceCommitmentWire {
    IndexedPublicNonceCommitmentWire {
        hash_index: rng.u16(),
        binder_pn: field(rng, 33),
        hidden_pn: field(rng, 33),
        code: field(rng, 32),
    }
}

fn gen_commitment_set(rng: &mut Rng) -> MemberNonceCommitmentSetWire {
    MemberNonceCommitmentSetWire {
        idx: rng.u16(),
        entries: (0..list_len(rng).min(6))
            .map(|_| gen_indexed_commitment(rng))
            .collect(),
    }
}

fn gen_sign_session(rng: &mut Rng) -> SignSessionPackageWire {
    SignSessionPackageWire {
        gid: field(rng, 32),
        sid: field(rng, 32),
        members: rand_u16_vec(rng),
        hashes: (0..list_len(rng).min(8)).map(|_| field(rng, 32)).collect(),
        content: match rng.below(4) {
            0 => None,
            1 => {
                let n = rng.below(64) as usize;
                Some(hex::encode(rng.bytes(n)))
            }
            2 => Some("not-hex".to_string()),
            _ => Some("ab".repeat(16 * 1024 + 1)),
        },
        kind: rand_ident(rng),
        stamp: rng.next_u64() as u32,
        nonces: if rng.bool() {
            None
        } else {
            Some(
                (0..list_len(rng).min(6))
                    .map(|_| gen_commitment_set(rng))
                    .collect(),
            )
        },
    }
}

fn gen_partial_entry(rng: &mut Rng) -> PartialSigEntryWire {
    PartialSigEntryWire {
        hash_index: rng.u16(),
        sighash: field(rng, 32),
        partial_sig: field(rng, 32),
    }
}

fn gen_partial_package(rng: &mut Rng) -> PartialSigPackageWire {
    PartialSigPackageWire {
        idx: rng.u16(),
        sid: field(rng, 32),
        pubkey: field(rng, 32),
        psigs: (0..list_len(rng).min(8))
            .map(|_| gen_partial_entry(rng))
            .collect(),
        nonce_code: if rng.bool() {
            None
        } else {
            Some(field(rng, 32))
        },
        replenish: if rng.bool() {
            None
        } else {
            Some((0..list_len(rng).min(4)).map(|_| gen_nonce(rng)).collect())
        },
    }
}

fn gen_ecdh_entry(rng: &mut Rng) -> EcdhEntryWire {
    EcdhEntryWire {
        ecdh_pk: field(rng, 32),
        keyshare: field(rng, 33),
    }
}

fn gen_ecdh_package(rng: &mut Rng) -> EcdhPackageWire {
    EcdhPackageWire {
        idx: rng.u16(),
        members: rand_u16_vec(rng),
        entries: (0..list_len(rng).min(8))
            .map(|_| gen_ecdh_entry(rng))
            .collect(),
    }
}

fn gen_method_policy(rng: &mut Rng) -> MethodPolicyWire {
    MethodPolicyWire {
        echo: rng.bool(),
        ping: rng.bool(),
        onboard: rng.bool(),
        sign: rng.bool(),
        ecdh: rng.bool(),
    }
}

fn gen_policy_profile(rng: &mut Rng) -> PeerScopedPolicyProfileWire {
    PeerScopedPolicyProfileWire {
        for_peer: field(rng, 32),
        revision: rng.next_u64(),
        updated: rng.next_u64(),
        block_all: rng.bool(),
        request: gen_method_policy(rng),
        respond: gen_method_policy(rng),
    }
}

fn gen_ping(rng: &mut Rng) -> PingPayloadWire {
    PingPayloadWire {
        version: if rng.bool() { 2 } else { rng.u16() },
        advertised_nonces: (0..list_len(rng).min(6)).map(|_| gen_nonce(rng)).collect(),
        held_peer_nonce_codes: (0..list_len(rng).min(6)).map(|_| field(rng, 32)).collect(),
        policy_profile: if rng.bool() {
            None
        } else {
            Some(gen_policy_profile(rng))
        },
        nonce_pool_generation: if rng.bool() {
            String::new()
        } else {
            field(rng, 32)
        },
    }
}

fn gen_member_public_nonce(rng: &mut Rng) -> MemberPublicNonceWire {
    MemberPublicNonceWire {
        idx: rng.u16(),
        binder_pn: field(rng, 33),
        hidden_pn: field(rng, 33),
        code: field(rng, 32),
    }
}

fn gen_share(rng: &mut Rng) -> SharePackageWire {
    SharePackageWire {
        idx: rng.u16(),
        seckey: field(rng, 32),
    }
}

/// Every `TryFrom<*Wire>` decoder must survive arbitrary input without
/// panicking. A panic in any decoder aborts the test at the wire.rs location,
/// reproducible from `SEED`.
#[test]
fn wire_decoders_never_panic_on_arbitrary_input() {
    let mut rng = Rng(SEED);
    for _ in 0..ROUNDS {
        let _ = MemberPackage::try_from(gen_member(&mut rng));
        let _ = GroupPackage::try_from(gen_group(&mut rng));
        let _ = SharePackage::try_from(gen_share(&mut rng));
        let _ = DerivedPublicNonce::try_from(gen_nonce(&mut rng));
        let _ = MemberPublicNonce::try_from(gen_member_public_nonce(&mut rng));
        let _ = IndexedPublicNonceCommitment::try_from(gen_indexed_commitment(&mut rng));
        let _ = MemberNonceCommitmentSet::try_from(gen_commitment_set(&mut rng));
        let _ = SignSessionPackage::try_from(gen_sign_session(&mut rng));
        let _ = PartialSigEntry::try_from(gen_partial_entry(&mut rng));
        let _ = PartialSigPackage::try_from(gen_partial_package(&mut rng));
        let _ = EcdhEntry::try_from(gen_ecdh_entry(&mut rng));
        let _ = EcdhPackage::try_from(gen_ecdh_package(&mut rng));
        let _ = PingPayload::try_from(gen_ping(&mut rng));
        let _ = MethodPolicy::try_from(gen_method_policy(&mut rng));
        let _ = PeerScopedPolicyProfile::try_from(gen_policy_profile(&mut rng));
        let _ = OnboardRequest::try_from(OnboardRequestWire {
            version: rng.u16(),
            nonces: (0..list_len(&mut rng).min(6))
                .map(|_| gen_nonce(&mut rng))
                .collect(),
        });
        let _ = OnboardResponse::try_from(OnboardResponseWire {
            group: gen_group(&mut rng),
            nonces: (0..list_len(&mut rng).min(6))
                .map(|_| gen_nonce(&mut rng))
                .collect(),
        });
    }
}

/// The outer envelope decode path (size guard + serde_json + field-bound
/// validation) must also never panic on junk, and must reject anything over the
/// size cap with `EnvelopeTooLarge` regardless of content.
#[test]
fn decode_bridge_envelope_never_panics_on_junk() {
    let mut rng = Rng(SEED ^ 0xA5A5_A5A5);
    for _ in 0..2000 {
        let len = rng.below(64) as usize;
        let raw: String = (0..len)
            .map(|_| {
                // Printable-ish ASCII plus the odd brace/quote to stress the
                // JSON parser without spending time on huge inputs.
                let c = (rng.below(95) as u8) + 32;
                c as char
            })
            .collect();
        // Must return Ok or Err, never panic.
        let _ = decode_bridge_envelope(&raw);
    }

    // Oversized inputs of varied length are always rejected pre-parse.
    for _ in 0..16 {
        let extra = 1 + rng.below(4096) as usize;
        let oversized = "x".repeat(MAX_BRIDGE_ENVELOPE_BYTES + extra);
        assert!(
            decode_bridge_envelope(&oversized).is_err(),
            "oversized envelope must be rejected"
        );
    }
}
