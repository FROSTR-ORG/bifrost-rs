//! Stack 2 (peer onboarding-protocol) NIP-44 known-answer test.
//!
//! Originally landed as part of the KAT-freeze (A.5.pre) ahead of the
//! NIP-44 cipher-stack consolidation in A.5.main. With consolidation
//! now complete (PR4), this test calls the canonical
//! `bifrost_core::nip44` API directly and re-asserts the SAME pinned
//! ciphertext bytes that the pre-consolidation `frostr-utils::protocol`
//! stack produced. Any byte drift during the move surfaces here.
//!
//! The three historical KAT stacks (signer peer bridge, onboarding
//! protocol, profile backup) now all route through
//! `bifrost_core::nip44`; each crate keeps its per-stack KAT file as a
//! byte-level regression anchor.

use bifrost_core::nip44;
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;

fn derive_xonly_bytes(seckey: &[u8; 32]) -> [u8; 32] {
    let sk = SecretKey::from_slice(seckey).expect("seckey");
    let encoded = sk.public_key().to_encoded_point(true);
    let mut out = [0u8; 32];
    out.copy_from_slice(&encoded.as_bytes()[1..]);
    out
}

/// KAT-freeze for Stack 2's encrypt/decrypt path. Inputs are fully fixed,
/// including the 32-byte nonce; the expected ciphertext is the pinned byte
/// string the pre-consolidation `frostr-utils::protocol` implementation
/// produced. A byte-for-byte match is required.
#[test]
fn stack2_encrypt_with_fixed_nonce_matches_pinned_ciphertext() {
    // Per plan: local seckey = [8u8; 32], peer seckey = [7u8; 32].
    let local_seckey: [u8; 32] = [8u8; 32];
    let peer_seckey: [u8; 32] = [7u8; 32];
    let peer_xonly = derive_xonly_bytes(&peer_seckey);
    let local_xonly = derive_xonly_bytes(&local_seckey);

    let plaintext = "stack2-protocol-kat";
    let nonce32: [u8; 32] = [11u8; 32];

    // Pinned ciphertext (base64, STANDARD_NO_PAD). Captured from the
    // pre-consolidation Stack 2 (`frostr-utils::protocol`)
    // implementation against the fixed tuple above.
    const EXPECTED: &str = "AgsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCgUyUep4VmwGtprFe5zyHEAvlNEjuJhYSQH3vWNduZIysmxz60+FcHKo1iXXBkGJ2oLKmmldqSXxeKoRtdYR2+qz";

    let actual = nip44::encrypt_for_peer(&local_seckey, &peer_xonly, &nonce32, plaintext)
        .expect("encrypt");
    assert_eq!(
        actual, EXPECTED,
        "Stack 2 ciphertext drift — any change must re-pin this constant"
    );

    // Round-trip: peer decrypts using their seckey and the local x-only.
    let recovered =
        nip44::decrypt_from_peer(&peer_seckey, &local_xonly, &actual).expect("round trip decrypt");
    assert_eq!(recovered, plaintext);
}
