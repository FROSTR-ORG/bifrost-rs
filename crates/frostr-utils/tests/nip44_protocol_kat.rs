//! Stack 2 (peer onboarding-protocol) NIP-44 known-answer test.
//!
//! Part of the KAT-freeze (A.5.pre) landed ahead of the NIP-44 cipher-stack
//! consolidation in A.5.main. These tests pin the exact ciphertext bytes
//! produced by the current `frostr-utils::protocol` stack for fixed inputs
//! so any byte drift during consolidation (A.5.main / PR4) fails loudly.
//!
//! Three KAT stacks exist across the workspace:
//!   - Stack 1: `bifrost-signer::crypto` (peer bridge)
//!   - Stack 2: `frostr-utils::protocol` (this file)
//!   - Stack 3: `frostr-utils::profile_packages` (profile backups)
//!
//! PR4 will collapse all three into `bifrost-core::nip44`; these KATs are
//! the byte-level regression net that migration will be validated against.

use frostr_utils::protocol::{decrypt_content_from_peer, encrypt_content_for_peer_with_nonce};
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;

fn derive_xonly_hex(seckey: &[u8; 32]) -> String {
    let sk = SecretKey::from_slice(seckey).expect("seckey");
    let encoded = sk.public_key().to_encoded_point(true);
    hex::encode(&encoded.as_bytes()[1..])
}

/// KAT-freeze for Stack 2's encrypt/decrypt path. Inputs are fully fixed,
/// including the 32-byte nonce; the expected ciphertext is the pinned byte
/// string that the current implementation produces. A byte-for-byte match
/// is required; any drift during A.5.main consolidation must re-capture
/// and re-commit.
#[test]
fn stack2_encrypt_with_fixed_nonce_matches_pinned_ciphertext() {
    // Per plan: local seckey = [8u8; 32], peer seckey = [7u8; 32].
    let local_seckey: [u8; 32] = [8u8; 32];
    let peer_seckey: [u8; 32] = [7u8; 32];
    let peer_xonly = derive_xonly_hex(&peer_seckey);
    let local_xonly = derive_xonly_hex(&local_seckey);

    let plaintext = "stack2-protocol-kat";
    let nonce32: [u8; 32] = [11u8; 32];

    // Pinned ciphertext (base64, STANDARD_NO_PAD). Captured from the
    // current Stack 2 (`frostr-utils::protocol`) implementation against the
    // fixed tuple above.
    const EXPECTED: &str = "AgsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCgUyUep4VmwGtprFe5zyHEAvlNEjuJhYSQH3vWNduZIysmxz60+FcHKo1iXXBkGJ2oLKmmldqSXxeKoRtdYR2+qz";

    let actual =
        encrypt_content_for_peer_with_nonce(local_seckey, &peer_xonly, plaintext, nonce32)
            .expect("encrypt");
    assert_eq!(
        actual, EXPECTED,
        "Stack 2 ciphertext drift — any A.5.main change must re-pin this constant"
    );

    // Round-trip: peer decrypts using their seckey and the local x-only.
    let recovered = decrypt_content_from_peer(peer_seckey, &local_xonly, &actual)
        .expect("round trip decrypt");
    assert_eq!(recovered, plaintext);
}
