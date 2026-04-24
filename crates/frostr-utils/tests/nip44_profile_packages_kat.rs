//! Stack 3 (profile backup) NIP-44 known-answer test.
//!
//! Part of the KAT-freeze (A.5.pre) landed ahead of the NIP-44 cipher-stack
//! consolidation in A.5.main. These tests pin the exact ciphertext bytes
//! produced by the current `frostr-utils::profile_packages` stack for a
//! fixed conversation key, nonce, and plaintext — bypassing the upstream
//! `derive_profile_backup_conversation_key` so that the KAT exercises only
//! the cipher stack, not the key-derivation path.
//!
//! Three KAT stacks exist across the workspace:
//!   - Stack 1: `bifrost-signer::crypto` (peer bridge)
//!   - Stack 2: `frostr-utils::protocol` (peer onboarding-protocol)
//!   - Stack 3: `frostr-utils::profile_packages` (this file)
//!
//! PR4 will collapse all three into `bifrost-core::nip44`; these KATs are
//! the byte-level regression net that migration will be validated against.

use frostr_utils::profile_packages::{
    decrypt_nip44_compatible_payload, encrypt_nip44_compatible_payload_with_nonce,
};

/// KAT-freeze for Stack 3's encrypt/decrypt path. Conversation key is
/// fixed at [42u8; 32], nonce at [13u8; 32], plaintext is a short fixed
/// string. The expected ciphertext is the pinned base64-NO_PAD byte
/// string the current implementation produces.
#[test]
fn stack3_encrypt_with_fixed_conversation_key_and_nonce_matches_pinned_ciphertext() {
    // Per plan: fix the conversation key directly, bypassing
    // `derive_profile_backup_conversation_key` so that the KAT isolates the
    // cipher stack from the key-derivation path.
    let conversation_key: [u8; 32] = [42u8; 32];
    let nonce32: [u8; 32] = [13u8; 32];
    let plaintext = "stack3-profile-backup-kat";

    // Pinned ciphertext (base64, STANDARD_NO_PAD). Captured from the
    // current Stack 3 (`frostr-utils::profile_packages`) implementation
    // against the fixed tuple above.
    const EXPECTED: &str = "Ag0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NfoDNVVGvwHhqyHOvLNntVSfhWKVWFf/UkXq/Vd/HVwp4vWV6Ev752nkPySZsi7h3hPhl5MZgg9DdhuAeHWzfUvZX";

    let actual =
        encrypt_nip44_compatible_payload_with_nonce(&conversation_key, &nonce32, plaintext)
            .expect("encrypt");
    assert_eq!(
        actual, EXPECTED,
        "Stack 3 ciphertext drift — any A.5.main change must re-pin this constant"
    );

    // Round-trip via the same conversation key.
    let recovered =
        decrypt_nip44_compatible_payload(&conversation_key, &actual).expect("round trip decrypt");
    assert_eq!(recovered, plaintext);
}
