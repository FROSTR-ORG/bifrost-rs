//! Stack 3 (profile backup) NIP-44 known-answer test.
//!
//! Originally landed as part of the KAT-freeze (A.5.pre) ahead of the
//! NIP-44 cipher-stack consolidation in A.5.main. With consolidation
//! now complete (PR4), this test calls the canonical
//! `bifrost_core::nip44` API directly and re-asserts the SAME pinned
//! ciphertext bytes that the pre-consolidation
//! `frostr-utils::profile_packages` stack produced.
//!
//! Conversation key is fixed directly (bypassing
//! `derive_profile_backup_conversation_key`) so the KAT exercises only
//! the cipher stack, not the key-derivation path.

use bifrost_core::nip44;

/// KAT-freeze for Stack 3's encrypt/decrypt path. Conversation key is
/// fixed at [42u8; 32], nonce at [13u8; 32], plaintext is a short fixed
/// string. The expected ciphertext is the pinned base64-NO_PAD byte
/// string the pre-consolidation implementation produced.
#[test]
fn stack3_encrypt_with_fixed_conversation_key_and_nonce_matches_pinned_ciphertext() {
    // Per plan: fix the conversation key directly, bypassing
    // `derive_profile_backup_conversation_key` so that the KAT isolates the
    // cipher stack from the key-derivation path.
    let conversation_key: [u8; 32] = [42u8; 32];
    let nonce32: [u8; 32] = [13u8; 32];
    let plaintext = "stack3-profile-backup-kat";

    // Pinned ciphertext (base64, STANDARD_NO_PAD). Captured from the
    // pre-consolidation Stack 3 (`frostr-utils::profile_packages`)
    // implementation against the fixed tuple above.
    const EXPECTED: &str = "Ag0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NfoDNVVGvwHhqyHOvLNntVSfhWKVWFf/UkXq/Vd/HVwp4vWV6Ev752nkPySZsi7h3hPhl5MZgg9DdhuAeHWzfUvZX";

    let actual = nip44::encrypt_under_conversation_key(&conversation_key, &nonce32, plaintext)
        .expect("encrypt");
    assert_eq!(
        actual, EXPECTED,
        "Stack 3 ciphertext drift — any change must re-pin this constant"
    );

    // Round-trip via the same conversation key.
    let recovered = nip44::decrypt_under_conversation_key(&conversation_key, &actual)
        .expect("round trip decrypt");
    assert_eq!(recovered, plaintext);
}
