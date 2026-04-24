//! Stack 1 (peer bridge) NIP-44 known-answer tests.
//!
//! Part of the KAT-freeze (A.5.pre) landed ahead of the NIP-44 cipher-stack
//! consolidation in A.5.main. These tests pin the exact ciphertext bytes
//! produced by the current `bifrost-signer::crypto` stack for fixed inputs so
//! any byte drift during consolidation (A.5.main / PR4) fails loudly.
//!
//! Three KAT stacks exist across the workspace:
//!   - Stack 1: `bifrost-signer::crypto` (this file)
//!   - Stack 2: `frostr-utils::protocol` (peer messaging)
//!   - Stack 3: `frostr-utils::profile_packages` (profile backups)
//!
//! PR4 will collapse all three into `bifrost-core::nip44`; these KATs are the
//! byte-level regression net that migration will be validated against.

use bifrost_signer::__kat_exports::{
    decrypt_content_from_peer, encrypt_content_for_peer_with_nonce,
};

/// JS-generated NIP-44 v2 payload captured from the reference TypeScript
/// implementation. This is the one load-bearing cross-implementation anchor
/// in the repo — the Rust stack MUST decrypt bytes the JS stack produced.
///
/// Originally exercised inline in `crates/bifrost-signer/src/crypto.rs`
/// before being hoisted here as part of A.5.pre.
#[test]
fn stack1_decrypts_js_generated_nip44_payload() {
    let local_seckey =
        hex::decode("579689f6508912ed1fc14b656426a1669b1e15510e33304b2c9e62248bd9299e")
            .expect("hex seckey");
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&local_seckey);

    let peer_pubkey32 = "c8d330c2d4cc93bd48e2d865beef3b86c45d80326e53d0f897df055816651dbd";
    let payload = "AgcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHVjH09L8c2jhZOTvj0AILSiZ+7cwhoXDehgU1ieJdokoDSRlLk23Sveljn8K8WcJ/4wPFfu19mxGKiht58B8eQf0C/agzO4RGabcZqH0XwSTBBY07UklU6qnJ06V3ij5NjWXU+XreZRV0Bc/e52u/h6SO4tKELe2OFsh3H6sCjdlNgattHxKHfiO5QQPj+VpjGeXVk1PyThUPsCVVJTjK+IIWedUFXd2cXuPBcT6RzrYtKjnrG7W9KsgqCyaWRneaGAbAbD0G/N8k8lrq6tl8aPmLPyoin4V12s4cwk6+Zd94Sw";
    let plaintext = decrypt_content_from_peer(sk, peer_pubkey32, payload).expect("decrypt");
    assert!(plaintext.contains("\"request_id\":\"vec-1\""));
    assert!(plaintext.contains("\"type\":\"OnboardRequest\""));
    assert!(plaintext.contains("\"idx\":2"));
}

/// KAT-freeze for Stack 1's encrypt path. Inputs are fully fixed, including
/// the 32-byte nonce; the expected ciphertext is the pinned byte string that
/// the current implementation produces. A byte-for-byte match is required;
/// any drift during A.5.main consolidation must re-capture and re-commit.
///
/// To re-capture after an intentional break: run this test, copy the
/// `actual` value from the assertion failure, paste it into EXPECTED, and
/// audit why the bytes changed.
#[test]
fn stack1_encrypt_with_fixed_nonce_matches_pinned_ciphertext() {
    // Fixed local seckey (Alice).
    let local_seckey =
        hex::decode("579689f6508912ed1fc14b656426a1669b1e15510e33304b2c9e62248bd9299e")
            .expect("alice seckey");
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&local_seckey);

    let plaintext = r#"{"hello":"world"}"#;
    let nonce32: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0, 0x01,
    ];

    // Deterministically derive Bob's x-only pubkey from a fixed seckey.
    let bob_seckey_hex = "9f4f7b8b4f3d5d8f553a0c4ff5f3f379c2f4ab78ac96f8f1db2098ea8b0f0d72";
    let bob_xonly = derive_fixed_peer_pubkey_hex(bob_seckey_hex);

    // Pinned ciphertext (base64, STANDARD_NO_PAD). Captured from the current
    // Stack 1 implementation against the fixed (seckey, peer_pubkey, nonce,
    // plaintext) tuple above.
    const EXPECTED: &str = "AhEiM0RVZneImaq7zN3u/wAQIDBAUGBwgJCgsMDQ4PABZ8K8mjjGm74/ln/n8hReOytGO3Wk5NvorJOZhSOES4CDZaApRQ3CU3da65KQVaNa2Y9wGYfMKvjxaFtWJTRL+/j3";

    let actual = encrypt_content_for_peer_with_nonce(sk, &bob_xonly, plaintext, nonce32)
        .expect("encrypt");
    assert_eq!(
        actual, EXPECTED,
        "Stack 1 ciphertext drift — see test doc for re-capture procedure"
    );

    // Round-trip sanity: Bob decrypts with his seckey and Alice's x-only.
    let mut bob_sk = [0u8; 32];
    bob_sk.copy_from_slice(&hex::decode(bob_seckey_hex).expect("bob seckey"));
    let alice_xonly = derive_fixed_peer_pubkey_hex(
        "579689f6508912ed1fc14b656426a1669b1e15510e33304b2c9e62248bd9299e",
    );
    let recovered =
        decrypt_content_from_peer(bob_sk, &alice_xonly, &actual).expect("round trip decrypt");
    assert_eq!(recovered, plaintext);
}

fn derive_fixed_peer_pubkey_hex(seckey_hex: &str) -> String {
    use k256::SecretKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let bytes = hex::decode(seckey_hex).expect("seckey hex");
    let sk = SecretKey::from_slice(&bytes).expect("seckey");
    let encoded = sk.public_key().to_encoded_point(true);
    hex::encode(&encoded.as_bytes()[1..])
}
