//! Stack 1 (peer bridge) NIP-44 known-answer tests.
//!
//! Originally landed as part of the KAT-freeze (A.5.pre) ahead of the
//! NIP-44 cipher-stack consolidation in A.5.main. With consolidation now
//! complete (PR4), these tests exercise the canonical implementation in
//! `bifrost_core::nip44` directly. They remain pinned to the same
//! ciphertext bytes that the pre-consolidation `bifrost-signer::crypto`
//! stack produced — any byte drift fails here.
//!
//! The three historical KAT stacks (signer peer bridge, onboarding
//! protocol, profile backup) now all route through
//! `bifrost_core::nip44`; their per-stack KAT files stay in place as
//! byte-level regression anchors.
//!
//! The co-located home for this Stack-1 KAT is preserved under
//! `bifrost-signer` so that the cross-implementation anchor keeps its
//! pre-existing repo location.

use bifrost_core::nip44;

fn derive_xonly_hex(seckey: &[u8; 32]) -> String {
    use k256::SecretKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let sk = SecretKey::from_slice(seckey).expect("seckey");
    let encoded = sk.public_key().to_encoded_point(true);
    hex::encode(&encoded.as_bytes()[1..])
}

fn xonly_bytes(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("xonly hex");
    assert_eq!(bytes.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// JS-generated NIP-44 v2 payload captured from the reference TypeScript
/// implementation. This is the one load-bearing cross-implementation anchor
/// in the repo — the Rust stack MUST decrypt bytes the JS stack produced.
///
/// Originally exercised inline in `crates/bifrost-signer/src/crypto.rs`
/// before being hoisted here as part of A.5.pre; PR4 routed this test
/// through `bifrost_core::nip44::decrypt_from_peer` directly.
#[test]
fn stack1_decrypts_js_generated_nip44_payload() {
    let local_seckey =
        hex::decode("579689f6508912ed1fc14b656426a1669b1e15510e33304b2c9e62248bd9299e")
            .expect("hex seckey");
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&local_seckey);

    let peer_pubkey32 = "c8d330c2d4cc93bd48e2d865beef3b86c45d80326e53d0f897df055816651dbd";
    let peer_pubkey = xonly_bytes(peer_pubkey32);

    let payload = "AgcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHVjH09L8c2jhZOTvj0AILSiZ+7cwhoXDehgU1ieJdokoDSRlLk23Sveljn8K8WcJ/4wPFfu19mxGKiht58B8eQf0C/agzO4RGabcZqH0XwSTBBY07UklU6qnJ06V3ij5NjWXU+XreZRV0Bc/e52u/h6SO4tKELe2OFsh3H6sCjdlNgattHxKHfiO5QQPj+VpjGeXVk1PyThUPsCVVJTjK+IIWedUFXd2cXuPBcT6RzrYtKjnrG7W9KsgqCyaWRneaGAbAbD0G/N8k8lrq6tl8aPmLPyoin4V12s4cwk6+Zd94Sw";
    let plaintext = nip44::decrypt_from_peer(&sk, &peer_pubkey, payload).expect("decrypt");
    assert!(plaintext.contains("\"request_id\":\"vec-1\""));
    assert!(plaintext.contains("\"type\":\"OnboardRequest\""));
    assert!(plaintext.contains("\"idx\":2"));
}

/// KAT-freeze for Stack 1's encrypt path. Inputs are fully fixed, including
/// the 32-byte nonce; the expected ciphertext is the pinned byte string that
/// the pre-consolidation implementation produced. Any byte drift after PR4
/// would surface here and must be investigated rather than re-pinned.
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
    let mut bob_sk = [0u8; 32];
    bob_sk.copy_from_slice(&hex::decode(bob_seckey_hex).expect("bob seckey"));
    let bob_xonly = xonly_bytes(&derive_xonly_hex(&bob_sk));

    // Pinned ciphertext (base64, STANDARD_NO_PAD). Captured from the
    // pre-consolidation Stack 1 implementation against the fixed
    // (seckey, peer_pubkey, nonce, plaintext) tuple above.
    const EXPECTED: &str = "AhEiM0RVZneImaq7zN3u/wAQIDBAUGBwgJCgsMDQ4PABZ8K8mjjGm74/ln/n8hReOytGO3Wk5NvorJOZhSOES4CDZaApRQ3CU3da65KQVaNa2Y9wGYfMKvjxaFtWJTRL+/j3";

    let actual = nip44::encrypt_for_peer(&sk, &bob_xonly, &nonce32, plaintext).expect("encrypt");
    assert_eq!(
        actual, EXPECTED,
        "Stack 1 ciphertext drift — see test doc for re-capture procedure"
    );

    // Round-trip sanity: Bob decrypts with his seckey and Alice's x-only.
    let alice_xonly = xonly_bytes(&derive_xonly_hex(&sk));
    let recovered =
        nip44::decrypt_from_peer(&bob_sk, &alice_xonly, &actual).expect("round trip decrypt");
    assert_eq!(recovered, plaintext);
}
