//! Thin adapter over `bifrost_core::nip44` for the peer-bridge cipher
//! path. The canonical implementation lives in
//! `crates/bifrost-core/src/nip44/mod.rs`; this module only translates
//! the hex-encoded peer pubkey that legacy signer call sites pass and
//! maps `CipherError` onto `SignerError::DecryptFailed`.

use bifrost_core::nip44::{self, CipherError};

use crate::{Result, SignerError};

pub(crate) fn encrypt_content_for_peer(
    seckey: [u8; 32],
    peer_pubkey32: &str,
    plaintext: &str,
) -> Result<String> {
    let peer_pubkey = decode_peer_pubkey32(peer_pubkey32)?;
    nip44::encrypt_for_peer_random_nonce(&seckey, &peer_pubkey, plaintext).map_err(cipher_error)
}

pub(crate) fn decrypt_content_from_peer(
    seckey: [u8; 32],
    peer_pubkey32: &str,
    payload: &str,
) -> Result<String> {
    let peer_pubkey = decode_peer_pubkey32(peer_pubkey32)?;
    nip44::decrypt_from_peer(&seckey, &peer_pubkey, payload).map_err(cipher_error)
}

/// Fixed-nonce encrypt variant. Crate-private; the test fixtures in
/// `lib.rs` use this to craft deterministic peer events. Integration
/// KAT anchor lives at `tests/nip44_kat.rs` and now calls
/// `bifrost_core::nip44::encrypt_for_peer` directly.
#[cfg(test)]
pub(crate) fn encrypt_content_for_peer_with_nonce(
    seckey: [u8; 32],
    peer_pubkey32: &str,
    plaintext: &str,
    nonce32: [u8; 32],
) -> Result<String> {
    let peer_pubkey = decode_peer_pubkey32(peer_pubkey32)?;
    nip44::encrypt_for_peer(&seckey, &peer_pubkey, &nonce32, plaintext).map_err(cipher_error)
}

fn decode_peer_pubkey32(peer_pubkey32: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(peer_pubkey32)
        .map_err(|e| SignerError::DecryptFailed(format!("invalid peer pubkey hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(SignerError::DecryptFailed(
            "peer pubkey must be 32 bytes x-only".to_string(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn cipher_error(e: CipherError) -> SignerError {
    SignerError::DecryptFailed(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        decrypt_content_from_peer, encrypt_content_for_peer_with_nonce,
    };
    use crate::SignerError;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    // The JS-generated NIP-44 cross-implementation KAT and encrypt /
    // decrypt byte-stability KAT live in
    // `tests/nip44_kat.rs::stack1_*`.

    #[test]
    fn encrypt_round_trip_with_fixed_nonce_is_stable_and_decryptable() {
        let alice_seckey =
            hex::decode("579689f6508912ed1fc14b656426a1669b1e15510e33304b2c9e62248bd9299e")
                .expect("alice seckey");
        let bob_seckey =
            hex::decode("9f4f7b8b4f3d5d8f553a0c4ff5f3f379c2f4ab78ac96f8f1db2098ea8b0f0d72")
                .expect("bob seckey");
        let mut alice = [0u8; 32];
        let mut bob = [0u8; 32];
        alice.copy_from_slice(&alice_seckey);
        bob.copy_from_slice(&bob_seckey);
        let bob_xonly = hex::encode(
            &k256::SecretKey::from_slice(&bob)
                .expect("bob secret key")
                .public_key()
                .to_encoded_point(true)
                .as_bytes()[1..],
        );
        let alice_xonly = hex::encode(
            &k256::SecretKey::from_slice(&alice)
                .expect("alice secret key")
                .public_key()
                .to_encoded_point(true)
                .as_bytes()[1..],
        );

        let payload = encrypt_content_for_peer_with_nonce(
            alice,
            &bob_xonly,
            r#"{"hello":"world"}"#,
            [7u8; 32],
        )
        .expect("encrypt");
        let plaintext =
            decrypt_content_from_peer(bob, &alice_xonly, &payload).expect("decrypt roundtrip");
        assert_eq!(plaintext, r#"{"hello":"world"}"#);
    }

    #[test]
    fn decrypt_rejects_tampered_mac_and_invalid_peer_key_material() {
        let alice_seckey =
            hex::decode("579689f6508912ed1fc14b656426a1669b1e15510e33304b2c9e62248bd9299e")
                .expect("alice seckey");
        let bob_seckey =
            hex::decode("9f4f7b8b4f3d5d8f553a0c4ff5f3f379c2f4ab78ac96f8f1db2098ea8b0f0d72")
                .expect("bob seckey");
        let mut alice = [0u8; 32];
        let mut bob = [0u8; 32];
        alice.copy_from_slice(&alice_seckey);
        bob.copy_from_slice(&bob_seckey);
        let bob_xonly = hex::encode(
            &k256::SecretKey::from_slice(&bob)
                .expect("bob secret key")
                .public_key()
                .to_encoded_point(true)
                .as_bytes()[1..],
        );
        let alice_xonly = hex::encode(
            &k256::SecretKey::from_slice(&alice)
                .expect("alice secret key")
                .public_key()
                .to_encoded_point(true)
                .as_bytes()[1..],
        );

        let payload =
            encrypt_content_for_peer_with_nonce(alice, &bob_xonly, "tamper-check", [3u8; 32])
                .expect("encrypt");
        let mut bytes = STANDARD_NO_PAD
            .decode(payload.as_bytes())
            .expect("decode payload");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = STANDARD_NO_PAD.encode(bytes);

        let err = decrypt_content_from_peer(bob, &alice_xonly, &tampered)
            .expect_err("tampered payload must fail");
        assert!(matches!(err, SignerError::DecryptFailed(_)));

        let err =
            decrypt_content_from_peer(bob, "zz", &payload).expect_err("invalid peer hex must fail");
        assert!(matches!(err, SignerError::DecryptFailed(_)));
    }

    #[test]
    fn decrypt_rejects_invalid_version_and_short_payload() {
        let err = decrypt_content_from_peer([1u8; 32], "11".repeat(32).as_str(), "#legacy")
            .expect_err("legacy marker must fail");
        assert!(matches!(err, SignerError::DecryptFailed(_)));

        let short = STANDARD_NO_PAD.encode([2u8; 10]);
        let err = decrypt_content_from_peer([1u8; 32], &"11".repeat(32), &short)
            .expect_err("short payload must fail");
        assert!(matches!(err, SignerError::DecryptFailed(_)));
    }

    /// Flip a single bit in the MAC tag at each of four representative
    /// positions (first byte, middle byte, last byte, alternate single-bit
    /// flip) and confirm `decrypt_content_from_peer` rejects with
    /// `DecryptFailed` every time. Guards against regressions in the
    /// constant-time MAC compare.
    #[test]
    fn decrypt_rejects_mac_mismatch_at_every_probed_position() {
        let alice_seckey =
            hex::decode("579689f6508912ed1fc14b656426a1669b1e15510e33304b2c9e62248bd9299e")
                .expect("alice seckey");
        let bob_seckey =
            hex::decode("9f4f7b8b4f3d5d8f553a0c4ff5f3f379c2f4ab78ac96f8f1db2098ea8b0f0d72")
                .expect("bob seckey");
        let mut alice = [0u8; 32];
        let mut bob = [0u8; 32];
        alice.copy_from_slice(&alice_seckey);
        bob.copy_from_slice(&bob_seckey);
        let bob_xonly = hex::encode(
            &k256::SecretKey::from_slice(&bob)
                .expect("bob secret key")
                .public_key()
                .to_encoded_point(true)
                .as_bytes()[1..],
        );
        let alice_xonly = hex::encode(
            &k256::SecretKey::from_slice(&alice)
                .expect("alice secret key")
                .public_key()
                .to_encoded_point(true)
                .as_bytes()[1..],
        );

        let payload =
            encrypt_content_for_peer_with_nonce(alice, &bob_xonly, "mac-probe", [9u8; 32])
                .expect("encrypt");
        let bytes = STANDARD_NO_PAD
            .decode(payload.as_bytes())
            .expect("decode payload");
        let mac_start = bytes.len() - 32;

        // Positions relative to MAC: first byte, middle byte, last byte,
        // and an alternate single-bit flip on the first byte.
        let probes: &[(usize, u8)] = &[(0, 0x80), (16, 0x01), (31, 0x40), (0, 0x01)];
        for &(offset, mask) in probes {
            let mut tampered = bytes.clone();
            tampered[mac_start + offset] ^= mask;
            let encoded = STANDARD_NO_PAD.encode(&tampered);
            let err = decrypt_content_from_peer(bob, &alice_xonly, &encoded).expect_err(&format!(
                "mac flip at offset {offset:#x} mask {mask:#x} must fail"
            ));
            assert!(matches!(err, SignerError::DecryptFailed(_)));
        }
    }
}
