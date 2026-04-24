//! NIP-44 v2 (Nostr encrypted payloads) cipher stack.
//!
//! Canonical implementation for FROSTR. This module is the single source
//! of truth for NIP-44 v2 encrypt / decrypt across the workspace.
//!
//! Three caller families existed historically (each with its own copy of
//! the same primitives):
//!   - peer-bridge messaging in `bifrost-signer::crypto`
//!   - peer onboarding protocol in `frostr-utils::protocol`
//!   - encrypted profile backups in `frostr-utils::profile_packages`
//!
//! A.5.main (remediation-2026-04-22) consolidated all three into this
//! module. The three pinned Known-Answer Tests (one per caller family)
//! are the byte-for-byte regression net and must remain green.
//!
//! # Wire format (NIP-44 v2)
//!
//! ```text
//!   version byte (0x02)
//!   nonce           32 bytes
//!   ciphertext      N  bytes (ChaCha20 keystream over padded plaintext)
//!   hmac_sha256(hmac_key, nonce || ciphertext)  32 bytes
//! ```
//!
//! Base64 encoding: `STANDARD_NO_PAD`. Minimum payload size on the wire
//! before base64 is `1 + 32 + (2 + 32) + 32 = 99` bytes; the plaintext
//! padding scheme pads to at least 32 bytes per NIP-44 v2.
//!
//! Conversation key derivation (for the peer-bridge path) is
//! `hkdf_extract_sha256(salt = b"nip44-v2", ikm = shared_secret_x)`;
//! callers that already possess a derived conversation key (the profile
//! backup path) pass it directly to the `*_under_conversation_key`
//! functions.

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use k256::ecdh::diffie_hellman;
use k256::{PublicKey, SecretKey};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// NIP-44 v2 HKDF salt (domain separation for the peer-bridge
/// conversation key derivation). This value is load-bearing for
/// cross-implementation interop with the reference TypeScript stack.
const NIP44_V2_SALT: &[u8] = b"nip44-v2";

/// Errors produced by the `nip44` module.
///
/// Callers map these to their crate's native error type at the boundary.
#[derive(Debug, Error)]
pub enum CipherError {
    /// Payload version byte was not `0x02`, or the payload started with
    /// the legacy `#` marker.
    #[error("unknown encryption version")]
    InvalidVersion,
    /// Payload is shorter than the NIP-44 v2 minimum (99 bytes plus
    /// padding before base64).
    #[error("invalid payload length")]
    PayloadTooShort,
    /// MAC compare failed. Intentionally opaque — see
    /// [`subtle::ConstantTimeEq`] for the compare primitive.
    #[error("invalid MAC")]
    MacMismatch,
    /// Payload did not decode as `STANDARD_NO_PAD` base64.
    #[error("invalid base64: {0}")]
    BadBase64(String),
    /// Decrypted padded plaintext did not pass UTF-8 validation.
    #[error("invalid utf8 payload")]
    BadUtf8,
    /// A fixed-length input (peer pubkey, plaintext size bound, padded
    /// frame shape) was malformed.
    #[error("invalid length: {0}")]
    BadLength(String),
    /// Wrapped upstream cryptographic failure — HKDF init, HMAC init,
    /// k256 scalar / point parsing, etc.
    #[error("crypto error: {0}")]
    Crypto(String),
}

// -------- Public API: peer-bridge (conversation key derived on the fly) --------

/// Encrypt `plaintext` to `peer_pubkey` using NIP-44 v2 with a
/// caller-supplied 32-byte nonce.
///
/// The nonce is **intentionally explicit**: it is an input to the
/// cipher, and exposing it to the caller lets the three KATs pin
/// exact ciphertext bytes. Production callers SHOULD use
/// [`encrypt_for_peer_random_nonce`] instead, which draws from
/// `rand_core::OsRng`.
pub fn encrypt_for_peer(
    local_seckey: &[u8; 32],
    peer_pubkey: &[u8; 32],
    nonce: &[u8; 32],
    plaintext: &str,
) -> Result<String, CipherError> {
    let shared_x = event_shared_x(local_seckey, peer_pubkey)?;
    let conversation_key = hkdf_extract_sha256(NIP44_V2_SALT, &shared_x)?;
    encrypt_under_conversation_key(&conversation_key, nonce, plaintext)
}

/// Decrypt a NIP-44 v2 payload produced by `peer_pubkey` destined for
/// `local_seckey`. The nonce is recovered from the payload itself.
pub fn decrypt_from_peer(
    local_seckey: &[u8; 32],
    peer_pubkey: &[u8; 32],
    payload_base64: &str,
) -> Result<String, CipherError> {
    let shared_x = event_shared_x(local_seckey, peer_pubkey)?;
    let conversation_key = hkdf_extract_sha256(NIP44_V2_SALT, &shared_x)?;
    decrypt_under_conversation_key(&conversation_key, payload_base64)
}

/// Random-nonce wrapper around [`encrypt_for_peer`]. Production callers
/// that do not need a deterministic nonce should prefer this variant.
pub fn encrypt_for_peer_random_nonce(
    local_seckey: &[u8; 32],
    peer_pubkey: &[u8; 32],
    plaintext: &str,
) -> Result<String, CipherError> {
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    encrypt_for_peer(local_seckey, peer_pubkey, &nonce, plaintext)
}

// -------- Public API: pre-derived conversation key --------

/// Encrypt `plaintext` under a pre-derived 32-byte NIP-44 conversation
/// key, with a caller-supplied nonce. Used by the profile-backup path
/// where the conversation key is derived outside NIP-44 (e.g. from a
/// share secret via an HMAC).
pub fn encrypt_under_conversation_key(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
    plaintext: &str,
) -> Result<String, CipherError> {
    let (chacha_key, chacha_nonce, hmac_key) = get_message_keys(conversation_key, nonce)?;

    let mut padded = pad_message(plaintext)?;
    let mut chacha = ChaCha20::new((&chacha_key).into(), (&chacha_nonce).into());
    chacha.apply_keystream(&mut padded);
    let mac = hmac_aad(&hmac_key, nonce, &padded)?;

    let mut encoded = Vec::with_capacity(1 + 32 + padded.len() + 32);
    encoded.push(2u8);
    encoded.extend_from_slice(nonce);
    encoded.extend_from_slice(&padded);
    encoded.extend_from_slice(&mac);
    Ok(STANDARD_NO_PAD.encode(encoded))
}

/// Decrypt a NIP-44 v2 payload under a pre-derived conversation key.
pub fn decrypt_under_conversation_key(
    conversation_key: &[u8; 32],
    payload_base64: &str,
) -> Result<String, CipherError> {
    // Legacy NIP-04 payloads begin with `#`; callers have historically
    // rejected them eagerly for a better error message.
    if payload_base64.is_empty() || payload_base64.starts_with('#') {
        return Err(CipherError::InvalidVersion);
    }
    let data = STANDARD_NO_PAD
        .decode(payload_base64.as_bytes())
        .map_err(|e| CipherError::BadBase64(e.to_string()))?;
    if data.len() < 99 {
        return Err(CipherError::PayloadTooShort);
    }
    if data[0] != 2 {
        return Err(CipherError::InvalidVersion);
    }
    let mut nonce32 = [0u8; 32];
    nonce32.copy_from_slice(&data[1..33]);
    let ciphertext = &data[33..data.len() - 32];
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&data[data.len() - 32..]);

    let (chacha_key, chacha_nonce, hmac_key) = get_message_keys(conversation_key, &nonce32)?;
    let expected_mac = hmac_aad(&hmac_key, &nonce32, ciphertext)?;
    if !ct_eq(&expected_mac, &mac) {
        return Err(CipherError::MacMismatch);
    }

    let mut padded = ciphertext.to_vec();
    let mut chacha = ChaCha20::new((&chacha_key).into(), (&chacha_nonce).into());
    chacha.apply_keystream(&mut padded);
    unpad_message(&padded)
}

// -------- Internal helpers (no pub) --------

fn event_shared_x(
    local_seckey: &[u8; 32],
    peer_pubkey: &[u8; 32],
) -> Result<[u8; 32], CipherError> {
    // Reconstruct the compressed SEC1 encoding of the peer x-only pubkey
    // with an even-parity (`0x02`) prefix, matching upstream NIP-44
    // behavior.
    let mut peer_bytes = [0u8; 33];
    peer_bytes[0] = 0x02;
    peer_bytes[1..].copy_from_slice(peer_pubkey);
    let peer_pk = PublicKey::from_sec1_bytes(&peer_bytes)
        .map_err(|e| CipherError::Crypto(format!("invalid peer pubkey: {e}")))?;
    let local_sk = SecretKey::from_slice(local_seckey)
        .map_err(|e| CipherError::Crypto(format!("invalid local seckey: {e}")))?;
    let shared = diffie_hellman(local_sk.to_nonzero_scalar(), peer_pk.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32], CipherError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt)
        .map_err(|e| CipherError::Crypto(format!("hkdf extract init failed: {e}")))?;
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&out);
    Ok(prk)
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, CipherError> {
    let mut okm = Vec::with_capacity(len);
    let mut t = Vec::<u8>::new();
    let mut counter: u8 = 1;
    while okm.len() < len {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk)
            .map_err(|e| CipherError::Crypto(format!("hkdf expand init failed: {e}")))?;
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().to_vec();
        let remaining = len - okm.len();
        if t.len() <= remaining {
            okm.extend_from_slice(&t);
        } else {
            okm.extend_from_slice(&t[..remaining]);
        }
        counter = counter.saturating_add(1);
        if counter == 0 {
            return Err(CipherError::Crypto("hkdf expand overflow".to_string()));
        }
    }
    Ok(okm)
}

fn get_message_keys(
    conversation_key: &[u8; 32],
    nonce32: &[u8; 32],
) -> Result<([u8; 32], [u8; 12], [u8; 32]), CipherError> {
    let keys = hkdf_expand_sha256(conversation_key, nonce32, 76)?;
    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];
    chacha_key.copy_from_slice(&keys[0..32]);
    chacha_nonce.copy_from_slice(&keys[32..44]);
    hmac_key.copy_from_slice(&keys[44..76]);
    Ok((chacha_key, chacha_nonce, hmac_key))
}

fn calc_padded_len(unpadded_len: usize) -> Result<usize, CipherError> {
    if unpadded_len == 0 {
        return Err(CipherError::BadLength("invalid plaintext size".to_string()));
    }
    if unpadded_len <= 32 {
        return Ok(32);
    }
    let next_power = 1usize << ((usize::BITS - (unpadded_len - 1).leading_zeros()) as usize);
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    Ok(chunk * (((unpadded_len - 1) / chunk) + 1))
}

fn pad_message(plaintext: &str) -> Result<Vec<u8>, CipherError> {
    let unpadded = plaintext.as_bytes();
    let unpadded_len = unpadded.len();
    if unpadded_len == 0 || unpadded_len > 0xffff {
        return Err(CipherError::BadLength(
            "invalid plaintext size: must be between 1 and 65535 bytes".to_string(),
        ));
    }
    let padded_len = calc_padded_len(unpadded_len)?;
    let mut out = Vec::with_capacity(2 + padded_len);
    out.extend_from_slice(&(unpadded_len as u16).to_be_bytes());
    out.extend_from_slice(unpadded);
    out.resize(2 + padded_len, 0u8);
    Ok(out)
}

fn unpad_message(padded: &[u8]) -> Result<String, CipherError> {
    if padded.len() < 2 {
        return Err(CipherError::BadLength("invalid padding".to_string()));
    }
    let unpadded_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if unpadded_len == 0 || unpadded_len > 0xffff {
        return Err(CipherError::BadLength("invalid padding".to_string()));
    }
    let expect = 2 + calc_padded_len(unpadded_len)?;
    if padded.len() != expect || padded.len() < 2 + unpadded_len {
        return Err(CipherError::BadLength("invalid padding".to_string()));
    }
    let unpadded = &padded[2..2 + unpadded_len];
    String::from_utf8(unpadded.to_vec()).map_err(|_| CipherError::BadUtf8)
}

fn hmac_aad(
    hmac_key: &[u8; 32],
    nonce32: &[u8; 32],
    ciphertext: &[u8],
) -> Result<[u8; 32], CipherError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|e| CipherError::Crypto(format!("hmac init failed: {e}")))?;
    mac.update(nonce32);
    mac.update(ciphertext);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    Ok(tag)
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_under_conversation_key_is_stable() {
        let key = [0x7fu8; 32];
        let nonce = [0x11u8; 32];
        let ciphertext = encrypt_under_conversation_key(&key, &nonce, "hello").expect("encrypt");
        let plaintext = decrypt_under_conversation_key(&key, &ciphertext).expect("decrypt");
        assert_eq!(plaintext, "hello");
    }

    #[test]
    fn decrypt_rejects_invalid_version_and_short_payload() {
        let err = decrypt_under_conversation_key(&[0u8; 32], "").expect_err("empty");
        assert!(matches!(err, CipherError::InvalidVersion));

        let err = decrypt_under_conversation_key(&[0u8; 32], "#legacy").expect_err("legacy");
        assert!(matches!(err, CipherError::InvalidVersion));

        let short = STANDARD_NO_PAD.encode([2u8; 10]);
        let err = decrypt_under_conversation_key(&[0u8; 32], &short).expect_err("short");
        assert!(matches!(err, CipherError::PayloadTooShort));
    }

    #[test]
    fn decrypt_rejects_wrong_version_byte() {
        let data = {
            let mut v = vec![3u8]; // wrong version
            v.extend_from_slice(&[0u8; 98]);
            v
        };
        let payload = STANDARD_NO_PAD.encode(data);
        let err = decrypt_under_conversation_key(&[0u8; 32], &payload).expect_err("version");
        assert!(matches!(err, CipherError::InvalidVersion));
    }

    #[test]
    fn decrypt_rejects_tampered_mac() {
        let key = [0x33u8; 32];
        let nonce = [0x22u8; 32];
        let ciphertext =
            encrypt_under_conversation_key(&key, &nonce, "mac-probe").expect("encrypt");
        let mut bytes = STANDARD_NO_PAD
            .decode(ciphertext.as_bytes())
            .expect("decode");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = STANDARD_NO_PAD.encode(&bytes);
        let err = decrypt_under_conversation_key(&key, &tampered).expect_err("tamper");
        assert!(matches!(err, CipherError::MacMismatch));
    }
}
