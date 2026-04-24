//! Argon2id key derivation for the host-local encrypted-profile envelope v2.
//!
//! PR6 defines the helper; PR7 performs the writer/reader cutover. The helper
//! takes a `&[u8]` passphrase today. Bucket C is expected to introduce a
//! `Passphrase` newtype with zeroize-on-drop; the signature will migrate to
//! `&Passphrase` then.

use crate::argon2_params::Argon2Params;
use crate::state_error::StateError;

/// Salt length in raw bytes that [`derive_profile_encryption_key_v2`]
/// accepts. Matches [`crate::aad::AAD_SALT_LEN`].
pub const KDF_SALT_LEN: usize = 16;

/// Derived key length in bytes (ChaCha20Poly1305 key).
pub const KDF_OUTPUT_LEN: usize = 32;

/// Derive a 32-byte ChaCha20Poly1305 key from a passphrase and salt using
/// Argon2id v0x13 with the operator-selected [`Argon2Params`].
///
/// The returned key must be zeroized by the caller (PR7 migration will wrap
/// this in a zeroize-on-drop newtype once Bucket C lands).
///
/// # Security note
///
/// The passphrase argument is currently `&[u8]` because the Bucket C
/// `Passphrase` newtype has not landed yet. That's intentional: PR6 is
/// crate-internal and no production call site pivots to the v2 KDF until
/// PR7. The signature will migrate to `&Passphrase` during the PR7 cutover.
pub fn derive_profile_encryption_key_v2(
    passphrase_bytes: &[u8],
    salt: &[u8; KDF_SALT_LEN],
    params: &Argon2Params,
) -> Result<[u8; KDF_OUTPUT_LEN], StateError> {
    let argon2 = params.to_argon2();
    let mut key = [0u8; KDF_OUTPUT_LEN];
    argon2
        .hash_password_into(passphrase_bytes, salt, &mut key)
        .map_err(|_err| StateError::UnsupportedParams {
            m_cost: params.m_cost(),
            t_cost: params.t_cost(),
            p_cost: params.p_cost(),
        })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> [u8; KDF_SALT_LEN] {
        *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    }

    // The default params run Argon2id at 256 MiB, which makes per-test
    // latency ~400–600 ms. The round-trip tests below use
    // `Argon2Params::minimum_secure()` (64 MiB) to keep `cargo test` brisk
    // while still exercising the real Argon2id code path.

    #[test]
    fn derive_is_deterministic_on_identical_inputs() {
        let params = Argon2Params::minimum_secure();
        let salt = test_salt();
        let a = derive_profile_encryption_key_v2(b"correct horse battery staple", &salt, &params)
            .expect("derive ok");
        let b = derive_profile_encryption_key_v2(b"correct horse battery staple", &salt, &params)
            .expect("derive ok");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_changes_with_passphrase() {
        let params = Argon2Params::minimum_secure();
        let salt = test_salt();
        let a =
            derive_profile_encryption_key_v2(b"passphrase-one", &salt, &params).expect("derive ok");
        let b =
            derive_profile_encryption_key_v2(b"passphrase-two", &salt, &params).expect("derive ok");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_changes_with_salt() {
        let params = Argon2Params::minimum_secure();
        let salt_a = test_salt();
        let mut salt_b = salt_a;
        salt_b[0] ^= 0xff;
        let a = derive_profile_encryption_key_v2(b"pw", &salt_a, &params).expect("derive ok");
        let b = derive_profile_encryption_key_v2(b"pw", &salt_b, &params).expect("derive ok");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_changes_with_params() {
        let salt = test_salt();
        let a = derive_profile_encryption_key_v2(b"pw", &salt, &Argon2Params::minimum_secure())
            .expect("derive ok");
        // Bump t_cost; use new() to keep within the floor/ceiling envelope.
        let heavier = Argon2Params::new(65_536, 4, 1).expect("heavier params must validate");
        let b = derive_profile_encryption_key_v2(b"pw", &salt, &heavier).expect("derive ok");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_accepts_empty_passphrase() {
        let params = Argon2Params::minimum_secure();
        let salt = test_salt();
        derive_profile_encryption_key_v2(b"", &salt, &params)
            .expect("empty passphrase must derive successfully");
    }
}
