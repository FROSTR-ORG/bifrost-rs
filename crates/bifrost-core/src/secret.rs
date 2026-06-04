//! Secret newtypes with hardened ergonomics.
//!
//! Every 32-byte secret the runtime holds should live inside one of these
//! newtypes. Each type:
//!
//! - drops with `ZeroizeOnDrop`, so the underlying buffer is wiped;
//! - implements `PartialEq`/`Eq` in constant time via `subtle::ConstantTimeEq`;
//! - prints as `"<Name>(<redacted>)"` in `Debug`, never leaking bytes;
//! - does **not** derive `Serialize`/`Deserialize` — persistence or wire
//!   crossings must go through an explicit DTO (e.g. `SharePackageWire`).
//!
//! ### `Clone` discipline
//!
//! `Clone` is intentionally opt-in, not blanket. A `Clone` impl means a live
//! copy of the secret exists somewhere else — each one has to be justified.
//! The current list:
//!
//! - [`SharePrivateKey`]: clones because `EncryptedFileStore::new` currently
//!   takes a `SharePackage` by value and many host call sites construct
//!   `DeviceState` and the store from the same `SharePackage`. Fan-out here
//!   is unavoidable without a larger refactor of the host entry points.
//! - [`NoncePoolSecret`]: clones because the (pre-split) `DeviceState` that
//!   owns the nonce-pool secret is itself `Clone`-ed into `InMemoryStore`
//!   snapshots and WASM bootstrap paths. PR2 hoists this into `DeviceSecrets`
//!   and keeps the same clone semantics via a manual impl.
//! - [`FileStoreKey`]: no `Clone`. Held in one place per store instance.
//! - [`EcdhSharedSecret`]: no `Clone`. Cached-by-value then dropped.
//! - [`RecoveredSigningKey`]: clones because `RecoveredKeyMaterial` is
//!   `Clone` (recovery flows fan out the recovered bytes through multiple
//!   downstream builders before zeroization).
//! - [`Passphrase`]: no `Clone` derive. Exposes an explicit `clone_secret()`
//!   for the rare host call sites that genuinely need a second owned copy
//!   (e.g. fanning a passphrase out to both a KDF and a verifier in one
//!   pass). Every such call is grep-able.
//! - [`DaemonToken`]: no `Clone` derive. Exposes an explicit `clone_secret()`
//!   for the same reason — the daemon retains the canonical token while
//!   handing a copy to whatever transport binding presents it to clients.
//!
//! Any new `Clone` impl must add a line here explaining why.

use core::fmt;

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// FROST signing share held by this host.
#[derive(ZeroizeOnDrop, Clone)]
pub struct SharePrivateKey([u8; 32]);

/// Per-device secret that seeds the FROST nonce pool.
#[derive(ZeroizeOnDrop, Clone)]
pub struct NoncePoolSecret([u8; 32]);

/// Pairwise ECDH shared secret cached for peer messaging.
#[derive(ZeroizeOnDrop)]
pub struct EcdhSharedSecret([u8; 32]);

/// Fully reconstructed Nostr signing key material from a recovery flow.
#[derive(ZeroizeOnDrop, Clone)]
pub struct RecoveredSigningKey([u8; 32]);

/// Symmetric key derived from the share used to seal on-disk device state.
#[derive(ZeroizeOnDrop)]
pub struct FileStoreKey([u8; 32]);

macro_rules! impl_secret_newtype {
    ($name:ident) => {
        impl $name {
            /// Wrap a 32-byte secret.
            ///
            /// The caller relinquishes the buffer — any prior copy on the
            /// stack should be zeroized at the source.
            #[inline]
            pub fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the underlying bytes. Named to make call sites
            /// searchable in audits (`rg 'expose_bytes'`).
            #[inline]
            pub fn expose_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }

        impl Eq for $name {}

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

impl_secret_newtype!(SharePrivateKey);
impl_secret_newtype!(NoncePoolSecret);
impl_secret_newtype!(EcdhSharedSecret);
impl_secret_newtype!(RecoveredSigningKey);
impl_secret_newtype!(FileStoreKey);

/// UTF-8 operator passphrase used to derive KDFs (profile encryption,
/// recovery flows, etc.).
///
/// The runtime never compares passphrases for equality, so this type
/// deliberately does not implement `PartialEq`/`Eq`. Use `expose_secret()`
/// or `expose_bytes()` and feed the result into a KDF or verifier — do not
/// build ad-hoc equality checks.
#[derive(ZeroizeOnDrop)]
pub struct Passphrase(String);

impl Passphrase {
    /// Wrap an owned UTF-8 passphrase. The caller relinquishes the string;
    /// any prior copy on the stack should be zeroized at the source.
    #[inline]
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Borrow the underlying UTF-8 passphrase. Named to make call sites
    /// searchable in audits (`rg 'expose_secret'`).
    #[inline]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Borrow the underlying passphrase as bytes. Convenient for KDFs that
    /// take `&[u8]` (PBKDF2, Argon2, HKDF, etc.).
    #[inline]
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Explicitly clone the wrapped passphrase. There is no `Clone` derive
    /// on purpose — every call site that needs a second owned copy must
    /// surface here so an auditor can find it.
    #[inline]
    pub fn clone_secret(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Passphrase(<redacted>)")
    }
}

/// Error type returned by [`DaemonToken::from_hex`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    /// The provided hex string was not exactly 64 characters long.
    #[error("daemon token must be 64 hex characters")]
    InvalidLength,
    /// The provided hex string contained a non-hex character.
    #[error("daemon token contains non-hex character {0:?}")]
    InvalidHex(char),
}

/// 32-byte random authentication token used by the local control-socket
/// daemon to gate access from co-located clients.
///
/// Equality is constant-time via [`subtle::ConstantTimeEq`] over the
/// underlying bytes. The token never appears in `Debug` output.
#[derive(ZeroizeOnDrop)]
pub struct DaemonToken {
    bytes: [u8; 32],
}

impl DaemonToken {
    /// Generate a fresh random token using the supplied
    /// cryptographically-secure RNG.
    #[inline]
    pub fn new_random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Parse a 64-character hex string into a `DaemonToken`. Accepts upper-
    /// or lower-case hex; the canonical wire form is lowercase.
    pub fn from_hex(s: &str) -> Result<Self, TokenError> {
        if s.len() != 64 {
            return Err(TokenError::InvalidLength);
        }
        if let Some(ch) = s.chars().find(|c| !c.is_ascii_hexdigit()) {
            return Err(TokenError::InvalidHex(ch));
        }
        let raw = hex::decode(s).map_err(|_| TokenError::InvalidLength)?;
        if raw.len() != 32 {
            return Err(TokenError::InvalidLength);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        Ok(Self { bytes })
    }

    /// Encode the token as a lowercase 64-character hex string.
    ///
    /// The returned `String` is owned — callers should be conscious that it
    /// is a copy of secret material outside the `ZeroizeOnDrop` guarantee.
    /// Prefer `expose_bytes()` where the consuming API can take bytes.
    #[inline]
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Borrow the underlying 32-byte token. Named to make call sites
    /// searchable in audits (`rg 'expose_bytes'`).
    #[inline]
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Explicitly clone the wrapped token. There is no `Clone` derive on
    /// purpose — every call site that needs a second owned copy must
    /// surface here so an auditor can find it.
    #[inline]
    pub fn clone_secret(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

impl PartialEq for DaemonToken {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for DaemonToken {}

impl fmt::Debug for DaemonToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DaemonToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn debug_redacts_contents() {
        let key = SharePrivateKey::new([0xAAu8; 32]);
        let rendered = format!("{:?}", key);
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("aa"));
    }

    #[test]
    fn equal_secrets_compare_equal() {
        let a = FileStoreKey::new([7u8; 32]);
        let b = FileStoreKey::new([7u8; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn unequal_secrets_compare_not_equal() {
        let a = FileStoreKey::new([7u8; 32]);
        let mut differ = [7u8; 32];
        differ[0] = 8;
        let b = FileStoreKey::new(differ);
        assert_ne!(a, b);
    }

    #[test]
    fn expose_bytes_round_trip() {
        let bytes = [3u8; 32];
        let key = NoncePoolSecret::new(bytes);
        assert_eq!(key.expose_bytes(), &bytes);
    }

    #[test]
    fn passphrase_debug_is_redacted() {
        let p = Passphrase::new("hunter2".into());
        let rendered = format!("{:?}", p);
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn passphrase_expose_round_trip() {
        let p = Passphrase::new("correct horse battery staple".into());
        assert_eq!(p.expose_secret(), "correct horse battery staple");
        assert_eq!(p.expose_bytes(), b"correct horse battery staple");
    }

    #[test]
    fn passphrase_clone_secret_round_trips() {
        let p = Passphrase::new("x".into());
        let q = p.clone_secret();
        assert_eq!(p.expose_secret(), q.expose_secret());
    }

    #[test]
    fn daemon_token_debug_is_redacted() {
        let token = DaemonToken {
            bytes: [0xABu8; 32],
        };
        let rendered = format!("{:?}", token);
        let hex_form = hex::encode(token.expose_bytes());
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&hex_form));
        assert!(!rendered.contains("ab"));
    }

    #[test]
    fn daemon_token_from_hex_round_trip() {
        let h: String = "00ff".repeat(16);
        assert_eq!(h.len(), 64);
        let t = DaemonToken::from_hex(&h).expect("valid hex");
        assert_eq!(t.to_hex(), h.to_lowercase());
    }

    #[test]
    fn daemon_token_from_hex_accepts_mixed_case() {
        let h_upper: String = "AABB".repeat(16);
        let h_lower = h_upper.to_lowercase();
        let t = DaemonToken::from_hex(&h_upper).expect("uppercase hex is valid");
        assert_eq!(t.to_hex(), h_lower);
    }

    #[test]
    fn daemon_token_from_hex_rejects_wrong_length() {
        let short = "ab".repeat(31) + "a"; // 63 chars
        assert_eq!(short.len(), 63);
        assert_eq!(
            DaemonToken::from_hex(&short),
            Err(TokenError::InvalidLength)
        );

        let long = "ab".repeat(32) + "a"; // 65 chars
        assert_eq!(long.len(), 65);
        assert_eq!(DaemonToken::from_hex(&long), Err(TokenError::InvalidLength));
    }

    #[test]
    fn daemon_token_from_hex_rejects_non_hex() {
        let mut s: String = "ab".repeat(32);
        // Replace one char with 'g' so length stays at 64.
        s.replace_range(0..1, "g");
        assert_eq!(s.len(), 64);
        assert_eq!(DaemonToken::from_hex(&s), Err(TokenError::InvalidHex('g')));
    }

    #[test]
    fn daemon_token_clone_secret_round_trips() {
        let t = DaemonToken {
            bytes: [0x11u8; 32],
        };
        let u = t.clone_secret();
        assert_eq!(t, u);
        assert_eq!(t.expose_bytes(), u.expose_bytes());
    }

    #[test]
    fn daemon_token_partialeq_via_subtle() {
        let a = DaemonToken {
            bytes: [0x33u8; 32],
        };
        let b = DaemonToken {
            bytes: [0x33u8; 32],
        };
        assert_eq!(a, b);

        let mut differ = [0x33u8; 32];
        differ[31] = 0x34;
        let c = DaemonToken { bytes: differ };
        assert_ne!(a, c);
    }

    #[test]
    fn daemon_token_new_random_is_distinct() {
        let mut rng = OsRng;
        let a = DaemonToken::new_random(&mut rng);
        let b = DaemonToken::new_random(&mut rng);
        assert_ne!(a, b);
    }
}
