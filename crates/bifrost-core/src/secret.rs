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
//!
//! Any new `Clone` impl must add a line here explaining why.

use core::fmt;

use subtle::ConstantTimeEq;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
