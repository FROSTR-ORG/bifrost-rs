//! Session-scoped Argon2 KDF cache for the daemon's encrypted profile.
//!
//! # Bucket C C.6 — `UnlockSession`
//!
//! The host-local encrypted profile envelope (v2) is sealed with a key derived
//! from the operator passphrase via Argon2id. With the default parameters
//! (`m = 256 MiB`, `t = 4`, `p = 1`), the KDF runs at roughly 400–600 ms on
//! 2020-era desktop hardware. Without caching, every Sign / Ecdh / Wipe path
//! that reaches for the share material would re-run the KDF and pay that cost
//! per request.
//!
//! [`UnlockSession`] caches the derived [`FileStoreKey`] for the daemon
//! process's lifetime so the KDF runs exactly once at startup. After
//! construction the session holds **only** the derived key — the passphrase is
//! consumed by [`UnlockSession::new`] and dropped (zeroized) before the
//! constructor returns.
//!
//! ## Lifetime contract
//!
//! - **One session per daemon process.** The session is created at startup
//!   immediately after the passphrase is read from stdin (see
//!   [`crate::host::read_passphrase_from_stdin`]) and held for the daemon's
//!   lifetime.
//! - **No idle TTL.** The session lives until the daemon process exits; it is
//!   not invalidated on idle.
//! - **No explicit invalidation.** Passphrase rotation requires a daemon
//!   restart (the hard-cut path per the Bucket C plan).
//! - **`ZeroizeOnDrop`.** The session is zeroized on drop via the
//!   [`FileStoreKey`] field, which already implements `ZeroizeOnDrop`.
//! - **No `Clone` impl.** Cloning the session would defeat the
//!   one-key-per-daemon invariant; every consumer borrows the same instance.
//!
//! ## Salt binding
//!
//! The cached [`FileStoreKey`] is derived from the *envelope's* Argon2id
//! parameters and the *record's* salt. Two records produced by independent
//! calls to `store_encrypted_profile` (or its `_with_params` variant) carry
//! independent random salts, so their cached keys differ even when sealed
//! with the same passphrase. In practice the daemon decrypts a single
//! profile record on its hot path, so this is not a limitation; PR12 / a
//! future change that wants multi-record caching will need a salt-indexed
//! map rather than a single `FileStoreKey`.

use bifrost_core::secret::{FileStoreKey, Passphrase};
use bifrost_profile::{
    EncryptedProfileRecord, FilesystemEncryptedProfileStore, derive_file_store_key_for_record,
};
use thiserror::Error;

/// Failure modes for [`UnlockSession::new`] and [`UnlockSession::decrypt_profile`].
#[derive(Debug, Error)]
pub enum UnlockError {
    /// Argon2id failed to derive a key from the supplied passphrase + envelope
    /// parameters. Surfaces metadata-shape errors (e.g. malformed `salt_hex`)
    /// alongside genuine KDF failures; both are non-recoverable from a session
    /// boundary.
    #[error("argon2id key derivation failed: {0}")]
    Argon2(String),

    /// The derived key was rejected by the validation record: either the
    /// passphrase was wrong, the envelope was tampered with, or the record
    /// metadata no longer matches the on-disk envelope's AAD. The session is
    /// not constructed when this fires — every subsequent decrypt would have
    /// failed the same way.
    #[error("encrypted profile decrypt rejected the derived key: {0}")]
    Decrypt(String),

    /// The envelope or sidecar metadata was unreadable / malformed before
    /// Argon2id ran (e.g. truncated file, unsupported version, parameters
    /// outside the floor/ceiling envelope).
    #[error("invalid encrypted profile envelope or parameters: {0}")]
    InvalidParams(String),
}

/// Daemon-scoped cache of the [`FileStoreKey`] derived from the operator
/// passphrase. See the module-level docs for the lifetime contract.
///
/// The passphrase is consumed by [`UnlockSession::new`] and dropped before
/// construction returns. Once constructed, the session exposes only the
/// post-KDF key path via [`UnlockSession::decrypt_profile`].
///
/// `UnlockSession` is intentionally **not** `Clone`. Holding more than one
/// copy of the key per daemon process would defeat the point of the cache.
#[derive(Debug)]
pub struct UnlockSession {
    profile_id: String,
    file_store_key: FileStoreKey,
}

impl UnlockSession {
    /// Run Argon2id once against the supplied passphrase + envelope salt /
    /// params, validate the derived key against the supplied
    /// [`EncryptedProfileRecord`], and return a session bound to `profile_id`.
    ///
    /// On wrong passphrase (or any other failure to decrypt the validation
    /// record) the constructor returns [`UnlockError::Decrypt`] rather than
    /// handing back a session that will silently fail on every subsequent
    /// call.
    ///
    /// The passphrase is consumed by this call; it is dropped (and its buffer
    /// zeroized via [`Passphrase`]'s `ZeroizeOnDrop`) before this function
    /// returns regardless of success or failure.
    pub fn new(
        passphrase: Passphrase,
        profile_id: impl Into<String>,
        validation_record: &EncryptedProfileRecord,
    ) -> Result<Self, UnlockError> {
        // Derive the key from the passphrase + the validation envelope's
        // recorded Argon2 params + salt. `derive_file_store_key_for_record`
        // reads the envelope, validates header/params, and runs Argon2id.
        let file_store_key =
            derive_file_store_key_for_record(validation_record, passphrase.expose_bytes())
                .map_err(|err| classify_derive_error(&err))?;
        // Drop the passphrase explicitly — its buffer is zeroized here.
        drop(passphrase);

        // Validate the derived key by decrypting the validation record once.
        // This catches wrong-passphrase up front instead of deferring the
        // failure to every subsequent `decrypt_profile` call.
        let store = ephemeral_store_for_record(validation_record);
        store
            .decrypt_encrypted_profile_with_key(validation_record, &file_store_key)
            .map_err(|err| UnlockError::Decrypt(err.to_string()))?;

        Ok(Self {
            profile_id: profile_id.into(),
            file_store_key,
        })
    }

    /// Decrypt an encrypted profile envelope using the cached key.
    ///
    /// This is the daemon's hot path. The KDF is **not** re-run — the cached
    /// [`FileStoreKey`] derived at `new()` time is reused. Per-call cost is
    /// dominated by the AEAD decrypt (~hundreds of microseconds) instead of
    /// the ~400-600 ms Argon2id derivation.
    ///
    /// Returns the UTF-8 plaintext on success. Any failure (record metadata
    /// mismatched against AAD, on-disk envelope tampered with, etc.) is
    /// surfaced as [`UnlockError::Decrypt`] — the session itself is not
    /// invalidated.
    pub fn decrypt_profile(&self, record: &EncryptedProfileRecord) -> Result<String, UnlockError> {
        let store = ephemeral_store_for_record(record);
        store
            .decrypt_encrypted_profile_with_key(record, &self.file_store_key)
            .map_err(|err| UnlockError::Decrypt(err.to_string()))
    }

    /// Profile id this session is bound to. Set by [`UnlockSession::new`] at
    /// construction time and immutable for the session's lifetime.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
}

/// `FilesystemEncryptedProfileStore` is currently only used by the decrypt
/// helpers as a method dispatch surface — the read goes through
/// `record.ciphertext_path`, not the store's metadata/ciphertext dirs. The
/// store's `new` therefore takes paths we never read from in this code path.
/// Construct an ephemeral store rooted at the record's ciphertext directory so
/// the helper's signature stays consistent with the rest of `bifrost-profile`.
fn ephemeral_store_for_record(record: &EncryptedProfileRecord) -> FilesystemEncryptedProfileStore {
    let ciphertext_dir = std::path::PathBuf::from(&record.ciphertext_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();
    FilesystemEncryptedProfileStore::new(&ciphertext_dir, &ciphertext_dir)
}

/// Map an `anyhow::Error` from `derive_file_store_key_for_record` to the
/// appropriate `UnlockError` variant. The helper bundles parameter-shape
/// errors and Argon2 failures into one `anyhow::Error`; we inspect the
/// downcast `StateError` (when present) to distinguish the two.
fn classify_derive_error(err: &anyhow::Error) -> UnlockError {
    if err.downcast_ref::<bifrost_profile::StateError>().is_some() {
        UnlockError::InvalidParams(err.to_string())
    } else {
        UnlockError::Argon2(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bifrost_profile::Argon2Params;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let id = format!(
            "bifrost-app-unlock-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        );
        std::env::temp_dir().join(id)
    }

    fn make_store(label: &str) -> (FilesystemEncryptedProfileStore, std::path::PathBuf) {
        let root = temp_dir(label);
        std::fs::create_dir_all(&root).expect("create temp dir");
        let store = FilesystemEncryptedProfileStore::new(&root, &root);
        (store, root)
    }

    fn store_with_passphrase(
        store: &FilesystemEncryptedProfileStore,
        payload: &str,
        passphrase: &str,
        now: u64,
    ) -> EncryptedProfileRecord {
        // `minimum_secure` keeps test latency reasonable while still exercising
        // the real Argon2id code path (the default 256 MiB profile would cost
        // ~500 ms per derive).
        store
            .store_encrypted_profile_with_params(
                "share_package",
                "file_import",
                payload,
                passphrase,
                now,
                &Argon2Params::minimum_secure(),
            )
            .expect("store encrypted profile")
    }

    #[test]
    fn unlock_session_creates_with_correct_passphrase() {
        let (store, root) = make_store("create-ok");
        let record = store_with_passphrase(&store, "{\"share\":1}", "correct-passphrase", 42);

        let session = UnlockSession::new(
            Passphrase::new("correct-passphrase".to_string()),
            "profile-1",
            &record,
        )
        .expect("session must construct with correct passphrase");
        assert_eq!(session.profile_id(), "profile-1");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unlock_session_wrong_passphrase_fails_at_create() {
        let (store, root) = make_store("create-bad");
        let record = store_with_passphrase(&store, "{\"share\":1}", "correct-passphrase", 42);

        let err = UnlockSession::new(
            Passphrase::new("wrong-passphrase".to_string()),
            "profile-1",
            &record,
        )
        .expect_err("wrong passphrase must reject at construction");
        match err {
            UnlockError::Decrypt(_) => {}
            other => panic!("expected UnlockError::Decrypt, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unlock_session_reuses_key_across_decrypts() {
        let (store, root) = make_store("reuse");
        // The session caches the derived FileStoreKey — call decrypt_profile
        // several times against the same record and assert each call returns
        // the expected plaintext. The key is salt-bound, so a "second record"
        // sealed independently would have a different salt and therefore a
        // different key; the daemon's real-world path decrypts the same
        // profile record repeatedly.
        let record = store_with_passphrase(&store, "{\"share\":1}", "passphrase", 42);

        let session = UnlockSession::new(
            Passphrase::new("passphrase".to_string()),
            "profile-1",
            &record,
        )
        .expect("session must construct");

        for _ in 0..3 {
            let plaintext = session.decrypt_profile(&record).expect("decrypt record");
            assert_eq!(plaintext, "{\"share\":1}");
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unlock_session_decrypt_wrong_profile_fails() {
        let (store, root) = make_store("wrong-profile");
        // Two records sealed with *different* passphrases. A session built
        // for the first record's passphrase must fail to decrypt the second.
        let record_a = store_with_passphrase(&store, "{\"a\":1}", "passphrase-a", 42);
        let record_b = store_with_passphrase(&store, "{\"b\":2}", "passphrase-b", 43);

        let session = UnlockSession::new(
            Passphrase::new("passphrase-a".to_string()),
            "profile-a",
            &record_a,
        )
        .expect("session must construct");

        let err = session
            .decrypt_profile(&record_b)
            .expect_err("decrypting a foreign-passphrase record must fail");
        match err {
            UnlockError::Decrypt(_) => {}
            other => panic!("expected UnlockError::Decrypt, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(root);
    }
}
