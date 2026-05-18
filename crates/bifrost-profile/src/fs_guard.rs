//! Filesystem hardening helpers for host-local secret-bearing paths.
//!
//! Bucket C C.1 (filesystem permissions) and C.2 (atomic manifest writes)
//! centralize every secret-bearing `fs::write` / `fs::create_dir_all` site in
//! `bifrost-profile` behind these helpers. Callers should never reach for the
//! bare `std::fs` equivalents on profile/manifest/ciphertext/log paths.
//!
//! All three helpers are `#[cfg(unix)]`-gated. The crate is currently
//! consumed only by Unix hosts (the daemon runtime is `#[cfg(unix)]`-only),
//! so providing only Unix implementations is intentional. On non-Unix targets
//! the module compiles to an empty surface and any caller that depends on the
//! helpers will fail to build there — that is the intended signal.
//!
//! The mode argument is taken as a raw `u32` rather than a typed wrapper so
//! that call sites read like the audit's prescription (e.g. `0o600`,
//! `0o700`).
//!
//! The module declaration in `lib.rs` is `#[cfg(unix)]`-gated; we deliberately
//! do not duplicate that gate at the file level so `cargo clippy` does not
//! warn under `clippy::duplicated_attributes`.

use std::fs::{File, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::NamedTempFile;
use thiserror::Error;

/// Errors surfaced by the [`fs_guard`](self) helpers.
#[derive(Debug, Error)]
pub enum FsGuardError {
    /// Underlying I/O error from the standard library.
    #[error("fs_guard io: {0}")]
    Io(#[from] std::io::Error),

    /// The target path had no parent directory; `write_restricted_bytes_atomic`
    /// requires a parent so the temp file lands on the same filesystem.
    #[error("fs_guard: target path has no parent directory")]
    NoParent,

    /// `tempfile::NamedTempFile::persist` returned its bespoke error type.
    /// Wrapped here so callers can use `?` without an extra conversion step.
    #[error("fs_guard persist: {0}")]
    Persist(#[from] tempfile::PersistError),
}

/// Idempotently create `path` (and missing ancestors) as a directory and apply
/// `mode` to its leaf via `chmod`.
///
/// The mode is applied even when the directory already exists. This allows the
/// helper to repair relaxed perms on existing trees (e.g. an upgrade from a
/// previous release that did not chmod its data dir).
///
/// Bucket C C.1 callers pass `0o700` for every secret-bearing directory.
pub fn ensure_dir_restricted(path: &Path, mode: u32) -> Result<(), FsGuardError> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(mode))?;
    Ok(())
}

/// Non-atomic write of `data` to `path` followed by an explicit `chmod` to
/// `mode`.
///
/// Use this only when atomicity is not required. Most secret-bearing call
/// sites should use [`write_restricted_bytes_atomic`] instead — Bucket C C.2
/// requires atomic manifest writes for crash safety.
pub fn write_restricted_bytes(path: &Path, data: &[u8], mode: u32) -> Result<(), FsGuardError> {
    std::fs::write(path, data)?;
    std::fs::set_permissions(path, Permissions::from_mode(mode))?;
    Ok(())
}

/// Atomically write `data` to `path` with the requested `mode`.
///
/// Implementation order (Bucket C C.2 plan):
/// 1. `NamedTempFile::new_in(parent)` — temp file lives on the same filesystem
///    as the target so `persist` is a single rename syscall.
/// 2. `write_all` + `sync_all` — flush the temp file's bytes to disk before
///    rename so the rename never reveals a partial write.
/// 3. `set_permissions(mode)` on the temp file BEFORE persist — the final
///    path never exists with the default tempfile mode, even momentarily.
/// 4. `persist(path)` — atomic same-device rename.
/// 5. `File::open(parent)?.sync_all()` — fsync the parent directory so the
///    rename is durable across a crash. Without this step the rename can be
///    lost on power-loss even though userspace observed it succeed.
///
/// Same-filesystem caveat: `tempfile::persist` is atomic only when the target
/// directory and the temp file share a filesystem. `NamedTempFile::new_in`
/// places the temp file in the same directory as the target so this holds in
/// practice; cross-device callers will see a non-atomic copy + cleanup.
pub fn write_restricted_bytes_atomic(
    path: &Path,
    data: &[u8],
    mode: u32,
) -> Result<(), FsGuardError> {
    let parent = path.parent().ok_or(FsGuardError::NoParent)?;
    let mut tmp = NamedTempFile::new_in(parent)?;

    // Write + fsync while still a temp file so the rename sees complete bytes.
    tmp.as_file_mut().write_all(data)?;
    tmp.as_file().sync_all()?;

    // Set the final mode BEFORE persist so the target path is never visible
    // with a broader mode, even for a microsecond.
    tmp.as_file()
        .set_permissions(Permissions::from_mode(mode))?;

    tmp.persist(path)?;

    // Fsync the parent directory so the rename survives a crash.
    let dir = File::open(parent)?;
    dir.sync_all()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use tempfile::tempdir;

    fn mode_bits(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn fs_guard_creates_dir_with_restricted_mode() {
        let scratch = tempdir().expect("tempdir");
        let target = scratch.path().join("a").join("b").join("c");

        ensure_dir_restricted(&target, 0o700).expect("ensure dir");

        assert!(target.is_dir(), "directory should be created");
        assert_eq!(mode_bits(&target), 0o700, "leaf should be 0o700");
    }

    #[test]
    fn ensure_dir_repairs_relaxed_mode() {
        let scratch = tempdir().expect("tempdir");
        let target = scratch.path().join("relaxed");
        fs::create_dir(&target).expect("pre-create dir");
        fs::set_permissions(&target, Permissions::from_mode(0o755)).expect("set 0o755");
        assert_eq!(mode_bits(&target), 0o755, "precondition: dir is 0o755");

        ensure_dir_restricted(&target, 0o700).expect("ensure dir");

        assert_eq!(
            mode_bits(&target),
            0o700,
            "ensure_dir_restricted should repair perms on existing dir"
        );
    }

    #[test]
    fn fs_guard_writes_file_with_restricted_mode() {
        let scratch = tempdir().expect("tempdir");
        let target = scratch.path().join("plain.bin");

        write_restricted_bytes(&target, b"hello", 0o600).expect("write");

        assert_eq!(fs::read(&target).expect("read"), b"hello");
        assert_eq!(mode_bits(&target), 0o600, "file should be 0o600");
    }

    #[test]
    fn atomic_write_round_trip() {
        let scratch = tempdir().expect("tempdir");
        let target = scratch.path().join("atomic.bin");
        let payload: &[u8] = b"the quick brown fox";

        write_restricted_bytes_atomic(&target, payload, 0o600).expect("write atomic");

        assert_eq!(fs::read(&target).expect("read"), payload);
        assert_eq!(mode_bits(&target), 0o600, "atomic write should be 0o600");
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let scratch = tempdir().expect("tempdir");
        let target = scratch.path().join("twice.bin");

        write_restricted_bytes_atomic(&target, b"first", 0o600).expect("first write");
        write_restricted_bytes_atomic(&target, b"second", 0o600).expect("second write");

        assert_eq!(
            fs::read(&target).expect("read"),
            b"second",
            "second write must replace first"
        );
        assert_eq!(mode_bits(&target), 0o600, "mode preserved after overwrite");
    }

    #[test]
    fn atomic_write_sets_final_mode_before_persist() {
        // Post-condition assertion: immediately after the helper returns, the
        // target file exists with the requested mode and never with anything
        // broader. Observing the intra-helper window directly would require
        // racing the tempfile rename; the spec guarantees the post-condition,
        // so we assert it across a few iterations to catch any regression
        // that allowed a default-tempfile-mode persist.
        let scratch = tempdir().expect("tempdir");
        let target = scratch.path().join("guarded.bin");

        for i in 0..16 {
            let payload = format!("iteration-{i}");
            write_restricted_bytes_atomic(&target, payload.as_bytes(), 0o600)
                .expect("atomic write");

            let bits = mode_bits(&target);
            assert_eq!(
                bits, 0o600,
                "post-persist mode must be 0o600 (iter {i}, observed {bits:o})"
            );
        }
    }
}
