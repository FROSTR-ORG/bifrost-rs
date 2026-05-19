//! Rotation intent journal.
//!
//! # Bucket C C.7 — rotation intent journal
//!
//! The rotation flow under [`super::rotation`] performs a multi-step
//! sequence: create the rotated profile, write the new manifest, remove the
//! old profile. If the host crashes between steps the on-disk state can be
//! ambiguous (e.g. a half-written manifest with no corresponding encrypted
//! profile record). The intent journal lets the next daemon process *detect*
//! that ambiguity at startup by leaving a small marker file in
//! `rotations_dir/<workspace_id>/.intent.json` that records the step
//! currently in progress.
//!
//! # File layout
//!
//! - `rotations_dir/<workspace_id>/.intent.json` — one file per active
//!   rotation, written atomically with `0o600` perms via
//!   [`crate::fs_guard::write_restricted_bytes_atomic`].
//!
//! # Scope
//!
//! Per the Bucket C plan, the intent file is *informational* — there is no
//! auto-recovery. On startup the daemon scans the directory and logs a
//! warning for every incomplete rotation (`step != Completed`). Recovery is
//! a manual operator step pending PR12 / a future audit-driven workflow.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

#[cfg(unix)]
use crate::fs_guard::{ensure_dir_restricted, write_restricted_bytes_atomic};
use crate::paths::ProfilePaths;

/// File name written under `rotations_dir/<workspace_id>/`. Dot-prefixed so
/// it sorts last and to keep it visually distinct from any sibling artifacts
/// a future rotation flow might add.
const INTENT_FILE_NAME: &str = ".intent.json";

/// Permissions for the on-disk intent file. `0o600` per Bucket C C.1.
const INTENT_FILE_MODE: u32 = 0o600;

/// Permissions for the per-workspace rotation directory. `0o700` per
/// Bucket C C.1.
const ROTATION_DIR_MODE: u32 = 0o700;

/// Which rotation flow produced this intent. Today only
/// [`RotationKind::RotateShare`] is wired by [`super::rotation`]; the
/// `RotateKeyset` variant is reserved for a follow-on flow that rotates the
/// full keyset (group + all shares) rather than a single device share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationKind {
    /// Single-device share rotation (the existing
    /// `finalize_rotation_update_import` flow).
    RotateShare,
    /// Full keyset rotation (reserved for a future flow).
    RotateKeyset,
}

/// Step the rotation flow is currently executing. Persisted with the intent
/// so a startup scan can tell *where* a crashed rotation stopped, not just
/// *that* one was in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStep {
    /// Written before any rotation work begins. If a crash leaves this
    /// behind, no on-disk state has been mutated yet.
    PreCreate,
    /// The new profile manifest + encrypted profile record were created.
    /// The old profile's manifest still points to its own encrypted record.
    PostCreateNewProfile,
    /// The new manifest has been written. From this point on, callers
    /// reading the profiles directory may see both the old and the new
    /// manifest until the cleanup step runs.
    PostWriteNewManifest,
    /// About to remove the old profile's manifest + encrypted record.
    /// Crash here: the new profile is fully usable, the old one is still
    /// present (and stale).
    PreRemoveOldProfile,
    /// Rotation finished successfully. Intents at this step are pruned by
    /// [`scan_rotation_intents`] (treated as already-finished, no warning
    /// emitted) and deleted by [`delete_intent`] at the end of the flow.
    Completed,
}

/// Journal record persisted to `rotations_dir/<workspace_id>/.intent.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationIntent {
    /// Identifier the rotation is keyed under in `rotations_dir`. Today
    /// this is the originating profile id; future multi-profile workspaces
    /// may map this to a workspace identifier instead.
    pub workspace_id: String,
    /// Which rotation flow produced this intent.
    pub kind: RotationKind,
    /// Profile being rotated *out of* (the existing manifest's id).
    pub profile_id: String,
    /// Unix seconds at which the rotation flow began.
    pub started_at: u64,
    /// Step the rotation flow most recently completed (or is about to
    /// perform — see the individual variant docs).
    pub step: RotationStep,
    /// Unix seconds at which `step` was last updated.
    pub updated_at: u64,
}

impl RotationIntent {
    /// Construct a fresh intent in the [`RotationStep::PreCreate`] state.
    /// The caller persists it with [`write_intent`] before any rotation
    /// work begins.
    pub fn new(
        workspace_id: impl Into<String>,
        kind: RotationKind,
        profile_id: impl Into<String>,
    ) -> Self {
        let now = now_unix_secs();
        Self {
            workspace_id: workspace_id.into(),
            kind,
            profile_id: profile_id.into(),
            started_at: now,
            step: RotationStep::PreCreate,
            updated_at: now,
        }
    }

    /// Move this intent to the next step and refresh `updated_at`.
    pub fn advance(&mut self, step: RotationStep) {
        self.step = step;
        self.updated_at = now_unix_secs();
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn workspace_dir(paths: &ProfilePaths, workspace_id: &str) -> PathBuf {
    paths.rotations_dir.join(workspace_id)
}

fn intent_path(paths: &ProfilePaths, workspace_id: &str) -> PathBuf {
    workspace_dir(paths, workspace_id).join(INTENT_FILE_NAME)
}

/// Write `intent` to `rotations_dir/<workspace_id>/.intent.json` atomically
/// with `0o600` perms.
///
/// The per-workspace parent directory is created with `0o700` perms if
/// necessary; the parent `rotations_dir` itself is expected to exist via
/// [`ProfilePaths::ensure`].
pub fn write_intent(paths: &ProfilePaths, intent: &RotationIntent) -> Result<()> {
    let workspace_dir = workspace_dir(paths, &intent.workspace_id);
    #[cfg(unix)]
    ensure_dir_restricted(&workspace_dir, ROTATION_DIR_MODE)
        .with_context(|| format!("create {}", workspace_dir.display()))?;
    #[cfg(not(unix))]
    fs::create_dir_all(&workspace_dir)
        .with_context(|| format!("create {}", workspace_dir.display()))?;

    let path = workspace_dir.join(INTENT_FILE_NAME);
    let bytes = serde_json::to_vec_pretty(intent).context("serialize rotation intent")?;

    #[cfg(unix)]
    write_restricted_bytes_atomic(&path, &bytes, INTENT_FILE_MODE)
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(not(unix))]
    fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;

    Ok(())
}

/// Remove `rotations_dir/<workspace_id>/.intent.json` if present. The
/// containing workspace directory is left in place — a future rotation in
/// the same workspace may reuse it.
///
/// Idempotent: a missing intent file is not an error.
pub fn delete_intent(paths: &ProfilePaths, workspace_id: &str) -> Result<()> {
    let path = intent_path(paths, workspace_id);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

/// Scan `rotations_dir` for incomplete rotation intents.
///
/// Returns every intent whose `step` is not [`RotationStep::Completed`].
/// `Completed` intents are treated as already-finished and silently
/// filtered. Directories without an `.intent.json` are skipped without
/// warning. Files whose JSON fails to parse log a `warn!` but do not
/// abort the scan — one malformed file should not hide other incomplete
/// rotations from the operator.
pub fn scan_rotation_intents(paths: &ProfilePaths) -> Result<Vec<RotationIntent>> {
    let dir = &paths.rotations_dir;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("iter {}", dir.display()))?;
        let workspace_dir = entry.path();
        if !workspace_dir.is_dir() {
            continue;
        }
        let intent_path = workspace_dir.join(INTENT_FILE_NAME);
        if !intent_path.exists() {
            continue;
        }
        match read_intent_file(&intent_path) {
            Ok(intent) if intent.step != RotationStep::Completed => out.push(intent),
            Ok(_) => {}
            Err(err) => warn!(
                path = %intent_path.display(),
                error = %err,
                "rotation intent file failed to parse; skipping",
            ),
        }
    }
    Ok(out)
}

fn read_intent_file(path: &Path) -> Result<RotationIntent> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_root() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "bifrost-profile-rotation-intent-{}-{nonce}-{seq}",
            std::process::id()
        ))
    }

    fn fixture_paths() -> (PathBuf, ProfilePaths) {
        let root = unique_root();
        fs::create_dir_all(&root).expect("create root");
        let paths = ProfilePaths::from_roots(root.join("config"), root.join("data"), root.join("state"));
        paths.ensure().expect("ensure paths");
        (root, paths)
    }

    #[test]
    fn rotation_intent_round_trip() {
        let intent = RotationIntent {
            workspace_id: "ws-1".to_string(),
            kind: RotationKind::RotateShare,
            profile_id: "prof-1".to_string(),
            started_at: 42,
            step: RotationStep::PostCreateNewProfile,
            updated_at: 50,
        };

        let raw = serde_json::to_string(&intent).expect("serialize");
        let parsed: RotationIntent = serde_json::from_str(&raw).expect("deserialize");
        assert_eq!(parsed, intent);
    }

    #[cfg(unix)]
    #[test]
    fn write_intent_uses_0600() {
        use std::os::unix::fs::PermissionsExt;

        let (root, paths) = fixture_paths();
        let intent = RotationIntent::new("ws-mode", RotationKind::RotateShare, "prof-1");
        write_intent(&paths, &intent).expect("write intent");

        let path = intent_path(&paths, "ws-mode");
        let mode = fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "intent file must be 0o600");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scan_returns_incomplete_intents() {
        let (root, paths) = fixture_paths();

        let mut incomplete = RotationIntent::new("ws-incomplete", RotationKind::RotateShare, "prof-1");
        incomplete.advance(RotationStep::PostCreateNewProfile);
        write_intent(&paths, &incomplete).expect("write incomplete intent");

        let mut completed = RotationIntent::new("ws-complete", RotationKind::RotateShare, "prof-2");
        completed.advance(RotationStep::Completed);
        write_intent(&paths, &completed).expect("write completed intent");

        let scanned = scan_rotation_intents(&paths).expect("scan");
        assert_eq!(scanned.len(), 1, "completed intents must be filtered");
        assert_eq!(scanned[0].workspace_id, "ws-incomplete");
        assert_eq!(scanned[0].step, RotationStep::PostCreateNewProfile);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scan_ignores_missing_intent_files() {
        let (root, paths) = fixture_paths();
        let scanned = scan_rotation_intents(&paths).expect("scan empty");
        assert!(scanned.is_empty());

        // A workspace directory without an .intent.json must be silently
        // skipped — a future rotation may re-use the directory.
        fs::create_dir_all(paths.rotations_dir.join("ws-empty")).expect("create empty ws dir");
        let scanned = scan_rotation_intents(&paths).expect("scan with empty ws");
        assert!(scanned.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn delete_intent_removes_file() {
        let (root, paths) = fixture_paths();

        let intent = RotationIntent::new("ws-del", RotationKind::RotateShare, "prof-1");
        write_intent(&paths, &intent).expect("write intent");
        assert!(intent_path(&paths, "ws-del").exists());

        delete_intent(&paths, "ws-del").expect("delete intent");
        assert!(!intent_path(&paths, "ws-del").exists());

        // Idempotent — deleting again is not an error.
        delete_intent(&paths, "ws-del").expect("delete again");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scan_logs_warning_for_malformed_intent_and_continues() {
        let (root, paths) = fixture_paths();

        // Seed one valid incomplete intent.
        let mut good = RotationIntent::new("ws-good", RotationKind::RotateShare, "prof-1");
        good.advance(RotationStep::PostWriteNewManifest);
        write_intent(&paths, &good).expect("write good intent");

        // Seed a workspace with a malformed .intent.json — must not abort
        // the scan.
        let bad_dir = paths.rotations_dir.join("ws-bad");
        fs::create_dir_all(&bad_dir).expect("create bad workspace");
        fs::write(bad_dir.join(INTENT_FILE_NAME), b"not json").expect("write bad intent");

        let scanned = scan_rotation_intents(&paths).expect("scan");
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].workspace_id, "ws-good");

        let _ = fs::remove_dir_all(root);
    }
}
