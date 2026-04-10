use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bifrost_signer::DeviceState;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RunMarker {
    version: u8,
    run_id: String,
    phase: RunPhase,
    state_hash: Option<String>,
    started_at: u64,
    updated_at: u64,
    completed_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RunPhase {
    Running,
    Clean,
}

const RUN_MARKER_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirtyRestartReason {
    MissingMarker,
    InvalidMarker,
    UnsupportedMarkerVersion,
    MarkerRunning,
    MissingStateHash,
    StateHashUnavailable,
    StateHashMismatch,
}

impl DirtyRestartReason {
    pub fn code(self) -> &'static str {
        match self {
            DirtyRestartReason::MissingMarker => "missing_marker",
            DirtyRestartReason::InvalidMarker => "invalid_marker",
            DirtyRestartReason::UnsupportedMarkerVersion => "unsupported_marker_version",
            DirtyRestartReason::MarkerRunning => "marker_running",
            DirtyRestartReason::MissingStateHash => "missing_state_hash",
            DirtyRestartReason::StateHashUnavailable => "state_hash_unavailable",
            DirtyRestartReason::StateHashMismatch => "state_hash_mismatch",
        }
    }

    pub fn event_id(self) -> &'static str {
        match self {
            DirtyRestartReason::MissingMarker => "BAPP-RUN-001",
            DirtyRestartReason::InvalidMarker => "BAPP-RUN-002",
            DirtyRestartReason::UnsupportedMarkerVersion => "BAPP-RUN-003",
            DirtyRestartReason::MarkerRunning => "BAPP-RUN-004",
            DirtyRestartReason::MissingStateHash => "BAPP-RUN-005",
            DirtyRestartReason::StateHashUnavailable => "BAPP-RUN-006",
            DirtyRestartReason::StateHashMismatch => "BAPP-RUN-007",
        }
    }

    pub(crate) fn counter(self) -> &'static AtomicU64 {
        match self {
            DirtyRestartReason::MissingMarker => &DIRTY_RESTART_MISSING_MARKER,
            DirtyRestartReason::InvalidMarker => &DIRTY_RESTART_INVALID_MARKER,
            DirtyRestartReason::UnsupportedMarkerVersion => {
                &DIRTY_RESTART_UNSUPPORTED_MARKER_VERSION
            }
            DirtyRestartReason::MarkerRunning => &DIRTY_RESTART_MARKER_RUNNING,
            DirtyRestartReason::MissingStateHash => &DIRTY_RESTART_MISSING_STATE_HASH,
            DirtyRestartReason::StateHashUnavailable => &DIRTY_RESTART_STATE_HASH_UNAVAILABLE,
            DirtyRestartReason::StateHashMismatch => &DIRTY_RESTART_STATE_HASH_MISMATCH,
        }
    }
}

static DIRTY_RESTART_MISSING_MARKER: AtomicU64 = AtomicU64::new(0);
static DIRTY_RESTART_INVALID_MARKER: AtomicU64 = AtomicU64::new(0);
static DIRTY_RESTART_UNSUPPORTED_MARKER_VERSION: AtomicU64 = AtomicU64::new(0);
static DIRTY_RESTART_MARKER_RUNNING: AtomicU64 = AtomicU64::new(0);
static DIRTY_RESTART_MISSING_STATE_HASH: AtomicU64 = AtomicU64::new(0);
static DIRTY_RESTART_STATE_HASH_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);
static DIRTY_RESTART_STATE_HASH_MISMATCH: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct StateHealthReport {
    pub state_path: String,
    pub marker_path: String,
    pub state_exists: bool,
    pub state_hash: Option<String>,
    pub marker: Option<RunMarkerInfo>,
    pub dirty_reason: Option<DirtyRestartReason>,
    pub clean: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunMarkerInfo {
    pub version: u8,
    pub run_id: String,
    pub phase: String,
    pub state_hash: Option<String>,
    pub started_at: u64,
    pub updated_at: u64,
    pub completed_at: Option<u64>,
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run_marker_path(state_path: &Path) -> PathBuf {
    state_path.with_extension("run.json")
}

fn hash_state_file(state_path: &Path) -> Result<String> {
    let bytes = fs::read(state_path).with_context(|| format!("read {}", state_path.display()))?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(digest))
}

pub fn last_shutdown_clean(state_path: &Path, _state: &DeviceState) -> bool {
    dirty_restart_reason(state_path).is_none()
}

pub fn dirty_restart_reason(state_path: &Path) -> Option<DirtyRestartReason> {
    let path = run_marker_path(state_path);
    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(_) => return Some(DirtyRestartReason::MissingMarker),
    };
    let marker = match serde_json::from_str::<RunMarker>(&raw) {
        Ok(v) => v,
        Err(_) => return Some(DirtyRestartReason::InvalidMarker),
    };
    if marker.version != RUN_MARKER_VERSION {
        return Some(DirtyRestartReason::UnsupportedMarkerVersion);
    }
    if marker.phase != RunPhase::Clean {
        return Some(DirtyRestartReason::MarkerRunning);
    }
    let Some(expected_hash) = marker.state_hash else {
        return Some(DirtyRestartReason::MissingStateHash);
    };
    let Ok(actual_hash) = hash_state_file(state_path) else {
        return Some(DirtyRestartReason::StateHashUnavailable);
    };
    if expected_hash != actual_hash {
        return Some(DirtyRestartReason::StateHashMismatch);
    }
    None
}

pub fn inspect_state_health(state_path: &Path) -> StateHealthReport {
    let marker_path = run_marker_path(state_path);
    let marker = fs::read_to_string(&marker_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<RunMarker>(&raw).ok())
        .map(|marker| RunMarkerInfo {
            version: marker.version,
            run_id: marker.run_id,
            phase: match marker.phase {
                RunPhase::Running => "running".to_string(),
                RunPhase::Clean => "clean".to_string(),
            },
            state_hash: marker.state_hash,
            started_at: marker.started_at,
            updated_at: marker.updated_at,
            completed_at: marker.completed_at,
        });
    let state_hash = hash_state_file(state_path).ok();
    let reason = dirty_restart_reason(state_path);

    StateHealthReport {
        state_path: state_path.display().to_string(),
        marker_path: marker_path.display().to_string(),
        state_exists: state_path.exists(),
        state_hash,
        marker,
        dirty_reason: reason,
        clean: reason.is_none(),
    }
}

pub fn begin_run(state_path: &Path) -> Result<String> {
    let mut run_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut run_bytes);
    let run_id = hex::encode(run_bytes);
    let now = now_unix_secs();
    let marker = RunMarker {
        version: RUN_MARKER_VERSION,
        run_id: run_id.clone(),
        phase: RunPhase::Running,
        state_hash: None,
        started_at: now,
        updated_at: now,
        completed_at: None,
    };
    let path = run_marker_path(state_path);
    write_json_atomic(&path, &marker)?;
    Ok(run_id)
}

pub fn complete_clean_run(state_path: &Path, run_id: &str, _state: &DeviceState) -> Result<()> {
    let now = now_unix_secs();
    let marker = RunMarker {
        version: RUN_MARKER_VERSION,
        run_id: run_id.to_string(),
        phase: RunPhase::Clean,
        state_hash: Some(hash_state_file(state_path)?),
        started_at: now,
        updated_at: now,
        completed_at: Some(now),
    };
    let path = run_marker_path(state_path);
    write_json_atomic(&path, &marker)?;
    Ok(())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    write_bytes_atomic(path, &bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = temp_sibling_path(path);
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_parent_dir(path)?;
    Ok(())
}

fn temp_sibling_path(path: &Path) -> PathBuf {
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    path.with_extension(format!("tmp-{}", hex::encode(suffix)))
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use bifrost_signer::DeviceState;

    use super::*;

    fn temp_path(name: &str, suffix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bifrost-health-{name}-{}-{nonce}.{suffix}",
            std::process::id()
        ))
    }

    fn write_state(path: &Path) {
        fs::write(path, b"state-bytes").expect("write state");
    }

    #[test]
    fn begin_and_complete_clean_run_round_trip_to_clean_health() {
        let state_path = temp_path("state", "bin");
        write_state(&state_path);

        let run_id = begin_run(&state_path).expect("begin run");
        assert_eq!(
            dirty_restart_reason(&state_path),
            Some(DirtyRestartReason::MarkerRunning)
        );

        complete_clean_run(&state_path, &run_id, &DeviceState::new(1, [7u8; 32]))
            .expect("complete clean run");
        let report = inspect_state_health(&state_path);
        assert!(report.clean);
        assert!(report.dirty_reason.is_none());
        assert_eq!(report.marker.as_ref().expect("marker").phase, "clean");
        assert!(last_shutdown_clean(
            &state_path,
            &DeviceState::new(1, [7u8; 32])
        ));

        let _ = fs::remove_file(&state_path);
        let _ = fs::remove_file(state_path.with_extension("run.json"));
    }

    #[test]
    fn dirty_restart_reason_distinguishes_missing_and_mismatched_state() {
        let missing_state = temp_path("missing", "bin");
        assert_eq!(
            dirty_restart_reason(&missing_state),
            Some(DirtyRestartReason::MissingMarker)
        );

        let state_path = temp_path("mismatch", "bin");
        write_state(&state_path);
        let run_id = begin_run(&state_path).expect("begin run");
        complete_clean_run(&state_path, &run_id, &DeviceState::new(1, [9u8; 32]))
            .expect("complete clean run");
        fs::write(&state_path, b"changed-state").expect("mutate state");

        assert_eq!(
            dirty_restart_reason(&state_path),
            Some(DirtyRestartReason::StateHashMismatch)
        );

        let _ = fs::remove_file(&state_path);
        let _ = fs::remove_file(state_path.with_extension("run.json"));
    }
}

use anyhow::Context;
