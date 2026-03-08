use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use bifrost_app::runtime::{
    DirtyRestartReason, begin_run, complete_clean_run, dirty_restart_reason, last_shutdown_clean,
};
use bifrost_signer::DeviceState;

fn temp_state_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bifrost-app-{name}-{}-{nonce}.json",
        std::process::id()
    ))
}

#[test]
fn run_marker_v2_clean_roundtrip() {
    let state_path = temp_state_path("marker-clean");
    let marker_path = state_path.with_extension("run.json");
    let _ = fs::remove_file(&state_path);
    let _ = fs::remove_file(&marker_path);

    let state = DeviceState::new(1, [1u8; 32]);
    let run_id = begin_run(&state_path).expect("begin run");
    fs::write(&state_path, b"state-bytes-clean").expect("write state bytes");
    assert!(!last_shutdown_clean(&state_path, &state));
    assert_eq!(
        dirty_restart_reason(&state_path),
        Some(DirtyRestartReason::MarkerRunning)
    );
    complete_clean_run(&state_path, &run_id, &state).expect("complete clean run");
    assert!(last_shutdown_clean(&state_path, &state));
    assert_eq!(dirty_restart_reason(&state_path), None);

    let _ = fs::remove_file(&state_path);
    let _ = fs::remove_file(&marker_path);
}

#[test]
fn run_marker_v2_hash_mismatch_is_dirty() {
    let state_path = temp_state_path("marker-hash-mismatch");
    let marker_path = state_path.with_extension("run.json");
    let _ = fs::remove_file(&state_path);
    let _ = fs::remove_file(&marker_path);

    let clean_state = DeviceState::new(1, [2u8; 32]);
    let run_id = begin_run(&state_path).expect("begin run");
    fs::write(&state_path, b"state-bytes-before").expect("write state bytes");
    complete_clean_run(&state_path, &run_id, &clean_state).expect("complete clean run");
    fs::write(&state_path, b"state-bytes-after").expect("mutate state bytes");

    let different_state = DeviceState::new(1, [3u8; 32]);
    assert!(!last_shutdown_clean(&state_path, &different_state));
    assert_eq!(
        dirty_restart_reason(&state_path),
        Some(DirtyRestartReason::StateHashMismatch)
    );

    let _ = fs::remove_file(&state_path);
    let _ = fs::remove_file(&marker_path);
}

#[test]
fn legacy_marker_is_treated_as_dirty() {
    let state_path = temp_state_path("marker-legacy");
    let marker_path = state_path.with_extension("run.json");
    let _ = fs::remove_file(&state_path);
    let _ = fs::remove_file(&marker_path);

    fs::write(
        &marker_path,
        r#"{"clean_shutdown":true,"run_id":"legacy","state_hash":null,"updated_at":1}"#,
    )
    .expect("write legacy marker");
    let state = DeviceState::new(1, [4u8; 32]);
    assert!(!last_shutdown_clean(&state_path, &state));
    assert_eq!(
        dirty_restart_reason(&state_path),
        Some(DirtyRestartReason::InvalidMarker)
    );

    let _ = fs::remove_file(&state_path);
    let _ = fs::remove_file(&marker_path);
}
