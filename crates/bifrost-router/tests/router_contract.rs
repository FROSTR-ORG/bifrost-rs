//! Public-contract pins for `bifrost-router` (R3 / Bucket I, PR-I3).
//!
//! ## Coverage gap note
//!
//! `bifrost-router` has no `tests/` directory of its own, but its *behavior* is
//! already well covered from two directions, so this file deliberately does NOT
//! re-test it:
//!
//! - **In-crate unit tests** (`src/lib.rs`, `#[cfg(test)]`): command-queue
//!   `QueueFull` and drop-oldest, inbound fail/drop-oldest, dedupe-cache
//!   eviction, `fail_request` -> `RequestPhase::Failed`, expiry -> `Failed`,
//!   `wipe_state` reset, and config validation.
//! - **`bifrost-bridge-tokio/tests/`** (integration, full relay round-trips):
//!   `request_phase_reaches_completed_for_successful_ping` /
//!   `..._onboard_and_sign` (the `Completed` transition), `publish_failure_marks_
//!   request_failed`, `locked_peer_timeout_marks_request_failed`,
//!   `inbound_duplicate_event_is_processed_once`, and
//!   `outbound_queue_overflow_fails_round`.
//!
//! What remains genuinely untested is the crate's **public type surface** — the
//! serialized wire forms, the documented default constants, and the error
//! Display strings — which this file pins as a regression fence. These need no
//! signer/relay harness, so the file stays dependency-light.
//!
//! Note surfaced while writing this: `RequestPhase::Expired` is defined and
//! serializable but is never assigned by the router — request timeouts transition
//! to `Failed` (see `expire_marks_timed_out_request_failed` in the in-crate
//! tests and `locked_peer_timeout_marks_request_failed` in bifrost-bridge-tokio).
//! The variant is retained for wire/forward-compatibility; the test below pins
//! its serialized form so any future use is wire-stable.

use bifrost_router::{
    BridgeConfig, BridgeCoreError, DEFAULT_COMMAND_OVERFLOW_POLICY, DEFAULT_COMMAND_QUEUE_CAPACITY,
    DEFAULT_EXPIRE_TICK_MS, DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT, DEFAULT_INBOUND_OVERFLOW_POLICY,
    DEFAULT_INBOUND_QUEUE_CAPACITY, DEFAULT_OUTBOUND_OVERFLOW_POLICY,
    DEFAULT_OUTBOUND_QUEUE_CAPACITY, QueueOverflowPolicy, RequestPhase,
};

#[test]
fn request_phase_serializes_in_snake_case() {
    let cases = [
        (RequestPhase::Created, "\"created\""),
        (RequestPhase::AwaitingResponses, "\"awaiting_responses\""),
        (RequestPhase::Completed, "\"completed\""),
        (RequestPhase::Failed, "\"failed\""),
        (RequestPhase::Expired, "\"expired\""),
    ];
    for (phase, expected) in cases {
        let encoded = serde_json::to_string(&phase).expect("serialize phase");
        assert_eq!(encoded, expected, "wire form for {phase:?}");
        let decoded: RequestPhase = serde_json::from_str(&encoded).expect("deserialize phase");
        assert_eq!(decoded, phase, "round-trip for {phase:?}");
    }
}

#[test]
fn queue_overflow_policy_serializes_with_variant_names() {
    // QueueOverflowPolicy has no rename attribute, so the wire form is the
    // verbatim variant name.
    assert_eq!(
        serde_json::to_string(&QueueOverflowPolicy::Fail).expect("serialize"),
        "\"Fail\""
    );
    assert_eq!(
        serde_json::to_string(&QueueOverflowPolicy::DropOldest).expect("serialize"),
        "\"DropOldest\""
    );
    for policy in [QueueOverflowPolicy::Fail, QueueOverflowPolicy::DropOldest] {
        let encoded = serde_json::to_string(&policy).expect("serialize");
        let decoded: QueueOverflowPolicy = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, policy);
    }
}

#[test]
fn bridge_config_default_matches_documented_constants() {
    // Guards against drift between the public DEFAULT_* constants (used by host
    // config docs/UI) and what BridgeConfig::default() actually produces.
    let cfg = BridgeConfig::default();
    assert_eq!(
        cfg.expire_tick,
        std::time::Duration::from_millis(DEFAULT_EXPIRE_TICK_MS)
    );
    assert_eq!(cfg.command_queue_capacity, DEFAULT_COMMAND_QUEUE_CAPACITY);
    assert_eq!(cfg.inbound_queue_capacity, DEFAULT_INBOUND_QUEUE_CAPACITY);
    assert_eq!(cfg.outbound_queue_capacity, DEFAULT_OUTBOUND_QUEUE_CAPACITY);
    assert_eq!(cfg.command_overflow_policy, DEFAULT_COMMAND_OVERFLOW_POLICY);
    assert_eq!(cfg.inbound_overflow_policy, DEFAULT_INBOUND_OVERFLOW_POLICY);
    assert_eq!(
        cfg.outbound_overflow_policy,
        DEFAULT_OUTBOUND_OVERFLOW_POLICY
    );
    assert_eq!(
        cfg.inbound_dedupe_cache_limit,
        DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT
    );

    // The documented default policy split: command/outbound fail closed,
    // inbound drops oldest.
    assert_eq!(cfg.command_overflow_policy, QueueOverflowPolicy::Fail);
    assert_eq!(cfg.outbound_overflow_policy, QueueOverflowPolicy::Fail);
    assert_eq!(cfg.inbound_overflow_policy, QueueOverflowPolicy::DropOldest);
}

#[test]
fn bridge_config_round_trips_through_json() {
    let cfg = BridgeConfig::default();
    let encoded = serde_json::to_string(&cfg).expect("serialize config");
    let decoded: BridgeConfig = serde_json::from_str(&encoded).expect("deserialize config");
    assert_eq!(decoded.command_queue_capacity, cfg.command_queue_capacity);
    assert_eq!(
        decoded.inbound_dedupe_cache_limit,
        cfg.inbound_dedupe_cache_limit
    );
    assert_eq!(decoded.command_overflow_policy, cfg.command_overflow_policy);
}

#[test]
fn bridge_core_error_display_is_stable() {
    let full = BridgeCoreError::QueueFull {
        queue: "command".to_string(),
    };
    assert_eq!(full.to_string(), "command queue is full");

    let internal = BridgeCoreError::Internal("boom".to_string());
    assert_eq!(internal.to_string(), "bridge internal failure: boom");
}
