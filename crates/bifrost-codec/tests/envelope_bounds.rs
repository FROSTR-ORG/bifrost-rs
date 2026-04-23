//! Bound checks around the bridge envelope surface.
//!
//! See `A.3` of the 2026-04-22 remediation plan: the decode path used to
//! accept arbitrarily large inputs and oversized string fields, giving any
//! authenticated peer a DoS oracle. These tests nail down both caps.

use bifrost_codec::bridge::{MAX_BRIDGE_ENVELOPE_BYTES, decode_bridge_envelope};
use bifrost_codec::error::CodecError;

/// The envelope-size cap must be applied *before* JSON parsing, so even
/// inputs that are textually not valid JSON fail with the size error.
/// The assertion here — that we return `EnvelopeTooLarge` without ever
/// invoking `serde_json::from_str` — is the allocation-safety claim
/// noted in the plan.
#[test]
fn decode_rejects_oversized_envelope_before_parse() {
    let oversized = "x".repeat(MAX_BRIDGE_ENVELOPE_BYTES + 1);
    let err = decode_bridge_envelope(&oversized).expect_err("must reject oversized envelope");
    assert!(matches!(err, CodecError::EnvelopeTooLarge));
}

#[test]
fn decode_accepts_maximum_sized_valid_input() {
    // Build a valid envelope, then pad it up to exactly
    // `MAX_BRIDGE_ENVELOPE_BYTES` using repeated spaces inside the JSON
    // object (the serde_json parser is whitespace-tolerant).
    let base = r#"{"request_id":"req-1","sent_at":1700000000,"payload":{"type":"Error","data":{"code":"ERR","message":"boom"}}}"#;
    assert!(base.len() < MAX_BRIDGE_ENVELOPE_BYTES);
    let pad = MAX_BRIDGE_ENVELOPE_BYTES - base.len();
    let mut padded = String::with_capacity(MAX_BRIDGE_ENVELOPE_BYTES);
    // Inject whitespace padding just inside the opening brace — stays
    // valid JSON.
    padded.push('{');
    padded.push_str(&" ".repeat(pad));
    padded.push_str(&base[1..]);
    assert_eq!(padded.len(), MAX_BRIDGE_ENVELOPE_BYTES);
    let decoded = decode_bridge_envelope(&padded).expect("max-sized envelope should decode");
    assert_eq!(decoded.request_id, "req-1");
}

#[test]
fn decode_rejects_oversized_field_in_valid_envelope() {
    // `code` is an identifier field with a 1 KiB cap.
    let oversized_code = "x".repeat(1025);
    let raw = format!(
        r#"{{"request_id":"req-1","sent_at":1700000000,"payload":{{"type":"Error","data":{{"code":"{oversized_code}","message":"boom"}}}}}}"#,
    );
    let err = decode_bridge_envelope(&raw).expect_err("must reject oversized code field");
    match err {
        CodecError::FieldTooLarge { field, limit } => {
            assert_eq!(field, "code");
            assert_eq!(limit, 1024);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn decode_rejects_oversized_content_hex() {
    // `content` is a 32 KiB hex payload.
    let oversized_content = "ab".repeat(16 * 1024 + 1); // 32 KiB + 2 bytes of hex
    let raw = format!(
        r#"{{"request_id":"req-1","sent_at":1700000000,"payload":{{"type":"SignRequest","data":{{"gid":"{gid}","sid":"{sid}","members":[1,2],"hashes":["{hash}"],"content":"{oversized_content}","kind":"nostr-event","stamp":1}}}}}}"#,
        gid = "01".repeat(32),
        sid = "02".repeat(32),
        hash = "03".repeat(32),
    );
    // Guard: the raw envelope itself should still fit under the envelope cap.
    assert!(raw.len() <= MAX_BRIDGE_ENVELOPE_BYTES);
    let err = decode_bridge_envelope(&raw).expect_err("must reject oversized content");
    match err {
        CodecError::FieldTooLarge { field, limit } => {
            assert_eq!(field, "content");
            assert_eq!(limit, 32 * 1024);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
