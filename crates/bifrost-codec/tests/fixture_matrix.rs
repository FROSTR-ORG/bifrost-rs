use std::fs;
use std::path::PathBuf;

use bifrost_codec::{
    decode_envelope, parse_onboard_request, parse_onboard_response, parse_session,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureCase {
    name: String,
    target: String,
    expect_ok: bool,
    #[serde(default)]
    error_contains: Option<String>,
    envelope: serde_json::Value,
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("rpc_parse_matrix.json")
}

#[test]
fn fixture_matrix_covers_rpc_session_onboard_edges() {
    let raw = fs::read_to_string(fixture_path()).expect("read fixture file");
    let cases: Vec<FixtureCase> = serde_json::from_str(&raw).expect("parse fixture json");

    for case in cases {
        let envelope_json =
            serde_json::to_string(&case.envelope).expect("serialize envelope value");

        let result = match case.target.as_str() {
            "decode_envelope" => decode_envelope(&envelope_json).map(|_| ()),
            "parse_session" => {
                let env =
                    decode_envelope(&envelope_json).expect("decode envelope for parse_session");
                parse_session(&env).map(|_| ())
            }
            "parse_onboard_request" => {
                let env = decode_envelope(&envelope_json)
                    .expect("decode envelope for parse_onboard_request");
                parse_onboard_request(&env).map(|_| ())
            }
            "parse_onboard_response" => {
                let env = decode_envelope(&envelope_json)
                    .expect("decode envelope for parse_onboard_response");
                parse_onboard_response(&env).map(|_| ())
            }
            other => panic!("unknown fixture target: {other}"),
        };

        if case.expect_ok {
            assert!(
                result.is_ok(),
                "fixture {} expected ok, got {result:?}",
                case.name
            );
        } else {
            let err = result.expect_err("fixture expected parse/decode failure");
            if let Some(needle) = case.error_contains.as_ref() {
                assert!(
                    err.to_string().contains(needle),
                    "fixture {} expected error containing '{}', got '{}'",
                    case.name,
                    needle,
                    err
                );
            }
        }
    }
}
