use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bifrost_rpc::{BifrostRpcRequest, BifrostRpcResponse, RpcRequestEnvelope, RpcResponseEnvelope};

struct Case {
    name: &'static str,
    cli_args: Vec<&'static str>,
    expected_request: BifrostRpcRequest,
    response_data: serde_json::Value,
    expected_stdout: &'static str,
}

#[test]
fn cli_e2e_covers_all_rpc_commands() {
    let cases = vec![
        Case {
            name: "negotiate",
            cli_args: vec!["negotiate", "bifrost-cli-test", "1"],
            expected_request: BifrostRpcRequest::Negotiate {
                client_name: "bifrost-cli-test".to_string(),
                client_version: 1,
            },
            response_data: serde_json::json!({"compatible": true, "server_version": 1}),
            expected_stdout: "\"compatible\": true",
        },
        Case {
            name: "health",
            cli_args: vec!["health"],
            expected_request: BifrostRpcRequest::Health,
            response_data: serde_json::json!({"ok": true}),
            expected_stdout: "\"ok\": true",
        },
        Case {
            name: "status",
            cli_args: vec!["status"],
            expected_request: BifrostRpcRequest::Status,
            response_data: serde_json::json!({"ready": true}),
            expected_stdout: "\"ready\": true",
        },
        Case {
            name: "events",
            cli_args: vec!["events", "7"],
            expected_request: BifrostRpcRequest::Events { limit: 7 },
            response_data: serde_json::json!({"events": ["ready", "message"]}),
            expected_stdout: "\"events\"",
        },
        Case {
            name: "echo",
            cli_args: vec!["echo", "peer1", "hello", "world"],
            expected_request: BifrostRpcRequest::Echo {
                peer: "peer1".to_string(),
                message: "hello world".to_string(),
            },
            response_data: serde_json::json!({"echo": "hello world"}),
            expected_stdout: "\"echo\"",
        },
        Case {
            name: "ping",
            cli_args: vec!["ping", "peer1"],
            expected_request: BifrostRpcRequest::Ping {
                peer: "peer1".to_string(),
            },
            response_data: serde_json::json!({"version": 1}),
            expected_stdout: "\"version\": 1",
        },
        Case {
            name: "onboard",
            cli_args: vec!["onboard", "peer1"],
            expected_request: BifrostRpcRequest::Onboard {
                peer: "peer1".to_string(),
            },
            response_data: serde_json::json!({"group": {"threshold": 2}}),
            expected_stdout: "\"threshold\": 2",
        },
        Case {
            name: "sign",
            cli_args: vec![
                "sign",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
            expected_request: BifrostRpcRequest::Sign {
                message32_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            },
            response_data: serde_json::json!({"signature": "ff"}),
            expected_stdout: "\"signature\"",
        },
        Case {
            name: "ecdh",
            cli_args: vec![
                "ecdh",
                "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
            expected_request: BifrostRpcRequest::Ecdh {
                pubkey33_hex: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            },
            response_data: serde_json::json!({"shared_secret": "ee"}),
            expected_stdout: "\"shared_secret\"",
        },
        Case {
            name: "shutdown",
            cli_args: vec!["shutdown"],
            expected_request: BifrostRpcRequest::Shutdown,
            response_data: serde_json::json!({"shutting_down": true}),
            expected_stdout: "\"shutting_down\": true",
        },
    ];

    for case in cases {
        run_case(case);
    }
}

fn run_case(case: Case) {
    let socket = unique_socket_path(case.name);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (req_tx, req_rx) = mpsc::channel();
    let response_data = case.response_data.clone();

    let socket_for_thread = socket.clone();
    let server = thread::spawn(move || {
        let _ = fs::remove_file(&socket_for_thread);
        let listener = UnixListener::bind(&socket_for_thread).expect("bind socket");
        ready_tx.send(()).expect("ready");

        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("read request line");
        let req: RpcRequestEnvelope = serde_json::from_str(line.trim()).expect("parse request");
        req_tx.send(req.clone()).expect("send request");

        let resp = RpcResponseEnvelope {
            id: req.id,
            response: BifrostRpcResponse::Ok(response_data),
        };
        let raw = serde_json::to_string(&resp).expect("encode response");
        stream.write_all(raw.as_bytes()).expect("write response");
        stream.write_all(b"\n").expect("write newline");
        stream.flush().expect("flush");

        drop(listener);
        let _ = fs::remove_file(&socket_for_thread);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("server ready");

    let mut args = vec!["--socket".to_string(), socket.display().to_string()];
    args.extend(case.cli_args.iter().map(|s| s.to_string()));

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
        .args(&args)
        .output()
        .expect("run bifrost-cli");

    assert!(
        output.status.success(),
        "case {} failed: stderr={}",
        case.name,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(case.expected_stdout),
        "case {} stdout did not contain {:?}; got {}",
        case.name,
        case.expected_stdout,
        stdout
    );

    let received = req_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("receive request");
    let got = serde_json::to_value(received.request).expect("serialize got");
    let expected = serde_json::to_value(case.expected_request).expect("serialize expected");
    assert_eq!(got, expected, "case {} request mismatch", case.name);

    server.join().expect("server thread");
}

fn unique_socket_path(label: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(PathBuf::from)
        .expect("workspace root");
    base.join(format!(".c-{label}-{pid}-{now}.sock"))
}
