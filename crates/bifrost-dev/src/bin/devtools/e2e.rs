use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

pub fn print_e2e_usage() {
    eprintln!("  e2e-node [--out-dir DIR] [--relay URL]");
    eprintln!(
        "  e2e-full [--out-dir DIR] [--relay URL] [--threshold N] [--count N] [--sign-iterations N] [--ecdh-iterations N] [--seed N]"
    );
}

pub fn run_e2e_node_command(args: &[String]) -> Result<()> {
    let mut out_dir: Option<PathBuf> = None;
    let mut relay = "ws://127.0.0.1:8194".to_string();

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--out-dir" => {
                let value = args
                    .get(idx + 1)
                    .context("missing value for --out-dir")?
                    .clone();
                out_dir = Some(PathBuf::from(value));
                idx += 2;
            }
            "--relay" => {
                relay = args
                    .get(idx + 1)
                    .context("missing value for --relay")?
                    .clone();
                idx += 2;
            }
            "help" | "--help" | "-h" => {
                print_e2e_usage();
                return Ok(());
            }
            other => bail!("unknown e2e-node argument: {other}"),
        }
    }

    let root = workspace_root()?;
    let out_dir = out_dir.unwrap_or_else(|| root.join("dev/data"));
    let logs_dir = out_dir.join("logs");
    fs::create_dir_all(&logs_dir).with_context(|| format!("create {}", logs_dir.display()))?;
    let out_file = logs_dir.join("node-e2e-output.txt");
    fs::write(&out_file, "").with_context(|| format!("create {}", out_file.display()))?;

    generate_runtime_material(&root, &out_dir, &relay, 2, 3)?;
    run_cargo_status(
        &root,
        [
            "build",
            "-p",
            "bifrost-dev",
            "-p",
            "bifrost-app",
            "--offline",
        ],
    )?;

    run_node_flow(&root, &out_dir, &logs_dir, &out_file, &relay)?;
    run_ecdh_flow(&root, &out_dir, &logs_dir, &out_file, &relay)?;

    println!("node e2e passed");
    Ok(())
}

fn run_node_flow(
    root: &Path,
    out_dir: &Path,
    logs_dir: &Path,
    out_file: &Path,
    relay: &str,
) -> Result<()> {
    let mut responders = start_responders(root, out_dir, logs_dir, relay)?;
    thread::sleep(Duration::from_secs(2));

    let alice_cfg = out_dir.join("bifrost-alice.json");
    let peers = extract_peers(&alice_cfg)?;
    run_bifrost_and_record(root, &alice_cfg, out_file, "status", &["status"])?;
    run_bifrost_and_record(root, &alice_cfg, out_file, "policies", &["policies"])?;
    for peer in &peers {
        run_bifrost_and_record(root, &alice_cfg, out_file, "ping", &["ping", peer])?;
    }
    for peer in &peers {
        run_bifrost_and_record(root, &alice_cfg, out_file, "onboard", &["onboard", peer])?;
    }

    let sign_output = run_bifrost_capture(
        root,
        &alice_cfg,
        &[
            "sign",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
    )?;
    append_output(out_file, "sign", &sign_output)?;
    let sig = extract_last_hex_line(&sign_output, 128).context("invalid signature output")?;
    if sig.len() != 128 {
        bail!("invalid signature output length: {}", sig.len());
    }

    responders.stop_all();
    Ok(())
}

fn run_ecdh_flow(
    root: &Path,
    out_dir: &Path,
    logs_dir: &Path,
    out_file: &Path,
    relay: &str,
) -> Result<()> {
    generate_runtime_material(root, out_dir, relay, 2, 3)?;

    let mut responders = start_responders(root, out_dir, logs_dir, relay)?;
    thread::sleep(Duration::from_secs(2));

    let alice_cfg = out_dir.join("bifrost-alice.json");
    let peers = extract_peers(&alice_cfg)?;
    let target_peer = peers
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("missing peer for ecdh flow"))?;
    for peer in &peers {
        run_bifrost_and_record(root, &alice_cfg, out_file, "ping-ecdh", &["ping", peer])?;
    }
    let ecdh_output = run_bifrost_capture(root, &alice_cfg, &["ecdh", &target_peer])?;
    append_output(out_file, "ecdh", &ecdh_output)?;
    let secret = extract_last_hex_line(&ecdh_output, 64).context("invalid ecdh output")?;
    if secret.len() != 64 {
        bail!("invalid ecdh output length: {}", secret.len());
    }

    responders.stop_all();
    Ok(())
}

fn generate_runtime_material(
    root: &Path,
    out_dir: &Path,
    relay: &str,
    threshold: u16,
    count: u16,
) -> Result<()> {
    prune_state_files(out_dir)?;
    let threshold_arg = threshold.to_string();
    let count_arg = count.to_string();
    run_cargo_status(
        root,
        [
            "run",
            "--quiet",
            "-p",
            "bifrost-dev",
            "--bin",
            "bifrost-devtools",
            "--offline",
            "--",
            "keygen",
            "--out-dir",
            out_dir
                .to_str()
                .ok_or_else(|| anyhow!("invalid out-dir utf8"))?,
            "--threshold",
            threshold_arg.as_str(),
            "--count",
            count_arg.as_str(),
            "--relay",
            relay,
        ],
    )
}

fn prune_state_files(out_dir: &Path) -> Result<()> {
    if !out_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(out_dir).with_context(|| format!("read {}", out_dir.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if (name.starts_with("state-") && (name.ends_with(".json") || name.ends_with(".lock")))
            || (name.starts_with("share-") && name.ends_with(".json"))
            || (name.starts_with("bifrost-") && name.ends_with(".json"))
            || name == "group.json"
        {
            fs::remove_file(entry.path())
                .with_context(|| format!("remove {}", entry.path().display()))?;
        }
    }
    Ok(())
}

fn start_responders(
    root: &Path,
    out_dir: &Path,
    logs_dir: &Path,
    relay: &str,
) -> Result<ProcessSet> {
    let relay_port = relay_port(relay)?;
    let relay_port_arg = relay_port.to_string();
    let mut processes = ProcessSet::default();

    processes.spawn_logged(
        Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "-p",
                "bifrost-dev",
                "--bin",
                "bifrost-devtools",
                "--offline",
                "--",
                "relay",
                relay_port_arg.as_str(),
            ])
            .current_dir(root),
        logs_dir.join("relay.log"),
    )?;

    let bob_cfg = out_dir.join("bifrost-bob.json");
    processes.spawn_logged(
        Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "-p",
                "bifrost-app",
                "--bin",
                "bifrost",
                "--offline",
                "--",
                "--config",
                bob_cfg
                    .to_str()
                    .ok_or_else(|| anyhow!("invalid utf8 in bob config path"))?,
                "listen",
            ])
            .current_dir(root),
        logs_dir.join("bifrost-bob.log"),
    )?;

    let carol_cfg = out_dir.join("bifrost-carol.json");
    processes.spawn_logged(
        Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "-p",
                "bifrost-app",
                "--bin",
                "bifrost",
                "--offline",
                "--",
                "--config",
                carol_cfg
                    .to_str()
                    .ok_or_else(|| anyhow!("invalid utf8 in carol config path"))?,
                "listen",
            ])
            .current_dir(root),
        logs_dir.join("bifrost-carol.log"),
    )?;

    Ok(processes)
}

fn extract_peers(config_path: &Path) -> Result<Vec<String>> {
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let parsed: Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", config_path.display()))?;
    let mut peers = parsed
        .get("peers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing peers array"))?
        .iter()
        .filter_map(|peer| {
            peer.get("pubkey")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    peers.sort();
    if peers.is_empty() {
        return Err(anyhow!(
            "failed to extract peer pubkeys from {}",
            config_path.display()
        ));
    }
    Ok(peers)
}

fn run_bifrost_and_record(
    root: &Path,
    config_path: &Path,
    out_file: &Path,
    label: &str,
    args: &[&str],
) -> Result<()> {
    let output = run_bifrost_capture(root, config_path, args)?;
    append_output(out_file, label, &output)
}

fn run_bifrost_capture(root: &Path, config_path: &Path, args: &[&str]) -> Result<String> {
    let config = config_path
        .to_str()
        .ok_or_else(|| anyhow!("invalid utf8 in config path"))?;
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "bifrost-app",
            "--bin",
            "bifrost",
            "--offline",
            "--",
            "--config",
            config,
        ])
        .args(args)
        .current_dir(root)
        .output()
        .context("run bifrost command")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "bifrost command failed ({:?})\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn append_output(out_file: &Path, label: &str, body: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(out_file)
        .with_context(|| format!("open {}", out_file.display()))?;
    writeln!(file, "\n### {label}")?;
    writeln!(file, "{body}")?;
    Ok(())
}

fn extract_last_hex_line(output: &str, len: usize) -> Option<String> {
    output
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| line.len() == len && line.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_string)
}

fn relay_port(relay: &str) -> Result<u16> {
    let without_scheme = relay
        .strip_prefix("ws://")
        .or_else(|| relay.strip_prefix("wss://"))
        .unwrap_or(relay);
    let port_str = without_scheme
        .rsplit(':')
        .next()
        .ok_or_else(|| anyhow!("relay URL missing port: {relay}"))?;
    port_str
        .parse::<u16>()
        .with_context(|| format!("invalid relay port in URL: {relay}"))
}

pub fn run_e2e_full_command(args: &[String]) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = args;
        bail!("e2e-full currently requires a unix target");
    }
    #[cfg(unix)]
    {
        let mut out_dir: Option<PathBuf> = None;
        let mut relay = "ws://127.0.0.1:8194".to_string();
        let mut threshold: u16 = 11;
        let mut count: u16 = 15;
        let mut sign_iterations: usize = 20;
        let mut ecdh_iterations: usize = 20;
        let mut seed: u64 = 0xB1F0_5EED_2026_0001;

        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--out-dir" => {
                    out_dir = Some(PathBuf::from(
                        args.get(idx + 1).context("missing value for --out-dir")?,
                    ));
                    idx += 2;
                }
                "--relay" => {
                    relay = args.get(idx + 1).context("missing value for --relay")?.clone();
                    idx += 2;
                }
                "--threshold" => {
                    threshold = args
                        .get(idx + 1)
                        .context("missing value for --threshold")?
                        .parse::<u16>()
                        .context("invalid --threshold")?;
                    idx += 2;
                }
                "--count" => {
                    count = args
                        .get(idx + 1)
                        .context("missing value for --count")?
                        .parse::<u16>()
                        .context("invalid --count")?;
                    idx += 2;
                }
                "--sign-iterations" => {
                    sign_iterations = args
                        .get(idx + 1)
                        .context("missing value for --sign-iterations")?
                        .parse::<usize>()
                        .context("invalid --sign-iterations")?;
                    idx += 2;
                }
                "--ecdh-iterations" => {
                    ecdh_iterations = args
                        .get(idx + 1)
                        .context("missing value for --ecdh-iterations")?
                        .parse::<usize>()
                        .context("invalid --ecdh-iterations")?;
                    idx += 2;
                }
                "--seed" => {
                    seed = args
                        .get(idx + 1)
                        .context("missing value for --seed")?
                        .parse::<u64>()
                        .context("invalid --seed")?;
                    idx += 2;
                }
                "help" | "--help" | "-h" => {
                    print_e2e_usage();
                    return Ok(());
                }
                other => bail!("unknown e2e-full argument: {other}"),
            }
        }

        if threshold < 2 || count < threshold {
            bail!("e2e-full requires count >= threshold >= 2");
        }

        let root = workspace_root()?;
        let out_dir = out_dir.unwrap_or_else(|| root.join("dev/data"));
        let logs_dir = out_dir.join("logs");
        fs::create_dir_all(&logs_dir).with_context(|| format!("create {}", logs_dir.display()))?;
        let out_file = logs_dir.join("node-e2e-full-output.txt");
        fs::write(&out_file, "").with_context(|| format!("create {}", out_file.display()))?;
        append_output(&out_file, "seed", &format!("{seed}"))?;

        generate_runtime_material(&root, &out_dir, &relay, threshold, count)?;
        run_cargo_status(
            &root,
            [
                "build",
                "-p",
                "bifrost-dev",
                "-p",
                "bifrost-app",
                "--offline",
            ],
        )?;

        let token = format!("e2e-full-token-{seed}");
        let mut processes = ProcessSet::default();
        start_relay_process(&mut processes, &root, &logs_dir, &relay)?;
        let nodes = load_nodes(&out_dir, &logs_dir, &token)?;
        start_node_listeners(&mut processes, &root, &nodes, &logs_dir, &token)?;
        wait_for_control_sockets(&nodes, Duration::from_secs(60))?;

        let mut request_seq = 1u64;
        run_onboarding_chain(&nodes, &token, &mut request_seq, &out_file)?;
        run_ping_mesh(&nodes, &token, &mut request_seq, None, &out_file)?;

        let mut rng = Lcg::new(seed);
        let policy_matrix =
            randomize_policies(&nodes, &token, &mut request_seq, &mut rng, &out_file)?;
        run_ping_mesh(
            &nodes,
            &token,
            &mut request_seq,
            Some(&policy_matrix),
            &out_file,
        )?;

        set_all_policies_allow(&nodes, &token, &mut request_seq, &out_file)?;
        run_sign_iterations(
            &nodes,
            &token,
            &mut request_seq,
            &mut rng,
            sign_iterations,
            &out_file,
        )?;
        run_ecdh_iterations(
            &nodes,
            &token,
            &mut request_seq,
            &mut rng,
            ecdh_iterations,
            &out_file,
        )?;
        run_edge_cases(&nodes, &token, &mut request_seq, &out_file)?;

        append_output(&out_file, "summary", "e2e-full passed")?;
        processes.stop_all();
        println!("node e2e-full passed");
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone)]
struct NodeContext {
    name: String,
    config_path: PathBuf,
    control_socket: PathBuf,
    self_pubkey: String,
}

#[cfg(unix)]
fn load_nodes(out_dir: &Path, logs_dir: &Path, _token: &str) -> Result<Vec<NodeContext>> {
    let mut configs = fs::read_dir(out_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().starts_with("bifrost-"))
                .unwrap_or(false)
                && path.extension().is_some_and(|ext| ext == "json")
        })
        .collect::<Vec<_>>();
    configs.sort();

    let mut out = Vec::new();
    for cfg in configs {
        let raw = fs::read_to_string(&cfg).with_context(|| format!("read {}", cfg.display()))?;
        let parsed: Value = serde_json::from_str(&raw).context("parse node config")?;
        let self_pubkey = derive_self_pubkey(&parsed)?;
        let name = cfg
            .file_stem()
            .map(|v| v.to_string_lossy().replace("bifrost-", ""))
            .unwrap_or_else(|| "node".to_string());
        let control_socket = logs_dir.join(format!("control-{name}.sock"));
        out.push(NodeContext {
            name,
            config_path: cfg,
            control_socket,
            self_pubkey,
        });
    }
    Ok(out)
}

#[cfg(unix)]
fn derive_self_pubkey(parsed_cfg: &Value) -> Result<String> {
    let share_path = parsed_cfg
        .get("share_path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing share_path"))?;
    let group_path = parsed_cfg
        .get("group_path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing group_path"))?;
    let share_raw = fs::read_to_string(share_path).with_context(|| format!("read {share_path}"))?;
    let group_raw = fs::read_to_string(group_path).with_context(|| format!("read {group_path}"))?;
    let share: Value = serde_json::from_str(&share_raw).context("parse share")?;
    let group: Value = serde_json::from_str(&group_raw).context("parse group")?;
    let share_idx = share
        .get("idx")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing share idx"))?;
    let members = group
        .get("members")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing group members"))?;
    let member_pubkey = members
        .iter()
        .find(|member| member.get("idx").and_then(Value::as_u64) == Some(share_idx))
        .and_then(|member| member.get("pubkey").and_then(Value::as_str))
        .ok_or_else(|| anyhow!("group member pubkey not found for idx {share_idx}"))?
        .to_string();

    let peers = parsed_cfg
        .get("peers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing peers"))?;
    let peer_len = peers
        .iter()
        .find_map(|p| p.get("pubkey").and_then(Value::as_str).map(str::len))
        .unwrap_or(member_pubkey.len());
    if member_pubkey.len() == peer_len {
        return Ok(member_pubkey);
    }
    if member_pubkey.len() == 66 && peer_len == 64 {
        return Ok(member_pubkey.chars().skip(2).collect());
    }
    Ok(member_pubkey)
}

#[cfg(unix)]
fn start_relay_process(processes: &mut ProcessSet, root: &Path, logs_dir: &Path, relay: &str) -> Result<()> {
    let relay_port = relay_port(relay)?;
    let relay_port_arg = relay_port.to_string();
    processes.spawn_logged(
        Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "-p",
                "bifrost-dev",
                "--bin",
                "bifrost-devtools",
                "--offline",
                "--",
                "relay",
                relay_port_arg.as_str(),
            ])
            .current_dir(root),
        logs_dir.join("relay.log"),
    )
}

#[cfg(unix)]
fn start_node_listeners(
    processes: &mut ProcessSet,
    root: &Path,
    nodes: &[NodeContext],
    logs_dir: &Path,
    token: &str,
) -> Result<()> {
    for node in nodes {
        if node.control_socket.exists() {
            let _ = fs::remove_file(&node.control_socket);
        }
        let log_path = logs_dir.join(format!("bifrost-{}.log", node.name));
        processes.spawn_logged(
            Command::new("cargo")
                .args([
                    "run",
                    "--quiet",
                    "-p",
                    "bifrost-app",
                    "--bin",
                    "bifrost",
                    "--offline",
                    "--",
                    "--config",
                    node.config_path
                        .to_str()
                        .ok_or_else(|| anyhow!("invalid utf8 config path"))?,
                    "listen",
                    "--control-socket",
                    node.control_socket
                        .to_str()
                        .ok_or_else(|| anyhow!("invalid utf8 socket path"))?,
                    "--control-token",
                    token,
                ])
                .current_dir(root),
            log_path,
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn wait_for_control_sockets(nodes: &[NodeContext], timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        let mut all_ready = true;
        for node in nodes {
            if !node.control_socket.exists() {
                all_ready = false;
                break;
            }
        }
        if all_ready {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            let missing = nodes
                .iter()
                .filter(|node| !node.control_socket.exists())
                .map(|node| node.control_socket.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            bail!("timed out waiting for control sockets: {missing}");
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(unix)]
fn send_control(
    socket_path: &Path,
    token: &str,
    request_seq: &mut u64,
    command: Value,
) -> Result<Value> {
    let mut stream =
        UnixStream::connect(socket_path).with_context(|| format!("connect {}", socket_path.display()))?;
    let request_id = format!("ctl-{}", *request_seq);
    *request_seq = request_seq.saturating_add(1);
    let request = json!({
        "request_id": request_id,
        "token": token,
    });
    let mut merged = request
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("control request object build failed"))?;
    let cmd_obj = command
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("control command object required"))?;
    for (k, v) in cmd_obj {
        merged.insert(k, v);
    }
    let raw = serde_json::to_vec(&Value::Object(merged))?;
    stream.write_all(&raw)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut out)?;
    let response: Value = serde_json::from_slice(&out).context("parse control response")?;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        let err = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown control error");
        bail!("control request failed: {err}");
    }
    Ok(response
        .get("result")
        .cloned()
        .unwrap_or_else(|| json!(null)))
}

#[cfg(unix)]
fn run_onboarding_chain(
    nodes: &[NodeContext],
    token: &str,
    request_seq: &mut u64,
    out_file: &Path,
) -> Result<()> {
    for idx in 0..nodes.len().saturating_sub(1) {
        let from = &nodes[idx];
        let to = &nodes[idx + 1];
        let result = send_control(
            &from.control_socket,
            token,
            request_seq,
            json!({"command":"onboard","peer":to.self_pubkey}),
        )?;
        append_output(out_file, "onboard", &format!("{} -> {} : {}", from.name, to.name, result))?;
    }
    Ok(())
}

#[cfg(unix)]
fn run_ping_mesh(
    nodes: &[NodeContext],
    token: &str,
    request_seq: &mut u64,
    policy_matrix: Option<&HashMap<(usize, usize), (bool, bool)>>,
    out_file: &Path,
) -> Result<()> {
    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i == j {
                continue;
            }
            let expected = policy_matrix
                .map(|matrix| {
                    let (send, _) = matrix.get(&(i, j)).copied().unwrap_or((true, true));
                    let (_, receive) = matrix.get(&(j, i)).copied().unwrap_or((true, true));
                    send && receive
                })
                .unwrap_or(true);
            let res = send_control(
                &nodes[i].control_socket,
                token,
                request_seq,
                json!({"command":"ping","peer":nodes[j].self_pubkey}),
            );
            let observed_ok = res.is_ok();
            if expected {
                res?;
            }
            append_output(
                out_file,
                "ping",
                &format!(
                    "{} -> {} expected={expected} observed_ok={observed_ok}",
                    nodes[i].name, nodes[j].name
                ),
            )?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn randomize_policies(
    nodes: &[NodeContext],
    token: &str,
    request_seq: &mut u64,
    rng: &mut Lcg,
    out_file: &Path,
) -> Result<HashMap<(usize, usize), (bool, bool)>> {
    let mut matrix = HashMap::new();
    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i == j {
                continue;
            }
            let send = rng.next_bool();
            let receive = rng.next_bool();
            matrix.insert((i, j), (send, receive));
            send_control(
                &nodes[i].control_socket,
                token,
                request_seq,
                json!({"command":"set_policy","peer":nodes[j].self_pubkey,"send":send,"receive":receive}),
            )?;
            append_output(
                out_file,
                "policy",
                &format!("{} -> {} send={send} receive={receive}", nodes[i].name, nodes[j].name),
            )?;
        }
    }
    Ok(matrix)
}

#[cfg(unix)]
fn set_all_policies_allow(
    nodes: &[NodeContext],
    token: &str,
    request_seq: &mut u64,
    out_file: &Path,
) -> Result<()> {
    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i == j {
                continue;
            }
            send_control(
                &nodes[i].control_socket,
                token,
                request_seq,
                json!({"command":"set_policy","peer":nodes[j].self_pubkey,"send":true,"receive":true}),
            )?;
        }
    }
    append_output(out_file, "policy", "reset all policies to allow")?;
    Ok(())
}

#[cfg(unix)]
fn run_sign_iterations(
    nodes: &[NodeContext],
    token: &str,
    request_seq: &mut u64,
    rng: &mut Lcg,
    iterations: usize,
    out_file: &Path,
) -> Result<()> {
    for n in 0..iterations {
        let idx = rng.next_usize(nodes.len());
        let message = rng.next_hex32();
        let result = send_control(
            &nodes[idx].control_socket,
            token,
            request_seq,
            json!({"command":"sign","message_hex32":message}),
        )?;
        append_output(out_file, "sign", &format!("iter={n} node={} result={result}", nodes[idx].name))?;
    }
    Ok(())
}

#[cfg(unix)]
fn run_ecdh_iterations(
    nodes: &[NodeContext],
    token: &str,
    request_seq: &mut u64,
    rng: &mut Lcg,
    iterations: usize,
    out_file: &Path,
) -> Result<()> {
    for n in 0..iterations {
        let initiator = rng.next_usize(nodes.len());
        let mut target = rng.next_usize(nodes.len());
        if target == initiator {
            target = (target + 1) % nodes.len();
        }
        let result = send_control(
            &nodes[initiator].control_socket,
            token,
            request_seq,
            json!({"command":"ecdh","pubkey_hex32":nodes[target].self_pubkey}),
        )?;
        append_output(out_file, "ecdh", &format!("iter={n} node={} target={} result={result}", nodes[initiator].name, nodes[target].name))?;
    }
    Ok(())
}

#[cfg(unix)]
fn run_edge_cases(
    nodes: &[NodeContext],
    _token: &str,
    request_seq: &mut u64,
    out_file: &Path,
) -> Result<()> {
    let bad_token = "invalid-token";
    let bad = send_control(
        &nodes[0].control_socket,
        bad_token,
        request_seq,
        json!({"command":"status"}),
    );
    if bad.is_ok() {
        bail!("expected invalid token edge case to fail");
    }
    append_output(out_file, "edge", "invalid token rejected")?;
    Ok(())
}

#[cfg(unix)]
struct Lcg {
    state: u64,
}

#[cfg(unix)]
impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        self.state
    }

    fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next_u64() as usize) % max
    }

    fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }

    fn next_hex32(&mut self) -> String {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        hex::encode(bytes)
    }
}

fn run_cargo_status<const N: usize>(root: &Path, args: [&str; N]) -> Result<()> {
    let status = Command::new("cargo")
        .args(args)
        .current_dir(root)
        .status()
        .context("run cargo command")?;
    if !status.success() {
        bail!(
            "cargo command failed ({:?}): cargo {}",
            status.code(),
            args.join(" ")
        );
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("resolve workspace root")?;
    Ok(root)
}

#[derive(Default)]
struct ProcessSet {
    children: Vec<Child>,
}

impl ProcessSet {
    fn spawn_logged(&mut self, command: &mut Command, log_path: PathBuf) -> Result<()> {
        let log =
            File::create(&log_path).with_context(|| format!("create {}", log_path.display()))?;
        let log_err = log
            .try_clone()
            .with_context(|| format!("clone {}", log_path.display()))?;
        let child = command
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .with_context(|| format!("spawn command for {}", log_path.display()))?;
        self.children.push(child);
        Ok(())
    }

    fn stop_all(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.children.clear();
    }
}

impl Drop for ProcessSet {
    fn drop(&mut self) {
        self.stop_all();
    }
}
