use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

pub fn print_e2e_usage() {
    eprintln!("  e2e-node [--out-dir DIR] [--relay URL]");
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

    generate_runtime_material(&root, &out_dir, &relay)?;
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
    let peer = extract_first_peer(&alice_cfg)?;
    run_bifrost_and_record(root, &alice_cfg, out_file, "status", &["status"])?;
    run_bifrost_and_record(root, &alice_cfg, out_file, "policies", &["policies"])?;
    run_bifrost_and_record(root, &alice_cfg, out_file, "ping", &["ping", &peer])?;
    run_bifrost_and_record(root, &alice_cfg, out_file, "onboard", &["onboard", &peer])?;

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
    generate_runtime_material(root, out_dir, relay)?;

    let mut responders = start_responders(root, out_dir, logs_dir, relay)?;
    thread::sleep(Duration::from_secs(2));

    let alice_cfg = out_dir.join("bifrost-alice.json");
    let peer = extract_first_peer(&alice_cfg)?;
    let ecdh_output = run_bifrost_capture(root, &alice_cfg, &["ecdh", &peer])?;
    append_output(out_file, "ecdh", &ecdh_output)?;
    let secret = extract_last_hex_line(&ecdh_output, 64).context("invalid ecdh output")?;
    if secret.len() != 64 {
        bail!("invalid ecdh output length: {}", secret.len());
    }

    responders.stop_all();
    Ok(())
}

fn generate_runtime_material(root: &Path, out_dir: &Path, relay: &str) -> Result<()> {
    prune_state_files(out_dir)?;
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
            "2",
            "--count",
            "3",
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
        if name.starts_with("state-") && (name.ends_with(".json") || name.ends_with(".lock")) {
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

fn extract_first_peer(config_path: &Path) -> Result<String> {
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
    peers.into_iter().next().ok_or_else(|| {
        anyhow!(
            "failed to extract peer pubkey from {}",
            config_path.display()
        )
    })
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
