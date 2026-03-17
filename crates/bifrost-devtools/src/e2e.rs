use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

const DEFAULT_RELAY: &str = "ws://127.0.0.1:8194";
const DEFAULT_VAULT_PASSPHRASE: &str = "igloo-shell-e2e-passphrase";

pub fn run_e2e_node_command(args: &[String]) -> Result<()> {
    let mut out_dir: Option<PathBuf> = None;
    let mut relay = DEFAULT_RELAY.to_string();
    let mut shell_bin: Option<PathBuf> = None;

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
            "--shell-bin" => {
                shell_bin = Some(PathBuf::from(
                    args.get(idx + 1).context("missing value for --shell-bin")?,
                ));
                idx += 2;
            }
            "help" | "--help" | "-h" => return Ok(()),
            other => bail!("unknown e2e-node argument: {other}"),
        }
    }

    let root = infra_root()?;
    let out_dir = out_dir.unwrap_or_else(|| root.join("repos/igloo-shell/dev/data"));
    let work_dir = out_dir.join("managed-e2e-node");
    let logs_dir = work_dir.join("logs");
    fs::create_dir_all(&logs_dir).with_context(|| format!("create {}", logs_dir.display()))?;
    let out_file = logs_dir.join("node-e2e-output.txt");
    fs::write(&out_file, "").with_context(|| format!("create {}", out_file.display()))?;

    let shell_exe = resolve_shell_exe(shell_bin)?;
    let mut devnet = ManagedDevnet::provision(&work_dir, &relay, 2, 3, shell_exe)?;
    run_sign_iterations(&mut devnet, &out_file, 1, 1)?;
    run_ecdh_iterations(&mut devnet, &out_file, 1, 1)?;
    append_output(&out_file, "summary", "node e2e passed")?;

    println!("node e2e passed");
    Ok(())
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
        let mut relay = DEFAULT_RELAY.to_string();
        let mut threshold = 11u16;
        let mut count = 15u16;
        let mut sign_iterations = 20usize;
        let mut ecdh_iterations = 20usize;
        let mut seed = 1u64;
        let mut shell_bin: Option<PathBuf> = None;

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
                    relay = args
                        .get(idx + 1)
                        .context("missing value for --relay")?
                        .clone();
                    idx += 2;
                }
                "--threshold" => {
                    threshold = args
                        .get(idx + 1)
                        .context("missing value for --threshold")?
                        .parse()
                        .context("invalid --threshold")?;
                    idx += 2;
                }
                "--count" => {
                    count = args
                        .get(idx + 1)
                        .context("missing value for --count")?
                        .parse()
                        .context("invalid --count")?;
                    idx += 2;
                }
                "--sign-iterations" => {
                    sign_iterations = args
                        .get(idx + 1)
                        .context("missing value for --sign-iterations")?
                        .parse()
                        .context("invalid --sign-iterations")?;
                    idx += 2;
                }
                "--ecdh-iterations" => {
                    ecdh_iterations = args
                        .get(idx + 1)
                        .context("missing value for --ecdh-iterations")?
                        .parse()
                        .context("invalid --ecdh-iterations")?;
                    idx += 2;
                }
                "--seed" => {
                    seed = args
                        .get(idx + 1)
                        .context("missing value for --seed")?
                        .parse()
                        .context("invalid --seed")?;
                    idx += 2;
                }
                "--shell-bin" => {
                    shell_bin = Some(PathBuf::from(
                        args.get(idx + 1).context("missing value for --shell-bin")?,
                    ));
                    idx += 2;
                }
                "help" | "--help" | "-h" => return Ok(()),
                other => bail!("unknown e2e-full argument: {other}"),
            }
        }

        if count < threshold || threshold < 2 {
            bail!("e2e-full requires count >= threshold >= 2");
        }

        let root = infra_root()?;
        let out_dir = out_dir.unwrap_or_else(|| root.join("repos/igloo-shell/dev/data"));
        let work_dir = out_dir.join("managed-e2e-full");
        let logs_dir = work_dir.join("logs");
        fs::create_dir_all(&logs_dir).with_context(|| format!("create {}", logs_dir.display()))?;
        let out_file = logs_dir.join("node-e2e-full-output.txt");
        fs::write(&out_file, "").with_context(|| format!("create {}", out_file.display()))?;

        let shell_exe = resolve_shell_exe(shell_bin)?;
        let mut devnet = ManagedDevnet::provision(&work_dir, &relay, threshold, count, shell_exe)?;
        run_policy_round_trip(&mut devnet, &out_file)?;
        run_sign_iterations(&mut devnet, &out_file, sign_iterations, seed)?;
        run_ecdh_iterations(&mut devnet, &out_file, ecdh_iterations, seed)?;
        append_output(&out_file, "summary", "e2e-full passed")?;

        println!("node e2e-full passed");
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ManagedShellEnv {
    xdg_config_home: PathBuf,
    xdg_data_home: PathBuf,
    xdg_state_home: PathBuf,
    vault_passphrase: String,
}

impl ManagedShellEnv {
    fn for_work_dir(work_dir: &Path) -> Self {
        Self {
            xdg_config_home: work_dir.join("config"),
            xdg_data_home: work_dir.join("data"),
            xdg_state_home: work_dir.join("state"),
            vault_passphrase: DEFAULT_VAULT_PASSPHRASE.to_string(),
        }
    }

    fn apply(&self, command: &mut Command) {
        command.env("XDG_CONFIG_HOME", &self.xdg_config_home);
        command.env("XDG_DATA_HOME", &self.xdg_data_home);
        command.env("XDG_STATE_HOME", &self.xdg_state_home);
        command.env("IGLOO_SHELL_VAULT_PASSPHRASE", &self.vault_passphrase);
    }
}

#[derive(Debug, Clone)]
struct NodeHandle {
    member: String,
    profile_id: String,
}

#[derive(Debug)]
struct ManagedDevnet {
    shell_exe: PathBuf,
    shell_env: ManagedShellEnv,
    relay_child: Option<Child>,
    profiles: Vec<NodeHandle>,
}

impl ManagedDevnet {
    fn provision(
        work_dir: &Path,
        relay_url: &str,
        threshold: u16,
        count: u16,
        shell_exe: PathBuf,
    ) -> Result<Self> {
        if work_dir.exists() {
            fs::remove_dir_all(work_dir)
                .with_context(|| format!("remove {}", work_dir.display()))?;
        }
        let material_dir = work_dir.join("material");
        let logs_dir = work_dir.join("logs");
        fs::create_dir_all(&material_dir)
            .with_context(|| format!("create {}", material_dir.display()))?;
        fs::create_dir_all(&logs_dir).with_context(|| format!("create {}", logs_dir.display()))?;

        let shell_env = ManagedShellEnv::for_work_dir(work_dir);
        let devtools_exe = std::env::current_exe().context("resolve current executable")?;

        run_command(
            &devtools_exe,
            None,
            &[
                "keygen",
                "--out-dir",
                path_arg(&material_dir)?,
                "--threshold",
                &threshold.to_string(),
                "--count",
                &count.to_string(),
                "--relay",
                relay_url,
            ],
            "bifrost-devtools",
        )?;

        let relay_child = Some(start_relay_process(
            &devtools_exe,
            relay_url,
            &logs_dir.join("relay.log"),
        )?);

        run_shell(
            &shell_exe,
            Some(&shell_env),
            &["relays", "set", "local", relay_url],
        )?;

        let mut profiles = import_profiles(&shell_exe, &shell_env, &material_dir)?;
        profiles.sort_by(|a, b| a.member.cmp(&b.member));
        for node in &profiles {
            run_shell(
                &shell_exe,
                Some(&shell_env),
                &["daemon", "start", "--profile", &node.profile_id],
            )?;
            wait_for_runtime(
                &shell_exe,
                &shell_env,
                &node.profile_id,
                Duration::from_secs(30),
            )?;
        }

        let mut devnet = Self {
            shell_exe,
            shell_env,
            relay_child,
            profiles,
        };
        prepare_alice_peers(&mut devnet)?;
        Ok(devnet)
    }

    fn alice(&self) -> Result<&NodeHandle> {
        self.profiles
            .iter()
            .find(|node| node.member == "alice")
            .ok_or_else(|| anyhow!("missing alice profile"))
    }

    fn alice_peer_pubkeys(&self) -> Result<Vec<String>> {
        let alice = self.alice()?;
        let peers = run_shell_json(
            &self.shell_exe,
            Some(&self.shell_env),
            &["peer", "list", "--profile", &alice.profile_id],
        )?;
        let entries = peers
            .as_array()
            .ok_or_else(|| anyhow!("peer list returned invalid json"))?;
        Ok(entries
            .iter()
            .filter_map(|entry| entry.get("pubkey").and_then(Value::as_str))
            .map(ToString::to_string)
            .collect())
    }

    fn stop_all(&mut self) {
        for node in &self.profiles {
            let _ = run_shell(
                &self.shell_exe,
                Some(&self.shell_env),
                &["daemon", "stop", "--profile", &node.profile_id],
            );
        }
        if let Some(child) = &mut self.relay_child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.relay_child = None;
    }
}

impl Drop for ManagedDevnet {
    fn drop(&mut self) {
        self.stop_all();
    }
}

fn import_profiles(
    shell_exe: &Path,
    shell_env: &ManagedShellEnv,
    material_dir: &Path,
) -> Result<Vec<NodeHandle>> {
    let mut members = Vec::new();
    for entry in
        fs::read_dir(material_dir).with_context(|| format!("read {}", material_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(member) = name
            .strip_prefix("share-")
            .and_then(|value| value.strip_suffix(".json"))
        else {
            continue;
        };
        let result = run_shell_json(
            shell_exe,
            Some(shell_env),
            &[
                "profile",
                "import",
                "--group",
                path_arg(&material_dir.join("group.json"))?,
                "--share",
                path_arg(&path)?,
                "--label",
                member,
                "--relay-profile",
                "local",
            ],
        )?;
        let profile_id = extract_json_string_field(&result, "id")
            .ok_or_else(|| anyhow!("profile import result did not include id"))?;
        members.push(NodeHandle {
            member: member.to_string(),
            profile_id,
        });
    }
    if members.is_empty() {
        bail!("no share packages found in {}", material_dir.display());
    }
    Ok(members)
}

fn prepare_alice_peers(devnet: &mut ManagedDevnet) -> Result<()> {
    let alice = devnet.alice()?.clone();
    let peers = wait_for_peer_list(
        &devnet.shell_exe,
        &devnet.shell_env,
        &alice.profile_id,
        devnet.profiles.len().saturating_sub(1),
        Duration::from_secs(30),
    )?;
    for peer in peers {
        run_shell(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &["peer", "ping", "--profile", &alice.profile_id, &peer],
        )?;
        run_shell(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &["peer", "onboard", "--profile", &alice.profile_id, &peer],
        )?;
    }
    wait_for_signing_readiness(devnet, Duration::from_secs(30))
}

fn wait_for_runtime(
    shell_exe: &Path,
    shell_env: &ManagedShellEnv,
    profile_id: &str,
    timeout: Duration,
) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if run_shell_json(
            shell_exe,
            Some(shell_env),
            &["runtime", "status", "--profile", profile_id],
        )
        .is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    bail!("timed out waiting for runtime status for profile {profile_id}")
}

fn wait_for_peer_list(
    shell_exe: &Path,
    shell_env: &ManagedShellEnv,
    profile_id: &str,
    expected_min: usize,
    timeout: Duration,
) -> Result<Vec<String>> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let peers = run_shell_json(
            shell_exe,
            Some(shell_env),
            &["peer", "list", "--profile", profile_id],
        )?;
        let values = peers
            .as_array()
            .ok_or_else(|| anyhow!("peer list returned invalid json"))?;
        let pubkeys = values
            .iter()
            .filter_map(|entry| entry.get("pubkey").and_then(Value::as_str))
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if pubkeys.len() >= expected_min {
            return Ok(pubkeys);
        }
        thread::sleep(Duration::from_millis(200));
    }
    bail!("timed out waiting for peer list for profile {profile_id}")
}

fn wait_for_signing_readiness(devnet: &ManagedDevnet, timeout: Duration) -> Result<()> {
    let alice = devnet.alice()?;
    let start = Instant::now();
    while start.elapsed() < timeout {
        let status = run_shell_json(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &["runtime", "status", "--profile", &alice.profile_id],
        )?;
        let readiness = status
            .get("readiness")
            .ok_or_else(|| anyhow!("runtime status missing readiness"))?;
        let sign_ready = readiness
            .get("sign_ready")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ecdh_ready = readiness
            .get("ecdh_ready")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if sign_ready && ecdh_ready {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    bail!("timed out waiting for alice sign/ecdh readiness")
}

fn run_sign_iterations(
    devnet: &mut ManagedDevnet,
    out_file: &Path,
    iterations: usize,
    seed: u64,
) -> Result<()> {
    let alice = devnet.alice()?.clone();
    for idx in 0..iterations {
        let message = format!("{:064x}", seed + idx as u64 + 1);
        let output = run_shell_json(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &["runtime", "sign", "--profile", &alice.profile_id, &message],
        )?;
        let signature = output
            .get("signatures_hex")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("sign result missing signatures_hex"))?;
        if signature.len() != 128 || !signature.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("invalid signature output length: {}", signature.len());
        }
        append_output(
            out_file,
            &format!("sign-{idx}"),
            &serde_json::to_string_pretty(&output)?,
        )?;
    }
    Ok(())
}

fn run_policy_round_trip(devnet: &mut ManagedDevnet, out_file: &Path) -> Result<()> {
    let alice = devnet.alice()?.clone();
    let target_peer = devnet
        .alice_peer_pubkeys()?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("missing peer pubkey for policy round trip"))?;

    let set_default = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &[
            "policy",
            "set-default",
            "--profile",
            &alice.profile_id,
            "--send",
            "false",
            "--receive",
            "true",
        ],
    )?;
    if set_default.get("restart_required").and_then(Value::as_bool) != Some(true) {
        bail!("policy set-default did not request restart");
    }
    append_output(
        out_file,
        "policy-set-default",
        &serde_json::to_string_pretty(&set_default)?,
    )?;

    run_shell_with_retry(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &["daemon", "restart", "--profile", &alice.profile_id],
        3,
    )?;
    wait_for_runtime(
        &devnet.shell_exe,
        &devnet.shell_env,
        &alice.profile_id,
        Duration::from_secs(30),
    )?;

    let set_peer = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &[
            "policy",
            "set-peer",
            "--profile",
            &alice.profile_id,
            &target_peer,
            "--send",
            "true",
            "--receive",
            "false",
        ],
    )?;
    if set_peer.get("updated").and_then(Value::as_bool) != Some(true)
        || set_peer.get("persisted").and_then(Value::as_bool) != Some(true)
    {
        bail!("policy set-peer did not report success");
    }
    append_output(
        out_file,
        "policy-set-peer",
        &serde_json::to_string_pretty(&set_peer)?,
    )?;

    let live = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &["policy", "show", "--profile", &alice.profile_id],
    )?;
    let live_entry = live
        .as_array()
        .and_then(|items| {
            items.iter().find(|entry| {
                entry.get("pubkey").and_then(Value::as_str) == Some(target_peer.as_str())
            })
        })
        .ok_or_else(|| anyhow!("policy show missing peer {target_peer}"))?;
    if live_entry
        .get("policy")
        .and_then(|policy| policy.get("request"))
        .and_then(|request| request.get("sign"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("policy show did not reflect peer send=true");
    }
    append_output(
        out_file,
        "policy-show",
        &serde_json::to_string_pretty(&live)?,
    )?;

    let cleared = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &[
            "policy",
            "clear-peer",
            "--profile",
            &alice.profile_id,
            &target_peer,
        ],
    )?;
    if cleared.get("updated").and_then(Value::as_bool) != Some(true)
        || cleared.get("persisted").and_then(Value::as_bool) != Some(true)
    {
        bail!("policy clear-peer did not report success");
    }
    append_output(
        out_file,
        "policy-clear-peer",
        &serde_json::to_string_pretty(&cleared)?,
    )?;

    let manifest = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &["profile", "show", &alice.profile_id],
    )?;
    let overrides = manifest
        .get("policy_overrides")
        .and_then(|value| value.get("peer_overrides"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("profile show missing peer_overrides"))?;
    if !overrides.is_empty() {
        bail!("policy clear-peer left peer overrides behind");
    }
    append_output(
        out_file,
        "policy-profile-show",
        &serde_json::to_string_pretty(&manifest)?,
    )?;

    Ok(())
}

fn run_ecdh_iterations(
    devnet: &mut ManagedDevnet,
    out_file: &Path,
    iterations: usize,
    seed: u64,
) -> Result<()> {
    let alice = devnet.alice()?.clone();
    let target_peer = devnet
        .alice_peer_pubkeys()?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("missing peer pubkey for ecdh"))?;
    for idx in 0..iterations {
        let _ = seed + idx as u64;
        let output = run_shell_json(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &[
                "runtime",
                "ecdh",
                "--profile",
                &alice.profile_id,
                &target_peer,
            ],
        )?;
        let secret = output
            .get("shared_secret_hex32")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("ecdh result missing shared_secret_hex32"))?;
        if secret.len() != 64 || !secret.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("invalid ecdh output length: {}", secret.len());
        }
        append_output(
            out_file,
            &format!("ecdh-{idx}"),
            &serde_json::to_string_pretty(&output)?,
        )?;
    }
    Ok(())
}

fn start_relay_process(devtools_exe: &Path, relay: &str, log_path: &Path) -> Result<Child> {
    let url = relay
        .strip_prefix("ws://")
        .ok_or_else(|| anyhow!("relay must be ws://host:port"))?;
    let (host, port) = url
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("relay must include port"))?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let err = log
        .try_clone()
        .with_context(|| format!("clone {}", log_path.display()))?;
    let child = Command::new(devtools_exe)
        .args(["relay", "--host", host, "--port", port])
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        .spawn()
        .context("spawn bifrost-devtools relay process")?;
    thread::sleep(Duration::from_secs(1));
    Ok(child)
}

fn run_shell(shell_exe: &Path, shell_env: Option<&ManagedShellEnv>, args: &[&str]) -> Result<()> {
    run_command(shell_exe, shell_env, args, "igloo-shell")
}

fn run_command(
    exe: &Path,
    shell_env: Option<&ManagedShellEnv>,
    args: &[&str],
    name: &str,
) -> Result<()> {
    let status = build_command(exe, shell_env, args)
        .status()
        .with_context(|| format!("run {name}"))?;
    if !status.success() {
        bail!("{name} failed: {status}");
    }
    Ok(())
}

fn run_shell_with_retry(
    shell_exe: &Path,
    shell_env: Option<&ManagedShellEnv>,
    args: &[&str],
    retries: usize,
) -> Result<()> {
    let attempts = retries.max(1);
    let mut last_error = None;
    for _ in 0..attempts {
        match run_shell(shell_exe, shell_env, args) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_error = Some(err);
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("igloo-shell retry failed")))
}

fn run_shell_json(
    shell_exe: &Path,
    shell_env: Option<&ManagedShellEnv>,
    args: &[&str],
) -> Result<Value> {
    let output = build_command(shell_exe, shell_env, args)
        .output()
        .context("capture igloo-shell output")?;
    if !output.status.success() {
        bail!(
            "igloo-shell failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse igloo-shell json output")
}

fn build_command(exe: &Path, shell_env: Option<&ManagedShellEnv>, args: &[&str]) -> Command {
    let mut command = Command::new(exe);
    if let Some(shell_env) = shell_env {
        shell_env.apply(&mut command);
    }
    command.args(args);
    command
}

fn append_output(path: &Path, label: &str, output: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(file, "== {label} ==")?;
    writeln!(file, "{output}")?;
    Ok(())
}

fn extract_json_string_field(value: &Value, field: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(field).and_then(Value::as_str) {
                return Some(found.to_string());
            }
            map.values()
                .find_map(|entry| extract_json_string_field(entry, field))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|entry| extract_json_string_field(entry, field)),
        _ => None,
    }
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("invalid path {}", path.display()))
}

fn infra_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("resolve infra root"))
}

fn resolve_shell_exe(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Ok(path) = env::var("IGLOO_SHELL_BIN") {
        return Ok(PathBuf::from(path));
    }
    let path = infra_root()?.join("repos/igloo-shell/target/debug/igloo-shell");
    if path.is_file() {
        return Ok(path);
    }
    bail!(
        "missing igloo-shell binary at {}. Build it first or pass --shell-bin / IGLOO_SHELL_BIN",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
    use frostr_utils::{CreateKeysetConfig, create_keyset};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("bifrost-devtools-e2e-{name}-{nanos}-{seq}"))
    }

    #[cfg(unix)]
    fn write_fake_shell(script: &str) -> PathBuf {
        let path = temp_path("fake-shell");
        fs::write(&path, script).expect("write fake shell");
        let mut perms = fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("chmod");
        path
    }

    #[test]
    fn extract_json_string_field_finds_nested_values() {
        let value = serde_json::json!({
            "outer": {
                "items": [
                    {"skip": true},
                    {"id": "profile-123"}
                ]
            }
        });
        assert_eq!(
            extract_json_string_field(&value, "id").as_deref(),
            Some("profile-123")
        );
        assert_eq!(extract_json_string_field(&value, "missing"), None);
    }

    #[test]
    fn path_arg_returns_str_for_valid_paths() {
        let path = PathBuf::from("/tmp/example.json");
        assert_eq!(path_arg(&path).expect("utf8 path"), "/tmp/example.json");
    }

    #[test]
    fn managed_shell_env_applies_expected_environment() {
        let work_dir = temp_path("env");
        let shell_env = ManagedShellEnv::for_work_dir(&work_dir);
        let mut command = Command::new("env");
        shell_env.apply(&mut command);
        let output = command.output().expect("run env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        assert!(stdout.contains("XDG_CONFIG_HOME="));
        assert!(stdout.contains("XDG_DATA_HOME="));
        assert!(stdout.contains("XDG_STATE_HOME="));
        assert!(stdout.contains("IGLOO_SHELL_VAULT_PASSPHRASE="));
    }

    #[test]
    fn build_command_includes_args_and_shell_environment() {
        let work_dir = temp_path("build-command");
        let shell_env = ManagedShellEnv::for_work_dir(&work_dir);
        let mut command = build_command(Path::new("env"), Some(&shell_env), &["TEST_ARG=1"]);
        let output = command.output().expect("run env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        assert!(stdout.contains("XDG_CONFIG_HOME="));
        assert!(stdout.contains("IGLOO_SHELL_VAULT_PASSPHRASE="));
    }

    #[test]
    fn run_shell_json_reports_non_json_and_non_zero_status() {
        let err = run_shell_json(Path::new("/bin/sh"), None, &["-c", "echo nope"])
            .expect_err("plain text output must fail");
        assert!(err.to_string().contains("parse igloo-shell json output"));

        let err = run_shell_json(Path::new("/bin/sh"), None, &["-c", "echo fail >&2; exit 7"])
            .expect_err("non-zero exit must fail");
        assert!(err.to_string().contains("igloo-shell failed"));
    }

    #[test]
    fn run_shell_with_retry_returns_last_error() {
        let err = run_shell_with_retry(Path::new("/bin/sh"), None, &["-c", "exit 9"], 2)
            .expect_err("retry must fail");
        assert!(err.to_string().contains("igloo-shell failed"));
    }

    #[test]
    fn append_output_and_resolve_shell_exe_behave_as_expected() {
        let log_path = temp_path("append").join("output.txt");
        fs::create_dir_all(log_path.parent().expect("parent")).expect("create parent");
        append_output(&log_path, "demo", "ok").expect("append output");
        let written = fs::read_to_string(&log_path).expect("read log");
        assert!(written.contains("== demo =="));
        assert!(written.contains("ok"));

        let explicit = PathBuf::from("/tmp/igloo-shell");
        assert_eq!(
            resolve_shell_exe(Some(explicit.clone())).expect("explicit"),
            explicit
        );

        let env_path = temp_path("shell-bin");
        fs::write(&env_path, "").expect("create fake shell");
        unsafe {
            env::set_var("IGLOO_SHELL_BIN", &env_path);
        }
        assert_eq!(resolve_shell_exe(None).expect("env var"), env_path);
        unsafe {
            env::remove_var("IGLOO_SHELL_BIN");
        }
        let resolved = resolve_shell_exe(None).expect("default resolution");
        assert!(resolved.ends_with("repos/igloo-shell/target/debug/igloo-shell"));
    }

    #[test]
    fn run_e2e_commands_validate_args() {
        let err = run_e2e_node_command(&["--bad".to_string()]).expect_err("unknown arg");
        assert!(err.to_string().contains("unknown e2e-node argument"));

        let err = run_e2e_full_command(&[
            "--threshold".to_string(),
            "4".to_string(),
            "--count".to_string(),
            "3".to_string(),
        ])
        .expect_err("invalid threshold/count");
        assert!(err.to_string().contains("count >= threshold >= 2"));
    }

    #[test]
    fn import_profiles_rejects_empty_material_directory() {
        let material_dir = temp_path("empty-material");
        fs::create_dir_all(&material_dir).expect("create material dir");
        let shell_env = ManagedShellEnv::for_work_dir(&temp_path("shell-env"));
        let err = import_profiles(Path::new("/bin/true"), &shell_env, &material_dir)
            .expect_err("empty material must fail");
        assert!(err.to_string().contains("no share packages found"));
        let _ = fs::remove_dir_all(&material_dir);
    }

    #[cfg(unix)]
    #[test]
    fn import_profiles_and_runtime_helpers_work_with_fake_shell() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let material_dir = temp_path("material");
        fs::create_dir_all(&material_dir).expect("create material dir");
        fs::write(
            material_dir.join("group.json"),
            serde_json::to_string(&GroupPackageWire::from(bundle.group.clone()))
                .expect("group json"),
        )
        .expect("write group");
        fs::write(
            material_dir.join("share-alice.json"),
            serde_json::to_string(&SharePackageWire::from(bundle.shares[0].clone()))
                .expect("share json"),
        )
        .expect("write alice share");
        fs::write(
            material_dir.join("share-bob.json"),
            serde_json::to_string(&SharePackageWire::from(bundle.shares[1].clone()))
                .expect("share json"),
        )
        .expect("write bob share");

        let fake_shell = write_fake_shell(
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "profile" && "$2" == "import" ]]; then
  label=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--label" ]]; then
      label="$2"
      break
    fi
    shift
  done
  printf '{"id":"profile-%s"}\n' "$label"
elif [[ "$1" == "runtime" && "$2" == "status" ]]; then
  printf '{"readiness":{"sign_ready":true,"ecdh_ready":true}}\n'
elif [[ "$1" == "peer" && "$2" == "list" ]]; then
  printf '[{"pubkey":"peer-1"},{"pubkey":"peer-2"}]\n'
else
  printf '{}\n'
fi
"#,
        );

        let shell_env = ManagedShellEnv::for_work_dir(&temp_path("shell-env"));
        let profiles =
            import_profiles(&fake_shell, &shell_env, &material_dir).expect("import profiles");
        assert_eq!(profiles.len(), 2);
        assert!(
            profiles
                .iter()
                .any(|entry| entry.profile_id == "profile-alice")
        );
        assert!(
            profiles
                .iter()
                .any(|entry| entry.profile_id == "profile-bob")
        );

        wait_for_runtime(
            &fake_shell,
            &shell_env,
            "profile-alice",
            Duration::from_secs(1),
        )
        .expect("wait runtime");
        let peers = wait_for_peer_list(
            &fake_shell,
            &shell_env,
            "profile-alice",
            2,
            Duration::from_secs(1),
        )
        .expect("wait peer list");
        assert_eq!(peers, vec!["peer-1".to_string(), "peer-2".to_string()]);

        let devnet = ManagedDevnet {
            shell_exe: fake_shell.clone(),
            shell_env,
            relay_child: None,
            profiles: vec![NodeHandle {
                member: "alice".to_string(),
                profile_id: "profile-alice".to_string(),
            }],
        };
        wait_for_signing_readiness(&devnet, Duration::from_secs(1)).expect("wait readiness");

        let _ = fs::remove_file(&fake_shell);
        let _ = fs::remove_dir_all(&material_dir);
    }

    #[cfg(unix)]
    #[test]
    fn sign_ecdh_and_policy_helpers_accept_fake_shell_json() {
        let fake_shell = write_fake_shell(
            r#"#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "runtime sign")
    printf '{"signatures_hex":["%0128d"]}\n' 0
    ;;
  "runtime ecdh")
    printf '{"shared_secret_hex32":"%064d"}\n' 0
    ;;
  "peer list")
    printf '[{"pubkey":"peer-a"}]\n'
    ;;
  "policy set-default")
    printf '{"restart_required":true}\n'
    ;;
  "daemon restart")
    printf '{}\n'
    ;;
  "policy set-peer")
    printf '{"updated":true,"persisted":true}\n'
    ;;
  "policy show")
    printf '[{"pubkey":"peer-a","policy":{"request":{"sign":true}}}]\n'
    ;;
  "policy clear-peer")
    printf '{"updated":true,"persisted":true}\n'
    ;;
  "profile show")
    printf '{"policy_overrides":{"peer_overrides":[]}}\n'
    ;;
  "runtime status")
    printf '{"readiness":{"sign_ready":true,"ecdh_ready":true}}\n'
    ;;
  *)
    printf '{}\n'
    ;;
esac
"#,
        );
        let out_file = temp_path("helper-output");
        let mut devnet = ManagedDevnet {
            shell_exe: fake_shell.clone(),
            shell_env: ManagedShellEnv::for_work_dir(&temp_path("shell-env")),
            relay_child: None,
            profiles: vec![NodeHandle {
                member: "alice".to_string(),
                profile_id: "profile-alice".to_string(),
            }],
        };

        run_sign_iterations(&mut devnet, &out_file, 1, 7).expect("sign iterations");
        run_ecdh_iterations(&mut devnet, &out_file, 1, 7).expect("ecdh iterations");
        run_policy_round_trip(&mut devnet, &out_file).expect("policy round trip");

        let written = fs::read_to_string(&out_file).expect("read output");
        assert!(written.contains("sign-0"));
        assert!(written.contains("ecdh-0"));
        assert!(written.contains("policy-set-default"));

        let _ = fs::remove_file(&fake_shell);
        let _ = fs::remove_file(&out_file);
    }

    #[cfg(unix)]
    #[test]
    fn e2e_helpers_report_timeout_and_invalid_output_errors() {
        let fake_shell = write_fake_shell(
            r#"#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "runtime status")
    printf '{"readiness":{"sign_ready":false,"ecdh_ready":false}}\n'
    ;;
  "peer list")
    printf '{"not":"an array"}\n'
    ;;
  "runtime sign")
    printf '{"signatures_hex":["deadbeef"]}\n'
    ;;
  "runtime ecdh")
    printf '{"shared_secret_hex32":"deadbeef"}\n'
    ;;
  *)
    printf '{}\n'
    ;;
esac
"#,
        );
        let shell_env = ManagedShellEnv::for_work_dir(&temp_path("shell-env"));

        let runtime_err = wait_for_runtime(
            &fake_shell,
            &shell_env,
            "profile-alice",
            Duration::from_millis(0),
        )
        .expect_err("runtime wait must time out");
        assert!(
            runtime_err
                .to_string()
                .contains("timed out waiting for runtime status")
        );

        let peer_err = wait_for_peer_list(
            &fake_shell,
            &shell_env,
            "profile-alice",
            1,
            Duration::from_millis(1),
        )
        .expect_err("peer list must fail");
        assert!(
            peer_err
                .to_string()
                .contains("peer list returned invalid json")
        );

        let mut devnet = ManagedDevnet {
            shell_exe: fake_shell.clone(),
            shell_env,
            relay_child: None,
            profiles: vec![NodeHandle {
                member: "alice".to_string(),
                profile_id: "profile-alice".to_string(),
            }],
        };
        let out_file = temp_path("invalid-output");

        let sign_err =
            run_sign_iterations(&mut devnet, &out_file, 1, 1).expect_err("invalid sign output");
        assert!(
            sign_err
                .to_string()
                .contains("invalid signature output length")
        );

        let ecdh_shell = write_fake_shell(
            r#"#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "peer list")
    printf '[{"pubkey":"peer-a"}]\n'
    ;;
  "runtime ecdh")
    printf '{"shared_secret_hex32":"deadbeef"}\n'
    ;;
  *)
    printf '{}\n'
    ;;
esac
"#,
        );
        devnet.shell_exe = ecdh_shell.clone();

        let ecdh_err =
            run_ecdh_iterations(&mut devnet, &out_file, 1, 1).expect_err("invalid ecdh output");
        assert!(ecdh_err.to_string().contains("invalid ecdh output length"));

        let _ = fs::remove_file(&fake_shell);
        let _ = fs::remove_file(&ecdh_shell);
    }
}
