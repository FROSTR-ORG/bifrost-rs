use std::fs;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow};
use bifrost_codec::wire::SharePackageWire;
use bifrost_profile::{
    EncryptedProfileStore, ProfileImportResult, ProfileManifest, ProfileManifestStore,
    ProfilePaths, ProfilePreview, RelayProfileStore, derive_profile_id_for_share_secret,
    finalize_rotation_update_import,
};
use frostr_utils::{BfProfileDevice, BfProfilePayload, decode_bfonboard_package};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use tokio::time::Duration;

use crate::host::{DaemonClient, DaemonTransportConfig, ShutdownPayload};
use crate::onboarding::{
    BootstrapImportResult, complete_onboarding_package, persist_validated_onboarding_state,
};
use crate::runtime::{AppOptions, ResolvedAppConfig};

const PROFILE_PASSPHRASE_ENV: &str = "IGLOO_SHELL_PROFILE_PASSPHRASE";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonMetadata {
    pub profile_id: String,
    pub pid: u32,
    pub socket_path: String,
    pub token: String,
    pub log_path: String,
    pub started_at: u64,
}

#[derive(Debug, Clone)]
pub struct ConnectedOnboardingImport {
    pub preview: ProfilePreview,
    pub completion: BootstrapImportResult,
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn profile_manifest_store(
    paths: &ProfilePaths,
) -> bifrost_profile::FilesystemProfileManifestStore {
    bifrost_profile::FilesystemProfileManifestStore::new(&paths.profiles_dir)
}

fn profile_domain(paths: &ProfilePaths) -> bifrost_profile::FilesystemProfileDomain {
    bifrost_profile::FilesystemProfileDomain::new(
        &paths.config_path,
        &paths.relay_profiles_path,
        &paths.profiles_dir,
        &paths.groups_dir,
        &paths.encrypted_profiles_dir,
        &paths.state_profiles_dir,
    )
}

fn read_relay_profile(
    paths: &ProfilePaths,
    relay_profile_id: &str,
) -> Result<bifrost_profile::RelayProfile> {
    bifrost_profile::FilesystemRelayProfileStore::new(&paths.relay_profiles_path)
        .list_relay_profiles()?
        .into_iter()
        .find(|profile| profile.id == relay_profile_id)
        .ok_or_else(|| anyhow!("unknown relay profile {relay_profile_id}"))
}

fn load_share_payload_with_passphrase(
    paths: &ProfilePaths,
    profile: &ProfileManifest,
    passphrase: Option<String>,
) -> Result<String> {
    if let Ok(record) =
        bifrost_profile::FilesystemEncryptedProfileStore::new(
            &paths.encrypted_profiles_dir,
            &paths.encrypted_profiles_dir,
        )
        .read_encrypted_profile(&profile.encrypted_profile_ref)
    {
        let passphrase = passphrase
            .or_else(|| std::env::var(PROFILE_PASSPHRASE_ENV).ok())
            .ok_or_else(|| anyhow!("passphrase not provided; set {PROFILE_PASSPHRASE_ENV}"))?;
        return bifrost_profile::FilesystemEncryptedProfileStore::new(
            &paths.encrypted_profiles_dir,
            &paths.encrypted_profiles_dir,
        )
        .decrypt_encrypted_profile(&record, &passphrase);
    }
    fs::read_to_string(&profile.encrypted_profile_ref)
        .with_context(|| format!("read {}", profile.encrypted_profile_ref))
}

fn resolve_profile_peers_and_overrides(
    group: &bifrost_core::types::GroupPackage,
    share: &bifrost_core::types::SharePackage,
    value: Value,
) -> Result<(
    Vec<String>,
    std::collections::HashMap<String, bifrost_core::types::PeerPolicyOverride>,
)> {
    let document = bifrost_profile::parse_policy_overrides_doc(value)?;
    let local_pubkey = bifrost_profile::derive_member_pubkey_hex(share.seckey)?;
    let peer_keys = group
        .members
        .iter()
        .map(|member| hex::encode(&member.pubkey[1..]))
        .filter(|pubkey| pubkey != &local_pubkey)
        .collect::<Vec<_>>();

    let mut peers = Vec::with_capacity(peer_keys.len());
    let mut manual_policy_overrides = std::collections::HashMap::new();
    for pubkey in peer_keys {
        let base = document.default_override.clone().unwrap_or_default();
        let specific = document
            .peer_overrides
            .iter()
            .find(|entry| entry.pubkey == pubkey)
            .map(|entry| entry.policy_override.clone())
            .unwrap_or_default();
        let effective = bifrost_core::types::PeerPolicyOverride {
            request: bifrost_core::types::MethodPolicyOverride {
                echo: match specific.request.echo {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.request.echo,
                    other => other,
                },
                ping: match specific.request.ping {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.request.ping,
                    other => other,
                },
                onboard: match specific.request.onboard {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.request.onboard,
                    other => other,
                },
                sign: match specific.request.sign {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.request.sign,
                    other => other,
                },
                ecdh: match specific.request.ecdh {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.request.ecdh,
                    other => other,
                },
            },
            respond: bifrost_core::types::MethodPolicyOverride {
                echo: match specific.respond.echo {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.respond.echo,
                    other => other,
                },
                ping: match specific.respond.ping {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.respond.ping,
                    other => other,
                },
                onboard: match specific.respond.onboard {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.respond.onboard,
                    other => other,
                },
                sign: match specific.respond.sign {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.respond.sign,
                    other => other,
                },
                ecdh: match specific.respond.ecdh {
                    bifrost_core::types::PolicyOverrideValue::Unset => base.respond.ecdh,
                    other => other,
                },
            },
        };
        manual_policy_overrides.insert(pubkey.clone(), effective);
        peers.push(pubkey);
    }
    peers.sort();
    Ok((peers, manual_policy_overrides))
}

fn preview_from_bootstrap_completion(
    completion: &BootstrapImportResult,
    label: Option<String>,
    source: &'static str,
    peer_pubkey: Option<String>,
) -> Result<ProfilePreview> {
    let share_public_key = bifrost_profile::derive_member_pubkey_hex(completion.share.seckey)?;
    Ok(ProfilePreview {
        profile_id: derive_profile_id_for_share_secret(&hex::encode(completion.share.seckey))?,
        label: label.unwrap_or_else(|| format!("Onboarded Device {}", completion.share.idx)),
        share_public_key,
        group_public_key: hex::encode(completion.group.group_pk),
        threshold: completion.group.threshold as usize,
        total_count: completion.group.members.len(),
        relays: completion.relays.clone(),
        peer_pubkey,
        source,
    })
}

fn shorten_unix_socket_path(raw_path: &str, profile_id: &str) -> PathBuf {
    let path = PathBuf::from(raw_path);
    #[cfg(unix)]
    {
        let raw_len = path.as_os_str().to_string_lossy().len();
        if raw_len >= 96 {
            let digest = sha2::Sha256::digest(profile_id.as_bytes());
            let short = hex::encode(&digest[..6]);
            return std::env::temp_dir().join(format!("igloo-shell-{short}.sock"));
        }
    }
    path
}

pub fn resolve_profile_runtime(
    paths: &ProfilePaths,
    profile_id: &str,
) -> Result<(ProfileManifest, ResolvedAppConfig)> {
    let profile = profile_manifest_store(paths).read_profile(profile_id)?;
    let relay_profile = read_relay_profile(paths, &profile.relay_profile)?;

    let group_raw = fs::read_to_string(&profile.group_ref)
        .with_context(|| format!("read {}", profile.group_ref))?;
    let share_raw = load_share_payload_with_passphrase(paths, &profile, None)?;
    let group = bifrost_codec::parse_group_package(&group_raw).context("parse profile group package")?;
    let share = bifrost_codec::parse_share_package(&share_raw).context("parse profile share package")?;
    let (peers, manual_policy_overrides) =
        resolve_profile_peers_and_overrides(&group, &share, profile.policy_overrides.clone())
            .context("resolve peer policy overrides")?;
    let options: AppOptions = if profile.runtime_options.is_null() {
        AppOptions::default()
    } else {
        serde_json::from_value(profile.runtime_options.clone()).context("parse runtime options")?
    };

    Ok((
        profile.clone(),
        ResolvedAppConfig {
            group,
            share,
            state_path: PathBuf::from(&profile.state_path),
            relays: relay_profile.relays,
            peers,
            manual_policy_overrides,
            options,
        },
    ))
}

pub fn resolve_profile_runtime_for_passphrase(
    paths: &ProfilePaths,
    profile_id: &str,
    passphrase: Option<String>,
) -> Result<(ProfileManifest, ResolvedAppConfig)> {
    let profile = profile_manifest_store(paths).read_profile(profile_id)?;
    let relay_profile = read_relay_profile(paths, &profile.relay_profile)?;
    let group_raw = fs::read_to_string(&profile.group_ref)
        .with_context(|| format!("read {}", profile.group_ref))?;
    let share_raw = load_share_payload_with_passphrase(paths, &profile, passphrase)?;
    let group = bifrost_codec::parse_group_package(&group_raw).context("parse profile group package")?;
    let share = bifrost_codec::parse_share_package(&share_raw).context("parse profile share package")?;
    let (peers, manual_policy_overrides) =
        resolve_profile_peers_and_overrides(&group, &share, profile.policy_overrides.clone())
            .context("resolve peer policy overrides")?;
    let options: AppOptions = if profile.runtime_options.is_null() {
        AppOptions::default()
    } else {
        serde_json::from_value(profile.runtime_options.clone()).context("parse runtime options")?
    };
    Ok((
        profile.clone(),
        ResolvedAppConfig {
            group,
            share,
            state_path: PathBuf::from(&profile.state_path),
            relays: relay_profile.relays,
            peers,
            manual_policy_overrides,
            options,
        },
    ))
}

pub fn read_daemon_metadata(paths: &ProfilePaths, profile_id: &str) -> Result<DaemonMetadata> {
    let path = paths.daemon_metadata_path(profile_id);
    if !path.exists() {
        anyhow::bail!("daemon metadata is not present for profile {profile_id}");
    }
    let contents = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&contents).context("parse daemon metadata")
}

pub fn write_daemon_metadata(
    paths: &ProfilePaths,
    profile_id: &str,
    metadata: &DaemonMetadata,
) -> Result<()> {
    let path = paths.daemon_metadata_path(profile_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&path, serde_json::to_vec_pretty(metadata)?)
        .with_context(|| format!("write {}", path.display()))
}

pub fn remove_daemon_metadata(paths: &ProfilePaths, profile_id: &str) -> Result<()> {
    let path = paths.daemon_metadata_path(profile_id);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

pub fn daemon_log_path(paths: &ProfilePaths, profile_id: &str) -> PathBuf {
    paths.daemon_log_path(profile_id)
}

pub fn build_daemon_transport(profile: &ProfileManifest) -> DaemonTransportConfig {
    let socket_path = shorten_unix_socket_path(&profile.daemon_socket_path, &profile.id);
    DaemonTransportConfig {
        socket_path,
        token: format!("daemon-{}-{}", profile.id, now_unix_secs()),
    }
}

#[cfg(unix)]
pub async fn start_profile_daemon_with_passphrase(
    paths: &ProfilePaths,
    profile_id: &str,
    passphrase: Option<String>,
) -> Result<DaemonMetadata> {
    paths.ensure()?;
    let profile = profile_manifest_store(paths).read_profile(profile_id)?;
    let _ = load_share_payload_with_passphrase(paths, &profile, passphrase.clone())?;
    let transport = build_daemon_transport(&profile);
    let log_path = paths.daemon_log_path(profile_id);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let stderr = stdout.try_clone().context("clone daemon log handle")?;
    let exe = std::env::current_exe().context("resolve current executable")?;
    let mut command = Command::new(exe);
    command
        .arg("__daemon-run")
        .arg("--profile")
        .arg(profile_id)
        .arg("--socket-path")
        .arg(&transport.socket_path)
        .arg("--token")
        .arg(&transport.token)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(passphrase) = &passphrase {
        command.env(PROFILE_PASSPHRASE_ENV, passphrase);
    }
    let mut child = command.spawn().context("spawn profile daemon")?;

    let metadata = DaemonMetadata {
        profile_id: profile_id.to_string(),
        pid: child.id(),
        socket_path: transport.socket_path.display().to_string(),
        token: transport.token.clone(),
        log_path: log_path.display().to_string(),
        started_at: now_unix_secs(),
    };
    write_daemon_metadata(paths, profile_id, &metadata)?;

    let client = DaemonClient::new(PathBuf::from(&metadata.socket_path), metadata.token.clone());
    let mut last_error = None;
    for _ in 0..50 {
        match client.runtime_metadata().await {
            Ok(_) => return Ok(metadata),
            Err(err) => last_error = Some(err.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if let Ok(None) = child.try_wait() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = remove_daemon_metadata(paths, profile_id);

    Err(anyhow!(
        "daemon did not become ready for profile {profile_id}: {}",
        last_error.unwrap_or_else(|| "unknown startup failure".to_string())
    ))
}

#[cfg(unix)]
pub async fn start_profile_daemon(
    paths: &ProfilePaths,
    profile_id: &str,
) -> Result<DaemonMetadata> {
    start_profile_daemon_with_passphrase(paths, profile_id, None).await
}

#[cfg(unix)]
pub async fn stop_profile_daemon_typed(
    paths: &ProfilePaths,
    profile_id: &str,
) -> Result<ShutdownPayload> {
    let metadata = read_daemon_metadata(paths, profile_id)?;
    let client = DaemonClient::new(PathBuf::from(metadata.socket_path), metadata.token);
    let result = client.shutdown().await?;
    remove_daemon_metadata(paths, profile_id)?;
    Ok(result)
}

#[cfg(unix)]
pub async fn stop_profile_daemon(paths: &ProfilePaths, profile_id: &str) -> Result<Value> {
    let result = stop_profile_daemon_typed(paths, profile_id).await?;
    serde_json::to_value(result).context("serialize daemon shutdown result")
}

pub async fn import_profile_from_onboarding_value(
    paths: &ProfilePaths,
    package_raw: &str,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<String>,
    onboarding_password: Option<String>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let password = onboarding_password
        .or_else(|| std::env::var("IGLOO_SHELL_ONBOARDING_PASSWORD").ok())
        .ok_or_else(|| anyhow!("onboarding package password not provided; set IGLOO_SHELL_ONBOARDING_PASSWORD"))?;
    let decoded = decode_bfonboard_package(package_raw, password.as_str())
        .context("decode bfonboard package")?;
    let completion = complete_onboarding_package(decoded, Duration::from_secs(30)).await?;
    let preview = preview_from_bootstrap_completion(
        &completion,
        None,
        "bfonboard",
        Some(completion.peer_pubkey.clone()),
    )?;
    finalize_connected_onboarding_import(
        paths,
        ConnectedOnboardingImport { preview, completion },
        label,
        relay_profile,
        passphrase,
    )
}

pub async fn connect_onboarding_package_preview(
    package_raw: &str,
    onboarding_password: String,
) -> Result<ConnectedOnboardingImport> {
    let decoded = decode_bfonboard_package(package_raw, onboarding_password.as_str())
        .context("decode bfonboard package")?;
    let completion = complete_onboarding_package(decoded, Duration::from_secs(30)).await?;
    let preview = preview_from_bootstrap_completion(
        &completion,
        None,
        "bfonboard",
        Some(completion.peer_pubkey.clone()),
    )?;
    Ok(ConnectedOnboardingImport { preview, completion })
}

pub fn finalize_connected_onboarding_import(
    paths: &ProfilePaths,
    connection: ConnectedOnboardingImport,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let relay_profile_id = profile_domain(paths).ensure_onboarding_relay_profile(
        relay_profile,
        label.as_deref(),
        &connection.completion.relays,
        now_unix_secs(),
    )?;
    let share_raw =
        serde_json::to_string_pretty(&SharePackageWire::from(connection.completion.share.clone()))
            .context("serialize onboarded share package")?;
    let share_record =
        bifrost_profile::FilesystemEncryptedProfileStore::new(
            &paths.encrypted_profiles_dir,
            &paths.encrypted_profiles_dir,
        )
        .store_encrypted_profile(
            "share_package",
            "bfonboard_import",
            &share_raw,
            &passphrase
                .or_else(|| std::env::var(PROFILE_PASSPHRASE_ENV).ok())
                .ok_or_else(|| anyhow!("passphrase not provided; set {PROFILE_PASSPHRASE_ENV}"))?,
            now_unix_secs(),
        )?;

    let imported = profile_domain(paths).finalize_onboarding_import(
        &connection.completion.group,
        &connection.completion.share,
        label,
        relay_profile_id,
        share_record,
        now_unix_secs(),
    )?;
    let profile = imported.profile;
    let encrypted_profile = imported.encrypted_profile;
    fs::create_dir_all(paths.profile_state_dir(&profile.id))
        .with_context(|| format!("create {}", paths.profile_state_dir(&profile.id).display()))?;
    let diagnostics =
        match persist_validated_onboarding_state(Path::new(&profile.state_path), &connection.completion) {
            Ok(report) => report,
            Err(error) => {
                let _ = fs::remove_file(&profile.group_ref);
                let _ = bifrost_profile::remove_encrypted_profile(paths, &encrypted_profile.id);
                let _ = fs::remove_dir_all(paths.profile_state_dir(&profile.id));
                return Err(error);
            }
        };
    profile_manifest_store(paths).write_profile(&profile)?;
    profile_domain(paths).touch_last_used_profile(&profile.id)?;

    Ok(ProfileImportResult::ProfileCreated {
        profile,
        encrypted_profile,
        diagnostics: Some(serde_json::to_value(diagnostics).context("serialize onboarding diagnostics")?),
        warnings: Vec::new(),
    })
}

pub async fn apply_rotation_update_from_bfonboard_value(
    paths: &ProfilePaths,
    target_profile_id: &str,
    package_raw: &str,
    onboarding_password: String,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    let target = profile_manifest_store(paths).read_profile(target_profile_id)?;
    let connection = connect_onboarding_package_preview(package_raw, onboarding_password).await?;

    let target_payload = {
        let relay_profile = read_relay_profile(paths, &target.relay_profile)?;
        let share_raw = load_share_payload_with_passphrase(paths, &target, passphrase.clone())?;
        let group_raw = fs::read_to_string(&target.group_ref)
            .with_context(|| format!("read {}", target.group_ref))?;
        let group = bifrost_codec::parse_group_package(&group_raw).context("parse profile group package")?;
        let share = bifrost_codec::parse_share_package(&share_raw).context("parse profile share package")?;
        let (_peers, manual_policy_overrides) =
            resolve_profile_peers_and_overrides(&group, &share, target.policy_overrides.clone())
                .context("resolve peer policy overrides")?;
        let manual_peer_policy_overrides = manual_policy_overrides
            .iter()
            .map(|(pubkey, policy_override)| frostr_utils::BfManualPeerPolicyOverride {
                pubkey: pubkey.clone(),
                policy: frostr_utils::core_peer_policy_override_to_bf(policy_override),
            })
            .collect::<Vec<_>>();
        BfProfilePayload {
            profile_id: target.id.clone(),
            version: 1,
            device: BfProfileDevice {
                name: target.label.clone(),
                share_secret: hex::encode(share.seckey),
                manual_peer_policy_overrides,
                relays: relay_profile.relays,
            },
            group_package: bifrost_codec::wire::GroupPackageWire::from(group),
        }
    };

    let rotated_payload = BfProfilePayload {
        profile_id: connection.preview.profile_id.clone(),
        version: 1,
        device: BfProfileDevice {
            name: target.label.clone(),
            share_secret: hex::encode(connection.completion.share.seckey),
            manual_peer_policy_overrides: Vec::new(),
            relays: connection.completion.relays.clone(),
        },
        group_package: bifrost_codec::wire::GroupPackageWire::from(connection.completion.group.clone()),
    };

    finalize_rotation_update_import(
        paths,
        &target,
        target_payload,
        &connection.completion.group,
        rotated_payload,
        passphrase,
    )
}
