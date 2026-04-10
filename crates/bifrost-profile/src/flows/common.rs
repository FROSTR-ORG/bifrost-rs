use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use bifrost_codec::{parse_group_package, parse_share_package, wire::GroupPackageWire};
use bifrost_core::types::{GroupPackage, PeerPolicyOverride, SharePackage};
use frostr_utils::{
    BfManualPeerPolicyOverride, BfProfileDevice, BfProfilePayload, core_peer_policy_override_to_bf,
};

use crate::{
    EncryptedProfileRecord, FilesystemEncryptedProfileStore, FilesystemProfileDomain,
    FilesystemProfileManifestStore, FilesystemRelayProfileStore, PolicyOverridesDocument,
    ProfileManifest, ProfileManifestStore, ProfilePaths, RelayProfile, RelayProfileStore,
    derive_member_pubkey_hex, parse_policy_overrides_doc,
};

const PROFILE_PASSPHRASE_ENV: &str = "IGLOO_SHELL_PROFILE_PASSPHRASE";

pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn profile_manifest_store(paths: &ProfilePaths) -> FilesystemProfileManifestStore {
    FilesystemProfileManifestStore::new(&paths.profiles_dir)
}

pub(crate) fn relay_profile_store(paths: &ProfilePaths) -> FilesystemRelayProfileStore {
    FilesystemRelayProfileStore::new(&paths.relay_profiles_path)
}

pub(crate) fn encrypted_profile_store(paths: &ProfilePaths) -> FilesystemEncryptedProfileStore {
    FilesystemEncryptedProfileStore::new(
        &paths.encrypted_profiles_dir,
        &paths.encrypted_profiles_dir,
    )
}

pub(crate) fn profile_domain(paths: &ProfilePaths) -> FilesystemProfileDomain {
    FilesystemProfileDomain::new(
        &paths.config_path,
        &paths.relay_profiles_path,
        &paths.profiles_dir,
        &paths.groups_dir,
        &paths.encrypted_profiles_dir,
        &paths.state_profiles_dir,
    )
}

pub(crate) fn resolve_secret(value: Option<String>, env_name: &str, label: &str) -> Result<String> {
    if let Some(value) = value {
        return Ok(value);
    }
    std::env::var(env_name).with_context(|| format!("{label} not provided; set {env_name}"))
}

pub(crate) fn read_relay_profile(
    paths: &ProfilePaths,
    relay_profile_id: &str,
) -> Result<RelayProfile> {
    relay_profile_store(paths)
        .list_relay_profiles()?
        .into_iter()
        .find(|profile| profile.id == relay_profile_id)
        .ok_or_else(|| anyhow!("unknown relay profile {relay_profile_id}"))
}

pub(crate) fn decrypt_encrypted_profile(
    paths: &ProfilePaths,
    record: &EncryptedProfileRecord,
    passphrase: Option<String>,
) -> Result<String> {
    let passphrase = resolve_secret(passphrase, PROFILE_PASSPHRASE_ENV, "passphrase")?;
    encrypted_profile_store(paths).decrypt_encrypted_profile(record, &passphrase)
}

pub(crate) fn load_share_payload_with_passphrase(
    paths: &ProfilePaths,
    profile: &ProfileManifest,
    passphrase: Option<String>,
) -> Result<String> {
    if let Ok(record) = super::read_encrypted_profile(paths, &profile.encrypted_profile_ref) {
        return decrypt_encrypted_profile(paths, &record, passphrase);
    }
    fs::read_to_string(&profile.encrypted_profile_ref)
        .with_context(|| format!("read {}", profile.encrypted_profile_ref))
}

fn effective_policy_override(
    document: &PolicyOverridesDocument,
    peer_pubkey: &str,
) -> PeerPolicyOverride {
    let base = document.default_override.clone().unwrap_or_default();
    let specific = document
        .peer_overrides
        .iter()
        .find(|entry| entry.pubkey == peer_pubkey)
        .map(|entry| entry.policy_override.clone())
        .unwrap_or_default();
    merge_policy_override(&base, &specific)
}

fn merge_policy_override(
    base: &PeerPolicyOverride,
    next: &PeerPolicyOverride,
) -> PeerPolicyOverride {
    fn resolve(
        base: bifrost_core::types::PolicyOverrideValue,
        next: bifrost_core::types::PolicyOverrideValue,
    ) -> bifrost_core::types::PolicyOverrideValue {
        match next {
            bifrost_core::types::PolicyOverrideValue::Unset => base,
            other => other,
        }
    }

    PeerPolicyOverride {
        request: bifrost_core::types::MethodPolicyOverride {
            echo: resolve(base.request.echo, next.request.echo),
            ping: resolve(base.request.ping, next.request.ping),
            onboard: resolve(base.request.onboard, next.request.onboard),
            sign: resolve(base.request.sign, next.request.sign),
            ecdh: resolve(base.request.ecdh, next.request.ecdh),
        },
        respond: bifrost_core::types::MethodPolicyOverride {
            echo: resolve(base.respond.echo, next.respond.echo),
            ping: resolve(base.respond.ping, next.respond.ping),
            onboard: resolve(base.respond.onboard, next.respond.onboard),
            sign: resolve(base.respond.sign, next.respond.sign),
            ecdh: resolve(base.respond.ecdh, next.respond.ecdh),
        },
    }
}

pub(crate) fn resolve_profile_peers_and_overrides(
    group: &GroupPackage,
    share: &SharePackage,
    value: serde_json::Value,
) -> Result<(Vec<String>, HashMap<String, PeerPolicyOverride>)> {
    let document = parse_policy_overrides_doc(value)?;
    let local_pubkey = derive_member_pubkey_hex(share.seckey)?;
    let peer_keys = group
        .members
        .iter()
        .map(|member| hex::encode(&member.pubkey[1..]))
        .filter(|pubkey| pubkey != &local_pubkey)
        .collect::<Vec<_>>();

    let mut peers = Vec::with_capacity(peer_keys.len());
    let mut manual_policy_overrides = HashMap::new();
    for pubkey in peer_keys {
        let effective_override = effective_policy_override(&document, &pubkey);
        manual_policy_overrides.insert(pubkey.clone(), effective_override);
        peers.push(pubkey);
    }
    peers.sort();
    Ok((peers, manual_policy_overrides))
}

pub(crate) fn profile_to_package_payload(
    paths: &ProfilePaths,
    profile_id: &str,
    passphrase: Option<String>,
) -> Result<BfProfilePayload> {
    let profile = profile_manifest_store(paths).read_profile(profile_id)?;
    let relay_profile = read_relay_profile(paths, &profile.relay_profile)?;
    let group_raw = fs::read_to_string(&profile.group_ref)
        .with_context(|| format!("read {}", profile.group_ref))?;
    let share_raw = load_share_payload_with_passphrase(paths, &profile, passphrase)?;
    let group = parse_group_package(&group_raw).context("parse profile group package")?;
    let share = parse_share_package(&share_raw).context("parse profile share package")?;
    let (_peers, manual_policy_overrides) =
        resolve_profile_peers_and_overrides(&group, &share, profile.policy_overrides.clone())
            .context("resolve peer policy overrides")?;
    let manual_peer_policy_overrides = manual_policy_overrides
        .iter()
        .map(|(pubkey, policy_override)| BfManualPeerPolicyOverride {
            pubkey: pubkey.clone(),
            policy: core_peer_policy_override_to_bf(policy_override),
        })
        .collect::<Vec<_>>();
    Ok(BfProfilePayload {
        profile_id: profile.id.clone(),
        version: 1,
        device: BfProfileDevice {
            name: profile.label,
            share_secret: hex::encode(share.seckey),
            manual_peer_policy_overrides,
            relays: relay_profile.relays,
        },
        group_package: GroupPackageWire::from(group),
    })
}

pub(crate) fn write_package_output(out_path: Option<&Path>, package: &str) -> Result<()> {
    if let Some(path) = out_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(path, package).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}
