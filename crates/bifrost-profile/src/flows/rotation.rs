use anyhow::{Result, bail};
use bifrost_core::types::GroupPackage;
use frostr_utils::BfProfilePayload;

use crate::{ProfileManifest, ProfileManifestStore, ProfilePaths, group_from_payload};

use super::common::{now_unix_secs, profile_domain, profile_manifest_store};
use super::types::ProfileImportResult;

pub fn finalize_rotation_update_import(
    paths: &ProfilePaths,
    target: &ProfileManifest,
    target_payload: BfProfilePayload,
    rotated_group: &GroupPackage,
    rotated_payload: BfProfilePayload,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    if hex::encode(rotated_group.group_pk)
        != hex::encode(group_from_payload(&target_payload)?.group_pk)
    {
        bail!("rotation update does not match the selected profile group public key");
    }
    if rotated_payload.profile_id == target_payload.profile_id {
        bail!("rotation update did not produce a new device profile id");
    }

    paths.ensure()?;
    let passphrase = passphrase
        .or_else(|| std::env::var("IGLOO_SHELL_PROFILE_PASSPHRASE").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("passphrase not provided; set IGLOO_SHELL_PROFILE_PASSPHRASE")
        })?;
    let imported = profile_domain(paths).import_profile_from_payload(
        &rotated_payload,
        Some(target.label.clone()),
        Some(target.relay_profile.clone()),
        &passphrase,
        now_unix_secs(),
    )?;
    let mut migrated = imported.profile;
    migrated.runtime_options = target.runtime_options.clone();
    migrated.last_used_at = target.last_used_at;
    profile_manifest_store(paths).write_profile(&migrated)?;
    super::export::remove_profile(paths, &target.id)?;
    profile_domain(paths).touch_last_used_profile(&migrated.id)?;

    Ok(ProfileImportResult::ProfileCreated {
        profile: migrated,
        encrypted_profile: imported.encrypted_profile,
        diagnostics: None,
        warnings: Vec::new(),
    })
}
