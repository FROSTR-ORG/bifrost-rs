use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use bifrost_codec::{parse_group_package, parse_share_package};
use frostr_utils::{BfProfilePayload, decode_bfprofile_package};

use crate::{ProfilePaths, ProfilePreview, preview_from_profile_payload};

use super::common::{now_unix_secs, profile_domain, resolve_secret};
use super::types::ProfileImportResult;

const PROFILE_PASSPHRASE_ENV: &str = "IGLOO_SHELL_PROFILE_PASSPHRASE";

pub fn import_profile_from_files(
    paths: &ProfilePaths,
    group_path: &Path,
    share_path: &Path,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let group_raw =
        fs::read_to_string(group_path).with_context(|| format!("read {}", group_path.display()))?;
    let share_raw =
        fs::read_to_string(share_path).with_context(|| format!("read {}", share_path.display()))?;
    let group = parse_group_package(&group_raw).context("parse group package")?;
    let share = parse_share_package(&share_raw).context("parse share package")?;
    let passphrase = resolve_secret(passphrase, PROFILE_PASSPHRASE_ENV, "passphrase")?;
    let imported = profile_domain(paths).import_profile_from_files(
        &group,
        &share,
        &share_raw,
        label,
        relay_profile,
        &passphrase,
        now_unix_secs(),
    )?;

    Ok(ProfileImportResult::ProfileCreated {
        profile: imported.profile,
        encrypted_profile: imported.encrypted_profile,
        diagnostics: None,
        warnings: Vec::new(),
    })
}

pub fn preview_bfprofile_value(
    package_raw: &str,
    package_password: String,
    label: Option<String>,
) -> Result<(ProfilePreview, BfProfilePayload)> {
    let payload = decode_bfprofile_package(package_raw, &package_password)
        .context("decode bfprofile package")?;
    let preview = preview_from_profile_payload(&payload, label, "bfprofile")?;
    Ok((preview, payload))
}

pub fn import_profile_from_bfprofile_value(
    paths: &ProfilePaths,
    package_raw: &str,
    package_password: String,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    let payload = decode_bfprofile_package(package_raw, &package_password)
        .context("decode bfprofile package")?;
    import_profile_from_bfprofile_payload(paths, payload, label, relay_profile, passphrase)
}

pub(crate) fn import_profile_from_bfprofile_payload(
    paths: &ProfilePaths,
    payload: BfProfilePayload,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let passphrase = resolve_secret(passphrase, PROFILE_PASSPHRASE_ENV, "passphrase")?;
    let relay_profile_id = profile_domain(paths).ensure_onboarding_relay_profile(
        relay_profile,
        Some(label.as_deref().unwrap_or(&payload.device.name)),
        &payload.device.relays,
        now_unix_secs(),
    )?;
    let imported = profile_domain(paths).import_profile_from_payload(
        &payload,
        label,
        Some(relay_profile_id),
        &passphrase,
        now_unix_secs(),
    )?;
    Ok(ProfileImportResult::ProfileCreated {
        profile: imported.profile,
        encrypted_profile: imported.encrypted_profile,
        diagnostics: None,
        warnings: Vec::new(),
    })
}
