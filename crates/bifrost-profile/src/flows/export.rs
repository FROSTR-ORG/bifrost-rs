use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use bifrost_codec::parse_share_package;
use frostr_utils::{
    BfOnboardPayload, BfSharePayload, encode_bfonboard_package, encode_bfprofile_package,
    encode_bfshare_package,
};

use crate::{
    ProfileManifestStore, ProfilePaths, derive_member_pubkey_hex, load_shell_config_file,
    save_shell_config_file,
};

use super::common::{
    load_share_payload_with_passphrase, profile_manifest_store, profile_to_package_payload,
    write_package_output,
};
use super::types::{ProfileExportResult, ProfilePackageExportResult};

pub fn export_profile(
    paths: &ProfilePaths,
    profile_id: &str,
    out_dir: &Path,
    passphrase: Option<String>,
) -> Result<ProfileExportResult> {
    paths.ensure()?;
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let profile = profile_manifest_store(paths).read_profile(profile_id)?;
    let group_path = out_dir.join("group.json");
    let share_path = out_dir.join(format!("share-{}.json", profile.id));

    fs::copy(&profile.group_ref, &group_path)
        .with_context(|| format!("copy {} -> {}", profile.group_ref, group_path.display()))?;
    let share_raw = load_share_payload_with_passphrase(paths, &profile, passphrase)?;
    fs::write(&share_path, share_raw).with_context(|| format!("write {}", share_path.display()))?;

    Ok(ProfileExportResult {
        profile_id: profile.id,
        out_dir: out_dir.display().to_string(),
        group_path: Some(group_path.display().to_string()),
        share_path: share_path.display().to_string(),
    })
}

pub fn export_profile_as_bfprofile(
    paths: &ProfilePaths,
    profile_id: &str,
    package_password: String,
    passphrase: Option<String>,
    out_path: Option<&Path>,
) -> Result<ProfilePackageExportResult> {
    let payload = profile_to_package_payload(paths, profile_id, passphrase)?;
    let package = encode_bfprofile_package(&payload, &package_password)
        .context("encode bfprofile package")?;
    write_package_output(out_path, &package)?;
    Ok(ProfilePackageExportResult {
        profile_id: profile_id.to_string(),
        format: "bfprofile".to_string(),
        out_path: out_path.map(|path| path.display().to_string()),
        package,
    })
}

pub fn export_profile_as_bfshare(
    paths: &ProfilePaths,
    profile_id: &str,
    package_password: String,
    passphrase: Option<String>,
    out_path: Option<&Path>,
) -> Result<ProfilePackageExportResult> {
    let payload = profile_to_package_payload(paths, profile_id, passphrase)?;
    let package = encode_bfshare_package(
        &BfSharePayload {
            share_secret: payload.device.share_secret,
            relays: payload.device.relays,
        },
        &package_password,
    )
    .context("encode bfshare package")?;
    write_package_output(out_path, &package)?;
    Ok(ProfilePackageExportResult {
        profile_id: profile_id.to_string(),
        format: "bfshare".to_string(),
        out_path: out_path.map(|path| path.display().to_string()),
        package,
    })
}

pub fn export_profile_as_bfonboard(
    paths: &ProfilePaths,
    profile_id: &str,
    recipient_share_path: &Path,
    relay_urls: Option<Vec<String>>,
    package_password: String,
    passphrase: Option<String>,
    out_path: Option<&Path>,
) -> Result<ProfilePackageExportResult> {
    let payload = profile_to_package_payload(paths, profile_id, passphrase)?;
    let recipient_share_raw = fs::read_to_string(recipient_share_path)
        .with_context(|| format!("read {}", recipient_share_path.display()))?;
    let recipient_share =
        parse_share_package(&recipient_share_raw).context("parse recipient share package")?;
    let relays = relay_urls.unwrap_or_else(|| payload.device.relays.clone());
    if relays.is_empty() {
        bail!("at least one relay is required");
    }
    let package = encode_bfonboard_package(
        &BfOnboardPayload {
            share_secret: hex::encode(recipient_share.seckey),
            relays,
            peer_pk: derive_member_pubkey_hex(
                crate::hex_to_bytes32(&payload.device.share_secret)
                    .context("decode profile share secret")?,
            )?,
        },
        &package_password,
    )
    .context("encode bfonboard package")?;
    write_package_output(out_path, &package)?;
    Ok(ProfilePackageExportResult {
        profile_id: profile_id.to_string(),
        format: "bfonboard".to_string(),
        out_path: out_path.map(|path| path.display().to_string()),
        package,
    })
}

pub fn remove_profile(paths: &ProfilePaths, profile_id: &str) -> Result<()> {
    paths.ensure()?;
    let profile = profile_manifest_store(paths).read_profile(profile_id)?;
    profile_manifest_store(paths).remove_profile(profile_id)?;

    let state_dir = paths.profile_state_dir(profile_id);
    if state_dir.exists() {
        fs::remove_dir_all(&state_dir)
            .with_context(|| format!("remove {}", state_dir.display()))?;
    }

    if is_managed_group_path(paths, &profile.group_ref)
        && !is_group_ref_in_use(paths, &profile.id, &profile.group_ref)?
        && Path::new(&profile.group_ref).exists()
    {
        fs::remove_file(&profile.group_ref)
            .with_context(|| format!("remove {}", profile.group_ref))?;
    }

    if let Ok(record) = super::read_encrypted_profile(paths, &profile.encrypted_profile_ref)
        && !is_encrypted_profile_in_use(paths, &profile.id, &record.id)?
    {
        super::remove_encrypted_profile(paths, &record.id)?;
    }

    let mut config = load_shell_config_file(&paths.config_path)?;
    if config.last_used_profile_id.as_deref() == Some(profile_id) {
        config.last_used_profile_id = None;
        save_shell_config_file(&paths.config_path, &config)?;
    }
    Ok(())
}

fn is_managed_group_path(paths: &ProfilePaths, group_ref: &str) -> bool {
    Path::new(group_ref).starts_with(&paths.groups_dir)
}

fn is_group_ref_in_use(
    paths: &ProfilePaths,
    skipped_profile_id: &str,
    group_ref: &str,
) -> Result<bool> {
    Ok(profile_manifest_store(paths)
        .list_profiles()?
        .into_iter()
        .filter(|profile| profile.id != skipped_profile_id)
        .any(|profile| profile.group_ref == group_ref))
}

fn is_encrypted_profile_in_use(
    paths: &ProfilePaths,
    skipped_profile_id: &str,
    encrypted_profile_id: &str,
) -> Result<bool> {
    Ok(profile_manifest_store(paths)
        .list_profiles()?
        .into_iter()
        .filter(|profile| profile.id != skipped_profile_id)
        .any(|profile| profile.encrypted_profile_ref == encrypted_profile_id))
}

#[cfg(test)]
mod tests {
    use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
    use frostr_utils::{CreateKeysetConfig, create_keyset};

    use super::*;
    use crate::{FilesystemRelayProfileStore, RelayProfile, RelayProfileStore};

    fn test_paths(label: &str) -> ProfilePaths {
        let unique = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        );
        let root =
            std::env::temp_dir().join(format!("bifrost-profile-export-test-{label}-{unique}",));
        let _ = fs::remove_dir_all(&root);
        ProfilePaths::from_roots(
            root.join("config").join("igloo-shell"),
            root.join("data").join("igloo-shell"),
            root.join("state").join("igloo-shell"),
        )
    }

    fn write_relay_profile(paths: &ProfilePaths) {
        let store = FilesystemRelayProfileStore::new(&paths.relay_profiles_path);
        store
            .write_relay_profiles(&[RelayProfile {
                id: "local".to_string(),
                label: "Local".to_string(),
                relays: vec!["ws://127.0.0.1:8194".to_string()],
            }])
            .expect("write relay profile");
    }

    fn import_sample_profile(paths: &ProfilePaths) -> String {
        paths.ensure().expect("ensure paths");
        write_relay_profile(paths);
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Export Test".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let group_path = paths.imports_dir.join("group.json");
        let share_path = paths.imports_dir.join("share.json");
        fs::create_dir_all(&paths.imports_dir).expect("create imports dir");
        fs::write(
            &group_path,
            serde_json::to_string_pretty(&GroupPackageWire::from(bundle.group)).expect("group"),
        )
        .expect("write group");
        fs::write(
            &share_path,
            serde_json::to_string_pretty(&SharePackageWire::from(bundle.shares[0].clone()))
                .expect("share"),
        )
        .expect("write share");
        let result = crate::import_profile_from_files(
            paths,
            &group_path,
            &share_path,
            Some("Alice".to_string()),
            Some("local".to_string()),
            Some("encrypted-profile-pass".to_string()),
        )
        .expect("import profile");
        match result {
            crate::ProfileImportResult::ProfileCreated { profile, .. } => profile.id,
            other => panic!("expected profile_created, got {other:?}"),
        }
    }

    #[test]
    fn raw_export_writes_group_and_share_files() {
        let paths = test_paths("raw");
        let profile_id = import_sample_profile(&paths);
        let out_dir = paths.data_dir.join("raw-export");
        let result = export_profile(
            &paths,
            &profile_id,
            &out_dir,
            Some("encrypted-profile-pass".into()),
        )
        .expect("export profile");
        assert_eq!(result.profile_id, profile_id);
        assert!(Path::new(result.group_path.as_deref().expect("group path")).exists());
        assert!(Path::new(&result.share_path).exists());
    }

    #[test]
    fn bfprofile_export_round_trips_into_import() {
        let paths = test_paths("bfprofile");
        let profile_id = import_sample_profile(&paths);
        let exported = export_profile_as_bfprofile(
            &paths,
            &profile_id,
            "package-pass".to_string(),
            Some("encrypted-profile-pass".to_string()),
            None,
        )
        .expect("export bfprofile");
        let imported = crate::import_profile_from_bfprofile_value(
            &paths,
            &exported.package,
            "package-pass".to_string(),
            Some("Recovered".to_string()),
            Some("local".to_string()),
            Some("encrypted-profile-pass".to_string()),
        )
        .expect("import bfprofile");
        match imported {
            crate::ProfileImportResult::ProfileCreated { profile, .. } => {
                assert_eq!(profile.label, "Recovered");
            }
            other => panic!("expected profile_created, got {other:?}"),
        }
    }
}
