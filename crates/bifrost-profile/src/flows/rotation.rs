use anyhow::{Result, bail};
use bifrost_core::secret::Passphrase;
use bifrost_core::types::GroupPackage;
use frostr_utils::BfProfilePayload;

use crate::{ProfileManifest, ProfileManifestStore, ProfilePaths, group_from_payload};

use super::common::{now_unix_secs, profile_domain, profile_manifest_store};
use super::rotation_intent::{
    RotationIntent, RotationKind, RotationStep, delete_intent, write_intent,
};
use super::types::ProfileImportResult;

pub fn finalize_rotation_update_import(
    paths: &ProfilePaths,
    target: &ProfileManifest,
    target_payload: BfProfilePayload,
    rotated_group: &GroupPackage,
    rotated_payload: BfProfilePayload,
    passphrase: Option<Passphrase>,
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
    // C.5: env-var fallback removed. Callers must provide a `Passphrase`
    // explicitly. The `IGLOO_SHELL_PROFILE_PASSPHRASE` env contract is
    // being retired (igloo-shell PR12 will follow the bifrost-rs change).
    let passphrase = passphrase.ok_or_else(|| anyhow::anyhow!("passphrase not provided"))?;

    // C.7: bracket the rotation flow with intent writes so a crashed
    // rotation leaves a journal entry the next daemon process can detect on
    // startup. The `workspace_id` is keyed off the originating profile id
    // today — future workspaces may map it to a workspace identifier
    // instead. No auto-recovery is performed; the journal is informational.
    let mut intent = RotationIntent::new(&target.id, RotationKind::RotateShare, &target.id);
    write_intent(paths, &intent)?;

    let imported = profile_domain(paths).import_profile_from_payload(
        &rotated_payload,
        Some(target.label.clone()),
        Some(target.relay_profile.clone()),
        passphrase.expose_secret(),
        now_unix_secs(),
    )?;
    intent.advance(RotationStep::PostCreateNewProfile);
    write_intent(paths, &intent)?;

    let mut migrated = imported.profile;
    migrated.runtime_options = target.runtime_options.clone();
    migrated.last_used_at = target.last_used_at;
    profile_manifest_store(paths).write_profile(&migrated)?;
    intent.advance(RotationStep::PostWriteNewManifest);
    write_intent(paths, &intent)?;

    intent.advance(RotationStep::PreRemoveOldProfile);
    write_intent(paths, &intent)?;
    super::export::remove_profile(paths, &target.id)?;

    profile_domain(paths).touch_last_used_profile(&migrated.id)?;
    intent.advance(RotationStep::Completed);
    write_intent(paths, &intent)?;
    delete_intent(paths, &intent.workspace_id)?;

    Ok(ProfileImportResult::ProfileCreated {
        profile: migrated,
        encrypted_profile: imported.encrypted_profile,
        diagnostics: None,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
    use frostr_utils::{
        BfProfileDevice, BfProfilePayload, CreateKeysetConfig, KeysetBundle, create_keyset,
    };

    use crate::flows::rotation_intent::{RotationStep, scan_rotation_intents};
    use crate::{
        FilesystemRelayProfileStore, ProfileManifestStore, RelayProfile, RelayProfileStore,
    };

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
            std::env::temp_dir().join(format!("bifrost-profile-rotation-test-{label}-{unique}",));
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

    /// Import bundle.shares[0] as the original ("target") profile via the
    /// canonical files-based import path. Returns the imported profile's id.
    fn import_target_profile(paths: &ProfilePaths, bundle: &KeysetBundle) -> String {
        paths.ensure().expect("ensure paths");
        write_relay_profile(paths);
        let group_path = paths.imports_dir.join("group.json");
        let share_path = paths.imports_dir.join("share.json");
        fs::create_dir_all(&paths.imports_dir).expect("create imports dir");
        fs::write(
            &group_path,
            serde_json::to_string_pretty(&GroupPackageWire::from(bundle.group.clone()))
                .expect("group"),
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
            Some(Passphrase::new("rotation-test-passphrase".to_string())),
        )
        .expect("import profile");
        match result {
            crate::ProfileImportResult::ProfileCreated { profile, .. } => profile.id,
            other => panic!("expected profile_created, got {other:?}"),
        }
    }

    /// Build a `BfProfilePayload` from a share in `bundle`. The `profile_id`
    /// is derived from the share secret so distinct shares yield distinct
    /// profile ids — this matches the production `import_profile_from_payload`
    /// expectation.
    fn payload_for_share(bundle: &KeysetBundle, share_idx: usize) -> BfProfilePayload {
        let share = &bundle.shares[share_idx];
        let profile_id =
            crate::derive_profile_id_for_share_secret(&hex::encode(share.seckey.expose_bytes()))
                .expect("derive profile id");
        BfProfilePayload {
            profile_id,
            version: 1,
            device: BfProfileDevice {
                name: format!("device-{}", share.idx),
                share_secret: hex::encode(share.seckey.expose_bytes()),
                manual_peer_policy_overrides: Vec::new(),
                relays: vec!["ws://127.0.0.1:8194".to_string()],
            },
            group_package: GroupPackageWire::from(bundle.group.clone()),
        }
    }

    #[test]
    fn rotation_intent_cleaned_up_on_success() {
        // Full E2E rotation: import shares[0] as the original profile, then
        // rotate to a new "rotated" profile derived from shares[1]. Both
        // share the same group_pk because they come from the same bundle.
        let paths = test_paths("clean-success");
        let bundle =
            create_keyset(CreateKeysetConfig::new("Rotation Test", 2, 3)).expect("create keyset");
        let target_id = import_target_profile(&paths, &bundle);
        let target = crate::FilesystemProfileManifestStore::new(&paths.profiles_dir)
            .read_profile(&target_id)
            .expect("read target profile");

        let target_payload = payload_for_share(&bundle, 0);
        let rotated_payload = payload_for_share(&bundle, 1);
        let rotated_group = bundle.group.clone();

        let result = finalize_rotation_update_import(
            &paths,
            &target,
            target_payload,
            &rotated_group,
            rotated_payload,
            Some(Passphrase::new("rotation-test-passphrase".to_string())),
        )
        .expect("rotation should succeed");

        // No intent file should remain after a successful rotation.
        let intent_path = paths.rotations_dir.join(&target.id).join(".intent.json");
        assert!(
            !intent_path.exists(),
            "intent file must be deleted after success: {}",
            intent_path.display()
        );

        // scan should find nothing to warn about.
        let incomplete = scan_rotation_intents(&paths).expect("scan");
        assert!(
            incomplete.is_empty(),
            "no incomplete intents expected, got {incomplete:?}"
        );

        // The migrated profile should be present and the target removed.
        match result {
            ProfileImportResult::ProfileCreated {
                profile: migrated, ..
            } => {
                let manifest_store =
                    crate::FilesystemProfileManifestStore::new(&paths.profiles_dir);
                assert!(
                    manifest_store.read_profile(&migrated.id).is_ok(),
                    "migrated profile manifest must be present"
                );
                assert!(
                    manifest_store.read_profile(&target_id).is_err(),
                    "target profile manifest must be removed"
                );
            }
            other => panic!("expected ProfileCreated, got {other:?}"),
        }

        let _ = fs::remove_dir_all(paths.config_dir.parent().unwrap_or(&paths.config_dir));
    }

    #[test]
    fn incomplete_rotation_intent_detected_after_partial_run() {
        // Simulate a rotation that crashed mid-flight by writing a
        // `PostCreateNewProfile` intent directly. The startup scan must
        // return it.
        let paths = test_paths("incomplete");
        paths.ensure().expect("ensure paths");

        let mut intent = RotationIntent::new(
            "ws-crashed",
            super::super::rotation_intent::RotationKind::RotateShare,
            "prof-orig",
        );
        intent.advance(RotationStep::PostCreateNewProfile);
        write_intent(&paths, &intent).expect("seed crashed-rotation intent");

        let incomplete = scan_rotation_intents(&paths).expect("scan");
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].workspace_id, "ws-crashed");
        assert_eq!(incomplete[0].step, RotationStep::PostCreateNewProfile);

        let _ = fs::remove_dir_all(paths.config_dir.parent().unwrap_or(&paths.config_dir));
    }
}
