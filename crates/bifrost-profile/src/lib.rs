mod config;
mod flows;
mod models;
mod native;
mod packages;
mod paths;
mod policy;
mod traits;

pub use config::{
    FallbackUnlockMode, KeyringPreference, RelayProfile, ShellConfig, validate_relay_profile,
};
pub use flows::{
    ProfileBackupPublishResult, ProfileExportResult, ProfileImportResult,
    ProfilePackageExportResult, StagedOnboardingImport, export_profile,
    export_profile_as_bfonboard, export_profile_as_bfprofile, export_profile_as_bfshare,
    finalize_rotation_update_import, import_profile_from_bfprofile_value,
    import_profile_from_files, preview_bfprofile_value, remove_encrypted_profile, remove_profile,
};
#[cfg(feature = "native-relay")]
pub use flows::{
    preview_bfshare_recovery, publish_profile_backup, recover_profile_from_bfshare_value,
};
pub use models::{EncryptedProfileRecord, ProfileManifest, ProfilePreview, build_profile_manifest};
pub use native::{
    FilesystemEncryptedProfileStore, FilesystemProfileDomain, FilesystemProfileManifestStore,
    FilesystemRelayProfileStore, ImportedProfileArtifacts, load_relay_profiles_file,
    load_shell_config_file, save_relay_profiles_file, save_shell_config_file,
};
pub use packages::{
    build_policy_overrides_value, derive_member_pubkey_hex, derive_profile_id_for_share_secret,
    find_member_index_for_share_secret, group_from_payload, hex_to_bytes32,
    preview_from_profile_payload, rotation_payload_from_share, share_from_payload,
};
pub use paths::ProfilePaths;
pub use policy::{
    PolicyOverrideEntry, PolicyOverridesDocument, empty_policy_overrides_document,
    empty_policy_overrides_value, parse_policy_overrides_doc,
};
pub use traits::{Clock, EncryptedProfileStore, ProfileManifestStore, RelayProfileStore};

pub const ENCRYPTED_PROFILE_VERSION: u8 = 1;
