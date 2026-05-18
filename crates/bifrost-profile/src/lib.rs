mod aad;
mod argon2_params;
mod config;
mod flows;
#[cfg(unix)]
pub mod fs_guard;
mod kdf;
mod models;
mod native;
mod packages;
mod paths;
mod policy;
mod state_error;
mod traits;

pub use aad::{AAD_DOMAIN_SEPARATOR, AAD_SALT_LEN, build_aad_hostlocal};
pub use argon2_params::{
    ARGON2_MAX_M_COST, ARGON2_MIN_M_COST, ARGON2_MIN_P_COST, ARGON2_MIN_T_COST, Argon2Params,
    ParamsError,
};
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
pub use kdf::{KDF_OUTPUT_LEN, KDF_SALT_LEN, derive_profile_encryption_key_v2};
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
pub use state_error::StateError;
pub use traits::{Clock, EncryptedProfileStore, ProfileManifestStore, RelayProfileStore};

/// Host-local encrypted-profile envelope version written by the writer and
/// required by the reader.
///
/// Bucket B B.1 (PR7, 2026-04-22 remediation track) flipped this from 1 to 2.
/// v1 envelopes are not readable by this crate — operators must re-onboard.
pub const ENCRYPTED_PROFILE_VERSION: u8 = 2;

/// Alias kept for call sites that want to signal the v2-specific envelope
/// shape explicitly. The crate-internal AAD builder uses this alias so the
/// version byte in the AAD stays pinned to `2` even if `ENCRYPTED_PROFILE_VERSION`
/// is later bumped to v3 (which would need a sibling AAD helper).
pub const ENCRYPTED_PROFILE_VERSION_V2: u8 = 2;

/// `kdf_id` byte identifying Argon2id in the v2 envelope header. A future
/// KDF family is signalled by bumping the envelope version, not by adding a
/// new `kdf_id` to the v2 header.
pub const KDF_ID_ARGON2ID: u8 = 1;
