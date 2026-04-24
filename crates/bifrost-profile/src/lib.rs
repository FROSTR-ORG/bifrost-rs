mod aad;
mod argon2_params;
mod config;
mod flows;
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

pub const ENCRYPTED_PROFILE_VERSION: u8 = 1;

/// Host-local encrypted-profile envelope version 2.
///
/// PR6 defines the constant for crate-internal use by the v2 AAD builder and
/// KDF helper. PR7 will flip `ENCRYPTED_PROFILE_VERSION` to this value and
/// wire the writer/reader over.
pub const ENCRYPTED_PROFILE_VERSION_V2: u8 = 2;

/// `kdf_id` byte identifying Argon2id in the v2 envelope header. A future
/// KDF family is signalled by bumping the envelope version, not by adding a
/// new `kdf_id` to the v2 header.
pub const KDF_ID_ARGON2ID: u8 = 1;
