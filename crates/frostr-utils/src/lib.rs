pub mod errors;
pub mod keyset;
pub mod profile_packages;
pub mod protocol;
pub mod recovery;
pub mod types;
pub mod verify;

pub use errors::{FrostUtilsError, FrostUtilsResult};
pub use keyset::{create_keyset, rotate_keyset_dealer};
pub use profile_packages::{
    BF_PACKAGE_IV_BYTES, BF_PACKAGE_PBKDF2_ITERATIONS, BF_PACKAGE_SALT_BYTES, BF_PACKAGE_VERSION,
    BfGroupMember, BfManualPeerPolicyOverride, BfMethodPolicy, BfMethodPolicyOverride,
    BfOnboardPayload, BfPeerPolicyOverride, BfPeerScopedPolicyProfile, BfPolicyOverrideValue,
    BfProfileDevice, BfProfileGroup, BfProfilePayload, BfRemotePeerPolicyObservation,
    BfSharePayload, EncryptedProfileBackup, EncryptedProfileBackupDevice, PREFIX_BFONBOARD,
    PREFIX_BFPROFILE, PREFIX_BFSHARE, PROFILE_BACKUP_EVENT_KIND, PROFILE_BACKUP_KEY_DOMAIN,
    PROFILE_ID_DOMAIN, ProfilePackagePair, bf_method_policy_override_to_core,
    bf_method_policy_to_core, bf_peer_scoped_policy_profile_to_core, bf_policy_override_to_core,
    build_profile_backup_event, core_method_policy_override_to_bf, core_method_policy_to_bf,
    core_peer_policy_override_to_bf, core_peer_scoped_policy_profile_to_bf,
    create_encrypted_profile_backup, create_profile_package_pair, decode_bfonboard_package,
    decode_bfprofile_package, decode_bfshare_package, decrypt_profile_backup_content,
    derive_profile_backup_conversation_key, derive_profile_id_from_share_pubkey,
    derive_profile_id_from_share_secret, encode_bfonboard_package, encode_bfprofile_package,
    encode_bfshare_package, encrypt_profile_backup_content, parse_profile_backup_event,
};
pub use protocol::{
    build_onboard_request_event, decode_onboard_response_event, ecdh_create_from_share,
    ecdh_finalize, generate_opaque_request_id, sign_create_partial, sign_finalize,
    sign_verify_partial, validate_sign_session,
};
pub use recovery::recover_key;
pub use types::{
    CreateKeysetConfig, KeysetBundle, KeysetVerificationReport, RecoverKeyInput,
    RecoveredKeyMaterial, RotateKeysetRequest, RotateKeysetResult,
};
pub use verify::{verify_group_config, verify_keyset, verify_share};
