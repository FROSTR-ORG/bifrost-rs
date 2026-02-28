pub mod errors;
pub mod keyset;
pub mod onboarding;
pub mod protocol;
pub mod recovery;
pub mod types;
pub mod verify;

pub use errors::{FrostUtilsError, FrostUtilsResult};
pub use keyset::{create_keyset, rotate_keyset_dealer};
pub use onboarding::{
    build_onboarding_package, decode_onboarding_package, deserialize_onboarding_data,
    encode_onboarding_package, serialize_onboarding_data,
};
pub use protocol::{
    ecdh_create_from_share, ecdh_finalize, sign_create_partial, sign_finalize, sign_verify_partial,
    validate_sign_session,
};
pub use recovery::recover_key;
pub use types::{
    CreateKeysetConfig, KeysetBundle, KeysetVerificationReport, OnboardingPackage, RecoverKeyInput,
    RecoveredKeyMaterial, RotateKeysetRequest, RotateKeysetResult,
};
pub use verify::{verify_group_config, verify_keyset, verify_share};
