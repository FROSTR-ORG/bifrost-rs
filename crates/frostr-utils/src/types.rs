use bifrost_core::secret::RecoveredSigningKey;
use bifrost_core::types::{Bytes32, GroupPackage, SharePackage};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateKeysetConfig {
    pub group_name: String,
    pub threshold: u16,
    pub count: u16,
    #[serde(default)]
    pub signing_key32: Option<Bytes32>,
}

impl CreateKeysetConfig {
    /// Construct a config that generates a fresh signing key.
    ///
    /// Optional generation inputs (such as an existing signing key) default to
    /// `None`, so adding further optional fields here does not churn call sites.
    pub fn new(group_name: impl Into<String>, threshold: u16, count: u16) -> Self {
        Self {
            group_name: group_name.into(),
            threshold,
            count,
            signing_key32: None,
        }
    }
}

// Serde intentionally dropped: these types transitively contain
// `SharePackage`, whose hard-cut lives strictly behind `SharePackageWire`.
// Callers that need a wire form build an explicit DTO (see
// `bifrost-bridge-wasm::RotateKeysetBundleInput`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetBundle {
    pub group: GroupPackage,
    pub shares: Vec<SharePackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetVerificationReport {
    pub member_count: usize,
    pub threshold: u16,
    pub verified_shares: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateKeysetRequest {
    pub shares: Vec<SharePackage>,
    pub threshold: u16,
    pub count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateKeysetResult {
    pub previous_group_id: Bytes32,
    pub next_group_id: Bytes32,
    pub next: KeysetBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverKeyInput {
    pub group: GroupPackage,
    pub shares: Vec<SharePackage>,
}

// Holds reconstructed Nostr signing material. Not a wire-crossing type:
// it is a short-lived return value from `recovery::recover_key` consumed
// inside `frostr-utils::keyset`. Serde intentionally omitted; the inner
// signing key bytes live inside `RecoveredSigningKey`, which zeroizes on
// drop and redacts in `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredKeyMaterial {
    pub signing_key32: RecoveredSigningKey,
}
