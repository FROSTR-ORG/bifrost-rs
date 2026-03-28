use bifrost_core::types::{Bytes32, GroupPackage, SharePackage};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateKeysetConfig {
    pub group_name: String,
    pub threshold: u16,
    pub count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeysetRequest {
    pub shares: Vec<SharePackage>,
    pub threshold: u16,
    pub count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeysetResult {
    pub previous_group_id: Bytes32,
    pub next_group_id: Bytes32,
    pub next: KeysetBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverKeyInput {
    pub group: GroupPackage,
    pub shares: Vec<SharePackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredKeyMaterial {
    pub signing_key32: Bytes32,
}
