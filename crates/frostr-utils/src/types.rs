use bifrost_core::types::{Bytes32, GroupPackage, SharePackage};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateKeysetConfig {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeysetRequest {
    pub threshold: u16,
    pub count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeysetResult {
    pub previous_group_id: Bytes32,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteToken {
    pub version: u8,
    pub callback_peer_pk: Bytes32,
    pub relays: Vec<String>,
    pub challenge: Bytes32,
    pub created_at: u64,
    pub expires_at: u64,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingPackage {
    pub share: SharePackage,
    pub peer_pk: Bytes32,
    pub relays: Vec<String>,
    #[serde(default)]
    pub challenge: Option<Bytes32>,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}
