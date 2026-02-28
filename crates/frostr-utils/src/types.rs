use bifrost_core::types::{Bytes32, GroupPackage, SharePackage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateKeysetConfig {
    pub threshold: u16,
    pub count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetBundle {
    pub group: GroupPackage,
    pub shares: Vec<SharePackage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetVerificationReport {
    pub member_count: usize,
    pub threshold: u16,
    pub verified_shares: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotateKeysetRequest {
    pub threshold: u16,
    pub count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateKeysetResult {
    pub previous_group_id: Bytes32,
    pub next: KeysetBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverKeyInput {
    pub group: GroupPackage,
    pub shares: Vec<SharePackage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredKeyMaterial {
    pub signing_key32: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingPackage {
    pub share: SharePackage,
    pub peer_pk: Bytes32,
    pub relays: Vec<String>,
}
