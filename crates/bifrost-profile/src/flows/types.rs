use serde::Serialize;
use serde_json::Value;

use crate::{EncryptedProfileRecord, ProfileManifest};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProfileImportResult {
    ProfileCreated {
        profile: ProfileManifest,
        encrypted_profile: EncryptedProfileRecord,
        diagnostics: Option<Value>,
        warnings: Vec<String>,
    },
    OnboardingStaged {
        encrypted_profile: EncryptedProfileRecord,
        staged_onboarding: StagedOnboardingImport,
        warnings: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct StagedOnboardingImport {
    pub id: String,
    pub encrypted_profile_id: String,
    pub label: Option<String>,
    pub relay_profile: String,
    pub peer_pubkey: String,
    pub relays: Vec<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileExportResult {
    pub profile_id: String,
    pub out_dir: String,
    pub group_path: Option<String>,
    pub share_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfilePackageExportResult {
    pub profile_id: String,
    pub format: String,
    pub out_path: Option<String>,
    pub package: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileBackupPublishResult {
    pub profile_id: String,
    pub relays: Vec<String>,
    pub event_id: String,
    pub author_pubkey: String,
}
