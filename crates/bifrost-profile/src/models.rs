use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::empty_policy_overrides_value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileManifest {
    pub id: String,
    pub label: String,
    pub group_ref: String,
    pub encrypted_profile_ref: String,
    pub relay_profile: String,
    #[serde(default)]
    pub runtime_options: Value,
    #[serde(default)]
    pub policy_overrides: Value,
    pub state_path: String,
    pub daemon_socket_path: String,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedProfileRecord {
    pub id: String,
    pub kind: String,
    pub source: String,
    pub ciphertext_path: String,
    pub key_source: String,
    pub salt_hex: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfilePreview {
    pub profile_id: String,
    pub label: String,
    pub share_public_key: String,
    pub group_public_key: String,
    pub threshold: usize,
    pub total_count: usize,
    pub relays: Vec<String>,
    pub peer_pubkey: Option<String>,
    pub source: &'static str,
}

pub fn build_profile_manifest(
    profile_id: &str,
    label: String,
    group_ref: String,
    encrypted_profile_ref: String,
    relay_profile: String,
    state_path: String,
    daemon_socket_path: String,
    created_at: u64,
) -> ProfileManifest {
    ProfileManifest {
        id: profile_id.to_string(),
        label,
        group_ref,
        encrypted_profile_ref,
        relay_profile,
        runtime_options: Value::Null,
        policy_overrides: empty_policy_overrides_value(),
        state_path,
        daemon_socket_path,
        created_at,
        last_used_at: Some(created_at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_profile_manifest_sets_default_policy_document() {
        let manifest = build_profile_manifest(
            "profile-1",
            "Profile".to_string(),
            "group.json".to_string(),
            "encrypted-profile-1".to_string(),
            "local".to_string(),
            "state.bin".to_string(),
            "daemon.sock".to_string(),
            42,
        );

        assert_eq!(manifest.id, "profile-1");
        assert_eq!(manifest.policy_overrides["default_override"], Value::Null);
        assert_eq!(
            manifest.policy_overrides["peer_overrides"],
            serde_json::json!([])
        );
    }
}
