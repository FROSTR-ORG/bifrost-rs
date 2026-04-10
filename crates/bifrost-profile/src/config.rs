use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellConfig {
    pub schema_version: u32,
    pub default_relay_profile_id: Option<String>,
    pub last_used_profile_id: Option<String>,
    #[serde(default)]
    pub keyring_preference: KeyringPreference,
    #[serde(default)]
    pub fallback_unlock_mode: FallbackUnlockMode,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            default_relay_profile_id: None,
            last_used_profile_id: None,
            keyring_preference: KeyringPreference::PreferOsKeyring,
            fallback_unlock_mode: FallbackUnlockMode::Passphrase,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyringPreference {
    #[default]
    PreferOsKeyring,
    PassphraseOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FallbackUnlockMode {
    #[default]
    Passphrase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayProfile {
    pub id: String,
    pub label: String,
    pub relays: Vec<String>,
}

pub fn validate_relay_profile(profile: &RelayProfile) -> Result<()> {
    if profile.id.trim().is_empty() {
        bail!("relay profile id must be non-empty");
    }
    if profile.label.trim().is_empty() {
        bail!("relay profile label must be non-empty");
    }
    if profile.relays.is_empty() {
        bail!(
            "relay profile {} must contain at least one relay",
            profile.id
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_config_defaults_are_stable() {
        let config = ShellConfig::default();
        assert_eq!(config.schema_version, 1);
        assert_eq!(
            config.keyring_preference,
            KeyringPreference::PreferOsKeyring
        );
        assert_eq!(config.fallback_unlock_mode, FallbackUnlockMode::Passphrase);
    }

    #[test]
    fn relay_profile_requires_relays() {
        let error = validate_relay_profile(&RelayProfile {
            id: "local".to_string(),
            label: "Local".to_string(),
            relays: Vec::new(),
        })
        .expect_err("validation should fail");
        assert!(error.to_string().contains("at least one relay"));
    }
}
