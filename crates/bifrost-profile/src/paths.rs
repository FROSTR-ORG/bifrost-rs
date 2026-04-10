use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};

#[derive(Debug, Clone)]
pub struct ProfilePaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub profiles_dir: PathBuf,
    pub groups_dir: PathBuf,
    pub encrypted_profiles_dir: PathBuf,
    pub state_profiles_dir: PathBuf,
    pub rotations_dir: PathBuf,
    pub config_path: PathBuf,
    pub relay_profiles_path: PathBuf,
    pub imports_dir: PathBuf,
}

impl ProfilePaths {
    pub fn resolve() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is not set"))?;

        let config_root = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let data_root = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local").join("share"));
        let state_root = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local").join("state"));

        Ok(Self::from_roots(config_root, data_root, state_root))
    }

    pub fn from_roots(config_root: PathBuf, data_root: PathBuf, state_root: PathBuf) -> Self {
        let config_dir = config_root.join("igloo-shell");
        let data_dir = data_root.join("igloo-shell");
        let state_dir = state_root.join("igloo-shell");

        Self {
            profiles_dir: config_dir.join("profiles"),
            groups_dir: data_dir.join("groups"),
            encrypted_profiles_dir: data_dir.join("encrypted-profiles"),
            state_profiles_dir: state_dir.join("profiles"),
            rotations_dir: state_dir.join("rotations"),
            config_path: config_dir.join("config.json"),
            relay_profiles_path: config_dir.join("relay-profiles.json"),
            imports_dir: data_dir.join("imports"),
            config_dir,
            data_dir,
            state_dir,
        }
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [
            &self.config_dir,
            &self.data_dir,
            &self.state_dir,
            &self.profiles_dir,
            &self.groups_dir,
            &self.encrypted_profiles_dir,
            &self.imports_dir,
            &self.state_profiles_dir,
            &self.rotations_dir,
        ] {
            fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        Ok(())
    }

    pub fn profile_path(&self, profile_id: &str) -> PathBuf {
        self.profiles_dir.join(format!("{profile_id}.json"))
    }

    pub fn profile_state_dir(&self, profile_id: &str) -> PathBuf {
        self.state_profiles_dir.join(profile_id)
    }

    pub fn daemon_metadata_path(&self, profile_id: &str) -> PathBuf {
        self.profile_state_dir(profile_id).join("daemon.json")
    }

    pub fn daemon_log_path(&self, profile_id: &str) -> PathBuf {
        self.profile_state_dir(profile_id).join("daemon.log")
    }

    pub fn encrypted_profile_metadata_path(&self, encrypted_profile_id: &str) -> PathBuf {
        self.encrypted_profiles_dir
            .join(format!("{encrypted_profile_id}.json"))
    }

    pub fn encrypted_profile_ciphertext_path(&self, encrypted_profile_id: &str) -> PathBuf {
        self.encrypted_profiles_dir
            .join(format!("{encrypted_profile_id}.enc"))
    }
}
