use anyhow::Result;

use crate::{EncryptedProfileRecord, ProfileManifest, RelayProfile};

pub trait ProfileManifestStore {
    fn list_profiles(&self) -> Result<Vec<ProfileManifest>>;
    fn read_profile(&self, profile_id: &str) -> Result<ProfileManifest>;
    fn write_profile(&self, profile: &ProfileManifest) -> Result<()>;
}

pub trait RelayProfileStore {
    fn list_relay_profiles(&self) -> Result<Vec<RelayProfile>>;
    fn write_relay_profiles(&self, profiles: &[RelayProfile]) -> Result<()>;
}

pub trait EncryptedProfileStore {
    fn read_encrypted_profile(&self, encrypted_profile_id: &str) -> Result<EncryptedProfileRecord>;
    fn write_encrypted_profile(&self, record: &EncryptedProfileRecord) -> Result<()>;
}

pub trait Clock {
    fn now_unix_secs(&self) -> u64;
}
