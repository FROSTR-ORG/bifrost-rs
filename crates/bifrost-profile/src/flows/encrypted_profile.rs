use anyhow::Result;

use crate::{EncryptedProfileRecord, EncryptedProfileStore, ProfilePaths};

use super::common::encrypted_profile_store;

pub fn read_encrypted_profile(
    paths: &ProfilePaths,
    encrypted_profile_id: &str,
) -> Result<EncryptedProfileRecord> {
    encrypted_profile_store(paths).read_encrypted_profile(encrypted_profile_id)
}

pub fn remove_encrypted_profile(paths: &ProfilePaths, encrypted_profile_id: &str) -> Result<()> {
    encrypted_profile_store(paths).remove_encrypted_profile(encrypted_profile_id)
}
