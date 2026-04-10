use anyhow::{Context, Result};
use frostr_utils::{
    BfProfileDevice, BfProfilePayload, decode_bfshare_package, parse_profile_backup_event,
};
use nostr::{Keys, SecretKey};

use crate::{
    ProfilePaths, ProfilePreview, derive_profile_id_for_share_secret, preview_from_profile_payload,
};

use super::backup::fetch_latest_nostr_event;
use super::imports::import_profile_from_bfprofile_payload;
use super::types::ProfileImportResult;

pub async fn preview_bfshare_recovery(
    package_raw: &str,
    package_password: String,
    label: Option<String>,
) -> Result<(ProfilePreview, BfProfilePayload)> {
    let share =
        decode_bfshare_package(package_raw, &package_password).context("decode bfshare package")?;
    let author = Keys::new(
        SecretKey::parse(&share.share_secret).context("parse bfshare share secret as nostr key")?,
    )
    .public_key()
    .to_string();
    let event = fetch_latest_nostr_event(
        &share.relays,
        &author,
        frostr_utils::PROFILE_BACKUP_EVENT_KIND,
    )
    .await?;
    let backup = parse_profile_backup_event(&event, &share.share_secret)
        .context("parse encrypted profile backup event")?;
    let payload = BfProfilePayload {
        profile_id: derive_profile_id_for_share_secret(&share.share_secret)?,
        version: backup.version,
        device: BfProfileDevice {
            name: backup.device.name,
            share_secret: share.share_secret,
            manual_peer_policy_overrides: backup.device.manual_peer_policy_overrides,
            relays: backup.device.relays,
        },
        group_package: backup.group_package,
    };
    let preview = preview_from_profile_payload(&payload, label, "bfshare")?;
    Ok((preview, payload))
}

pub async fn recover_profile_from_bfshare_value(
    paths: &ProfilePaths,
    package_raw: &str,
    package_password: String,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    let (_preview, payload) =
        preview_bfshare_recovery(package_raw, package_password, label.clone()).await?;
    import_profile_from_bfprofile_payload(paths, payload, label, relay_profile, passphrase)
}
