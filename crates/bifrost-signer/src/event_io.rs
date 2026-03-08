use k256::FieldBytes;
use k256::schnorr::SigningKey;
use nostr::Event;
use sha2::{Digest, Sha256};

use crate::Result;
use crate::util::now_unix_secs;

pub(crate) fn event_kind(event: &Event) -> Result<u64> {
    Ok(u64::from(event.kind.as_u16()))
}

pub(crate) fn event_content(event: &Event) -> Result<String> {
    Ok(event.content.clone())
}

pub(crate) fn event_pubkey_xonly(event: &Event) -> Result<String> {
    Ok(event.pubkey.to_hex())
}

pub(crate) fn build_signed_event(
    seckey: [u8; 32],
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
) -> Result<Event> {
    let created_at = now_unix_secs();

    let fb = FieldBytes::from(seckey);
    let signing_key = SigningKey::from_bytes(&fb)
        .map_err(|e| crate::SignerError::InvalidRequest(format!("invalid signing key: {e}")))?;
    let pubkey = hex::encode(signing_key.verifying_key().to_bytes());

    let preimage = serde_json::json!([0, pubkey, created_at, kind, tags, content]).to_string();
    let digest = Sha256::digest(preimage.as_bytes());
    let id = hex::encode(digest);

    let aux = [0u8; 32];
    let sig = signing_key
        .sign_raw(digest.as_slice(), &aux)
        .map_err(|e| crate::SignerError::InvalidRequest(format!("failed signing event: {e}")))?;

    serde_json::from_value(serde_json::json!({
        "id": id,
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": hex::encode(sig.to_bytes()),
    }))
    .map_err(|e| crate::SignerError::InvalidRequest(format!("build nostr event: {e}")))
}
