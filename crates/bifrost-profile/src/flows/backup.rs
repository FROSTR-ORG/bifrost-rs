use anyhow::{Context, Result, anyhow, bail};
use frostr_utils::{build_profile_backup_event, create_encrypted_profile_backup};
use futures_util::{SinkExt, StreamExt};
use nostr::Event;
use serde_json::Value;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::ProfilePaths;

use super::common::{now_unix_secs, profile_to_package_payload};
use super::types::ProfileBackupPublishResult;

pub(super) async fn publish_nostr_event(relays: &[String], event: &Event) -> Result<()> {
    let event_value = serde_json::to_value(event).context("serialize nostr event")?;
    let payload = serde_json::json!(["EVENT", event_value]).to_string();
    let mut published = false;
    for relay in relays {
        let attempt = async {
            let (mut stream, _) = timeout(Duration::from_secs(3), connect_async(relay.as_str()))
                .await
                .map_err(|_| anyhow!("timed out connecting to relay"))??;
            stream.send(Message::Text(payload.clone().into())).await?;
            while let Some(message) = timeout(Duration::from_secs(3), stream.next())
                .await
                .map_err(|_| anyhow!("timed out waiting for relay acknowledgement"))?
            {
                let message = message?;
                if let Message::Text(text) = message {
                    let value: Value =
                        serde_json::from_str(&text).context("parse relay response")?;
                    if let Some(array) = value.as_array() {
                        match array.first().and_then(Value::as_str) {
                            Some("OK") => {
                                let ok = array.get(2).and_then(Value::as_bool).unwrap_or(false);
                                if !ok {
                                    bail!("relay rejected backup event");
                                }
                                return Ok(());
                            }
                            Some("NOTICE") => bail!(
                                "{}",
                                array
                                    .get(1)
                                    .and_then(Value::as_str)
                                    .unwrap_or("relay notice")
                            ),
                            _ => {}
                        }
                    }
                }
            }
            bail!("relay closed before confirming backup event")
        }
        .await;
        if attempt.is_ok() {
            published = true;
            break;
        }
    }
    if !published {
        bail!("failed to publish encrypted profile backup to configured relays");
    }
    Ok(())
}

pub(super) async fn fetch_latest_nostr_event(
    relays: &[String],
    author_pubkey: &str,
    kind: u16,
) -> Result<Event> {
    let subscription_id = format!("igloo-shell-{}", now_unix_secs());
    let filter = serde_json::json!({
        "authors": [author_pubkey],
        "kinds": [kind],
    });
    let request = serde_json::json!(["REQ", subscription_id, filter]).to_string();
    let close = serde_json::json!(["CLOSE", subscription_id]).to_string();
    let mut best: Option<Event> = None;
    for relay in relays {
        let attempt = async {
            let (mut stream, _) = connect_async(relay.as_str()).await?;
            stream.send(Message::Text(request.clone().into())).await?;
            while let Some(message) = timeout(Duration::from_secs(3), stream.next()).await? {
                let message = message?;
                if let Message::Text(text) = message {
                    let value: Value = serde_json::from_str(&text).context("parse relay event")?;
                    let Some(array) = value.as_array() else {
                        continue;
                    };
                    match array.first().and_then(Value::as_str) {
                        Some("EVENT") => {
                            if let Some(event_value) = array.get(2) {
                                let event: Event = serde_json::from_value(event_value.clone())
                                    .context("decode nostr event")?;
                                if best
                                    .as_ref()
                                    .map(|existing| event.created_at > existing.created_at)
                                    .unwrap_or(true)
                                {
                                    best = Some(event);
                                }
                            }
                        }
                        Some("EOSE") => break,
                        Some("NOTICE") => break,
                        _ => {}
                    }
                }
            }
            let _ = stream.send(Message::Text(close.clone().into())).await;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let _ = attempt;
    }
    best.ok_or_else(|| anyhow!("no encrypted profile backup was found for this share"))
}

pub async fn publish_profile_backup(
    paths: &ProfilePaths,
    profile_id: &str,
    passphrase: Option<String>,
) -> Result<ProfileBackupPublishResult> {
    let payload = profile_to_package_payload(paths, profile_id, passphrase)?;
    let backup = create_encrypted_profile_backup(&payload).context("build encrypted backup")?;
    let event = build_profile_backup_event(&payload.device.share_secret, &backup, None)
        .context("build backup event")?;
    publish_nostr_event(&payload.device.relays, &event).await?;
    Ok(ProfileBackupPublishResult {
        profile_id: profile_id.to_string(),
        relays: payload.device.relays,
        event_id: event.id.to_hex(),
        author_pubkey: event.pubkey.to_string(),
    })
}
