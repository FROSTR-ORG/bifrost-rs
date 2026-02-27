use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[tokio::main]
async fn main() -> Result<()> {
    let relay = std::env::var("NOSTR_RELAY").unwrap_or_else(|_| "wss://relay.damus.io".to_string());
    let subscription_id = format!("example-{}", unix_seconds());

    let (mut ws, _response) = connect_async(&relay)
        .await
        .with_context(|| format!("failed to connect to relay: {relay}"))?;

    println!("Connected to relay: {relay}");

    let filter = json!({
        "kinds": [1],
        "limit": 5
    });

    let req = json!(["REQ", subscription_id, filter]);
    ws.send(Message::Text(req.to_string()))
        .await
        .context("failed to send REQ")?;

    println!("Sent REQ; waiting for events...");

    loop {
        let next_msg = timeout(Duration::from_secs(15), ws.next()).await;
        let maybe_msg = match next_msg {
            Ok(item) => item,
            Err(_) => {
                println!("Timed out waiting for relay response.");
                break;
            }
        };

        let msg = match maybe_msg {
            Some(Ok(m)) => m,
            Some(Err(e)) => return Err(e).context("websocket read error"),
            None => {
                println!("Relay closed connection.");
                break;
            }
        };

        if let Message::Text(text) = msg {
            if let Some(done) = handle_nostr_message(&text, &subscription_id)? {
                if done {
                    break;
                }
            }
        }
    }

    let close = json!(["CLOSE", subscription_id]);
    ws.send(Message::Text(close.to_string()))
        .await
        .context("failed to send CLOSE")?;

    println!("Subscription closed.");
    Ok(())
}

fn handle_nostr_message(text: &str, subscription_id: &str) -> Result<Option<bool>> {
    let parsed: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let Some(items) = parsed.as_array() else {
        return Ok(None);
    };

    let Some(kind) = items.first().and_then(|v| v.as_str()) else {
        return Ok(None);
    };

    match kind {
        "EVENT" => {
            let same_sub = items.get(1).and_then(|v| v.as_str()) == Some(subscription_id);
            if !same_sub {
                return Ok(Some(false));
            }
            let event = items.get(2).cloned().unwrap_or_default();
            let content = event
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let pubkey = event
                .get("pubkey")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");
            let created_at = event
                .get("created_at")
                .and_then(|v| v.as_i64())
                .unwrap_or_default();

            println!(
                "EVENT pubkey={} created_at={} content={}",
                shorten(pubkey),
                created_at,
                trim(content, 120)
            );
            Ok(Some(false))
        }
        "EOSE" => {
            let same_sub = items.get(1).and_then(|v| v.as_str()) == Some(subscription_id);
            if same_sub {
                println!("Received EOSE for subscription {subscription_id}");
                return Ok(Some(true));
            }
            Ok(Some(false))
        }
        "NOTICE" => {
            if let Some(notice) = items.get(1).and_then(|v| v.as_str()) {
                println!("NOTICE: {notice}");
            }
            Ok(Some(false))
        }
        _ => Ok(Some(false)),
    }
}

fn shorten(s: &str) -> String {
    if s.len() <= 16 {
        return s.to_string();
    }
    format!("{}...{}", &s[..8], &s[s.len() - 8..])
}

fn trim(s: &str, max_chars: usize) -> String {
    let mut out: String = s.chars().take(max_chars).collect();
    if s.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
