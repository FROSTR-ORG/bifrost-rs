use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, interval};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    #[serde(default)]
    pub ids: Option<Vec<String>>,
    #[serde(default)]
    pub authors: Option<Vec<String>>,
    #[serde(default)]
    pub kinds: Option<Vec<u64>>,
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEvent {
    pub content: String,
    pub created_at: u64,
    pub id: String,
    pub kind: u64,
    pub pubkey: String,
    pub sig: String,
    pub tags: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
struct Subscription {
    client_id: u64,
    sub_id: String,
    filters: Vec<EventFilter>,
}

#[derive(Debug)]
struct RelayState {
    cache: Vec<SignedEvent>,
    subscriptions: HashMap<String, Subscription>,
    clients: HashMap<u64, mpsc::UnboundedSender<Message>>,
    conn: usize,
    next_client_id: u64,
}

impl RelayState {
    fn new() -> Self {
        Self {
            cache: Vec::new(),
            subscriptions: HashMap::new(),
            clients: HashMap::new(),
            conn: 0,
            next_client_id: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NostrRelay {
    pub host: String,
    pub port: u16,
    pub purge_interval_secs: Option<u64>,
    state: Arc<Mutex<RelayState>>,
}

impl NostrRelay {
    pub fn new(host: impl Into<String>, port: u16, purge_interval_secs: Option<u64>) -> Self {
        Self {
            host: host.into(),
            port,
            purge_interval_secs,
            state: Arc::new(Mutex::new(RelayState::new())),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("bind relay {addr}"))?;

        if let Some(purge_secs) = self.purge_interval_secs {
            let state = self.state.clone();
            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(purge_secs));
                loop {
                    ticker.tick().await;
                    let mut guard = state.lock().await;
                    guard.cache.clear();
                }
            });
        }

        loop {
            let (stream, _) = listener.accept().await.context("accept ws client")?;
            let relay = self.clone();
            tokio::spawn(async move {
                if let Err(err) = relay.handle_client(stream).await {
                    tracing::debug!(domain = "relay", event = "client_ended", error = %err);
                }
            });
        }
    }

    async fn handle_client(&self, stream: TcpStream) -> Result<()> {
        let ws = accept_async(stream).await.context("ws accept")?;
        let (mut writer, mut reader) = ws.split();

        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        let client_id = {
            let mut state = self.state.lock().await;
            let id = state.next_client_id;
            state.next_client_id = state.next_client_id.saturating_add(1);
            state.conn = state.conn.saturating_add(1);
            state.clients.insert(id, tx);
            id
        };

        let writer_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if writer.send(msg).await.is_err() {
                    break;
                }
            }
        });

        while let Some(frame) = reader.next().await {
            match frame {
                Ok(Message::Text(text)) => {
                    self.handle_text(client_id, text.as_ref()).await;
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }

        writer_task.abort();
        self.cleanup_client(client_id).await;
        Ok(())
    }

    async fn cleanup_client(&self, client_id: u64) {
        let mut state = self.state.lock().await;
        state.clients.remove(&client_id);
        state.conn = state.conn.saturating_sub(1);

        let remove_ids: Vec<String> = state
            .subscriptions
            .iter()
            .filter_map(|(k, v)| {
                if v.client_id == client_id {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for key in remove_ids {
            state.subscriptions.remove(&key);
        }
    }

    async fn handle_text(&self, client_id: u64, text: &str) {
        let parsed: Result<Value, _> = serde_json::from_str(text);
        let Ok(Value::Array(parts)) = parsed else {
            self.send_notice(client_id, "Unable to parse message").await;
            return;
        };

        let Some(Value::String(verb)) = parts.first() else {
            self.send_notice(client_id, "Unable to parse message").await;
            return;
        };

        match verb.as_str() {
            "REQ" => self.handle_req(client_id, &parts).await,
            "EVENT" => self.handle_event(client_id, &parts).await,
            "CLOSE" => self.handle_close(client_id, &parts).await,
            _ => {
                self.send_notice(client_id, "Unable to handle message")
                    .await
            }
        }
    }

    async fn handle_req(&self, client_id: u64, parts: &[Value]) {
        let Some(Value::String(sub_id)) = parts.get(1) else {
            self.send_notice(client_id, "Invalid REQ").await;
            return;
        };

        let filters = if parts.len() == 3 {
            if let Some(Value::Array(items)) = parts.get(2) {
                items
                    .iter()
                    .filter_map(|v| serde_json::from_value::<EventFilter>(v.clone()).ok())
                    .collect::<Vec<_>>()
            } else {
                parts[2..]
                    .iter()
                    .filter_map(|v| serde_json::from_value::<EventFilter>(v.clone()).ok())
                    .collect::<Vec<_>>()
            }
        } else {
            parts[2..]
                .iter()
                .filter_map(|v| serde_json::from_value::<EventFilter>(v.clone()).ok())
                .collect::<Vec<_>>()
        };

        if filters.is_empty() {
            self.send_notice(client_id, "Invalid REQ filters").await;
            return;
        }

        let (events, sender) = {
            let mut state = self.state.lock().await;
            let key = format!("{client_id}/{sub_id}");
            state.subscriptions.insert(
                key,
                Subscription {
                    client_id,
                    sub_id: sub_id.clone(),
                    filters: filters.clone(),
                },
            );

            let cache = state.cache.clone();
            let sender = state.clients.get(&client_id).cloned();
            (cache, sender)
        };

        if let Some(tx) = sender {
            for filter in &filters {
                let mut remaining = filter.limit;
                for event in &events {
                    let allow = remaining.map(|r| r > 0).unwrap_or(true);
                    if !allow {
                        break;
                    }
                    if match_filter(event, filter) {
                        let msg = json!(["EVENT", sub_id, event]);
                        let _ = tx.send(Message::Text(msg.to_string()));
                        if let Some(rem) = remaining.as_mut() {
                            *rem = rem.saturating_sub(1);
                        }
                    }
                }
            }
            let _ = tx.send(Message::Text(json!(["EOSE", sub_id]).to_string()));
        }
    }

    async fn handle_close(&self, client_id: u64, parts: &[Value]) {
        let Some(Value::String(sub_id)) = parts.get(1) else {
            self.send_notice(client_id, "Invalid CLOSE").await;
            return;
        };

        let key = format!("{client_id}/{sub_id}");
        let mut state = self.state.lock().await;
        state.subscriptions.remove(&key);
    }

    async fn handle_event(&self, client_id: u64, parts: &[Value]) {
        let Some(event_value) = parts.get(1) else {
            self.send_notice(client_id, "Invalid EVENT").await;
            return;
        };

        let Ok(event) = serde_json::from_value::<SignedEvent>(event_value.clone()) else {
            self.send_notice(client_id, "Unable to parse message").await;
            return;
        };

        if !verify_event(&event) {
            self.send_ok(client_id, &event.id, false, "event failed validation")
                .await;
            return;
        }

        self.send_ok(client_id, &event.id, true, "").await;

        let (subs, clients) = {
            let mut state = self.state.lock().await;
            state.cache.push(event.clone());
            state.cache.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            (
                state.subscriptions.values().cloned().collect::<Vec<_>>(),
                state.clients.clone(),
            )
        };

        for sub in subs {
            let matches = sub.filters.iter().any(|f| match_filter(&event, f));
            if !matches {
                continue;
            }
            if let Some(tx) = clients.get(&sub.client_id) {
                let msg = json!(["EVENT", sub.sub_id, event]);
                let _ = tx.send(Message::Text(msg.to_string()));
            }
        }
    }

    async fn send_notice(&self, client_id: u64, notice: &str) {
        let sender = {
            let state = self.state.lock().await;
            state.clients.get(&client_id).cloned()
        };
        if let Some(tx) = sender {
            let _ = tx.send(Message::Text(json!(["NOTICE", notice]).to_string()));
        }
    }

    async fn send_ok(&self, client_id: u64, event_id: &str, ok: bool, reason: &str) {
        let sender = {
            let state = self.state.lock().await;
            state.clients.get(&client_id).cloned()
        };
        if let Some(tx) = sender {
            let _ = tx.send(Message::Text(
                json!(["OK", event_id, ok, reason]).to_string(),
            ));
        }
    }
}

pub fn match_filter(event: &SignedEvent, filter: &EventFilter) -> bool {
    if let Some(ids) = &filter.ids
        && !ids.iter().any(|i| i == &event.id)
    {
        return false;
    }
    if let Some(since) = filter.since
        && event.created_at < since
    {
        return false;
    }
    if let Some(until) = filter.until
        && event.created_at > until
    {
        return false;
    }
    if let Some(authors) = &filter.authors
        && !authors.iter().any(|a| a == &event.pubkey)
    {
        return false;
    }
    if let Some(kinds) = &filter.kinds
        && !kinds.contains(&event.kind)
    {
        return false;
    }

    let tag_filters = filter
        .extra
        .iter()
        .filter_map(|(key, value)| {
            if !key.starts_with('#') {
                return None;
            }
            let arr = value.as_array()?;
            let terms = arr
                .iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect::<Vec<_>>();
            let mut out = vec![key.trim_start_matches('#').to_string()];
            out.extend(terms);
            Some(out)
        })
        .collect::<Vec<_>>();

    if tag_filters.is_empty() {
        return true;
    }
    match_tags(&tag_filters, &event.tags)
}

pub fn match_tags(filters: &[Vec<String>], tags: &[Vec<String>]) -> bool {
    for filter in filters {
        let Some((key, terms)) = filter.split_first() else {
            continue;
        };
        let mut matched_key = false;
        let mut matched_terms = false;
        for tag in tags {
            let Some((tag_key, params)) = tag.split_first() else {
                continue;
            };
            if tag_key == key {
                matched_key = true;
                if terms.iter().all(|term| params.iter().any(|p| p == term)) {
                    matched_terms = true;
                    break;
                }
            }
        }
        if !matched_key || !matched_terms {
            return false;
        }
    }
    true
}

pub fn verify_event(event: &SignedEvent) -> bool {
    let preimage = json!([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content
    ])
    .to_string();

    let digest = Sha256::digest(preimage.as_bytes());
    let digest_hex = hex::encode(digest);
    if digest_hex != event.id {
        return false;
    }

    let sig_bytes = match hex::decode(&event.sig) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let id_bytes = match hex::decode(&event.id) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let pubkey_bytes = match hex::decode(&event.pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let signature = match Signature::try_from(sig_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };

    verifying_key.verify_raw(&id_bytes, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use k256::schnorr::SigningKey;
    use rand_core::OsRng;
    use sha2::Digest;

    use super::{EventFilter, SignedEvent, match_filter, match_tags, verify_event};

    #[test]
    fn verify_event_accepts_valid_signature() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        let pubkey_hex = hex::encode(vk.to_bytes());

        let tags = vec![vec!["p".to_string(), "abcdef".to_string()]];
        let content = "hello".to_string();
        let created_at = 1_700_000_000u64;
        let kind = 1u64;

        let preimage =
            serde_json::json!([0, pubkey_hex, created_at, kind, tags, content]).to_string();
        let digest = sha2::Sha256::digest(preimage.as_bytes());
        let digest_hex = hex::encode(digest);

        let aux = [0u8; 32];
        let sig = sk.sign_raw(digest.as_slice(), &aux).expect("sign_raw");
        let sig_hex = hex::encode(sig.to_bytes());

        let event = SignedEvent {
            content: "hello".to_string(),
            created_at,
            id: digest_hex,
            kind,
            pubkey: pubkey_hex,
            sig: sig_hex,
            tags: vec![vec!["p".to_string(), "abcdef".to_string()]],
        };

        assert!(verify_event(&event));
    }

    #[test]
    fn filter_matches_kind_author_and_tag() {
        let event = SignedEvent {
            content: "x".to_string(),
            created_at: 10,
            id: "11".repeat(32),
            kind: 7,
            pubkey: "22".repeat(32),
            sig: "33".repeat(64),
            tags: vec![vec!["p".to_string(), "friend".to_string()]],
        };

        let mut filter = EventFilter {
            ids: None,
            authors: Some(vec!["22".repeat(32)]),
            kinds: Some(vec![7]),
            since: Some(1),
            until: Some(99),
            limit: None,
            extra: std::collections::HashMap::new(),
        };
        filter
            .extra
            .insert("#p".to_string(), serde_json::json!(["friend"]));

        assert!(match_filter(&event, &filter));
    }

    #[test]
    fn tag_filters_require_matching_tag_key() {
        let filters = vec![vec!["e".to_string(), "deadbeef".to_string()]];
        let tags = vec![vec!["p".to_string(), "deadbeef".to_string()]];
        assert!(!match_tags(&filters, &tags));
    }
}
