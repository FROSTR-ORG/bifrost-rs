use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use bifrost_codec::rpc::{decode_envelope, encode_envelope};
use bifrost_transport::{
    IncomingMessage, OutgoingMessage, ResponseHandle, Transport, TransportError, TransportResult,
};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use futures_util::stream::FuturesUnordered;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use k256::ecdh::diffie_hellman;
use k256::schnorr::SigningKey;
use k256::{FieldBytes, PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionState {
    Disconnected = 0,
    Connecting = 1,
    Backoff = 2,
    Connected = 3,
    Closing = 4,
}

#[derive(Debug, Clone, Copy)]
pub struct WsTransportConfig {
    pub max_retries: u32,
    pub backoff_initial_ms: u64,
    pub backoff_max_ms: u64,
    pub rpc_kind: u64,
}

impl Default for WsTransportConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_initial_ms: 250,
            backoff_max_ms: 5_000,
            rpc_kind: 20_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WsNostrConfig {
    pub sender_pubkey33: String,
    pub sender_seckey32: [u8; 32],
    pub peer_pubkeys33: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RelayHealth {
    pub successes: u64,
    pub failures: u64,
    pub last_success_unix: Option<u64>,
    pub last_failure_unix: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedEvent {
    content: String,
    created_at: u64,
    id: String,
    kind: u64,
    pubkey: String,
    sig: String,
    tags: Vec<Vec<String>>,
}

#[derive(Debug)]
struct PendingRequest {
    expected_peer: String,
    request_id: String,
    tx: oneshot::Sender<IncomingMessage>,
}

#[derive(Debug)]
pub struct WebSocketTransport {
    relays: Vec<String>,
    config: WsTransportConfig,
    nostr: WsNostrConfig,
    connected: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
    active_relay: Arc<Mutex<Option<String>>>,
    relay_health: Arc<Mutex<HashMap<String, RelayHealth>>>,
    outbound_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Message>>>>,
    inbound_rx: Mutex<mpsc::UnboundedReceiver<IncomingMessage>>,
    inbound_tx: mpsc::UnboundedSender<IncomingMessage>,
    pending: Arc<Mutex<HashMap<String, PendingRequest>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl WebSocketTransport {
    pub fn new(relays: Vec<String>, nostr: WsNostrConfig) -> Self {
        Self::with_config(relays, WsTransportConfig::default(), nostr)
    }

    pub fn with_config(
        relays: Vec<String>,
        config: WsTransportConfig,
        nostr: WsNostrConfig,
    ) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let relay_health = relays
            .iter()
            .cloned()
            .map(|relay| (relay, RelayHealth::default()))
            .collect();
        Self {
            relays,
            config,
            nostr,
            connected: Arc::new(AtomicBool::new(false)),
            state: Arc::new(AtomicU8::new(ConnectionState::Disconnected as u8)),
            active_relay: Arc::new(Mutex::new(None)),
            relay_health: Arc::new(Mutex::new(relay_health)),
            outbound_tx: Arc::new(Mutex::new(None)),
            inbound_rx: Mutex::new(inbound_rx),
            inbound_tx,
            pending: Arc::new(Mutex::new(HashMap::new())),
            tasks: Mutex::new(Vec::new()),
        }
    }

    pub fn state(&self) -> ConnectionState {
        match self.state.load(Ordering::Relaxed) {
            1 => ConnectionState::Connecting,
            2 => ConnectionState::Backoff,
            3 => ConnectionState::Connected,
            4 => ConnectionState::Closing,
            _ => ConnectionState::Disconnected,
        }
    }

    pub async fn active_relay(&self) -> Option<String> {
        self.active_relay.lock().await.clone()
    }

    pub async fn relay_health_snapshot(&self) -> HashMap<String, RelayHealth> {
        self.relay_health.lock().await.clone()
    }

    fn set_state(&self, state: ConnectionState) {
        self.state.store(state as u8, Ordering::Relaxed);
    }

    fn ensure_connected(&self) -> TransportResult<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TransportError::NotConnected);
        }
        Ok(())
    }

    fn backoff_ms(&self, attempt: u32) -> u64 {
        let mult = 1u64.checked_shl(attempt.min(20)).unwrap_or(u64::MAX);
        self.config
            .backoff_initial_ms
            .saturating_mul(mult)
            .min(self.config.backoff_max_ms)
    }

    fn now_unix_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn local_xonly_pubkey_hex(&self) -> TransportResult<String> {
        let fb = FieldBytes::from(self.nostr.sender_seckey32);
        let sk = SigningKey::from_bytes(&fb)
            .map_err(|e| TransportError::Backend(format!("invalid sender seckey: {e}")))?;
        Ok(hex::encode(sk.verifying_key().to_bytes()))
    }

    fn local_pubkey33_hex(&self) -> TransportResult<String> {
        let sk = SecretKey::from_slice(&self.nostr.sender_seckey32)
            .map_err(|e| TransportError::Backend(format!("invalid sender seckey: {e}")))?;
        Ok(hex::encode(sk.public_key().to_sec1_bytes()))
    }

    fn peer33_to_xonly(peer: &str) -> Option<String> {
        if peer.len() != 66 {
            return None;
        }
        let prefix = &peer[..2];
        if prefix != "02" && prefix != "03" {
            return None;
        }
        Some(peer[2..].to_string())
    }

    fn event_mentions_recipient(tags: &[Vec<String>], recipient_xonly: &str) -> bool {
        tags.iter().any(|t| {
            t.first().map(String::as_str) == Some("p")
                && t.get(1).map(String::as_str) == Some(recipient_xonly)
        })
    }

    fn tag_value<'a>(tags: &'a [Vec<String>], key: &str) -> Option<&'a str> {
        for tag in tags {
            if tag.first().map(String::as_str) == Some(key)
                && let Some(value) = tag.get(1)
            {
                return Some(value.as_str());
            }
        }
        None
    }

    fn pending_key(request_id: &str, expected_peer: &str) -> String {
        format!("{request_id}|{expected_peer}")
    }

    fn threshold_unreachable(
        successes: usize,
        attempted: usize,
        total: usize,
        required: usize,
    ) -> bool {
        let remaining = total.saturating_sub(attempted);
        successes.saturating_add(remaining) < required
    }

    async fn relay_order(&self) -> Vec<String> {
        let health = self.relay_health.lock().await;
        let mut ordered: Vec<(String, RelayHealth)> = self
            .relays
            .iter()
            .cloned()
            .map(|relay| {
                let stats = health.get(&relay).cloned().unwrap_or_default();
                (relay, stats)
            })
            .collect();

        ordered.sort_by(|a, b| {
            a.1.failures
                .cmp(&b.1.failures)
                .then_with(|| b.1.successes.cmp(&a.1.successes))
                .then_with(|| a.0.cmp(&b.0))
        });

        ordered.into_iter().map(|(relay, _)| relay).collect()
    }

    async fn mark_relay_success(&self, relay: &str) {
        let mut health = self.relay_health.lock().await;
        let entry = health.entry(relay.to_string()).or_default();
        entry.successes = entry.successes.saturating_add(1);
        entry.last_success_unix = Some(Self::now_unix_seconds());
        entry.last_error = None;
    }

    async fn mark_relay_failure(&self, relay: &str, err: &str) {
        let mut health = self.relay_health.lock().await;
        let entry = health.entry(relay.to_string()).or_default();
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure_unix = Some(Self::now_unix_seconds());
        entry.last_error = Some(err.to_string());
    }

    async fn mark_disconnected(
        active_relay: Arc<Mutex<Option<String>>>,
        outbound_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Message>>>>,
        pending: Arc<Mutex<HashMap<String, PendingRequest>>>,
        connected: Arc<AtomicBool>,
        state: Arc<AtomicU8>,
    ) {
        connected.store(false, Ordering::Relaxed);
        state.store(ConnectionState::Disconnected as u8, Ordering::Relaxed);

        {
            let mut active = active_relay.lock().await;
            *active = None;
        }

        {
            let mut outbound = outbound_tx.lock().await;
            *outbound = None;
        }

        {
            let mut pending_map = pending.lock().await;
            pending_map.clear();
        }
    }

    fn event_shared_x(&self, peer_pubkey33: &str) -> TransportResult<[u8; 32]> {
        let peer_bytes = hex::decode(peer_pubkey33)
            .map_err(|e| TransportError::Backend(format!("invalid peer pubkey hex: {e}")))?;
        if peer_bytes.len() != 33 {
            return Err(TransportError::Backend(
                "peer pubkey must be 33 bytes compressed hex".to_string(),
            ));
        }
        let peer_pk = PublicKey::from_sec1_bytes(&peer_bytes)
            .map_err(|e| TransportError::Backend(format!("invalid peer pubkey: {e}")))?;
        let local_sk = SecretKey::from_slice(&self.nostr.sender_seckey32)
            .map_err(|e| TransportError::Backend(format!("invalid sender seckey: {e}")))?;
        let shared = diffie_hellman(local_sk.to_nonzero_scalar(), peer_pk.as_affine());

        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }

    fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> TransportResult<[u8; 32]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(salt)
            .map_err(|e| TransportError::Backend(format!("hkdf extract init failed: {e}")))?;
        mac.update(ikm);
        let out = mac.finalize().into_bytes();
        let mut prk = [0u8; 32];
        prk.copy_from_slice(&out);
        Ok(prk)
    }

    fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> TransportResult<Vec<u8>> {
        let mut okm = Vec::with_capacity(len);
        let mut t = Vec::<u8>::new();
        let mut counter: u8 = 1;
        while okm.len() < len {
            let mut mac = Hmac::<Sha256>::new_from_slice(prk)
                .map_err(|e| TransportError::Backend(format!("hkdf expand init failed: {e}")))?;
            mac.update(&t);
            mac.update(info);
            mac.update(&[counter]);
            t = mac.finalize().into_bytes().to_vec();
            let remaining = len - okm.len();
            if t.len() <= remaining {
                okm.extend_from_slice(&t);
            } else {
                okm.extend_from_slice(&t[..remaining]);
            }
            counter = counter.saturating_add(1);
            if counter == 0 {
                return Err(TransportError::Backend("hkdf expand overflow".to_string()));
            }
        }
        Ok(okm)
    }

    fn get_conversation_key(shared_x: &[u8; 32]) -> TransportResult<[u8; 32]> {
        Self::hkdf_extract_sha256(b"nip44-v2", shared_x)
    }

    fn get_message_keys(
        conversation_key: &[u8; 32],
        nonce32: &[u8; 32],
    ) -> TransportResult<([u8; 32], [u8; 12], [u8; 32])> {
        let keys = Self::hkdf_expand_sha256(conversation_key, nonce32, 76)?;
        let mut chacha_key = [0u8; 32];
        let mut chacha_nonce = [0u8; 12];
        let mut hmac_key = [0u8; 32];
        chacha_key.copy_from_slice(&keys[0..32]);
        chacha_nonce.copy_from_slice(&keys[32..44]);
        hmac_key.copy_from_slice(&keys[44..76]);
        Ok((chacha_key, chacha_nonce, hmac_key))
    }

    fn calc_padded_len(unpadded_len: usize) -> TransportResult<usize> {
        if unpadded_len == 0 {
            return Err(TransportError::Backend(
                "invalid plaintext size: must be between 1 and 65535 bytes".to_string(),
            ));
        }
        if unpadded_len <= 32 {
            return Ok(32);
        }
        let next_power = 1usize << ((usize::BITS - (unpadded_len - 1).leading_zeros()) as usize);
        let chunk = if next_power <= 256 {
            32
        } else {
            next_power / 8
        };
        Ok(chunk * (((unpadded_len - 1) / chunk) + 1))
    }

    fn pad_message(plaintext: &str) -> TransportResult<Vec<u8>> {
        let unpadded = plaintext.as_bytes();
        let unpadded_len = unpadded.len();
        if unpadded_len == 0 || unpadded_len > 0xffff {
            return Err(TransportError::Backend(
                "invalid plaintext size: must be between 1 and 65535 bytes".to_string(),
            ));
        }
        let padded_len = Self::calc_padded_len(unpadded_len)?;
        let mut out = Vec::with_capacity(2 + padded_len);
        out.extend_from_slice(&(unpadded_len as u16).to_be_bytes());
        out.extend_from_slice(unpadded);
        out.resize(2 + padded_len, 0u8);
        Ok(out)
    }

    fn unpad_message(padded: &[u8]) -> TransportResult<String> {
        if padded.len() < 2 {
            return Err(TransportError::Backend("invalid padding".to_string()));
        }
        let unpadded_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
        if unpadded_len == 0 || unpadded_len > 0xffff {
            return Err(TransportError::Backend("invalid padding".to_string()));
        }
        let expect = 2 + Self::calc_padded_len(unpadded_len)?;
        if padded.len() != expect || padded.len() < 2 + unpadded_len {
            return Err(TransportError::Backend("invalid padding".to_string()));
        }
        let unpadded = &padded[2..2 + unpadded_len];
        String::from_utf8(unpadded.to_vec())
            .map_err(|e| TransportError::Backend(format!("invalid utf8 payload: {e}")))
    }

    fn hmac_aad(
        hmac_key: &[u8; 32],
        nonce32: &[u8; 32],
        ciphertext: &[u8],
    ) -> TransportResult<[u8; 32]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key)
            .map_err(|e| TransportError::Backend(format!("hmac init failed: {e}")))?;
        mac.update(nonce32);
        mac.update(ciphertext);
        let out = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&out);
        Ok(tag)
    }

    fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }

    fn encrypt_content_for_peer_with_nonce(
        &self,
        peer_pubkey33: &str,
        plaintext: &str,
        nonce32: [u8; 32],
    ) -> TransportResult<String> {
        let shared_x = self.event_shared_x(peer_pubkey33)?;
        let conversation_key = Self::get_conversation_key(&shared_x)?;
        let (chacha_key, chacha_nonce, hmac_key) =
            Self::get_message_keys(&conversation_key, &nonce32)?;

        let mut padded = Self::pad_message(plaintext)?;
        let mut chacha = ChaCha20::new((&chacha_key).into(), (&chacha_nonce).into());
        chacha.apply_keystream(&mut padded);
        let mac = Self::hmac_aad(&hmac_key, &nonce32, &padded)?;

        let mut encoded = Vec::with_capacity(1 + 32 + padded.len() + 32);
        encoded.push(2u8);
        encoded.extend_from_slice(&nonce32);
        encoded.extend_from_slice(&padded);
        encoded.extend_from_slice(&mac);

        Ok(STANDARD_NO_PAD.encode(encoded))
    }

    fn encrypt_content_for_peer(
        &self,
        peer_pubkey33: &str,
        plaintext: &str,
    ) -> TransportResult<String> {
        let mut nonce32 = [0u8; 32];
        OsRng.fill_bytes(&mut nonce32);
        self.encrypt_content_for_peer_with_nonce(peer_pubkey33, plaintext, nonce32)
    }

    fn decrypt_content_from_peer(
        &self,
        peer_pubkey33: &str,
        payload: &str,
    ) -> TransportResult<String> {
        if payload.is_empty() || payload.starts_with('#') {
            return Err(TransportError::Backend(
                "unknown encryption version".to_string(),
            ));
        }

        let plen = payload.len();
        if !(132..=87472).contains(&plen) {
            return Err(TransportError::Backend(format!(
                "invalid payload length: {plen}"
            )));
        }
        let data = STANDARD_NO_PAD
            .decode(payload.as_bytes())
            .or_else(|_| URL_SAFE_NO_PAD.decode(payload.as_bytes()))
            .map_err(|e| TransportError::Backend(format!("invalid base64: {e}")))?;
        let dlen = data.len();
        if !(99..=65603).contains(&dlen) {
            return Err(TransportError::Backend(format!(
                "invalid data length: {dlen}"
            )));
        }
        if data[0] != 2 {
            return Err(TransportError::Backend(format!(
                "unknown encryption version {}",
                data[0]
            )));
        }

        let mut nonce32 = [0u8; 32];
        nonce32.copy_from_slice(&data[1..33]);
        let ciphertext = &data[33..dlen - 32];
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[dlen - 32..]);

        let shared_x = self.event_shared_x(peer_pubkey33)?;
        let conversation_key = Self::get_conversation_key(&shared_x)?;
        let (chacha_key, chacha_nonce, hmac_key) =
            Self::get_message_keys(&conversation_key, &nonce32)?;
        let expected_mac = Self::hmac_aad(&hmac_key, &nonce32, ciphertext)?;
        if !Self::ct_eq_32(&expected_mac, &mac) {
            return Err(TransportError::Backend("invalid MAC".to_string()));
        }

        let mut padded = ciphertext.to_vec();
        let mut chacha = ChaCha20::new((&chacha_key).into(), (&chacha_nonce).into());
        chacha.apply_keystream(&mut padded);
        Self::unpad_message(&padded)
    }

    fn build_signed_event(&self, msg: &OutgoingMessage) -> TransportResult<SignedEvent> {
        let created_at = Self::now_unix_seconds();
        let envelope_json =
            encode_envelope(&msg.envelope).map_err(|e| TransportError::Codec(e.to_string()))?;
        let content = self.encrypt_content_for_peer(&msg.peer, &envelope_json)?;

        let sender_xonly = self.local_xonly_pubkey_hex()?;
        let sender_pubkey33 = self.local_pubkey33_hex()?;
        let recipient_xonly = Self::peer33_to_xonly(&msg.peer).ok_or_else(|| {
            TransportError::Backend("peer must be 33-byte compressed pubkey hex".to_string())
        })?;

        let tags = vec![
            vec!["p".to_string(), recipient_xonly],
            vec!["b".to_string(), sender_pubkey33],
        ];

        let preimage = json!([
            0,
            sender_xonly,
            created_at,
            self.config.rpc_kind,
            tags,
            content
        ])
        .to_string();
        let digest = Sha256::digest(preimage.as_bytes());
        let id = hex::encode(digest);

        let fb = FieldBytes::from(self.nostr.sender_seckey32);
        let sk = SigningKey::from_bytes(&fb)
            .map_err(|e| TransportError::Backend(format!("invalid sender seckey: {e}")))?;
        let aux = [0u8; 32];
        let sig = sk
            .sign_raw(digest.as_slice(), &aux)
            .map_err(|e| TransportError::Backend(format!("failed to sign event: {e}")))?;

        Ok(SignedEvent {
            content,
            created_at,
            id,
            kind: self.config.rpc_kind,
            pubkey: sender_xonly,
            sig: hex::encode(sig.to_bytes()),
            tags,
        })
    }

    async fn send_envelope(&self, msg: OutgoingMessage) -> TransportResult<()> {
        self.ensure_connected()?;
        let signed = self.build_signed_event(&msg)?;

        let maybe_tx = self.outbound_tx.lock().await.clone();
        let Some(tx) = maybe_tx else {
            return Err(TransportError::NotConnected);
        };

        let frame = json!(["EVENT", signed]).to_string();
        tx.send(Message::Text(frame))
            .map_err(|e| TransportError::Backend(e.to_string()))
    }

    fn build_subscribe_message(&self) -> Value {
        let mut filter = serde_json::Map::new();
        filter.insert("kinds".to_string(), json!([self.config.rpc_kind]));

        let authors = self
            .nostr
            .peer_pubkeys33
            .iter()
            .filter_map(|p| Self::peer33_to_xonly(p))
            .collect::<Vec<_>>();

        if !authors.is_empty() {
            filter.insert("authors".to_string(), json!(authors));
        }

        json!(["REQ", "bifrost-rpc", Value::Object(filter)])
    }

    fn validate_identity(&self) -> TransportResult<()> {
        let computed = self.local_pubkey33_hex()?;
        if computed != self.nostr.sender_pubkey33 {
            return Err(TransportError::Backend(
                "nostr sender_pubkey33 does not match sender_seckey32".to_string(),
            ));
        }
        Ok(())
    }

    async fn establish_connection(&self, relay: &str) -> TransportResult<()> {
        let (stream, _) = connect_async(relay)
            .await
            .map_err(|e| TransportError::Backend(e.to_string()))?;

        let (mut writer, mut reader) = stream.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

        {
            let mut guard = self.outbound_tx.lock().await;
            *guard = Some(out_tx.clone());
        }

        self.connected.store(true, Ordering::Relaxed);
        self.set_state(ConnectionState::Connected);
        {
            let mut active = self.active_relay.lock().await;
            *active = Some(relay.to_string());
        }

        let sub_msg = self.build_subscribe_message().to_string();
        out_tx
            .send(Message::Text(sub_msg))
            .map_err(|e| TransportError::Backend(e.to_string()))?;

        let inbound_tx = self.inbound_tx.clone();
        let pending = self.pending.clone();
        let outbound = self.outbound_tx.clone();
        let active_relay = self.active_relay.clone();
        let connected = self.connected.clone();
        let state = self.state.clone();
        let recipient_xonly = self.local_xonly_pubkey_hex()?;
        let rpc_kind = self.config.rpc_kind;
        let known_peers = self.nostr.peer_pubkeys33.clone();
        let decrypt_nostr = self.nostr.clone();

        let connected_writer = connected.clone();
        let state_writer = state.clone();
        let outbound_writer = outbound.clone();
        let pending_writer = pending.clone();
        let active_writer = active_relay.clone();
        let writer_task = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if let Err(err) = writer.send(msg).await {
                    warn!("websocket send failed: {}", err);
                    break;
                }
            }

            WebSocketTransport::mark_disconnected(
                active_writer,
                outbound_writer,
                pending_writer,
                connected_writer,
                state_writer,
            )
            .await;
        });

        let connected_reader = connected.clone();
        let state_reader = state.clone();
        let outbound_reader = outbound;
        let pending_reader = pending;
        let active_reader = active_relay;
        let reader_task = tokio::spawn(async move {
            let decryptor = WebSocketTransport::with_config(
                vec![],
                WsTransportConfig {
                    rpc_kind,
                    ..WsTransportConfig::default()
                },
                decrypt_nostr,
            );
            while let Some(next) = reader.next().await {
                let Ok(frame) = next else {
                    warn!("websocket read failed");
                    break;
                };

                let Message::Text(text) = frame else {
                    continue;
                };

                let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(text.as_ref()) else {
                    debug!("ignoring non-json relay frame");
                    continue;
                };

                let Some(Value::String(verb)) = parts.first() else {
                    continue;
                };

                match verb.as_str() {
                    "EVENT" => {
                        let Some(event_value) = parts.get(2) else {
                            continue;
                        };
                        let Ok(event) = serde_json::from_value::<SignedEvent>(event_value.clone())
                        else {
                            continue;
                        };

                        if event.kind != rpc_kind {
                            continue;
                        }

                        if !WebSocketTransport::event_mentions_recipient(
                            &event.tags,
                            &recipient_xonly,
                        ) {
                            continue;
                        }

                        let Some(sender33) = WebSocketTransport::tag_value(&event.tags, "b") else {
                            continue;
                        };
                        if !known_peers.iter().any(|p| p == sender33) {
                            continue;
                        }
                        let Some(sender_xonly) = WebSocketTransport::peer33_to_xonly(sender33)
                        else {
                            continue;
                        };
                        if sender_xonly != event.pubkey {
                            continue;
                        }

                        let Ok(plaintext) =
                            decryptor.decrypt_content_from_peer(sender33, &event.content)
                        else {
                            continue;
                        };

                        let Ok(envelope) = decode_envelope(&plaintext) else {
                            continue;
                        };
                        if envelope.sender != sender33 {
                            continue;
                        }

                        let incoming = IncomingMessage {
                            peer: envelope.sender.clone(),
                            envelope,
                        };

                        let mut pending_map = pending_reader.lock().await;
                        let pending_key =
                            WebSocketTransport::pending_key(&incoming.envelope.id, &incoming.peer);
                        if let Some(pending) = pending_map.remove(&pending_key) {
                            if pending.expected_peer != incoming.peer
                                || pending.request_id != incoming.envelope.id
                            {
                                continue;
                            }
                            let _ = pending.tx.send(incoming);
                            continue;
                        }
                        drop(pending_map);

                        if inbound_tx.send(incoming).is_err() {
                            break;
                        }
                    }
                    "NOTICE" => {
                        if let Some(Value::String(msg)) = parts.get(1) {
                            debug!("relay notice: {}", msg);
                        }
                    }
                    "OK" => {
                        if let (Some(Value::String(event_id)), Some(Value::Bool(ok))) =
                            (parts.get(1), parts.get(2))
                            && !ok
                        {
                            debug!("relay rejected event {}", event_id);
                        }
                    }
                    _ => {}
                }
            }

            WebSocketTransport::mark_disconnected(
                active_reader,
                outbound_reader,
                pending_reader,
                connected_reader,
                state_reader,
            )
            .await;
        });

        let mut tasks = self.tasks.lock().await;
        tasks.push(writer_task);
        tasks.push(reader_task);

        Ok(())
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn connect(&self) -> TransportResult<()> {
        if self.connected.load(Ordering::Relaxed) {
            return Ok(());
        }

        if self.relays.is_empty() {
            self.set_state(ConnectionState::Disconnected);
            return Err(TransportError::Backend("no relay configured".to_string()));
        }
        if self.nostr.sender_pubkey33.is_empty() {
            return Err(TransportError::Backend(
                "nostr sender_pubkey33 must not be empty".to_string(),
            ));
        }
        self.validate_identity()?;

        self.set_state(ConnectionState::Connecting);
        let mut last_err: Option<TransportError> = None;

        for attempt in 0..=self.config.max_retries {
            let relay_order = self.relay_order().await;
            for relay in relay_order {
                match self.establish_connection(&relay).await {
                    Ok(()) => {
                        self.mark_relay_success(&relay).await;
                        return Ok(());
                    }
                    Err(err) => {
                        self.mark_relay_failure(&relay, &err.to_string()).await;
                        last_err = Some(err);
                    }
                }
            }

            if attempt < self.config.max_retries {
                self.set_state(ConnectionState::Backoff);
                sleep(Duration::from_millis(self.backoff_ms(attempt))).await;
                self.set_state(ConnectionState::Connecting);
            }
        }

        self.set_state(ConnectionState::Disconnected);
        Err(last_err.unwrap_or_else(|| {
            TransportError::Backend("failed to connect to any relay".to_string())
        }))
    }

    async fn close(&self) -> TransportResult<()> {
        self.set_state(ConnectionState::Closing);
        self.connected.store(false, Ordering::Relaxed);

        if let Some(tx) = self.outbound_tx.lock().await.clone() {
            let _ = tx.send(Message::Text(json!(["CLOSE", "bifrost-rpc"]).to_string()));
        }

        {
            let mut active = self.active_relay.lock().await;
            *active = None;
        }

        {
            let mut outbound = self.outbound_tx.lock().await;
            *outbound = None;
        }

        {
            let mut pending = self.pending.lock().await;
            pending.clear();
        }

        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }

        self.set_state(ConnectionState::Disconnected);
        Ok(())
    }

    async fn request(
        &self,
        msg: OutgoingMessage,
        timeout_ms: u64,
    ) -> TransportResult<IncomingMessage> {
        self.ensure_connected()?;

        let (tx, rx) = oneshot::channel::<IncomingMessage>();
        let pending_key = Self::pending_key(&msg.envelope.id, &msg.peer);
        {
            let mut pending = self.pending.lock().await;
            pending.insert(
                pending_key.clone(),
                PendingRequest {
                    expected_peer: msg.peer.clone(),
                    request_id: msg.envelope.id.clone(),
                    tx,
                },
            );
        }

        if let Err(err) = self.send_envelope(msg.clone()).await {
            let mut pending = self.pending.lock().await;
            pending.remove(&pending_key);
            return Err(err);
        }

        match timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(TransportError::Backend(
                "request channel closed before response".to_string(),
            )),
            Err(_) => {
                let mut pending = self.pending.lock().await;
                pending.remove(&pending_key);
                Err(TransportError::Timeout)
            }
        }
    }

    async fn cast(
        &self,
        msg: OutgoingMessage,
        peers: &[String],
        threshold: usize,
        timeout_ms: u64,
    ) -> TransportResult<Vec<IncomingMessage>> {
        self.ensure_connected()?;
        if peers.is_empty() {
            return Err(TransportError::PeerNotFound);
        }

        let required = threshold.max(1);
        let total = peers.len();
        let mut results: Vec<IncomingMessage> = Vec::new();
        let mut attempted = 0usize;
        let mut last_err: Option<TransportError> = None;

        let mut inflight = FuturesUnordered::new();
        for peer in peers.iter() {
            let mut req = msg.clone();
            req.peer = peer.clone();
            inflight.push(async move { self.request(req, timeout_ms).await });
        }

        while let Some(outcome) = inflight.next().await {
            attempted = attempted.saturating_add(1);
            match outcome {
                Ok(res) => {
                    results.push(res);
                    if results.len() >= required {
                        return Ok(results);
                    }
                }
                Err(err) => {
                    last_err = Some(err);
                }
            }

            if Self::threshold_unreachable(results.len(), attempted, total, required) {
                return Err(last_err.unwrap_or_else(|| {
                    TransportError::Backend("cast did not reach threshold".to_string())
                }));
            }
        }

        if results.len() >= required {
            Ok(results)
        } else {
            Err(last_err.unwrap_or_else(|| {
                TransportError::Backend("cast did not reach threshold".to_string())
            }))
        }
    }

    async fn send_response(
        &self,
        handle: ResponseHandle,
        mut response: OutgoingMessage,
    ) -> TransportResult<()> {
        self.ensure_connected()?;
        response.peer = handle.peer;
        response.envelope.id = handle.request_id;
        self.send_envelope(response).await
    }

    async fn next_incoming(&self) -> TransportResult<IncomingMessage> {
        self.ensure_connected()?;
        let mut rx = self.inbound_rx.lock().await;
        rx.recv().await.ok_or_else(|| {
            TransportError::Backend("incoming channel closed while waiting for message".to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const SEC1: [u8; 32] = {
        let mut out = [0u8; 32];
        out[31] = 1;
        out
    };
    const SEC2: [u8; 32] = {
        let mut out = [0u8; 32];
        out[31] = 2;
        out
    };
    const NIP44_SAMPLE_PAYLOAD: &str = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";
    const NIP44_SAMPLE_CONVO_KEY: &str =
        "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d";

    fn pubkey33_hex(seckey: [u8; 32]) -> String {
        let sk = SecretKey::from_slice(&seckey).expect("secret key");
        hex::encode(sk.public_key().to_sec1_bytes())
    }

    fn transport_with_keypair(seckey: [u8; 32], peers: Vec<String>) -> WebSocketTransport {
        WebSocketTransport::new(
            vec![],
            WsNostrConfig {
                sender_pubkey33: pubkey33_hex(seckey),
                sender_seckey32: seckey,
                peer_pubkeys33: peers,
            },
        )
    }

    #[derive(Debug, Deserialize)]
    struct VectorFile {
        vectors: Vec<Nip44Vector>,
    }

    #[derive(Debug, Deserialize)]
    struct Nip44Vector {
        name: String,
        mode: String,
        sec_sender_hex: String,
        sec_receiver_hex: String,
        plaintext: Option<String>,
        nonce_hex: Option<String>,
        expected_payload: Option<String>,
        payload: Option<String>,
        expected_plaintext: Option<String>,
        expected_error_contains: Option<String>,
    }

    fn parse_hex32(value: &str) -> [u8; 32] {
        let bytes = hex::decode(value).expect("valid hex");
        assert_eq!(bytes.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let transport = WebSocketTransport::with_config(
            vec!["wss://relay.example".to_string()],
            WsTransportConfig {
                max_retries: 3,
                backoff_initial_ms: 100,
                backoff_max_ms: 250,
                rpc_kind: 20_000,
            },
            WsNostrConfig {
                sender_pubkey33: "02".to_string() + &"11".repeat(32),
                sender_seckey32: [7u8; 32],
                peer_pubkeys33: vec![],
            },
        );

        assert_eq!(transport.backoff_ms(0), 100);
        assert_eq!(transport.backoff_ms(1), 200);
        assert_eq!(transport.backoff_ms(2), 250);
        assert_eq!(transport.backoff_ms(8), 250);
    }

    #[test]
    fn peer33_to_xonly_requires_compressed_prefix() {
        let x = WebSocketTransport::peer33_to_xonly(&format!("02{}", "aa".repeat(32))).unwrap();
        assert_eq!(x.len(), 64);
        assert!(WebSocketTransport::peer33_to_xonly(&"04aa".repeat(33)).is_none());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let sender_pk = pubkey33_hex(SEC1);
        let receiver_pk = pubkey33_hex(SEC2);
        let sender = transport_with_keypair(SEC1, vec![receiver_pk.clone()]);
        let receiver = transport_with_keypair(SEC2, vec![sender_pk.clone()]);

        let cipher = sender
            .encrypt_content_for_peer(&receiver_pk, "hello")
            .expect("encrypt");
        let plain = receiver
            .decrypt_content_from_peer(&sender_pk, &cipher)
            .expect("decrypt");
        assert_eq!(plain, "hello");
    }

    #[test]
    fn nip44_vector_conversation_key_matches_spec() {
        let sender = transport_with_keypair(SEC1, vec![pubkey33_hex(SEC2)]);
        let shared = sender.event_shared_x(&pubkey33_hex(SEC2)).expect("shared");
        let convo = WebSocketTransport::get_conversation_key(&shared).expect("conversation");
        assert_eq!(hex::encode(convo), NIP44_SAMPLE_CONVO_KEY);
    }

    #[test]
    fn nip44_vector_encrypt_matches_spec_payload() {
        let sender_pk = pubkey33_hex(SEC1);
        let receiver_pk = pubkey33_hex(SEC2);
        let sender = transport_with_keypair(SEC1, vec![receiver_pk.clone()]);
        let mut nonce = [0u8; 32];
        nonce[31] = 1;

        let payload = sender
            .encrypt_content_for_peer_with_nonce(&receiver_pk, "a", nonce)
            .expect("encrypt");
        assert_eq!(payload, NIP44_SAMPLE_PAYLOAD);

        // sanity decrypt with the opposite keypair
        let receiver = transport_with_keypair(SEC2, vec![sender_pk.clone()]);
        let plaintext = receiver
            .decrypt_content_from_peer(&sender_pk, &payload)
            .expect("decrypt");
        assert_eq!(plaintext, "a");
    }

    #[test]
    fn nip44_vector_decrypt_matches_spec_payload() {
        let sender_pk = pubkey33_hex(SEC1);
        let receiver = transport_with_keypair(SEC2, vec![sender_pk.clone()]);
        let plaintext = receiver
            .decrypt_content_from_peer(&sender_pk, NIP44_SAMPLE_PAYLOAD)
            .expect("decrypt");
        assert_eq!(plaintext, "a");
    }

    #[test]
    fn nip44_fixture_vectors() {
        let file: VectorFile = serde_json::from_str(include_str!("../tests/nip44_vectors.json"))
            .expect("fixture json");
        for v in file.vectors {
            let sender_sk = parse_hex32(&v.sec_sender_hex);
            let receiver_sk = parse_hex32(&v.sec_receiver_hex);
            let sender_pk = pubkey33_hex(sender_sk);
            let receiver_pk = pubkey33_hex(receiver_sk);
            let sender = transport_with_keypair(sender_sk, vec![receiver_pk.clone()]);
            let receiver = transport_with_keypair(receiver_sk, vec![sender_pk.clone()]);

            match v.mode.as_str() {
                "encrypt" => {
                    let plaintext = v.plaintext.as_ref().expect("plaintext");
                    let nonce = parse_hex32(v.nonce_hex.as_ref().expect("nonce_hex"));
                    let expected = v.expected_payload.as_ref().expect("expected_payload");
                    let payload = sender
                        .encrypt_content_for_peer_with_nonce(&receiver_pk, plaintext, nonce)
                        .unwrap_or_else(|e| panic!("{} encrypt failed: {e}", v.name));
                    assert_eq!(payload, *expected, "{}", v.name);
                }
                "decrypt" => {
                    let payload = v.payload.as_ref().expect("payload");
                    match receiver.decrypt_content_from_peer(&sender_pk, payload) {
                        Ok(plaintext) => {
                            let expected = v
                                .expected_plaintext
                                .as_ref()
                                .unwrap_or_else(|| panic!("{} expected plaintext missing", v.name));
                            assert_eq!(plaintext, *expected, "{}", v.name);
                        }
                        Err(err) => {
                            let expect_contains =
                                v.expected_error_contains.as_ref().unwrap_or_else(|| {
                                    panic!("{} unexpected decrypt error: {err}", v.name)
                                });
                            assert!(
                                err.to_string().contains(expect_contains),
                                "{} error mismatch: got '{err}' expected contains '{}'",
                                v.name,
                                expect_contains
                            );
                        }
                    }
                }
                "roundtrip" => {
                    let plaintext = v.plaintext.as_ref().expect("plaintext");
                    let payload = if let Some(nonce_hex) = v.nonce_hex.as_ref() {
                        let nonce = parse_hex32(nonce_hex);
                        sender
                            .encrypt_content_for_peer_with_nonce(&receiver_pk, plaintext, nonce)
                            .unwrap_or_else(|e| panic!("{} encrypt failed: {e}", v.name))
                    } else {
                        sender
                            .encrypt_content_for_peer(&receiver_pk, plaintext)
                            .unwrap_or_else(|e| panic!("{} encrypt failed: {e}", v.name))
                    };
                    if let Some(expected) = v.expected_payload.as_ref() {
                        assert_eq!(&payload, expected, "{}", v.name);
                    }
                    let out = receiver
                        .decrypt_content_from_peer(&sender_pk, &payload)
                        .unwrap_or_else(|e| panic!("{} decrypt failed: {e}", v.name));
                    assert_eq!(out, *plaintext, "{}", v.name);
                }
                _ => panic!("unknown fixture mode {}", v.mode),
            }
        }
    }

    #[test]
    fn nip44_deterministic_matrix_and_mutation_rejects() {
        let sender_pk = pubkey33_hex(SEC1);
        let receiver_pk = pubkey33_hex(SEC2);
        let sender = transport_with_keypair(SEC1, vec![receiver_pk.clone()]);
        let receiver = transport_with_keypair(SEC2, vec![sender_pk.clone()]);
        let wrong_receiver = transport_with_keypair([3u8; 32], vec![sender_pk.clone()]);

        let plaintexts = vec![
            "a".to_string(),
            "hello world".to_string(),
            "hello 😀 world 💻".to_string(),
            "x".repeat(31),
            "x".repeat(32),
            "x".repeat(33),
            "x".repeat(255),
            "x".repeat(256),
            "x".repeat(257),
            "x".repeat(1024),
            "x".repeat(8192),
        ];

        for (idx, plaintext) in plaintexts.iter().enumerate() {
            let mut nonce = [0u8; 32];
            nonce[24..32].copy_from_slice(&(idx as u64 + 11).to_be_bytes());
            let payload = sender
                .encrypt_content_for_peer_with_nonce(&receiver_pk, plaintext, nonce)
                .unwrap_or_else(|e| panic!("encrypt idx {idx} failed: {e}"));

            let roundtrip = receiver
                .decrypt_content_from_peer(&sender_pk, &payload)
                .unwrap_or_else(|e| panic!("decrypt idx {idx} failed: {e}"));
            assert_eq!(&roundtrip, plaintext, "plaintext mismatch at idx {idx}");

            let wrong_key_err = wrong_receiver
                .decrypt_content_from_peer(&sender_pk, &payload)
                .expect_err("wrong receiver key must fail");
            assert!(
                wrong_key_err.to_string().contains("invalid MAC"),
                "wrong-key error mismatch: {wrong_key_err}"
            );

            let mut bytes = payload.as_bytes().to_vec();
            let mut_pos = bytes.len().saturating_sub(3).max(1);
            bytes[mut_pos] = if bytes[mut_pos] == b'A' { b'B' } else { b'A' };
            let tampered = String::from_utf8(bytes).expect("utf8 payload mutation");
            let tampered_err = receiver
                .decrypt_content_from_peer(&sender_pk, &tampered)
                .expect_err("tampered payload must fail");
            let tampered_msg = tampered_err.to_string();
            assert!(
                tampered_msg.contains("invalid MAC")
                    || tampered_msg.contains("invalid base64")
                    || tampered_msg.contains("invalid padding")
                    || tampered_msg.contains("invalid utf8"),
                "tampered error mismatch: {tampered_err}"
            );
        }
    }

    #[test]
    fn threshold_unreachable_detects_impossible_quorum() {
        assert!(WebSocketTransport::threshold_unreachable(1, 3, 4, 3));
        assert!(!WebSocketTransport::threshold_unreachable(2, 3, 4, 3));
    }

    #[test]
    fn connect_failover_forced_fault_records_relay_health() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let transport = WebSocketTransport::with_config(
                vec![
                    "not-a-valid-url".to_string(),
                    "ws://127.0.0.1:0".to_string(),
                ],
                WsTransportConfig {
                    max_retries: 1,
                    backoff_initial_ms: 1,
                    backoff_max_ms: 2,
                    rpc_kind: 20_000,
                },
                WsNostrConfig {
                    sender_pubkey33: pubkey33_hex(SEC1),
                    sender_seckey32: SEC1,
                    peer_pubkeys33: vec![pubkey33_hex(SEC2)],
                },
            );

            let err = transport.connect().await.expect_err("connect should fail");
            let err_text = err.to_string();
            assert!(
                err_text.contains("all relays failed")
                    || err_text.contains("invalid relay URL")
                    || err_text.contains("failed to connect")
                    || err_text.contains("Connection refused")
                    || err_text.contains("IO error"),
                "unexpected connect error: {err_text}"
            );

            let health = transport.relay_health_snapshot().await;
            let bad_url = health.get("not-a-valid-url").expect("bad-url relay health");
            let bad_port = health
                .get("ws://127.0.0.1:0")
                .expect("bad-port relay health");
            assert!(
                bad_url.failures > 0,
                "expected bad-url failures to increment"
            );
            assert!(
                bad_port.failures > 0,
                "expected bad-port failures to increment"
            );
            assert_eq!(transport.state(), ConnectionState::Disconnected);
            assert!(transport.active_relay().await.is_none());
        });
    }
}
