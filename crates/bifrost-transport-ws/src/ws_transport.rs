use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use bifrost_codec::rpc::{decode_envelope, encode_envelope};
use bifrost_transport::{
    IncomingMessage, OutgoingMessage, ResponseHandle, Transport, TransportError, TransportResult,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};

#[derive(Debug)]
pub struct WebSocketTransport {
    relays: Vec<String>,
    connected: AtomicBool,
    outbound_tx: Mutex<Option<mpsc::UnboundedSender<Message>>>,
    inbound_rx: Mutex<mpsc::UnboundedReceiver<IncomingMessage>>,
    inbound_tx: mpsc::UnboundedSender<IncomingMessage>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<IncomingMessage>>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl WebSocketTransport {
    pub fn new(relays: Vec<String>) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        Self {
            relays,
            connected: AtomicBool::new(false),
            outbound_tx: Mutex::new(None),
            inbound_rx: Mutex::new(inbound_rx),
            inbound_tx,
            pending: Arc::new(Mutex::new(HashMap::new())),
            tasks: Mutex::new(Vec::new()),
        }
    }

    fn ensure_connected(&self) -> TransportResult<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TransportError::NotConnected);
        }
        Ok(())
    }

    async fn send_envelope(&self, msg: OutgoingMessage) -> TransportResult<()> {
        self.ensure_connected()?;
        let encoded =
            encode_envelope(&msg.envelope).map_err(|e| TransportError::Codec(e.to_string()))?;

        let maybe_tx = self.outbound_tx.lock().await.clone();
        let Some(tx) = maybe_tx else {
            return Err(TransportError::NotConnected);
        };

        tx.send(Message::Text(encoded.into()))
            .map_err(|e| TransportError::Backend(e.to_string()))
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn connect(&self) -> TransportResult<()> {
        if self.connected.load(Ordering::Relaxed) {
            return Ok(());
        }

        let relay = self
            .relays
            .first()
            .ok_or_else(|| TransportError::Backend("no relay configured".to_string()))?
            .clone();

        let (stream, _) = connect_async(&relay)
            .await
            .map_err(|e| TransportError::Backend(e.to_string()))?;

        let (mut writer, mut reader) = stream.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

        {
            let mut guard = self.outbound_tx.lock().await;
            *guard = Some(out_tx);
        }

        self.connected.store(true, Ordering::Relaxed);

        let writer_task = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if let Err(err) = writer.send(msg).await {
                    warn!("websocket send failed: {}", err);
                    break;
                }
            }
        });

        let inbound_tx = self.inbound_tx.clone();
        let pending = self.pending.clone();
        let reader_task = tokio::spawn(async move {
            while let Some(next) = reader.next().await {
                let Ok(frame) = next else {
                    warn!("websocket read failed");
                    break;
                };

                match frame {
                    Message::Text(text) => {
                        let Ok(envelope) = decode_envelope(text.as_ref()) else {
                            debug!("ignoring invalid envelope frame");
                            continue;
                        };

                        let incoming = IncomingMessage {
                            peer: envelope.sender.clone(),
                            envelope,
                        };

                        let mut pending_map = pending.lock().await;
                        if let Some(sender) = pending_map.remove(&incoming.envelope.id) {
                            let _ = sender.send(incoming);
                            continue;
                        }
                        drop(pending_map);

                        if inbound_tx.send(incoming).is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });

        let mut tasks = self.tasks.lock().await;
        tasks.push(writer_task);
        tasks.push(reader_task);

        Ok(())
    }

    async fn close(&self) -> TransportResult<()> {
        self.connected.store(false, Ordering::Relaxed);

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

        Ok(())
    }

    async fn request(
        &self,
        msg: OutgoingMessage,
        timeout_ms: u64,
    ) -> TransportResult<IncomingMessage> {
        self.ensure_connected()?;

        let (tx, rx) = oneshot::channel::<IncomingMessage>();
        {
            let mut pending = self.pending.lock().await;
            pending.insert(msg.envelope.id.clone(), tx);
        }

        if let Err(err) = self.send_envelope(msg.clone()).await {
            let mut pending = self.pending.lock().await;
            pending.remove(&msg.envelope.id);
            return Err(err);
        }

        match timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(TransportError::Backend(
                "request channel closed before response".to_string(),
            )),
            Err(_) => {
                let mut pending = self.pending.lock().await;
                pending.remove(&msg.envelope.id);
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
        let mut results = Vec::new();
        let mut last_err: Option<TransportError> = None;

        for (i, peer) in peers.iter().enumerate() {
            let mut req = msg.clone();
            req.peer = peer.clone();
            req.envelope.id = format!("{}:{}", req.envelope.id, i);

            match self.request(req, timeout_ms).await {
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
