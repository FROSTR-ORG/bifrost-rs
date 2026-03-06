use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bifrost_core::types::PeerPolicy;
use bifrost_router::{
    BridgeCommand as RouterCommand, BridgeConfig as RouterConfig, BridgeCore, RequestPhase,
    RouterPort,
};
use bifrost_signer::{
    CompletedOperation, DeviceState, DeviceStatus, OperationFailure, OperationFailureCode,
    PersistenceHint, SigningDevice,
};
use nostr::{Event, Filter};
use nostr_sdk::{Client, RelayPoolNotification};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub use bifrost_router::{
    DEFAULT_COMMAND_OVERFLOW_POLICY, DEFAULT_COMMAND_QUEUE_CAPACITY, DEFAULT_EXPIRE_TICK_MS,
    DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT, DEFAULT_INBOUND_OVERFLOW_POLICY,
    DEFAULT_INBOUND_QUEUE_CAPACITY, DEFAULT_OUTBOUND_OVERFLOW_POLICY, DEFAULT_OUTBOUND_QUEUE_CAPACITY,
    QueueOverflowPolicy,
};

#[async_trait]
pub trait RelayAdapter: Send {
    async fn connect(&mut self) -> Result<()>;
    async fn disconnect(&mut self) -> Result<()>;
    async fn subscribe(&mut self, filters: Vec<Filter>) -> Result<()>;
    async fn publish(&mut self, event: Event) -> Result<()>;
    async fn next_event(&mut self) -> Result<Event>;
}

pub const DEFAULT_RELAY_BACKOFF_MS: u64 = 50;

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("operation timed out")]
    Timeout,
    #[error("locked peer timeout for request {request_id}")]
    LockedPeerTimeout { request_id: String },
    #[error("invalid locked peer response for request {request_id}: {message}")]
    InvalidLockedPeerResponse { request_id: String, message: String },
    #[error("round failed for request {request_id}: {code} ({message})")]
    RoundFailed {
        request_id: String,
        code: String,
        message: String,
    },
    #[error("bridge command channel closed")]
    CommandChannelClosed,
    #[error("unexpected completion variant")]
    UnexpectedCompletion,
    #[error("bridge internal failure: {0}")]
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct SignResult {
    pub request_id: String,
    pub signatures: Vec<[u8; 64]>,
}

#[derive(Debug, Clone)]
pub struct EcdhResult {
    pub request_id: String,
    pub shared_secret: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct PingResult {
    pub request_id: String,
    pub peer: String,
}

#[derive(Debug, Clone)]
pub struct OnboardResult {
    pub request_id: String,
    pub group_member_count: usize,
}

enum BridgeCommand {
    Sign {
        op_id: String,
        message: [u8; 32],
        completion: oneshot::Sender<std::result::Result<CompletedOperation, BridgeError>>,
    },
    Ecdh {
        op_id: String,
        pubkey: [u8; 32],
        completion: oneshot::Sender<std::result::Result<CompletedOperation, BridgeError>>,
    },
    Ping {
        op_id: String,
        peer: String,
        completion: oneshot::Sender<std::result::Result<CompletedOperation, BridgeError>>,
    },
    Onboard {
        op_id: String,
        peer: String,
        completion: oneshot::Sender<std::result::Result<CompletedOperation, BridgeError>>,
    },
    SnapshotState {
        reply: oneshot::Sender<std::result::Result<DeviceState, BridgeError>>,
    },
    Status {
        reply: oneshot::Sender<std::result::Result<DeviceStatus, BridgeError>>,
    },
    Policies {
        reply: oneshot::Sender<std::result::Result<HashMap<String, PeerPolicy>, BridgeError>>,
    },
    SetPolicy {
        peer: String,
        policy: PeerPolicy,
        reply: oneshot::Sender<std::result::Result<(), BridgeError>>,
    },
    TakePersistenceHint {
        reply: oneshot::Sender<std::result::Result<PersistenceHint, BridgeError>>,
    },
    RequestPhase {
        request_id: String,
        reply: oneshot::Sender<std::result::Result<Option<RequestPhase>, BridgeError>>,
    },
    Shutdown,
}

struct OperationWaiter {
    op_id: String,
    completion: oneshot::Sender<std::result::Result<CompletedOperation, BridgeError>>,
}

pub struct Bridge {
    cmd_tx: mpsc::Sender<BridgeCommand>,
    join_handle: Option<JoinHandle<()>>,
    op_seq: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub expire_tick: Duration,
    pub relay_backoff: Duration,
    pub command_queue_capacity: usize,
    pub inbound_queue_capacity: usize,
    pub outbound_queue_capacity: usize,
    pub command_overflow_policy: QueueOverflowPolicy,
    pub inbound_overflow_policy: QueueOverflowPolicy,
    pub outbound_overflow_policy: QueueOverflowPolicy,
    pub inbound_dedupe_cache_limit: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            expire_tick: Duration::from_millis(DEFAULT_EXPIRE_TICK_MS),
            relay_backoff: Duration::from_millis(DEFAULT_RELAY_BACKOFF_MS),
            command_queue_capacity: DEFAULT_COMMAND_QUEUE_CAPACITY,
            inbound_queue_capacity: DEFAULT_INBOUND_QUEUE_CAPACITY,
            outbound_queue_capacity: DEFAULT_OUTBOUND_QUEUE_CAPACITY,
            command_overflow_policy: DEFAULT_COMMAND_OVERFLOW_POLICY,
            inbound_overflow_policy: DEFAULT_INBOUND_OVERFLOW_POLICY,
            outbound_overflow_policy: DEFAULT_OUTBOUND_OVERFLOW_POLICY,
            inbound_dedupe_cache_limit: DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT,
        }
    }
}

impl Bridge {
    pub async fn start<A>(adapter: A, signer: SigningDevice) -> Result<Self>
    where
        A: RelayAdapter + 'static,
    {
        Self::start_with_config(adapter, signer, BridgeConfig::default()).await
    }

    pub async fn start_with_config<A>(
        mut adapter: A,
        signer: SigningDevice,
        config: BridgeConfig,
    ) -> Result<Self>
    where
        A: RelayAdapter + 'static,
    {
        let config = validate_config(config)?;
        let router_cfg = RouterConfig {
            expire_tick: config.expire_tick,
            command_queue_capacity: config.command_queue_capacity,
            inbound_queue_capacity: config.inbound_queue_capacity,
            outbound_queue_capacity: config.outbound_queue_capacity,
            command_overflow_policy: config.command_overflow_policy,
            inbound_overflow_policy: config.inbound_overflow_policy,
            outbound_overflow_policy: config.outbound_overflow_policy,
            inbound_dedupe_cache_limit: config.inbound_dedupe_cache_limit,
        };
        let mut core = BridgeCore::new(signer, router_cfg)?;
        let filters = core.subscription_filters()?;

        adapter.connect().await?;
        adapter.subscribe(filters).await?;

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<BridgeCommand>(config.command_queue_capacity);
        let join_handle = tokio::spawn(async move {
            let mut waiters: HashMap<String, OperationWaiter> = HashMap::new();
            let mut adapter = adapter;
            let mut expire_tick = tokio::time::interval(config.expire_tick);
            let mut shutdown = false;

            loop {
                tokio::select! {
                    _ = expire_tick.tick() => {
                        core.tick(now_unix_millis());
                    }
                    Some(cmd) = cmd_rx.recv() => {
                        match cmd {
                            BridgeCommand::Shutdown => {
                                shutdown = true;
                            }
                            BridgeCommand::Sign { op_id, message, completion } => {
                                handle_operation_command(
                                    &mut core,
                                    &mut waiters,
                                    op_id,
                                    completion,
                                    RouterCommand::Sign { message },
                                );
                            }
                            BridgeCommand::Ecdh { op_id, pubkey, completion } => {
                                handle_operation_command(
                                    &mut core,
                                    &mut waiters,
                                    op_id,
                                    completion,
                                    RouterCommand::Ecdh { pubkey },
                                );
                            }
                            BridgeCommand::Ping { op_id, peer, completion } => {
                                handle_operation_command(
                                    &mut core,
                                    &mut waiters,
                                    op_id,
                                    completion,
                                    RouterCommand::Ping { peer },
                                );
                            }
                            BridgeCommand::Onboard { op_id, peer, completion } => {
                                handle_operation_command(
                                    &mut core,
                                    &mut waiters,
                                    op_id,
                                    completion,
                                    RouterCommand::Onboard { peer },
                                );
                            }
                            BridgeCommand::SnapshotState { reply } => {
                                let _ = reply.send(Ok(core.snapshot_state()));
                            }
                            BridgeCommand::Status { reply } => {
                                let _ = reply.send(Ok(core.status()));
                            }
                            BridgeCommand::Policies { reply } => {
                                let _ = reply.send(Ok(core.policies()));
                            }
                            BridgeCommand::SetPolicy { peer, policy, reply } => {
                                let result = core
                                    .set_policy(peer, policy)
                                    .map_err(|e| BridgeError::Internal(e.to_string()));
                                let _ = reply.send(result);
                            }
                            BridgeCommand::TakePersistenceHint { reply } => {
                                let _ = reply.send(Ok(core.take_persistence_hint()));
                            }
                            BridgeCommand::RequestPhase { request_id, reply } => {
                                let _ = reply.send(Ok(core.request_phase(&request_id)));
                            }
                        }
                    }
                    inbound = adapter.next_event() => {
                        match inbound {
                            Ok(event) => {
                                let event_id = event.id.to_hex();
                                if core.enqueue_inbound_event(event) {
                                    warn!("inbound queue full; dropped relay event");
                                } else {
                                    info!(event_id = %event_id, "relay event received");
                                }
                            }
                            Err(err) => {
                                warn!(%err, "relay adapter next_event failed");
                                tokio::time::sleep(config.relay_backoff).await;
                            }
                        }
                    }
                    else => {
                        shutdown = true;
                    }
                }

                core.tick(now_unix_millis());
                flush_router(&mut core, &mut adapter, &mut waiters).await;

                if shutdown {
                    for (_, waiter) in waiters.drain() {
                        let _ = waiter.completion.send(Err(BridgeError::CommandChannelClosed));
                    }
                    let _ = adapter.disconnect().await;
                    break;
                }
            }
        });

        Ok(Self {
            cmd_tx,
            join_handle: Some(join_handle),
            op_seq: AtomicU64::new(1),
        })
    }

    pub async fn sign(
        &self,
        message: [u8; 32],
        timeout: Duration,
    ) -> std::result::Result<SignResult, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::Sign {
                op_id: self.next_op_id(),
                message,
                completion: tx,
            })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        let completed = wait_completion(rx, timeout).await?;
        match completed {
            CompletedOperation::Sign {
                request_id,
                signatures,
            } => Ok(SignResult {
                request_id,
                signatures,
            }),
            _ => Err(BridgeError::UnexpectedCompletion),
        }
    }

    pub async fn ecdh(
        &self,
        pubkey: [u8; 32],
        timeout: Duration,
    ) -> std::result::Result<EcdhResult, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::Ecdh {
                op_id: self.next_op_id(),
                pubkey,
                completion: tx,
            })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        let completed = wait_completion(rx, timeout).await?;
        match completed {
            CompletedOperation::Ecdh {
                request_id,
                shared_secret,
            } => Ok(EcdhResult {
                request_id,
                shared_secret,
            }),
            _ => Err(BridgeError::UnexpectedCompletion),
        }
    }

    pub async fn ping(
        &self,
        peer: String,
        timeout: Duration,
    ) -> std::result::Result<PingResult, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::Ping {
                op_id: self.next_op_id(),
                peer,
                completion: tx,
            })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        let completed = wait_completion(rx, timeout).await?;
        match completed {
            CompletedOperation::Ping { request_id, peer } => Ok(PingResult { request_id, peer }),
            _ => Err(BridgeError::UnexpectedCompletion),
        }
    }

    pub async fn onboard(
        &self,
        peer: String,
        timeout: Duration,
    ) -> std::result::Result<OnboardResult, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::Onboard {
                op_id: self.next_op_id(),
                peer,
                completion: tx,
            })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        let completed = wait_completion(rx, timeout).await?;
        match completed {
            CompletedOperation::Onboard {
                request_id,
                group_member_count,
            } => Ok(OnboardResult {
                request_id,
                group_member_count,
            }),
            _ => Err(BridgeError::UnexpectedCompletion),
        }
    }

    pub async fn snapshot_state(&self) -> std::result::Result<DeviceState, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::SnapshotState { reply: tx })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        rx.await.map_err(|_| BridgeError::CommandChannelClosed)?
    }

    pub async fn status(&self) -> std::result::Result<DeviceStatus, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::Status { reply: tx })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        rx.await.map_err(|_| BridgeError::CommandChannelClosed)?
    }

    pub async fn policies(&self) -> std::result::Result<HashMap<String, PeerPolicy>, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::Policies { reply: tx })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        rx.await.map_err(|_| BridgeError::CommandChannelClosed)?
    }

    pub async fn set_policy(
        &self,
        peer: String,
        policy: PeerPolicy,
    ) -> std::result::Result<(), BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::SetPolicy {
                peer,
                policy,
                reply: tx,
            })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        rx.await.map_err(|_| BridgeError::CommandChannelClosed)?
    }

    pub async fn take_persistence_hint(&self) -> std::result::Result<PersistenceHint, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::TakePersistenceHint { reply: tx })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        rx.await.map_err(|_| BridgeError::CommandChannelClosed)?
    }

    pub async fn request_phase(
        &self,
        request_id: String,
    ) -> std::result::Result<Option<RequestPhase>, BridgeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(BridgeCommand::RequestPhase {
                request_id,
                reply: tx,
            })
            .await
            .map_err(|_| BridgeError::CommandChannelClosed)?;
        rx.await.map_err(|_| BridgeError::CommandChannelClosed)?
    }

    pub async fn shutdown(mut self) {
        let _ = self.cmd_tx.send(BridgeCommand::Shutdown).await;
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
    }

    fn next_op_id(&self) -> String {
        let id = self.op_seq.fetch_add(1, Ordering::Relaxed);
        format!("op-{id}")
    }
}

fn handle_operation_command(
    core: &mut impl RouterPort<Error = bifrost_router::BridgeCoreError>,
    waiters: &mut HashMap<String, OperationWaiter>,
    op_id: String,
    completion: oneshot::Sender<std::result::Result<CompletedOperation, BridgeError>>,
    input: RouterCommand,
) {
    match core.submit_command(input) {
        Ok(request_id) => {
            info!(
                op_id = %op_id,
                request_id = %request_id,
                phase = "created",
                "operation accepted"
            );
            waiters.insert(request_id, OperationWaiter { op_id, completion });
        }
        Err(err) => {
            warn!(
                op_id = %op_id,
                phase = "failed",
                error = %err,
                "operation rejected"
            );
            let _ = completion.send(Err(BridgeError::Internal(err.to_string())));
        }
    }
}

async fn flush_router<A: RelayAdapter>(
    core: &mut impl RouterPort<Error = bifrost_router::BridgeCoreError>,
    adapter: &mut A,
    waiters: &mut HashMap<String, OperationWaiter>,
) {
    loop {
        let outbound = core.drain_outbound_packets();
        let completions = core.drain_completions();
        let failures = core.drain_failures();
        if outbound.is_empty() && completions.is_empty() && failures.is_empty() {
            break;
        }

        for queued in outbound {
            if let Err(err) = adapter.publish(queued.event).await {
                warn!(%err, "bridge publish failed");
                if let Some(request_id) = queued.request_id {
                    warn!(
                        request_id = %request_id,
                        phase = "failed",
                        code = "relay_publish_failed",
                        "operation failed during publish"
                    );
                    let _ = core.fail_request(request_id, format!("relay publish failed: {err}"));
                }
            }
        }

        for failure in failures {
            resolve_failure(waiters, failure);
        }

        for completion in completions {
            let request_id = completion.request_id().to_string();
            let completion_kind = completed_operation_kind(&completion);
            info!(request_id = %request_id, kind = completion_kind, "operation completed");
            if let Some(waiter) = waiters.remove(&request_id) {
                let _ = waiter.completion.send(Ok(completion));
            }
        }
    }
}

fn validate_config(config: BridgeConfig) -> Result<BridgeConfig> {
    if config.expire_tick.is_zero() {
        return Err(anyhow!("router.expire_tick must be greater than zero"));
    }
    if config.command_queue_capacity == 0 {
        return Err(anyhow!(
            "router.command_queue_capacity must be greater than zero"
        ));
    }
    if config.inbound_queue_capacity == 0 {
        return Err(anyhow!(
            "router.inbound_queue_capacity must be greater than zero"
        ));
    }
    if config.outbound_queue_capacity == 0 {
        return Err(anyhow!(
            "router.outbound_queue_capacity must be greater than zero"
        ));
    }
    if config.inbound_dedupe_cache_limit == 0 {
        return Err(anyhow!(
            "router.inbound_dedupe_cache_limit must be greater than zero"
        ));
    }
    Ok(config)
}

async fn wait_completion(
    receiver: oneshot::Receiver<std::result::Result<CompletedOperation, BridgeError>>,
    timeout: Duration,
) -> std::result::Result<CompletedOperation, BridgeError> {
    match tokio::time::timeout(timeout, receiver).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(BridgeError::CommandChannelClosed),
        Err(_) => Err(BridgeError::Timeout),
    }
}

fn resolve_failure(waiters: &mut HashMap<String, OperationWaiter>, failure: OperationFailure) {
    if let Some(waiter) = waiters.remove(&failure.request_id) {
        let request_id = failure.request_id.clone();
        let error = match failure.code {
            OperationFailureCode::Timeout => BridgeError::LockedPeerTimeout {
                request_id: request_id.clone(),
            },
            OperationFailureCode::InvalidLockedPeerResponse => {
                BridgeError::InvalidLockedPeerResponse {
                    request_id: request_id.clone(),
                    message: failure.message,
                }
            }
            OperationFailureCode::PeerRejected => BridgeError::RoundFailed {
                request_id: request_id.clone(),
                code: "peer_rejected".to_string(),
                message: failure.message,
            },
        };
        let _ = waiter.completion.send(Err(error));
        warn!(
            op_id = %waiter.op_id,
            request_id = %request_id,
            phase = "failed",
            code = ?failure.code,
            "bridge operation failed"
        );
    }
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn completed_operation_kind(operation: &CompletedOperation) -> &'static str {
    match operation {
        CompletedOperation::Sign { .. } => "sign",
        CompletedOperation::Ecdh { .. } => "ecdh",
        CompletedOperation::Ping { .. } => "ping",
        CompletedOperation::Onboard { .. } => "onboard",
    }
}

pub struct NostrSdkAdapter {
    client: Client,
    relays: Vec<String>,
    notifications: Option<broadcast::Receiver<RelayPoolNotification>>,
}

impl NostrSdkAdapter {
    pub fn new(relays: Vec<String>) -> Self {
        Self {
            client: Client::default(),
            relays,
            notifications: None,
        }
    }
}

#[async_trait]
impl RelayAdapter for NostrSdkAdapter {
    async fn connect(&mut self) -> Result<()> {
        self.notifications = Some(self.client.notifications());
        for relay in &self.relays {
            self.client
                .add_relay(relay)
                .await
                .map_err(|e| anyhow!("add relay {relay}: {e}"))?;
        }
        self.client.connect().await;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.client.disconnect().await;
        self.notifications = None;
        Ok(())
    }

    async fn subscribe(&mut self, filters: Vec<Filter>) -> Result<()> {
        for filter in filters {
            self.client.subscribe(filter, None).await?;
        }
        Ok(())
    }

    async fn publish(&mut self, event: Event) -> Result<()> {
        self.client.send_event(&event).await?;
        Ok(())
    }

    async fn next_event(&mut self) -> Result<Event> {
        let receiver = self
            .notifications
            .as_mut()
            .ok_or_else(|| anyhow!("notifications receiver not initialized"))?;
        loop {
            let notification = match receiver.recv().await {
                Ok(notification) => notification,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(anyhow!("relay notifications channel closed"));
                }
            };
            if let RelayPoolNotification::Event { event, .. } = notification {
                return Ok((*event).clone());
            }
        }
    }
}
