use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bifrost_core::types::PeerPolicy;
use bifrost_signer::{
    CompletedOperation, DeviceState, DeviceStatus, OperationFailure, OperationFailureCode,
    SignerEffects, SignerInput, SigningDevice,
};
use nostr::{Event, Filter};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{info, warn};

#[async_trait]
pub trait RelayAdapter: Send {
    async fn connect(&mut self) -> Result<()>;
    async fn disconnect(&mut self) -> Result<()>;
    async fn subscribe(&mut self, filters: Vec<Filter>) -> Result<()>;
    async fn publish(&mut self, event: Event) -> Result<()>;
    async fn next_event(&mut self) -> Result<Event>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueOverflowPolicy {
    Fail,
    DropOldest,
}

pub const DEFAULT_EXPIRE_TICK_MS: u64 = 1_000;
pub const DEFAULT_RELAY_BACKOFF_MS: u64 = 50;
pub const DEFAULT_COMMAND_QUEUE_CAPACITY: usize = 128;
pub const DEFAULT_INBOUND_QUEUE_CAPACITY: usize = 4_096;
pub const DEFAULT_OUTBOUND_QUEUE_CAPACITY: usize = 1_024;
pub const DEFAULT_COMMAND_OVERFLOW_POLICY: QueueOverflowPolicy = QueueOverflowPolicy::Fail;
pub const DEFAULT_INBOUND_OVERFLOW_POLICY: QueueOverflowPolicy = QueueOverflowPolicy::DropOldest;
pub const DEFAULT_OUTBOUND_OVERFLOW_POLICY: QueueOverflowPolicy = QueueOverflowPolicy::Fail;
pub const DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT: usize = 16_384;

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
    #[error("{queue} queue is full")]
    QueueFull { queue: String },
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
        pubkey: [u8; 33],
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
    Shutdown,
}

struct OperationWaiter {
    op_id: String,
    completion: oneshot::Sender<std::result::Result<CompletedOperation, BridgeError>>,
}

struct QueuedOutbound {
    event: Event,
    request_id: Option<String>,
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
        mut signer: SigningDevice,
        config: BridgeConfig,
    ) -> Result<Self>
    where
        A: RelayAdapter + 'static,
    {
        adapter.connect().await?;
        let filters = signer
            .subscription_filters()
            .map_err(|e| anyhow!(e.to_string()))?;
        adapter.subscribe(filters).await?;

        let config = validate_config(config)?;
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<BridgeCommand>(config.command_queue_capacity);

        let join_handle = tokio::spawn(async move {
            let mut waiters: HashMap<String, OperationWaiter> = HashMap::new();
            let mut command_queue: VecDeque<BridgeCommand> = VecDeque::new();
            let mut inbound_queue: VecDeque<Event> = VecDeque::new();
            let mut outbound_queue: VecDeque<QueuedOutbound> = VecDeque::new();
            let mut seen_inbound_ids: HashSet<String> = HashSet::new();
            let mut seen_inbound_order: VecDeque<String> = VecDeque::new();
            let mut adapter = adapter;
            let mut expire_tick = tokio::time::interval(config.expire_tick);
            let mut shutdown = false;

            loop {
                if let Some(cmd) = command_queue.pop_front() {
                    let should_shutdown = process_command(
                        &mut signer,
                        &mut waiters,
                        &mut outbound_queue,
                        &config,
                        cmd,
                    );
                    if should_shutdown {
                        shutdown = true;
                    }
                    continue;
                }

                if let Some(queued) = outbound_queue.pop_front() {
                    let request_id = queued.request_id.clone();
                    if let Err(err) = adapter.publish(queued.event).await {
                        warn!(%err, "bridge publish failed");
                        if let Some(request_id) = request_id {
                            fail_request_and_dispatch(
                                &mut signer,
                                &mut waiters,
                                &mut outbound_queue,
                                &config,
                                request_id,
                                format!("relay publish failed: {err}"),
                            );
                        }
                    }
                    continue;
                }

                if let Some(event) = inbound_queue.pop_front() {
                    match signer.apply(SignerInput::ProcessEvent { event }) {
                        Ok(effects) => dispatch_effects(
                            &mut signer,
                            &mut waiters,
                            &mut outbound_queue,
                            &config,
                            effects,
                            None,
                        ),
                        Err(err) => warn!(%err, "signer process_event failed"),
                    }
                    continue;
                }

                if shutdown {
                    for (_, waiter) in waiters.drain() {
                        let _ = waiter
                            .completion
                            .send(Err(BridgeError::CommandChannelClosed));
                    }
                    let _ = adapter.disconnect().await;
                    break;
                }

                tokio::select! {
                    _ = expire_tick.tick() => {
                        match signer.apply(SignerInput::Expire { now: now_unix_secs() }) {
                            Ok(effects) => dispatch_effects(
                                &mut signer,
                                &mut waiters,
                                &mut outbound_queue,
                                &config,
                                effects,
                                None,
                            ),
                            Err(err) => warn!(%err, "signer expire failed"),
                        }
                    }
                    Some(cmd) = cmd_rx.recv() => {
                        enqueue_command(&mut command_queue, cmd, &config);
                    }
                    inbound = adapter.next_event() => {
                        match inbound {
                            Ok(event) => {
                                let event_id = event.id.to_hex();
                                let dropped = enqueue_inbound(
                                    &mut inbound_queue,
                                    &mut seen_inbound_ids,
                                    &mut seen_inbound_order,
                                    event,
                                    &config,
                                );
                                if dropped {
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
        pubkey: [u8; 33],
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

fn validate_config(config: BridgeConfig) -> Result<BridgeConfig> {
    if config.command_queue_capacity == 0 {
        return Err(anyhow!(
            "bridge.command_queue_capacity must be greater than zero"
        ));
    }
    if config.inbound_queue_capacity == 0 {
        return Err(anyhow!(
            "bridge.inbound_queue_capacity must be greater than zero"
        ));
    }
    if config.outbound_queue_capacity == 0 {
        return Err(anyhow!(
            "bridge.outbound_queue_capacity must be greater than zero"
        ));
    }
    if config.inbound_dedupe_cache_limit == 0 {
        return Err(anyhow!(
            "bridge.inbound_dedupe_cache_limit must be greater than zero"
        ));
    }
    Ok(config)
}

fn process_command(
    signer: &mut SigningDevice,
    waiters: &mut HashMap<String, OperationWaiter>,
    outbound_queue: &mut VecDeque<QueuedOutbound>,
    config: &BridgeConfig,
    cmd: BridgeCommand,
) -> bool {
    match cmd {
        BridgeCommand::Shutdown => true,
        BridgeCommand::Sign {
            op_id,
            message,
            completion,
        } => {
            let input = SignerInput::BeginSign { message };
            process_operation_command(
                signer,
                waiters,
                outbound_queue,
                config,
                op_id,
                completion,
                input,
            );
            false
        }
        BridgeCommand::Ecdh {
            op_id,
            pubkey,
            completion,
        } => {
            let input = SignerInput::BeginEcdh { pubkey };
            process_operation_command(
                signer,
                waiters,
                outbound_queue,
                config,
                op_id,
                completion,
                input,
            );
            false
        }
        BridgeCommand::Ping {
            op_id,
            peer,
            completion,
        } => {
            let input = SignerInput::BeginPing { peer };
            process_operation_command(
                signer,
                waiters,
                outbound_queue,
                config,
                op_id,
                completion,
                input,
            );
            false
        }
        BridgeCommand::Onboard {
            op_id,
            peer,
            completion,
        } => {
            let input = SignerInput::BeginOnboard { peer };
            process_operation_command(
                signer,
                waiters,
                outbound_queue,
                config,
                op_id,
                completion,
                input,
            );
            false
        }
        BridgeCommand::SnapshotState { reply } => {
            let _ = reply.send(Ok(signer.state().clone()));
            false
        }
        BridgeCommand::Status { reply } => {
            let _ = reply.send(Ok(signer.status()));
            false
        }
        BridgeCommand::Policies { reply } => {
            let _ = reply.send(Ok(signer.policies().clone()));
            false
        }
        BridgeCommand::SetPolicy {
            peer,
            policy,
            reply,
        } => {
            let result = signer
                .set_peer_policy(&peer, policy)
                .map_err(|err| BridgeError::Internal(err.to_string()));
            let _ = reply.send(result);
            false
        }
    }
}

fn process_operation_command(
    signer: &mut SigningDevice,
    waiters: &mut HashMap<String, OperationWaiter>,
    outbound_queue: &mut VecDeque<QueuedOutbound>,
    config: &BridgeConfig,
    op_id: String,
    completion: oneshot::Sender<std::result::Result<CompletedOperation, BridgeError>>,
    input: SignerInput,
) {
    let op_kind = signer_input_kind(&input);
    match signer.apply(input) {
        Ok(effects) => {
            if let Some(request_id) = effects.latest_request_id.clone() {
                info!(op_kind = op_kind, op_id = %op_id, request_id = %request_id, "operation started");
                waiters.insert(request_id, OperationWaiter { op_id, completion });
            } else {
                let _ =
                    completion.send(Err(BridgeError::Internal("missing request id".to_string())));
                return;
            }
            dispatch_effects(signer, waiters, outbound_queue, config, effects, None);
        }
        Err(err) => {
            let _ = completion.send(Err(BridgeError::Internal(err.to_string())));
        }
    }
}

fn dispatch_effects(
    signer: &mut SigningDevice,
    waiters: &mut HashMap<String, OperationWaiter>,
    outbound_queue: &mut VecDeque<QueuedOutbound>,
    config: &BridgeConfig,
    effects: SignerEffects,
    request_hint: Option<String>,
) {
    let request_id = request_hint.or(effects.latest_request_id.clone());

    for event in effects.outbound {
        let event_id = event.id.to_hex();
        if let Some(failed_request_id) = enqueue_outbound(
            outbound_queue,
            QueuedOutbound {
                event,
                request_id: request_id.clone(),
            },
            config,
        ) {
            fail_request_and_dispatch(
                signer,
                waiters,
                outbound_queue,
                config,
                failed_request_id,
                "outbound queue overflow".to_string(),
            );
        } else {
            info!(event_id = %event_id, request_id = ?request_id, "outbound event queued");
        }
    }

    for failure in effects.failures {
        resolve_failure(waiters, failure);
    }
    for completion in effects.completions {
        let request_id = completion.request_id().to_string();
        let completion_kind = completed_operation_kind(&completion);
        info!(request_id = %request_id, kind = completion_kind, "operation completed");
        if let Some(waiter) = waiters.remove(&request_id) {
            let _ = waiter.completion.send(Ok(completion));
        }
    }
}

fn fail_request_and_dispatch(
    signer: &mut SigningDevice,
    waiters: &mut HashMap<String, OperationWaiter>,
    outbound_queue: &mut VecDeque<QueuedOutbound>,
    config: &BridgeConfig,
    request_id: String,
    message: String,
) {
    match signer.apply(SignerInput::FailRequest {
        request_id,
        code: OperationFailureCode::PeerRejected,
        message,
    }) {
        Ok(effects) => dispatch_effects(signer, waiters, outbound_queue, config, effects, None),
        Err(err) => warn!(%err, "signer fail_request failed"),
    }
}

fn enqueue_command(queue: &mut VecDeque<BridgeCommand>, cmd: BridgeCommand, config: &BridgeConfig) {
    if queue.len() < config.command_queue_capacity {
        queue.push_back(cmd);
        return;
    }

    match config.command_overflow_policy {
        QueueOverflowPolicy::Fail => {
            reject_command(
                cmd,
                BridgeError::QueueFull {
                    queue: "command".to_string(),
                },
            );
        }
        QueueOverflowPolicy::DropOldest => {
            if let Some(oldest) = queue.pop_front() {
                reject_command(
                    oldest,
                    BridgeError::QueueFull {
                        queue: "command".to_string(),
                    },
                );
            }
            queue.push_back(cmd);
        }
    }
}

fn enqueue_inbound(
    queue: &mut VecDeque<Event>,
    seen_ids: &mut HashSet<String>,
    seen_order: &mut VecDeque<String>,
    event: Event,
    config: &BridgeConfig,
) -> bool {
    let event_id = event.id.to_hex();
    if seen_ids.contains(&event_id) {
        return false;
    }
    seen_ids.insert(event_id.clone());
    seen_order.push_back(event_id);
    while seen_order.len() > config.inbound_dedupe_cache_limit {
        if let Some(oldest) = seen_order.pop_front() {
            seen_ids.remove(&oldest);
        }
    }

    if queue.len() < config.inbound_queue_capacity {
        queue.push_back(event);
        return false;
    }

    match config.inbound_overflow_policy {
        QueueOverflowPolicy::Fail => true,
        QueueOverflowPolicy::DropOldest => {
            let _ = queue.pop_front();
            queue.push_back(event);
            false
        }
    }
}

fn enqueue_outbound(
    queue: &mut VecDeque<QueuedOutbound>,
    outbound: QueuedOutbound,
    config: &BridgeConfig,
) -> Option<String> {
    if queue.len() < config.outbound_queue_capacity {
        queue.push_back(outbound);
        return None;
    }

    match config.outbound_overflow_policy {
        QueueOverflowPolicy::Fail => outbound.request_id,
        QueueOverflowPolicy::DropOldest => {
            let dropped = queue.pop_front().and_then(|value| value.request_id);
            queue.push_back(outbound);
            dropped
        }
    }
}

fn reject_command(cmd: BridgeCommand, error: BridgeError) {
    match cmd {
        BridgeCommand::Sign { completion, .. }
        | BridgeCommand::Ecdh { completion, .. }
        | BridgeCommand::Ping { completion, .. }
        | BridgeCommand::Onboard { completion, .. } => {
            let _ = completion.send(Err(error));
        }
        BridgeCommand::SnapshotState { reply } => {
            let _ = reply.send(Err(error));
        }
        BridgeCommand::Status { reply } => {
            let _ = reply.send(Err(error));
        }
        BridgeCommand::Policies { reply } => {
            let _ = reply.send(Err(error));
        }
        BridgeCommand::SetPolicy { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        BridgeCommand::Shutdown => {}
    }
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
            code = ?failure.code,
            "bridge operation failed"
        );
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn signer_input_kind(input: &SignerInput) -> &'static str {
    match input {
        SignerInput::BeginSign { .. } => "sign",
        SignerInput::BeginEcdh { .. } => "ecdh",
        SignerInput::BeginPing { .. } => "ping",
        SignerInput::BeginOnboard { .. } => "onboard",
        SignerInput::ProcessEvent { .. } => "process_event",
        SignerInput::Expire { .. } => "expire",
        SignerInput::FailRequest { .. } => "fail_request",
    }
}

fn completed_operation_kind(operation: &CompletedOperation) -> &'static str {
    match operation {
        CompletedOperation::Sign { .. } => "sign",
        CompletedOperation::Ecdh { .. } => "ecdh",
        CompletedOperation::Ping { .. } => "ping",
        CompletedOperation::Onboard { .. } => "onboard",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_signer::PendingOpType;

    fn waiter_channel() -> (
        OperationWaiter,
        oneshot::Receiver<std::result::Result<CompletedOperation, BridgeError>>,
    ) {
        let (tx, rx) = oneshot::channel();
        (
            OperationWaiter {
                op_id: "op-1".to_string(),
                completion: tx,
            },
            rx,
        )
    }

    #[tokio::test]
    async fn resolve_failure_maps_timeout_code() {
        let mut waiters = HashMap::new();
        let (waiter, rx) = waiter_channel();
        waiters.insert("req-timeout".to_string(), waiter);

        resolve_failure(
            &mut waiters,
            OperationFailure {
                request_id: "req-timeout".to_string(),
                op_type: PendingOpType::Sign,
                code: OperationFailureCode::Timeout,
                message: "timed out".to_string(),
                failed_peer: None,
            },
        );

        match rx.await.expect("recv").expect_err("must fail") {
            BridgeError::LockedPeerTimeout { request_id } => assert_eq!(request_id, "req-timeout"),
            other => panic!("unexpected bridge error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_failure_maps_invalid_locked_peer_code() {
        let mut waiters = HashMap::new();
        let (waiter, rx) = waiter_channel();
        waiters.insert("req-invalid".to_string(), waiter);

        resolve_failure(
            &mut waiters,
            OperationFailure {
                request_id: "req-invalid".to_string(),
                op_type: PendingOpType::Ecdh,
                code: OperationFailureCode::InvalidLockedPeerResponse,
                message: "invalid response payload".to_string(),
                failed_peer: Some("peer-1".to_string()),
            },
        );

        match rx.await.expect("recv").expect_err("must fail") {
            BridgeError::InvalidLockedPeerResponse {
                request_id,
                message,
            } => {
                assert_eq!(request_id, "req-invalid");
                assert_eq!(message, "invalid response payload");
            }
            other => panic!("unexpected bridge error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_failure_maps_peer_rejected_code() {
        let mut waiters = HashMap::new();
        let (waiter, rx) = waiter_channel();
        waiters.insert("req-reject".to_string(), waiter);

        resolve_failure(
            &mut waiters,
            OperationFailure {
                request_id: "req-reject".to_string(),
                op_type: PendingOpType::Ping,
                code: OperationFailureCode::PeerRejected,
                message: "policy denied".to_string(),
                failed_peer: Some("peer-2".to_string()),
            },
        );

        match rx.await.expect("recv").expect_err("must fail") {
            BridgeError::RoundFailed {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, "req-reject");
                assert_eq!(code, "peer_rejected");
                assert_eq!(message, "policy denied");
            }
            other => panic!("unexpected bridge error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn enqueue_command_drop_oldest_rejects_oldest() {
        let config = BridgeConfig {
            command_queue_capacity: 1,
            command_overflow_policy: QueueOverflowPolicy::DropOldest,
            ..BridgeConfig::default()
        };
        let mut queue = VecDeque::new();

        let (old_tx, old_rx) = oneshot::channel();
        let old_cmd = BridgeCommand::Ping {
            op_id: "op-old".to_string(),
            peer: "peer-old".to_string(),
            completion: old_tx,
        };
        enqueue_command(&mut queue, old_cmd, &config);

        let (new_tx, new_rx) = oneshot::channel();
        let new_cmd = BridgeCommand::Ping {
            op_id: "op-new".to_string(),
            peer: "peer-new".to_string(),
            completion: new_tx,
        };
        enqueue_command(&mut queue, new_cmd, &config);

        match old_rx
            .await
            .expect("recv")
            .expect_err("old command must fail")
        {
            BridgeError::QueueFull { queue } => assert_eq!(queue, "command"),
            other => panic!("unexpected old command error: {other:?}"),
        }

        let queued = queue.pop_front().expect("new command queued");
        assert!(matches!(
            queued,
            BridgeCommand::Ping {
                ref op_id,
                ref peer,
                ..
            } if op_id == "op-new" && peer == "peer-new"
        ));

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), new_rx)
                .await
                .is_err(),
            "new command should not be rejected when queued"
        );
    }
}
