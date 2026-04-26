use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use anyhow::{Result, anyhow};
use bifrost_core::types::PeerPolicyOverride;
use bifrost_signer::{
    CompletedOperation, DeviceConfig, DeviceConfigPatch, DeviceState, DeviceStatus,
    OperationFailure, OperationFailureCode, PeerPermissionState, PeerStatus, PendingOpType,
    PersistenceHint, RuntimeMetadata, RuntimeReadiness, RuntimeStatusSummary, SignerActivity,
    SignerEffects, SignerInput, SigningDevice,
};
use nostr::{Event, Filter};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueOverflowPolicy {
    Fail,
    DropOldest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestPhase {
    Created,
    AwaitingResponses,
    Completed,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundEventDisposition {
    /// The event is addressed to this runtime and was queued for processing.
    Queued,
    /// The event is duplicate, not addressed to this runtime, or otherwise benign.
    Ignored,
    /// The event was routable but could not be queued under the configured policy.
    DroppedOverflow,
}

pub const DEFAULT_EXPIRE_TICK_MS: u64 = 1_000;
pub const DEFAULT_COMMAND_QUEUE_CAPACITY: usize = 128;
pub const DEFAULT_INBOUND_QUEUE_CAPACITY: usize = 4_096;
pub const DEFAULT_OUTBOUND_QUEUE_CAPACITY: usize = 1_024;
pub const DEFAULT_COMMAND_OVERFLOW_POLICY: QueueOverflowPolicy = QueueOverflowPolicy::Fail;
pub const DEFAULT_INBOUND_OVERFLOW_POLICY: QueueOverflowPolicy = QueueOverflowPolicy::DropOldest;
pub const DEFAULT_OUTBOUND_OVERFLOW_POLICY: QueueOverflowPolicy = QueueOverflowPolicy::Fail;
pub const DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT: usize = 16_384;

#[derive(Debug, thiserror::Error)]
pub enum BridgeCoreError {
    #[error("{queue} queue is full")]
    QueueFull { queue: String },
    #[error("bridge internal failure: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    pub expire_tick: Duration,
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

#[derive(Debug, Clone)]
pub enum BridgeCommand {
    Sign { message: [u8; 32] },
    Ecdh { pubkey: [u8; 32] },
    Ping { peer: String },
    Onboard { peer: String },
}

#[derive(Debug)]
struct QueuedOutbound {
    event: Event,
    request_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OutboundEvent {
    pub event: Event,
    pub request_id: Option<String>,
}

pub struct BridgeCore {
    signer: SigningDevice,
    config: BridgeConfig,
    command_queue: VecDeque<BridgeCommand>,
    inbound_queue: VecDeque<Event>,
    outbound_queue: VecDeque<QueuedOutbound>,
    seen_inbound_ids: HashSet<String>,
    seen_inbound_order: VecDeque<String>,
    completions: VecDeque<CompletedOperation>,
    failures: VecDeque<OperationFailure>,
    activities: VecDeque<SignerActivity>,
    request_phases: HashMap<String, RequestPhase>,
    last_expire_at_ms: u64,
    persistence_hint: PersistenceHint,
}

pub trait RouterPort {
    type Error;

    fn submit_command(&mut self, cmd: BridgeCommand) -> std::result::Result<String, Self::Error>;
    fn enqueue_inbound_event(&mut self, event: Event) -> InboundEventDisposition;
    fn tick(&mut self, now_unix_ms: u64);
    fn drain_outbound_packets(&mut self) -> Vec<OutboundEvent>;
    fn drain_completions(&mut self) -> Vec<CompletedOperation>;
    fn drain_failures(&mut self) -> Vec<OperationFailure>;
    fn drain_activities(&mut self) -> Vec<SignerActivity>;
    fn fail_request(
        &mut self,
        request_id: String,
        message: String,
    ) -> std::result::Result<(), Self::Error>;
    fn status(&self) -> DeviceStatus;
    fn snapshot_state(&self) -> DeviceState;
    fn take_persistence_hint(&mut self) -> PersistenceHint;
    fn subscription_filters(&self) -> Result<Vec<Filter>>;
    fn request_phase(&self, request_id: &str) -> Option<RequestPhase>;
    fn request_phases(&self) -> HashMap<String, RequestPhase>;
}

impl BridgeCore {
    pub fn new(signer: SigningDevice, config: BridgeConfig) -> Result<Self> {
        let config = validate_config(config)?;
        Ok(Self {
            signer,
            config,
            command_queue: VecDeque::new(),
            inbound_queue: VecDeque::new(),
            outbound_queue: VecDeque::new(),
            seen_inbound_ids: HashSet::new(),
            seen_inbound_order: VecDeque::new(),
            completions: VecDeque::new(),
            failures: VecDeque::new(),
            activities: VecDeque::new(),
            request_phases: HashMap::new(),
            last_expire_at_ms: 0,
            persistence_hint: PersistenceHint::None,
        })
    }

    pub fn subscription_filters(&self) -> Result<Vec<Filter>> {
        self.signer
            .subscription_filters()
            .map_err(|e| anyhow!(e.to_string()))
    }

    pub fn is_event_routable(&self, event: &Event) -> bool {
        self.signer.has_exact_local_recipient_tag(event)
    }

    pub fn enqueue_command(
        &mut self,
        cmd: BridgeCommand,
    ) -> std::result::Result<(), BridgeCoreError> {
        if self.command_queue.len() < self.config.command_queue_capacity {
            self.command_queue.push_back(cmd);
            return Ok(());
        }

        match self.config.command_overflow_policy {
            QueueOverflowPolicy::Fail => Err(BridgeCoreError::QueueFull {
                queue: "command".to_string(),
            }),
            QueueOverflowPolicy::DropOldest => {
                let _ = self.command_queue.pop_front();
                self.command_queue.push_back(cmd);
                Ok(())
            }
        }
    }

    pub fn submit_command(
        &mut self,
        cmd: BridgeCommand,
    ) -> std::result::Result<String, BridgeCoreError> {
        let op_type = pending_type_for_command(&cmd);
        let input = match cmd {
            BridgeCommand::Sign { message } => SignerInput::BeginSign { message },
            BridgeCommand::Ecdh { pubkey } => SignerInput::BeginEcdh { pubkey },
            BridgeCommand::Ping { peer } => SignerInput::BeginPing { peer },
            BridgeCommand::Onboard { peer } => SignerInput::BeginOnboard { peer },
        };

        match self.signer.apply(input) {
            Ok(effects) => {
                let request_id = effects
                    .latest_request_id
                    .clone()
                    .ok_or_else(|| BridgeCoreError::Internal("missing request id".to_string()))?;
                self.request_phases
                    .insert(request_id.clone(), RequestPhase::Created);
                self.dispatch_effects(effects, Some(request_id.clone()));
                Ok(request_id)
            }
            Err(err) => {
                self.failures.push_back(OperationFailure {
                    request_id: "local-command".to_string(),
                    op_type,
                    code: OperationFailureCode::PeerRejected,
                    message: err.to_string(),
                    failed_peer: None,
                });
                Err(BridgeCoreError::Internal(err.to_string()))
            }
        }
    }

    pub fn enqueue_inbound_event(&mut self, event: Event) -> InboundEventDisposition {
        if !self.is_event_routable(&event) {
            return InboundEventDisposition::Ignored;
        }

        let event_id = event.id.to_hex();
        if self.seen_inbound_ids.contains(&event_id) {
            return InboundEventDisposition::Ignored;
        }

        self.seen_inbound_ids.insert(event_id.clone());
        self.seen_inbound_order.push_back(event_id);
        while self.seen_inbound_order.len() > self.config.inbound_dedupe_cache_limit {
            if let Some(oldest) = self.seen_inbound_order.pop_front() {
                self.seen_inbound_ids.remove(&oldest);
            }
        }

        if self.inbound_queue.len() < self.config.inbound_queue_capacity {
            self.inbound_queue.push_back(event);
            return InboundEventDisposition::Queued;
        }

        match self.config.inbound_overflow_policy {
            QueueOverflowPolicy::Fail => InboundEventDisposition::DroppedOverflow,
            QueueOverflowPolicy::DropOldest => {
                let _ = self.inbound_queue.pop_front();
                self.inbound_queue.push_back(event);
                InboundEventDisposition::Queued
            }
        }
    }

    pub fn tick(&mut self, now_unix_ms: u64) {
        if self.should_expire(now_unix_ms) {
            let signer_now_secs = now_unix_ms / 1_000;
            match self.signer.apply(SignerInput::Expire {
                now: signer_now_secs,
            }) {
                Ok(effects) => self.dispatch_effects(effects, None),
                Err(err) => self.push_internal_failure(
                    "internal-expire".to_string(),
                    PendingOpType::Ping,
                    err.to_string(),
                ),
            }
            self.last_expire_at_ms = now_unix_ms;
        }

        while let Some(cmd) = self.command_queue.pop_front() {
            self.process_command(cmd);
        }

        while let Some(event) = self.inbound_queue.pop_front() {
            let event_id = event.id.to_hex();
            match self.signer.apply(SignerInput::ProcessEvent { event }) {
                Ok(effects) => self.dispatch_effects(effects, None),
                Err(err) => self.push_internal_failure(
                    format!("internal-inbound-{event_id}"),
                    PendingOpType::Ping,
                    err.to_string(),
                ),
            }
        }
    }

    pub fn status(&self) -> DeviceStatus {
        self.signer.status()
    }

    pub fn read_config(&self) -> DeviceConfig {
        self.signer.read_config()
    }

    pub fn runtime_metadata(&self) -> RuntimeMetadata {
        self.signer.runtime_metadata()
    }

    pub fn peer_status(&self) -> Vec<PeerStatus> {
        self.signer.peer_status()
    }

    pub fn readiness(&self) -> RuntimeReadiness {
        self.signer.readiness()
    }

    pub fn runtime_status(&self) -> RuntimeStatusSummary {
        self.signer.runtime_status()
    }

    pub fn wipe_state(&mut self) {
        self.signer.wipe_state();
        self.command_queue.clear();
        self.inbound_queue.clear();
        self.outbound_queue.clear();
        self.seen_inbound_ids.clear();
        self.seen_inbound_order.clear();
        self.completions.clear();
        self.failures.clear();
        self.activities.clear();
        self.request_phases.clear();
        self.last_expire_at_ms = 0;
        self.persistence_hint = PersistenceHint::Immediate;
    }

    pub fn peer_permission_states(&self) -> Vec<PeerPermissionState> {
        self.signer.peer_permission_states()
    }

    pub fn snapshot_state(&self) -> DeviceState {
        self.signer.state().clone()
    }

    pub fn set_policy_override(
        &mut self,
        peer: String,
        policy: PeerPolicyOverride,
    ) -> std::result::Result<(), BridgeCoreError> {
        self.signer
            .set_peer_policy_override(&peer, policy)
            .map_err(|e| BridgeCoreError::Internal(e.to_string()))?;
        self.persistence_hint = self.persistence_hint.merge(PersistenceHint::Immediate);
        Ok(())
    }

    pub fn clear_policy_overrides(&mut self) {
        self.signer.clear_peer_policy_overrides();
        self.persistence_hint = self.persistence_hint.merge(PersistenceHint::Immediate);
    }

    pub fn update_config(
        &mut self,
        patch: DeviceConfigPatch,
    ) -> std::result::Result<(), BridgeCoreError> {
        self.signer
            .update_config(patch)
            .map_err(|e| BridgeCoreError::Internal(e.to_string()))?;
        self.persistence_hint = self.persistence_hint.merge(PersistenceHint::Immediate);
        Ok(())
    }

    pub fn take_persistence_hint(&mut self) -> PersistenceHint {
        let hint = self.persistence_hint;
        self.persistence_hint = PersistenceHint::None;
        hint
    }

    pub fn drain_outbound_events(&mut self) -> Vec<Event> {
        self.drain_outbound_packets()
            .into_iter()
            .map(|queued| queued.event)
            .collect()
    }

    pub fn drain_outbound_packets(&mut self) -> Vec<OutboundEvent> {
        self.outbound_queue
            .drain(..)
            .map(|queued| OutboundEvent {
                event: queued.event,
                request_id: queued.request_id,
            })
            .collect()
    }

    pub fn drain_completions(&mut self) -> Vec<CompletedOperation> {
        self.completions.drain(..).collect()
    }

    pub fn drain_failures(&mut self) -> Vec<OperationFailure> {
        self.failures.drain(..).collect()
    }

    pub fn drain_activities(&mut self) -> Vec<SignerActivity> {
        self.activities.drain(..).collect()
    }

    pub fn request_phase(&self, request_id: &str) -> Option<RequestPhase> {
        self.request_phases.get(request_id).copied()
    }

    pub fn request_phases(&self) -> HashMap<String, RequestPhase> {
        self.request_phases.clone()
    }

    pub fn fail_request(
        &mut self,
        request_id: String,
        message: String,
    ) -> std::result::Result<(), BridgeCoreError> {
        match self.signer.apply(SignerInput::FailRequest {
            request_id,
            code: OperationFailureCode::PeerRejected,
            message,
        }) {
            Ok(effects) => {
                self.dispatch_effects(effects, None);
                Ok(())
            }
            Err(err) => {
                self.push_internal_failure(
                    "local-fail-request".to_string(),
                    PendingOpType::Ping,
                    err.to_string(),
                );
                Err(BridgeCoreError::Internal(err.to_string()))
            }
        }
    }

    fn should_expire(&self, now_unix_ms: u64) -> bool {
        if self.last_expire_at_ms == 0 {
            return true;
        }

        let expire_tick_ms = u64::try_from(self.config.expire_tick.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        now_unix_ms.saturating_sub(self.last_expire_at_ms) >= expire_tick_ms
    }

    fn process_command(&mut self, cmd: BridgeCommand) {
        let op_type = pending_type_for_command(&cmd);
        let input = match cmd {
            BridgeCommand::Sign { message } => SignerInput::BeginSign { message },
            BridgeCommand::Ecdh { pubkey } => SignerInput::BeginEcdh { pubkey },
            BridgeCommand::Ping { peer } => SignerInput::BeginPing { peer },
            BridgeCommand::Onboard { peer } => SignerInput::BeginOnboard { peer },
        };

        match self.signer.apply(input) {
            Ok(effects) => self.dispatch_effects(effects, None),
            Err(err) => self.failures.push_back(OperationFailure {
                request_id: "local-command".to_string(),
                op_type,
                code: OperationFailureCode::PeerRejected,
                message: err.to_string(),
                failed_peer: None,
            }),
        }
    }

    fn dispatch_effects(&mut self, effects: SignerEffects, request_hint: Option<String>) {
        self.persistence_hint = self.persistence_hint.merge(effects.persistence_hint);
        let request_id = request_hint.or(effects.latest_request_id.clone());
        let has_outbound = !effects.outbound.is_empty();

        if let Some(request_id) = request_id.as_ref() {
            self.request_phases
                .entry(request_id.clone())
                .or_insert(RequestPhase::Created);
            if has_outbound {
                self.request_phases
                    .insert(request_id.clone(), RequestPhase::AwaitingResponses);
            }
        }

        for event in effects.outbound {
            if let Some(failed_request_id) = self.enqueue_outbound(QueuedOutbound {
                event,
                request_id: request_id.clone(),
            }) {
                self.fail_request_and_dispatch(
                    failed_request_id,
                    "outbound queue overflow".to_string(),
                );
            }
        }

        for completion in effects.completions {
            self.request_phases
                .insert(completion.request_id().to_string(), RequestPhase::Completed);
            self.completions.push_back(completion);
        }

        for failure in effects.failures {
            self.request_phases
                .insert(failure.request_id.clone(), RequestPhase::Failed);
            self.failures.push_back(failure);
        }

        for activity in effects.activities {
            self.activities.push_back(activity);
        }
    }

    fn enqueue_outbound(&mut self, outbound: QueuedOutbound) -> Option<String> {
        if self.outbound_queue.len() < self.config.outbound_queue_capacity {
            self.outbound_queue.push_back(outbound);
            return None;
        }

        match self.config.outbound_overflow_policy {
            QueueOverflowPolicy::Fail => outbound.request_id,
            QueueOverflowPolicy::DropOldest => {
                let dropped = self
                    .outbound_queue
                    .pop_front()
                    .and_then(|value| value.request_id);
                self.outbound_queue.push_back(outbound);
                dropped
            }
        }
    }

    fn fail_request_and_dispatch(&mut self, request_id: String, message: String) {
        match self.signer.apply(SignerInput::FailRequest {
            request_id,
            code: OperationFailureCode::PeerRejected,
            message,
        }) {
            Ok(effects) => self.dispatch_effects(effects, None),
            Err(err) => self.failures.push_back(OperationFailure {
                request_id: "local-fail-request".to_string(),
                op_type: bifrost_signer::PendingOpType::Ping,
                code: OperationFailureCode::PeerRejected,
                message: err.to_string(),
                failed_peer: None,
            }),
        }
    }

    fn push_internal_failure(
        &mut self,
        request_id: String,
        op_type: PendingOpType,
        message: String,
    ) {
        self.failures.push_back(OperationFailure {
            request_id,
            op_type,
            code: OperationFailureCode::PeerRejected,
            message,
            failed_peer: None,
        });
    }
}

impl RouterPort for BridgeCore {
    type Error = BridgeCoreError;

    fn submit_command(&mut self, cmd: BridgeCommand) -> std::result::Result<String, Self::Error> {
        BridgeCore::submit_command(self, cmd)
    }

    fn enqueue_inbound_event(&mut self, event: Event) -> InboundEventDisposition {
        BridgeCore::enqueue_inbound_event(self, event)
    }

    fn tick(&mut self, now_unix_ms: u64) {
        BridgeCore::tick(self, now_unix_ms)
    }

    fn drain_outbound_packets(&mut self) -> Vec<OutboundEvent> {
        BridgeCore::drain_outbound_packets(self)
    }

    fn drain_completions(&mut self) -> Vec<CompletedOperation> {
        BridgeCore::drain_completions(self)
    }

    fn drain_failures(&mut self) -> Vec<OperationFailure> {
        BridgeCore::drain_failures(self)
    }

    fn drain_activities(&mut self) -> Vec<SignerActivity> {
        BridgeCore::drain_activities(self)
    }

    fn fail_request(
        &mut self,
        request_id: String,
        message: String,
    ) -> std::result::Result<(), Self::Error> {
        BridgeCore::fail_request(self, request_id, message)
    }

    fn status(&self) -> DeviceStatus {
        BridgeCore::status(self)
    }

    fn snapshot_state(&self) -> DeviceState {
        BridgeCore::snapshot_state(self)
    }

    fn take_persistence_hint(&mut self) -> PersistenceHint {
        BridgeCore::take_persistence_hint(self)
    }

    fn subscription_filters(&self) -> Result<Vec<Filter>> {
        BridgeCore::subscription_filters(self)
    }

    fn request_phase(&self, request_id: &str) -> Option<RequestPhase> {
        BridgeCore::request_phase(self, request_id)
    }

    fn request_phases(&self) -> HashMap<String, RequestPhase> {
        BridgeCore::request_phases(self)
    }
}

fn validate_config(config: BridgeConfig) -> Result<BridgeConfig> {
    if config.expire_tick.is_zero() {
        return Err(anyhow!("bridge.expire_tick must be greater than zero"));
    }
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

fn pending_type_for_command(command: &BridgeCommand) -> PendingOpType {
    match command {
        BridgeCommand::Sign { .. } => PendingOpType::Sign,
        BridgeCommand::Ecdh { .. } => PendingOpType::Ecdh,
        BridgeCommand::Ping { .. } => PendingOpType::Ping,
        BridgeCommand::Onboard { .. } => PendingOpType::Onboard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_core::types::{GroupPackage, SharePackage};
    use bifrost_signer::{DeviceConfig, DeviceState, SignerActivityAction, SigningDevice};
    use frostr_utils::{CreateKeysetConfig, create_keyset};
    use nostr::{Alphabet, Event, SingleLetterTag, TagKind};

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn build_signer(group: &GroupPackage, share: &SharePackage) -> SigningDevice {
        let peers = group
            .members
            .iter()
            .filter(|member| member.idx != share.idx)
            .map(|member| encode_hex(&member.pubkey[1..]))
            .collect::<Vec<_>>();
        SigningDevice::new(
            group.clone(),
            share.clone(),
            peers,
            DeviceState::new(share.idx, share.seckey),
            DeviceConfig::default(),
        )
        .expect("build signer")
    }

    fn ping_event_peer(event: &Event) -> String {
        let p_tag = SingleLetterTag::lowercase(Alphabet::P);
        event
            .tags
            .iter()
            .find_map(|tag| match tag.kind() {
                TagKind::SingleLetter(letter) if letter == p_tag => {
                    tag.content().map(str::to_string)
                }
                _ => None,
            })
            .expect("peer p-tag")
    }

    fn ping_request_event(group: &GroupPackage, share: &SharePackage, local_pubkey: &str) -> Event {
        let mut signer = build_signer(group, share);
        signer
            .initiate_ping(local_pubkey)
            .expect("remote ping request")
            .into_iter()
            .next()
            .expect("one ping event")
    }

    #[test]
    fn validate_config_rejects_zero_capacities() {
        let cfg = BridgeConfig {
            command_queue_capacity: 0,
            ..BridgeConfig::default()
        };
        assert!(validate_config(cfg).is_err());

        let cfg = BridgeConfig {
            inbound_queue_capacity: 0,
            ..BridgeConfig::default()
        };
        assert!(validate_config(cfg).is_err());

        let cfg = BridgeConfig {
            outbound_queue_capacity: 0,
            ..BridgeConfig::default()
        };
        assert!(validate_config(cfg).is_err());

        let cfg = BridgeConfig {
            inbound_dedupe_cache_limit: 0,
            ..BridgeConfig::default()
        };
        assert!(validate_config(cfg).is_err());
    }

    #[test]
    fn pending_type_for_command_maps_variants() {
        assert!(matches!(
            pending_type_for_command(&BridgeCommand::Sign { message: [0u8; 32] }),
            PendingOpType::Sign
        ));
        assert!(matches!(
            pending_type_for_command(&BridgeCommand::Ecdh { pubkey: [2u8; 32] }),
            PendingOpType::Ecdh
        ));
        assert!(matches!(
            pending_type_for_command(&BridgeCommand::Ping {
                peer: "peer-a".to_string()
            }),
            PendingOpType::Ping
        ));
        assert!(matches!(
            pending_type_for_command(&BridgeCommand::Onboard {
                peer: "peer-b".to_string(),
            }),
            PendingOpType::Onboard
        ));
    }

    #[test]
    fn enqueue_command_returns_queue_full_when_capacity_is_exhausted() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let mut core = BridgeCore::new(
            build_signer(&bundle.group, &share),
            BridgeConfig {
                command_queue_capacity: 1,
                command_overflow_policy: QueueOverflowPolicy::Fail,
                ..BridgeConfig::default()
            },
        )
        .expect("bridge core");

        core.enqueue_command(BridgeCommand::Ping {
            peer: encode_hex(&bundle.group.members[1].pubkey[1..]),
        })
        .expect("first enqueue");
        let err = core
            .enqueue_command(BridgeCommand::Ping {
                peer: encode_hex(&bundle.group.members[2].pubkey[1..]),
            })
            .expect_err("second enqueue should fail");
        assert!(matches!(err, BridgeCoreError::QueueFull { queue } if queue == "command"));
    }

    #[test]
    fn enqueue_command_drop_oldest_keeps_newest_command() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let peer_a = encode_hex(&bundle.group.members[1].pubkey[1..]);
        let peer_b = encode_hex(&bundle.group.members[2].pubkey[1..]);
        let mut core = BridgeCore::new(
            build_signer(&bundle.group, &share),
            BridgeConfig {
                command_queue_capacity: 1,
                command_overflow_policy: QueueOverflowPolicy::DropOldest,
                ..BridgeConfig::default()
            },
        )
        .expect("bridge core");

        core.enqueue_command(BridgeCommand::Ping { peer: peer_a })
            .expect("first enqueue");
        core.enqueue_command(BridgeCommand::Ping {
            peer: peer_b.clone(),
        })
        .expect("drop oldest enqueue");
        core.tick(1_700_000_000_000);

        let outbound = core.drain_outbound_packets();
        assert_eq!(outbound.len(), 1);
        assert_eq!(ping_event_peer(&outbound[0].event), peer_b);
        assert_eq!(core.request_phases().len(), 1);
    }

    #[test]
    fn inbound_sign_response_activity_drains_without_responder_completion() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 2,
        })
        .expect("create keyset");
        let alice_share = bundle.shares[0].clone();
        let bob_share = bundle.shares[1].clone();
        let alice_pubkey = encode_hex(&bundle.group.members[0].pubkey[1..]);
        let bob_pubkey = encode_hex(&bundle.group.members[1].pubkey[1..]);

        let mut alice_state = DeviceState::new(alice_share.idx, alice_share.seckey);
        let mut bob_state = DeviceState::new(bob_share.idx, bob_share.seckey);
        let bob_nonces = bob_state
            .nonce_pool
            .generate_for_peer(alice_share.idx, 10)
            .expect("generate bob nonces");
        alice_state
            .nonce_pool
            .store_incoming(bob_share.idx, bob_nonces);

        let alice_signer = SigningDevice::new(
            bundle.group.clone(),
            alice_share,
            vec![bob_pubkey.clone()],
            alice_state,
            DeviceConfig::default(),
        )
        .expect("alice signer");
        let bob_signer = SigningDevice::new(
            bundle.group.clone(),
            bob_share,
            vec![alice_pubkey.clone()],
            bob_state,
            DeviceConfig::default(),
        )
        .expect("bob signer");
        let mut alice = BridgeCore::new(alice_signer, BridgeConfig::default()).expect("alice core");
        let mut bob = BridgeCore::new(bob_signer, BridgeConfig::default()).expect("bob core");

        let request_id = alice
            .submit_command(BridgeCommand::Sign {
                message: [0x77; 32],
            })
            .expect("submit sign");
        let outbound = alice.drain_outbound_packets();
        assert_eq!(outbound.len(), 1);

        assert_eq!(
            bob.enqueue_inbound_event(outbound[0].event.clone()),
            InboundEventDisposition::Queued,
        );
        bob.tick(1_700_000_000_000);

        assert!(bob.drain_completions().is_empty());
        let activities = bob.drain_activities();
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].request_id, request_id);
        assert!(matches!(activities[0].op_type, PendingOpType::Sign));
        assert_eq!(activities[0].peer, alice_pubkey);
        assert_eq!(activities[0].action, SignerActivityAction::ResponseSent);
        assert_eq!(bob.drain_outbound_packets().len(), 1);
    }

    #[test]
    fn wipe_state_resets_request_phases_and_persistence_hint() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let peer = encode_hex(&bundle.group.members[1].pubkey[1..]);
        let mut core =
            BridgeCore::new(build_signer(&bundle.group, &share), BridgeConfig::default())
                .expect("bridge core");

        core.submit_command(BridgeCommand::Ping { peer })
            .expect("submit ping");
        assert!(!core.request_phases().is_empty());

        core.wipe_state();

        assert!(core.request_phases().is_empty());
        assert!(matches!(
            core.take_persistence_hint(),
            PersistenceHint::Immediate
        ));
        assert!(matches!(
            core.take_persistence_hint(),
            PersistenceHint::None
        ));
    }

    #[test]
    fn inbound_queue_fail_policy_rejects_newest_event() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let local_pubkey = encode_hex(
            &bundle
                .group
                .members
                .iter()
                .find(|member| member.idx == share.idx)
                .expect("local member")
                .pubkey[1..],
        );
        let peer_a = bundle.shares[1].clone();
        let peer_b = bundle.shares[2].clone();
        let event_a = ping_request_event(&bundle.group, &peer_a, &local_pubkey);
        let event_b = ping_request_event(&bundle.group, &peer_b, &local_pubkey);

        let mut core = BridgeCore::new(
            build_signer(&bundle.group, &share),
            BridgeConfig {
                inbound_queue_capacity: 1,
                inbound_overflow_policy: QueueOverflowPolicy::Fail,
                ..BridgeConfig::default()
            },
        )
        .expect("bridge core");

        assert_eq!(
            core.enqueue_inbound_event(event_a),
            InboundEventDisposition::Queued,
        );
        assert_eq!(
            core.enqueue_inbound_event(event_b),
            InboundEventDisposition::DroppedOverflow,
        );
        core.tick(1_700_000_000_000);

        let outbound = core.drain_outbound_packets();
        assert_eq!(outbound.len(), 1);
        assert_eq!(
            ping_event_peer(&outbound[0].event),
            encode_hex(&bundle.group.members[1].pubkey[1..])
        );
    }

    #[test]
    fn inbound_queue_drop_oldest_keeps_newest_event() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let local_pubkey = encode_hex(
            &bundle
                .group
                .members
                .iter()
                .find(|member| member.idx == share.idx)
                .expect("local member")
                .pubkey[1..],
        );
        let peer_a = bundle.shares[1].clone();
        let peer_b = bundle.shares[2].clone();
        let event_a = ping_request_event(&bundle.group, &peer_a, &local_pubkey);
        let event_b = ping_request_event(&bundle.group, &peer_b, &local_pubkey);

        let mut core = BridgeCore::new(
            build_signer(&bundle.group, &share),
            BridgeConfig {
                inbound_queue_capacity: 1,
                inbound_overflow_policy: QueueOverflowPolicy::DropOldest,
                ..BridgeConfig::default()
            },
        )
        .expect("bridge core");

        assert_eq!(
            core.enqueue_inbound_event(event_a),
            InboundEventDisposition::Queued,
        );
        assert_eq!(
            core.enqueue_inbound_event(event_b),
            InboundEventDisposition::Queued,
        );
        core.tick(1_700_000_000_000);

        let outbound = core.drain_outbound_packets();
        assert_eq!(outbound.len(), 1);
        assert_eq!(
            ping_event_peer(&outbound[0].event),
            encode_hex(&bundle.group.members[2].pubkey[1..])
        );
    }

    #[test]
    fn dedupe_cache_eviction_allows_reprocessing_oldest_event() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let local_pubkey = encode_hex(
            &bundle
                .group
                .members
                .iter()
                .find(|member| member.idx == share.idx)
                .expect("local member")
                .pubkey[1..],
        );
        let peer_a = bundle.shares[1].clone();
        let peer_b = bundle.shares[2].clone();
        let event_a = ping_request_event(&bundle.group, &peer_a, &local_pubkey);
        let event_b = ping_request_event(&bundle.group, &peer_b, &local_pubkey);

        let mut core = BridgeCore::new(
            build_signer(&bundle.group, &share),
            BridgeConfig {
                inbound_dedupe_cache_limit: 1,
                ..BridgeConfig::default()
            },
        )
        .expect("bridge core");

        assert_eq!(
            core.enqueue_inbound_event(event_a.clone()),
            InboundEventDisposition::Queued,
        );
        assert_eq!(
            core.enqueue_inbound_event(event_b),
            InboundEventDisposition::Queued,
        );
        assert_eq!(
            core.enqueue_inbound_event(event_a),
            InboundEventDisposition::Queued,
        );
        core.tick(1_700_000_000_000);

        let outbound = core.drain_outbound_packets();
        assert_eq!(outbound.len(), 2);
    }

    #[test]
    fn duplicate_inbound_event_is_ignored_without_queueing_again() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let local_pubkey = encode_hex(
            &bundle
                .group
                .members
                .iter()
                .find(|member| member.idx == share.idx)
                .expect("local member")
                .pubkey[1..],
        );
        let peer = bundle.shares[1].clone();
        let event = ping_request_event(&bundle.group, &peer, &local_pubkey);

        let mut core =
            BridgeCore::new(build_signer(&bundle.group, &share), BridgeConfig::default())
                .expect("bridge core");

        assert_eq!(
            core.enqueue_inbound_event(event.clone()),
            InboundEventDisposition::Queued,
        );
        assert_eq!(
            core.enqueue_inbound_event(event),
            InboundEventDisposition::Ignored,
        );
        core.tick(1_700_000_000_000);

        let outbound = core.drain_outbound_packets();
        assert_eq!(outbound.len(), 1);
    }

    #[test]
    fn non_routable_inbound_event_is_ignored_without_queueing() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let wrong_recipient_pubkey = encode_hex(&bundle.group.members[2].pubkey[1..]);
        let peer = bundle.shares[1].clone();
        let event = ping_request_event(&bundle.group, &peer, &wrong_recipient_pubkey);

        let mut core =
            BridgeCore::new(build_signer(&bundle.group, &share), BridgeConfig::default())
                .expect("bridge core");

        assert_eq!(
            core.enqueue_inbound_event(event),
            InboundEventDisposition::Ignored,
        );
        core.tick(1_700_000_000_000);

        let outbound = core.drain_outbound_packets();
        assert!(outbound.is_empty());
    }

    #[test]
    fn fail_request_marks_phase_failed_and_emits_failure() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let peer = encode_hex(&bundle.group.members[1].pubkey[1..]);
        let mut core =
            BridgeCore::new(build_signer(&bundle.group, &share), BridgeConfig::default())
                .expect("bridge core");

        let request_id = core
            .submit_command(BridgeCommand::Ping { peer })
            .expect("submit ping");
        assert_eq!(
            core.request_phase(&request_id),
            Some(RequestPhase::AwaitingResponses)
        );

        core.fail_request(request_id.clone(), "synthetic failure".to_string())
            .expect("fail request");

        assert_eq!(core.request_phase(&request_id), Some(RequestPhase::Failed));
        let failures = core.drain_failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].request_id, request_id);
    }

    #[test]
    fn expire_marks_timed_out_request_failed() {
        let bundle = create_keyset(CreateKeysetConfig {
            group_name: "Test Group".to_string(),
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let share = bundle.shares[0].clone();
        let peer = encode_hex(&bundle.group.members[1].pubkey[1..]);
        let mut core = BridgeCore::new(
            SigningDevice::new(
                bundle.group.clone(),
                share.clone(),
                vec![
                    peer.clone(),
                    encode_hex(&bundle.group.members[2].pubkey[1..]),
                ],
                DeviceState::new(share.idx, share.seckey),
                DeviceConfig {
                    ping_timeout_secs: 1,
                    ..DeviceConfig::default()
                },
            )
            .expect("signer"),
            BridgeConfig {
                expire_tick: std::time::Duration::from_millis(1),
                ..BridgeConfig::default()
            },
        )
        .expect("bridge core");

        let request_id = core
            .submit_command(BridgeCommand::Ping { peer })
            .expect("submit ping");
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        core.tick(now_secs * 1_000);
        core.tick((now_secs + 2) * 1_000);

        assert_eq!(core.request_phase(&request_id), Some(RequestPhase::Failed));
        let failures = core.drain_failures();
        assert_eq!(failures.len(), 1);
        assert!(matches!(failures[0].code, OperationFailureCode::Timeout));
    }
}
