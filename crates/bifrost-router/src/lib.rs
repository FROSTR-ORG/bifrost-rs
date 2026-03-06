use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use anyhow::{Result, anyhow};
use bifrost_core::types::PeerPolicy;
use bifrost_signer::{
    CompletedOperation, DeviceState, DeviceStatus, OperationFailure, OperationFailureCode,
    PendingOpType, PersistenceHint, SignerEffects, SignerInput, SigningDevice,
};
use nostr::{Event, Filter};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueOverflowPolicy {
    Fail,
    DropOldest,
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
    last_expire_at_ms: u64,
    persistence_hint: PersistenceHint,
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
            last_expire_at_ms: 0,
            persistence_hint: PersistenceHint::None,
        })
    }

    pub fn subscription_filters(&self) -> Result<Vec<Filter>> {
        self.signer
            .subscription_filters()
            .map_err(|e| anyhow!(e.to_string()))
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

    pub fn enqueue_inbound_event(&mut self, event: Event) -> bool {
        let event_id = event.id.to_hex();
        if self.seen_inbound_ids.contains(&event_id) {
            return false;
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
            return false;
        }

        match self.config.inbound_overflow_policy {
            QueueOverflowPolicy::Fail => true,
            QueueOverflowPolicy::DropOldest => {
                let _ = self.inbound_queue.pop_front();
                self.inbound_queue.push_back(event);
                false
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

    pub fn policies(&self) -> HashMap<String, PeerPolicy> {
        self.signer.policies().clone()
    }

    pub fn snapshot_state(&self) -> DeviceState {
        self.signer.state().clone()
    }

    pub fn set_policy(
        &mut self,
        peer: String,
        policy: PeerPolicy,
    ) -> std::result::Result<(), BridgeCoreError> {
        self.signer
            .set_peer_policy(&peer, policy)
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
            self.completions.push_back(completion);
        }

        for failure in effects.failures {
            self.failures.push_back(failure);
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

    fn push_internal_failure(&mut self, request_id: String, op_type: PendingOpType, message: String) {
        self.failures.push_back(OperationFailure {
            request_id,
            op_type,
            code: OperationFailureCode::PeerRejected,
            message,
            failed_peer: None,
        });
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
                peer: "peer-b".to_string()
            }),
            PendingOpType::Onboard
        ));
    }
}
