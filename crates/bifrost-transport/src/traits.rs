use async_trait::async_trait;

use crate::error::TransportResult;
use crate::types::{IncomingMessage, OutgoingMessage, ResponseHandle};

pub trait Clock: Send + Sync {
    fn now_unix_seconds(&self) -> u64;
}

#[async_trait]
pub trait Sleeper: Send + Sync {
    async fn sleep_ms(&self, ms: u64);
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self) -> TransportResult<()>;
    async fn close(&self) -> TransportResult<()>;

    async fn request(
        &self,
        msg: OutgoingMessage,
        timeout_ms: u64,
    ) -> TransportResult<IncomingMessage>;
    async fn cast(
        &self,
        msg: OutgoingMessage,
        peers: &[String],
        threshold: usize,
        timeout_ms: u64,
    ) -> TransportResult<Vec<IncomingMessage>>;

    async fn send_response(
        &self,
        handle: ResponseHandle,
        response: OutgoingMessage,
    ) -> TransportResult<()>;

    async fn next_incoming(&self) -> TransportResult<IncomingMessage>;
}
