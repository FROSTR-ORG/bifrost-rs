use crate::error::TransportResult;
use crate::types::{IncomingMessage, OutgoingMessage, ResponseHandle};

pub trait Clock: Send + Sync {
    fn now_unix_seconds(&self) -> u64;
}

pub trait Sleeper: Send + Sync {
    fn sleep_ms(&self, ms: u64) -> impl std::future::Future<Output = ()> + Send;
}

pub trait Transport: Send + Sync {
    fn connect(&self) -> impl std::future::Future<Output = TransportResult<()>> + Send;
    fn close(&self) -> impl std::future::Future<Output = TransportResult<()>> + Send;

    fn request(
        &self,
        msg: OutgoingMessage,
        timeout_ms: u64,
    ) -> impl std::future::Future<Output = TransportResult<IncomingMessage>> + Send;
    fn cast(
        &self,
        msg: OutgoingMessage,
        peers: &[String],
        threshold: usize,
        timeout_ms: u64,
    ) -> impl std::future::Future<Output = TransportResult<Vec<IncomingMessage>>> + Send;

    fn send_response(
        &self,
        handle: ResponseHandle,
        response: OutgoingMessage,
    ) -> impl std::future::Future<Output = TransportResult<()>> + Send;

    fn next_incoming(
        &self,
    ) -> impl std::future::Future<Output = TransportResult<IncomingMessage>> + Send;
}
