use std::sync::Arc;

use bifrost_transport::{Clock, Transport};

use crate::{BifrostNode, NodeResult, PeerNonceHealth};

pub trait NodeMiddleware: Send + Sync {
    fn before_request(&self, _operation: &'static str) {}
    fn after_request(&self, _operation: &'static str, _ok: bool) {}
}

#[derive(Clone)]
pub struct NodeClient<T: Transport, C: Clock> {
    node: Arc<BifrostNode<T, C>>,
    middleware: Vec<Arc<dyn NodeMiddleware>>,
}

impl<T: Transport, C: Clock> NodeClient<T, C> {
    pub fn new(node: Arc<BifrostNode<T, C>>) -> Self {
        Self {
            node,
            middleware: Vec::new(),
        }
    }

    pub fn with_middleware(mut self, middleware: Arc<dyn NodeMiddleware>) -> Self {
        self.middleware.push(middleware);
        self
    }

    fn before(&self, op: &'static str) {
        for m in &self.middleware {
            m.before_request(op);
        }
    }

    fn after(&self, op: &'static str, ok: bool) {
        for m in &self.middleware {
            m.after_request(op, ok);
        }
    }

    pub async fn connect(&self) -> NodeResult<()> {
        self.before("connect");
        let r = self.node.connect().await;
        self.after("connect", r.is_ok());
        r
    }

    pub async fn close(&self) -> NodeResult<()> {
        self.before("close");
        let r = self.node.close().await;
        self.after("close", r.is_ok());
        r
    }

    pub async fn echo(&self, peer: &str, challenge: &str) -> NodeResult<String> {
        self.before("echo");
        let r = self.node.echo(peer, challenge).await;
        self.after("echo", r.is_ok());
        r
    }

    pub async fn ping(&self, peer: &str) -> NodeResult<bifrost_core::types::PingPayload> {
        self.before("ping");
        let r = self.node.ping(peer).await;
        self.after("ping", r.is_ok());
        r
    }

    pub async fn onboard(&self, peer: &str) -> NodeResult<bifrost_core::types::OnboardResponse> {
        self.before("onboard");
        let r = self.node.onboard(peer).await;
        self.after("onboard", r.is_ok());
        r
    }

    pub async fn sign(&self, message: [u8; 32]) -> NodeResult<[u8; 64]> {
        self.before("sign");
        let r = self.node.sign(message).await;
        self.after("sign", r.is_ok());
        r
    }

    pub async fn sign_batch(&self, messages: &[[u8; 32]]) -> NodeResult<Vec<[u8; 64]>> {
        self.before("sign_batch");
        let r = self.node.sign_batch(messages).await;
        self.after("sign_batch", r.is_ok());
        r
    }

    pub async fn ecdh(&self, pubkey: [u8; 33]) -> NodeResult<[u8; 32]> {
        self.before("ecdh");
        let r = self.node.ecdh(pubkey).await;
        self.after("ecdh", r.is_ok());
        r
    }

    pub fn node(&self) -> &Arc<BifrostNode<T, C>> {
        &self.node
    }
}

#[derive(Clone)]
pub struct Signer<T: Transport, C: Clock> {
    client: NodeClient<T, C>,
}

impl<T: Transport, C: Clock> Signer<T, C> {
    pub fn new(client: NodeClient<T, C>) -> Self {
        Self { client }
    }

    pub async fn sign_message(&self, message: [u8; 32]) -> NodeResult<[u8; 64]> {
        self.client.sign(message).await
    }

    pub async fn sign_messages(&self, messages: &[[u8; 32]]) -> NodeResult<Vec<[u8; 64]>> {
        self.client.sign_batch(messages).await
    }
}

#[derive(Clone)]
pub struct NoncePoolView<T: Transport, C: Clock> {
    node: Arc<BifrostNode<T, C>>,
}

impl<T: Transport, C: Clock> NoncePoolView<T, C> {
    pub fn new(node: Arc<BifrostNode<T, C>>) -> Self {
        Self { node }
    }

    pub fn peer_health(&self, peer: &str) -> NodeResult<PeerNonceHealth> {
        self.node.peer_nonce_health(peer)
    }

    pub fn config(&self) -> bifrost_core::nonce::NoncePoolConfig {
        self.node.nonce_pool_config()
    }
}
