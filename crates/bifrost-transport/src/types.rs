use bifrost_codec::rpc::RpcEnvelope;

#[derive(Debug, Clone)]
pub struct OutgoingMessage {
    pub peer: String,
    pub envelope: RpcEnvelope,
}

#[derive(Debug, Clone)]
pub struct IncomingMessage {
    pub peer: String,
    pub envelope: RpcEnvelope,
}

#[derive(Debug, Clone)]
pub struct ResponseHandle {
    pub peer: String,
    pub request_id: String,
}
