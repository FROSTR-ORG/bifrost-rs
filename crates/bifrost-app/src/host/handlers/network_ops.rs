use std::time::Duration;

use anyhow::{Result, anyhow};
use bifrost_bridge_tokio::Bridge;

use crate::host::protocol::ControlCommand;
use crate::host::types::{
    ControlResultPayload, EcdhPayload, OnboardPayload, PingPayload, SignPayload,
};
use crate::runtime::ResolvedAppConfig;

pub(super) async fn execute_network_command(
    bridge: &Bridge,
    config: &ResolvedAppConfig,
    command: ControlCommand,
) -> Result<(ControlResultPayload, bool)> {
    match command {
        ControlCommand::Ping { peer, timeout_secs } => {
            let result = bridge
                .ping(
                    peer,
                    Duration::from_secs(timeout_secs.unwrap_or(config.options.ping_timeout_secs)),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::Ping(PingPayload {
                    request_id: result.request_id,
                    peer: result.peer,
                }),
                false,
            ))
        }
        ControlCommand::Onboard { peer, timeout_secs } => {
            let result = bridge
                .onboard(
                    peer,
                    Duration::from_secs(
                        timeout_secs.unwrap_or(config.options.onboard_timeout_secs),
                    ),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::Onboard(OnboardPayload {
                    request_id: result.request_id,
                    group_member_count: result.group_member_count,
                }),
                false,
            ))
        }
        ControlCommand::Sign {
            message_hex32,
            timeout_secs,
        } => {
            let message = super::decode_hex32(&message_hex32)?;
            let result = bridge
                .sign(
                    message,
                    Duration::from_secs(timeout_secs.unwrap_or(config.options.sign_timeout_secs)),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::Sign(SignPayload {
                    request_id: result.request_id,
                    signatures_hex: result.signatures.iter().map(hex::encode).collect(),
                }),
                false,
            ))
        }
        ControlCommand::Ecdh {
            pubkey_hex32,
            timeout_secs,
        } => {
            let pubkey = super::decode_hex32(&pubkey_hex32)?;
            let result = bridge
                .ecdh(
                    pubkey,
                    Duration::from_secs(timeout_secs.unwrap_or(config.options.ecdh_timeout_secs)),
                )
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::Ecdh(EcdhPayload {
                    request_id: result.request_id,
                    shared_secret_hex32: hex::encode(result.shared_secret),
                }),
                false,
            ))
        }
        _ => unreachable!("non-network command dispatched to network handler"),
    }
}
