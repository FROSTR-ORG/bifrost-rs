use anyhow::{Result, anyhow};
use bifrost_bridge_tokio::Bridge;

use crate::host::protocol::ControlCommand;
use crate::host::types::{
    ControlResultPayload, PeerStatusPayload, ReadinessPayload, RuntimeDiagnosticsSnapshot,
    RuntimeMetadataPayload, RuntimeStatusPayload,
};

pub(super) async fn execute_runtime_read(
    bridge: &Bridge,
    command: ControlCommand,
) -> Result<(ControlResultPayload, bool)> {
    match command {
        ControlCommand::PeerStatus => {
            let status = bridge
                .peer_status()
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::PeerStatus(PeerStatusPayload(status)),
                false,
            ))
        }
        ControlCommand::Readiness => {
            let readiness = bridge
                .readiness()
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::Readiness(ReadinessPayload(readiness)),
                false,
            ))
        }
        ControlCommand::RuntimeStatus => {
            let status = bridge
                .runtime_status()
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::RuntimeStatus(RuntimeStatusPayload(status)),
                false,
            ))
        }
        ControlCommand::RuntimeDiagnostics => {
            let status = bridge
                .runtime_status()
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::RuntimeDiagnostics(RuntimeDiagnosticsSnapshot {
                    runtime_status: RuntimeStatusPayload(status),
                }),
                false,
            ))
        }
        ControlCommand::RuntimeMetadata => {
            let metadata = bridge
                .runtime_metadata()
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::RuntimeMetadata(RuntimeMetadataPayload(metadata)),
                false,
            ))
        }
        _ => unreachable!("non-runtime-read command dispatched to runtime read handler"),
    }
}
