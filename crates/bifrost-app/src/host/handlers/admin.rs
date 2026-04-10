use anyhow::{Context, Result, anyhow};
use bifrost_bridge_tokio::Bridge;
use bifrost_core::types::PeerPolicyOverride;
use bifrost_signer::DeviceConfigPatch;

use crate::host::protocol::ControlCommand;
use crate::host::types::{
    ControlResultPayload, ReadConfigPayload, ShutdownPayload, StatusPayload, UpdatedPayload,
    WipedPayload,
};

pub(super) async fn execute_admin_command(
    bridge: &Bridge,
    command: ControlCommand,
) -> Result<(ControlResultPayload, bool)> {
    match command {
        ControlCommand::Status => {
            let status = bridge.status().await.map_err(|e| anyhow!(e.to_string()))?;
            Ok((ControlResultPayload::Status(StatusPayload(status)), false))
        }
        ControlCommand::SetPolicyOverride {
            peer,
            policy_override_json,
        } => {
            let policy: PeerPolicyOverride = serde_json::from_str(&policy_override_json)
                .context("invalid policy override json")?;
            bridge
                .set_policy_override(peer, policy)
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::Updated(UpdatedPayload { updated: true }),
                false,
            ))
        }
        ControlCommand::ClearPeerPolicyOverrides => {
            bridge
                .clear_policy_overrides()
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::Updated(UpdatedPayload { updated: true }),
                false,
            ))
        }
        ControlCommand::ReadConfig => {
            let config = bridge
                .read_config()
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::ReadConfig(ReadConfigPayload(config)),
                false,
            ))
        }
        ControlCommand::UpdateConfig { config_patch_json } => {
            let patch: DeviceConfigPatch =
                serde_json::from_str(&config_patch_json).context("invalid config patch json")?;
            bridge
                .update_config(patch)
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::Updated(UpdatedPayload { updated: true }),
                false,
            ))
        }
        ControlCommand::WipeState => {
            bridge
                .wipe_state()
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            Ok((
                ControlResultPayload::Wiped(WipedPayload { wiped: true }),
                false,
            ))
        }
        ControlCommand::Shutdown => Ok((
            ControlResultPayload::Shutdown(ShutdownPayload { shutdown: true }),
            true,
        )),
        _ => unreachable!("non-admin command dispatched to admin handler"),
    }
}
