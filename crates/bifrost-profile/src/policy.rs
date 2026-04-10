use anyhow::{Context, Result};
use bifrost_core::types::PeerPolicyOverride;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyOverridesDocument {
    #[serde(default)]
    pub default_override: Option<PeerPolicyOverride>,
    #[serde(default)]
    pub peer_overrides: Vec<PolicyOverrideEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyOverrideEntry {
    pub pubkey: String,
    #[serde(default)]
    pub policy_override: PeerPolicyOverride,
}

pub fn empty_policy_overrides_document() -> PolicyOverridesDocument {
    PolicyOverridesDocument {
        default_override: None,
        peer_overrides: Vec::new(),
    }
}

pub fn empty_policy_overrides_value() -> Value {
    serde_json::to_value(empty_policy_overrides_document())
        .expect("empty policy overrides document should serialize")
}

pub fn parse_policy_overrides_doc(value: Value) -> Result<PolicyOverridesDocument> {
    if value.is_null() {
        return Ok(empty_policy_overrides_document());
    }
    serde_json::from_value(value).context("parse policy overrides document")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_policy_overrides_parses_as_empty_document() {
        let parsed = parse_policy_overrides_doc(Value::Null).expect("parse");
        assert!(parsed.default_override.is_none());
        assert!(parsed.peer_overrides.is_empty());
    }
}
