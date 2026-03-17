use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub type Bytes32 = [u8; 32];
pub type Bytes33 = [u8; 33];
pub type IdentityPubkey32 = Bytes32;
pub type VerifyingShare33 = Bytes33;

mod serde_fixed_array {
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;
    use serde::de::Error as _;
    use serde::ser::SerializeSeq;
    use std::convert::TryInto;

    pub mod bytes32 {
        use super::deserialize_fixed_array;
        use super::serialize_fixed_array;

        pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serialize_fixed_array(bytes, serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserialize_fixed_array::<D, 32>(deserializer)
        }
    }

    pub mod vec_bytes32 {
        use super::deserialize_vec_arrays;
        use super::serialize_vec_arrays;

        pub fn serialize<S>(values: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serialize_vec_arrays(values, serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserialize_vec_arrays::<D, 32>(deserializer)
        }
    }

    pub mod bytes33 {
        use super::deserialize_fixed_array;
        use super::serialize_fixed_array;

        pub fn serialize<S>(bytes: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serialize_fixed_array(bytes, serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserialize_fixed_array::<D, 33>(deserializer)
        }
    }

    pub mod bytes64 {
        use super::deserialize_fixed_array;
        use super::serialize_fixed_array;

        pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serialize_fixed_array(bytes, serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserialize_fixed_array::<D, 64>(deserializer)
        }
    }

    fn serialize_fixed_array<S, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(N))?;
        for byte in bytes {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }

    fn deserialize_fixed_array<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<u8>::deserialize(deserializer)?;
        if values.len() != N {
            return Err(D::Error::custom(format!(
                "invalid fixed array length: expected {N}, got {}",
                values.len()
            )));
        }
        let actual = values.len();
        values.try_into().map_err(|_| {
            D::Error::custom(format!(
                "invalid fixed array length: expected {N}, got {}",
                actual
            ))
        })
    }

    fn serialize_vec_arrays<S>(values: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut outer = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            outer.serialize_element(value)?;
        }
        outer.end()
    }

    fn deserialize_vec_arrays<'de, D, const N: usize>(
        deserializer: D,
    ) -> Result<Vec<[u8; N]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut values = Vec::<[u8; N]>::new();
        let raw: Vec<Vec<u8>> = Vec::deserialize(deserializer)?;
        for value in raw {
            if value.len() != N {
                return Err(D::Error::custom(format!(
                    "invalid fixed array length: expected {N}, got {}",
                    value.len()
                )));
            }
            let actual = value.len();
            values.push(value.try_into().map_err(|_| {
                D::Error::custom(format!(
                    "invalid fixed array length: expected {N}, got {}",
                    actual
                ))
            })?);
        }
        Ok(values)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberPackage {
    pub idx: u16,
    #[serde(with = "serde_fixed_array::bytes33")]
    pub pubkey: VerifyingShare33,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPackage {
    #[serde(with = "serde_fixed_array::bytes32")]
    pub group_pk: IdentityPubkey32,
    pub threshold: u16,
    pub members: Vec<MemberPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SharePackage {
    pub idx: u16,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub seckey: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedPublicNonce {
    #[serde(with = "serde_fixed_array::bytes33")]
    pub binder_pn: Bytes33,
    #[serde(with = "serde_fixed_array::bytes33")]
    pub hidden_pn: Bytes33,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub code: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberPublicNonce {
    pub idx: u16,
    #[serde(with = "serde_fixed_array::bytes33")]
    pub binder_pn: Bytes33,
    #[serde(with = "serde_fixed_array::bytes33")]
    pub hidden_pn: Bytes33,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub code: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignSessionTemplate {
    pub members: Vec<u16>,
    #[serde(with = "serde_fixed_array::vec_bytes32")]
    pub hashes: Vec<Bytes32>,
    pub content: Option<Vec<u8>>,
    pub kind: String,
    pub stamp: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedPublicNonceCommitment {
    pub hash_index: u16,
    #[serde(with = "serde_fixed_array::bytes33")]
    pub binder_pn: Bytes33,
    #[serde(with = "serde_fixed_array::bytes33")]
    pub hidden_pn: Bytes33,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub code: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberNonceCommitmentSet {
    pub idx: u16,
    pub entries: Vec<IndexedPublicNonceCommitment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignSessionPackage {
    #[serde(with = "serde_fixed_array::bytes32")]
    pub gid: Bytes32,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub sid: Bytes32,
    pub members: Vec<u16>,
    #[serde(with = "serde_fixed_array::vec_bytes32")]
    pub hashes: Vec<Bytes32>,
    pub content: Option<Vec<u8>>,
    pub kind: String,
    pub stamp: u32,
    pub nonces: Option<Vec<MemberNonceCommitmentSet>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    pub session: SignSessionPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSigEntry {
    pub hash_index: u16,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub sighash: Bytes32,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub partial_sig: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSigPackage {
    pub idx: u16,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub sid: Bytes32,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub pubkey: IdentityPubkey32,
    pub psigs: Vec<PartialSigEntry>,
    pub nonce_code: Option<Bytes32>,
    pub replenish: Option<Vec<DerivedPublicNonce>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEntry {
    #[serde(with = "serde_fixed_array::bytes32")]
    pub sighash: Bytes32,
    #[serde(with = "serde_fixed_array::bytes32")]
    pub pubkey: IdentityPubkey32,
    #[serde(with = "serde_fixed_array::bytes64")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdhEntry {
    #[serde(with = "serde_fixed_array::bytes32")]
    pub ecdh_pk: IdentityPubkey32,
    #[serde(with = "serde_fixed_array::bytes33")]
    pub keyshare: Bytes33,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdhPackage {
    pub idx: u16,
    pub members: Vec<u16>,
    pub entries: Vec<EcdhEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PeerPolicy {
    pub block_all: bool,
    pub request: MethodPolicy,
    pub respond: MethodPolicy,
}

impl PeerPolicy {
    pub fn from_send_receive(send: bool, receive: bool) -> Self {
        let request = MethodPolicy {
            echo: send,
            ping: send,
            onboard: send,
            sign: send,
            ecdh: send,
        };
        let respond = MethodPolicy {
            echo: receive,
            ping: receive,
            onboard: receive,
            sign: receive,
            ecdh: receive,
        };

        Self {
            block_all: !send && !receive,
            request,
            respond,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOverrideValue {
    #[default]
    Unset,
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MethodPolicyOverride {
    #[serde(default)]
    pub echo: PolicyOverrideValue,
    #[serde(default)]
    pub ping: PolicyOverrideValue,
    #[serde(default)]
    pub onboard: PolicyOverrideValue,
    #[serde(default)]
    pub sign: PolicyOverrideValue,
    #[serde(default)]
    pub ecdh: PolicyOverrideValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PeerPolicyOverride {
    #[serde(default)]
    pub request: MethodPolicyOverride,
    #[serde(default)]
    pub respond: MethodPolicyOverride,
}

impl PeerPolicyOverride {
    pub fn from_peer_policy(policy: &PeerPolicy) -> Self {
        Self {
            request: MethodPolicyOverride::from_method_policy(&policy.request),
            respond: MethodPolicyOverride::from_method_policy(&policy.respond),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodPolicy {
    pub echo: bool,
    pub ping: bool,
    pub onboard: bool,
    pub sign: bool,
    pub ecdh: bool,
}

impl Default for MethodPolicy {
    fn default() -> Self {
        Self {
            echo: true,
            ping: true,
            onboard: true,
            sign: true,
            ecdh: true,
        }
    }
}

impl MethodPolicyOverride {
    pub fn from_method_policy(policy: &MethodPolicy) -> Self {
        Self {
            echo: if policy.echo {
                PolicyOverrideValue::Allow
            } else {
                PolicyOverrideValue::Deny
            },
            ping: if policy.ping {
                PolicyOverrideValue::Allow
            } else {
                PolicyOverrideValue::Deny
            },
            onboard: if policy.onboard {
                PolicyOverrideValue::Allow
            } else {
                PolicyOverrideValue::Deny
            },
            sign: if policy.sign {
                PolicyOverrideValue::Allow
            } else {
                PolicyOverrideValue::Deny
            },
            ecdh: if policy.ecdh {
                PolicyOverrideValue::Allow
            } else {
                PolicyOverrideValue::Deny
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerScopedPolicyProfile {
    #[serde(with = "serde_fixed_array::bytes32")]
    pub for_peer: IdentityPubkey32,
    pub revision: u64,
    pub updated: u64,
    pub block_all: bool,
    pub request: MethodPolicy,
    pub respond: MethodPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingPayload {
    pub version: u16,
    pub nonces: Option<Vec<DerivedPublicNonce>>,
    pub policy_profile: Option<PeerScopedPolicyProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardRequest {
    pub version: u16,
    pub nonces: Vec<DerivedPublicNonce>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardResponse {
    pub group: GroupPackage,
    pub nonces: Vec<DerivedPublicNonce>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn peer_policy_from_send_receive_maps_request_and_response_flags() {
        let policy = PeerPolicy::from_send_receive(false, true);
        assert!(!policy.request.echo);
        assert!(!policy.request.ping);
        assert!(policy.respond.echo);
        assert!(policy.respond.sign);
        assert!(!policy.block_all);

        let blocked = PeerPolicy::from_send_receive(false, false);
        assert!(blocked.block_all);
    }

    #[test]
    fn method_policy_default_enables_all_methods() {
        let policy = MethodPolicy::default();
        assert!(policy.echo);
        assert!(policy.ping);
        assert!(policy.onboard);
        assert!(policy.sign);
        assert!(policy.ecdh);
    }

    #[test]
    fn core_runtime_types_preserve_expected_fields() {
        let ping = PingPayload {
            version: 1,
            nonces: Some(vec![DerivedPublicNonce {
                binder_pn: [5u8; 33],
                hidden_pn: [6u8; 33],
                code: [7u8; 32],
            }]),
            policy_profile: Some(PeerScopedPolicyProfile {
                for_peer: [8u8; 32],
                revision: 9,
                updated: 10,
                block_all: false,
                request: MethodPolicy::default(),
                respond: MethodPolicy::default(),
            }),
        };
        let onboard = OnboardResponse {
            group: GroupPackage {
                group_pk: [1u8; 32],
                threshold: 2,
                members: vec![
                    MemberPackage {
                        idx: 1,
                        pubkey: [2u8; 33],
                    },
                    MemberPackage {
                        idx: 2,
                        pubkey: [3u8; 33],
                    },
                ],
            },
            nonces: ping.nonces.clone().expect("nonces"),
        };
        let share = SharePackage {
            idx: 2,
            seckey: [4u8; 32],
        };

        assert_eq!(share.idx, 2);
        assert_eq!(onboard.group.threshold, 2);
        assert_eq!(onboard.group.members.len(), 2);
        assert_eq!(ping.version, 1);
        assert_eq!(
            ping.policy_profile
                .as_ref()
                .expect("policy profile")
                .for_peer,
            [8u8; 32]
        );
        assert_eq!(onboard.nonces.len(), 1);
    }

    #[test]
    fn serde_round_trip_uses_fixed_array_helpers() {
        let share = SharePackage {
            idx: 7,
            seckey: [11u8; 32],
        };
        let encoded = serde_json::to_string(&share).expect("encode share");
        let decoded: SharePackage = serde_json::from_str(&encoded).expect("decode share");
        assert_eq!(decoded, share);

        let session = SignSessionTemplate {
            members: vec![1, 2],
            hashes: vec![[3u8; 32], [4u8; 32]],
            content: Some(vec![9, 8, 7]),
            kind: "nostr-event".to_string(),
            stamp: 42,
        };
        let encoded = serde_json::to_string(&session).expect("encode session");
        let decoded: SignSessionTemplate = serde_json::from_str(&encoded).expect("decode session");
        assert_eq!(decoded, session);
    }

    #[test]
    fn serde_rejects_invalid_fixed_array_lengths() {
        let err = serde_json::from_value::<SharePackage>(json!({
            "idx": 1,
            "seckey": vec![1u8; 31],
        }))
        .expect_err("share package must reject short key");
        assert!(err.to_string().contains("invalid fixed array length"));

        let err = serde_json::from_value::<SignSessionTemplate>(json!({
            "members": [1, 2],
            "hashes": [vec![0u8; 32], vec![1u8; 31]],
            "content": null,
            "kind": "kind",
            "stamp": 7,
        }))
        .expect_err("sign session must reject short hash");
        assert!(err.to_string().contains("invalid fixed array length"));
    }
}
