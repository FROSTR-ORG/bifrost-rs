use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub type Bytes32 = [u8; 32];
pub type Bytes33 = [u8; 33];

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
    pub pubkey: Bytes33,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPackage {
    #[serde(with = "serde_fixed_array::bytes33")]
    pub group_pk: Bytes33,
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
    #[serde(with = "serde_fixed_array::bytes33")]
    pub pubkey: Bytes33,
    pub psigs: Vec<PartialSigEntry>,
    pub nonce_code: Option<Bytes32>,
    pub replenish: Option<Vec<DerivedPublicNonce>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEntry {
    #[serde(with = "serde_fixed_array::bytes32")]
    pub sighash: Bytes32,
    #[serde(with = "serde_fixed_array::bytes33")]
    pub pubkey: Bytes33,
    #[serde(with = "serde_fixed_array::bytes64")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdhEntry {
    #[serde(with = "serde_fixed_array::bytes33")]
    pub ecdh_pk: Bytes33,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerScopedPolicyProfile {
    #[serde(with = "serde_fixed_array::bytes33")]
    pub for_peer: Bytes33,
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
    #[serde(with = "serde_fixed_array::bytes33")]
    pub share_pk: Bytes33,
    pub idx: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardResponse {
    pub group: GroupPackage,
    pub nonces: Vec<DerivedPublicNonce>,
}
