use bifrost_core::types::{
    DerivedPublicNonce, EcdhEntry, EcdhPackage, GroupPackage, MemberPackage, MemberPublicNonce,
    OnboardRequest, OnboardResponse, PartialSigEntry, PartialSigPackage, PingPayload, SharePackage,
    SignSessionPackage,
};
use serde::{Deserialize, Serialize};

use crate::error::CodecResult;
use crate::hexbytes;

const MAX_GROUP_MEMBERS: usize = 1000;
const MAX_SIGN_BATCH_SIZE: usize = 100;
const MAX_ECDH_BATCH_SIZE: usize = 100;
const MAX_NONCE_PACKAGE: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberPackageWire {
    pub idx: u16,
    pub pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPackageWire {
    pub group_pk: String,
    pub threshold: u16,
    pub members: Vec<MemberPackageWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharePackageWire {
    pub idx: u16,
    pub seckey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedPublicNonceWire {
    pub binder_pn: String,
    pub hidden_pn: String,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberPublicNonceWire {
    pub idx: u16,
    pub binder_pn: String,
    pub hidden_pn: String,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignSessionPackageWire {
    pub gid: String,
    pub sid: String,
    pub members: Vec<u16>,
    pub hashes: Vec<Vec<String>>,
    pub content: Option<String>,
    pub kind: String,
    pub stamp: u32,
    pub nonces: Option<Vec<MemberPublicNonceWire>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSigEntryWire {
    pub sighash: String,
    pub partial_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSigPackageWire {
    pub idx: u16,
    pub sid: String,
    pub pubkey: String,
    pub psigs: Vec<PartialSigEntryWire>,
    pub nonce_code: Option<String>,
    pub replenish: Option<Vec<DerivedPublicNonceWire>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdhEntryWire {
    pub ecdh_pk: String,
    pub keyshare: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdhPackageWire {
    pub idx: u16,
    pub members: Vec<u16>,
    pub entries: Vec<EcdhEntryWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingPayloadWire {
    pub version: u16,
    pub nonces: Option<Vec<DerivedPublicNonceWire>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardRequestWire {
    pub share_pk: String,
    pub idx: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardResponseWire {
    pub group: GroupPackageWire,
    pub nonces: Vec<DerivedPublicNonceWire>,
}

impl TryFrom<MemberPackageWire> for MemberPackage {
    type Error = crate::error::CodecError;

    fn try_from(value: MemberPackageWire) -> Result<Self, Self::Error> {
        Ok(Self {
            idx: value.idx,
            pubkey: hexbytes::decode(&value.pubkey)?,
        })
    }
}

impl From<MemberPackage> for MemberPackageWire {
    fn from(value: MemberPackage) -> Self {
        Self {
            idx: value.idx,
            pubkey: hexbytes::encode(&value.pubkey),
        }
    }
}

impl TryFrom<GroupPackageWire> for GroupPackage {
    type Error = crate::error::CodecError;

    fn try_from(value: GroupPackageWire) -> Result<Self, Self::Error> {
        if value.members.is_empty() {
            return Err(crate::error::CodecError::InvalidPayload(
                "group members must not be empty",
            ));
        }
        if value.members.len() > MAX_GROUP_MEMBERS {
            return Err(crate::error::CodecError::InvalidPayload(
                "group members exceed max size",
            ));
        }

        let mut members = Vec::with_capacity(value.members.len());
        for m in value.members {
            members.push(m.try_into()?);
        }

        Ok(Self {
            group_pk: hexbytes::decode(&value.group_pk)?,
            threshold: value.threshold,
            members,
        })
    }
}

impl From<GroupPackage> for GroupPackageWire {
    fn from(value: GroupPackage) -> Self {
        Self {
            group_pk: hexbytes::encode(&value.group_pk),
            threshold: value.threshold,
            members: value.members.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<SharePackageWire> for SharePackage {
    type Error = crate::error::CodecError;

    fn try_from(value: SharePackageWire) -> Result<Self, Self::Error> {
        Ok(Self {
            idx: value.idx,
            seckey: hexbytes::decode(&value.seckey)?,
        })
    }
}

impl From<SharePackage> for SharePackageWire {
    fn from(value: SharePackage) -> Self {
        Self {
            idx: value.idx,
            seckey: hexbytes::encode(&value.seckey),
        }
    }
}

impl TryFrom<DerivedPublicNonceWire> for DerivedPublicNonce {
    type Error = crate::error::CodecError;

    fn try_from(value: DerivedPublicNonceWire) -> Result<Self, Self::Error> {
        Ok(Self {
            binder_pn: hexbytes::decode(&value.binder_pn)?,
            hidden_pn: hexbytes::decode(&value.hidden_pn)?,
            code: hexbytes::decode(&value.code)?,
        })
    }
}

impl From<DerivedPublicNonce> for DerivedPublicNonceWire {
    fn from(value: DerivedPublicNonce) -> Self {
        Self {
            binder_pn: hexbytes::encode(&value.binder_pn),
            hidden_pn: hexbytes::encode(&value.hidden_pn),
            code: hexbytes::encode(&value.code),
        }
    }
}

impl TryFrom<MemberPublicNonceWire> for MemberPublicNonce {
    type Error = crate::error::CodecError;

    fn try_from(value: MemberPublicNonceWire) -> Result<Self, Self::Error> {
        Ok(Self {
            idx: value.idx,
            binder_pn: hexbytes::decode(&value.binder_pn)?,
            hidden_pn: hexbytes::decode(&value.hidden_pn)?,
            code: hexbytes::decode(&value.code)?,
        })
    }
}

impl From<MemberPublicNonce> for MemberPublicNonceWire {
    fn from(value: MemberPublicNonce) -> Self {
        Self {
            idx: value.idx,
            binder_pn: hexbytes::encode(&value.binder_pn),
            hidden_pn: hexbytes::encode(&value.hidden_pn),
            code: hexbytes::encode(&value.code),
        }
    }
}

impl TryFrom<SignSessionPackageWire> for SignSessionPackage {
    type Error = crate::error::CodecError;

    fn try_from(value: SignSessionPackageWire) -> Result<Self, Self::Error> {
        if value.members.is_empty() {
            return Err(crate::error::CodecError::InvalidPayload(
                "sign session members must not be empty",
            ));
        }
        if value.members.len() > MAX_GROUP_MEMBERS {
            return Err(crate::error::CodecError::InvalidPayload(
                "sign session members exceed max size",
            ));
        }
        if value.hashes.is_empty() {
            return Err(crate::error::CodecError::InvalidPayload(
                "sign session hashes must not be empty",
            ));
        }
        if value.hashes.len() > MAX_SIGN_BATCH_SIZE {
            return Err(crate::error::CodecError::InvalidPayload(
                "sign session hash groups exceed max size",
            ));
        }

        let mut hashes = Vec::with_capacity(value.hashes.len());
        for vec in value.hashes {
            if vec.is_empty() {
                return Err(crate::error::CodecError::InvalidPayload(
                    "sign session hash group must not be empty",
                ));
            }
            if vec.len() > MAX_SIGN_BATCH_SIZE {
                return Err(crate::error::CodecError::InvalidPayload(
                    "sign session hash group exceeds max size",
                ));
            }
            hashes.push(
                vec.into_iter()
                    .map(|h| hexbytes::decode::<32>(&h))
                    .collect::<CodecResult<Vec<_>>>()?,
            );
        }

        let nonces = value
            .nonces
            .map(|n| {
                if n.len() > MAX_NONCE_PACKAGE {
                    return Err(crate::error::CodecError::InvalidPayload(
                        "sign session nonces exceed max size",
                    ));
                }
                n.into_iter().map(TryInto::try_into).collect()
            })
            .transpose()?;

        Ok(Self {
            gid: hexbytes::decode(&value.gid)?,
            sid: hexbytes::decode(&value.sid)?,
            members: value.members,
            hashes,
            content: value.content.map(|c| c.into_bytes()),
            kind: value.kind,
            stamp: value.stamp,
            nonces,
        })
    }
}

impl From<SignSessionPackage> for SignSessionPackageWire {
    fn from(value: SignSessionPackage) -> Self {
        Self {
            gid: hexbytes::encode(&value.gid),
            sid: hexbytes::encode(&value.sid),
            members: value.members,
            hashes: value
                .hashes
                .into_iter()
                .map(|v| v.into_iter().map(|h| hexbytes::encode(&h)).collect())
                .collect(),
            content: value
                .content
                .map(|c| String::from_utf8_lossy(&c).to_string()),
            kind: value.kind,
            stamp: value.stamp,
            nonces: value
                .nonces
                .map(|n| n.into_iter().map(Into::into).collect()),
        }
    }
}

impl TryFrom<PartialSigEntryWire> for PartialSigEntry {
    type Error = crate::error::CodecError;

    fn try_from(value: PartialSigEntryWire) -> Result<Self, Self::Error> {
        Ok(Self {
            sighash: hexbytes::decode(&value.sighash)?,
            partial_sig: hexbytes::decode(&value.partial_sig)?,
        })
    }
}

impl From<PartialSigEntry> for PartialSigEntryWire {
    fn from(value: PartialSigEntry) -> Self {
        Self {
            sighash: hexbytes::encode(&value.sighash),
            partial_sig: hexbytes::encode(&value.partial_sig),
        }
    }
}

impl TryFrom<PartialSigPackageWire> for PartialSigPackage {
    type Error = crate::error::CodecError;

    fn try_from(value: PartialSigPackageWire) -> Result<Self, Self::Error> {
        if value.psigs.is_empty() {
            return Err(crate::error::CodecError::InvalidPayload(
                "partial signature list must not be empty",
            ));
        }
        if value.psigs.len() > MAX_SIGN_BATCH_SIZE {
            return Err(crate::error::CodecError::InvalidPayload(
                "partial signature list exceeds max size",
            ));
        }

        Ok(Self {
            idx: value.idx,
            sid: hexbytes::decode(&value.sid)?,
            pubkey: hexbytes::decode(&value.pubkey)?,
            psigs: value
                .psigs
                .into_iter()
                .map(TryInto::try_into)
                .collect::<CodecResult<Vec<_>>>()?,
            nonce_code: value.nonce_code.map(|v| hexbytes::decode(&v)).transpose()?,
            replenish: value
                .replenish
                .map(|n| n.into_iter().map(TryInto::try_into).collect())
                .transpose()?,
        })
    }
}

impl From<PartialSigPackage> for PartialSigPackageWire {
    fn from(value: PartialSigPackage) -> Self {
        Self {
            idx: value.idx,
            sid: hexbytes::encode(&value.sid),
            pubkey: hexbytes::encode(&value.pubkey),
            psigs: value.psigs.into_iter().map(Into::into).collect(),
            nonce_code: value.nonce_code.map(|v| hexbytes::encode(&v)),
            replenish: value
                .replenish
                .map(|n| n.into_iter().map(Into::into).collect()),
        }
    }
}

impl TryFrom<EcdhEntryWire> for EcdhEntry {
    type Error = crate::error::CodecError;

    fn try_from(value: EcdhEntryWire) -> Result<Self, Self::Error> {
        Ok(Self {
            ecdh_pk: hexbytes::decode(&value.ecdh_pk)?,
            keyshare: hexbytes::decode(&value.keyshare)?,
        })
    }
}

impl From<EcdhEntry> for EcdhEntryWire {
    fn from(value: EcdhEntry) -> Self {
        Self {
            ecdh_pk: hexbytes::encode(&value.ecdh_pk),
            keyshare: hexbytes::encode(&value.keyshare),
        }
    }
}

impl TryFrom<EcdhPackageWire> for EcdhPackage {
    type Error = crate::error::CodecError;

    fn try_from(value: EcdhPackageWire) -> Result<Self, Self::Error> {
        if value.members.is_empty() {
            return Err(crate::error::CodecError::InvalidPayload(
                "ecdh members must not be empty",
            ));
        }
        if value.members.len() > MAX_GROUP_MEMBERS {
            return Err(crate::error::CodecError::InvalidPayload(
                "ecdh members exceed max size",
            ));
        }
        if value.entries.is_empty() {
            return Err(crate::error::CodecError::InvalidPayload(
                "ecdh entries must not be empty",
            ));
        }
        if value.entries.len() > MAX_ECDH_BATCH_SIZE {
            return Err(crate::error::CodecError::InvalidPayload(
                "ecdh entries exceed max size",
            ));
        }

        Ok(Self {
            idx: value.idx,
            members: value.members,
            entries: value
                .entries
                .into_iter()
                .map(TryInto::try_into)
                .collect::<CodecResult<Vec<_>>>()?,
        })
    }
}

impl From<EcdhPackage> for EcdhPackageWire {
    fn from(value: EcdhPackage) -> Self {
        Self {
            idx: value.idx,
            members: value.members,
            entries: value.entries.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<PingPayloadWire> for PingPayload {
    type Error = crate::error::CodecError;

    fn try_from(value: PingPayloadWire) -> Result<Self, Self::Error> {
        let nonces = value
            .nonces
            .map(|n| {
                if n.len() > MAX_NONCE_PACKAGE {
                    return Err(crate::error::CodecError::InvalidPayload(
                        "ping nonces exceed max size",
                    ));
                }
                n.into_iter().map(TryInto::try_into).collect()
            })
            .transpose()?;

        Ok(Self {
            version: value.version,
            nonces,
        })
    }
}

impl From<PingPayload> for PingPayloadWire {
    fn from(value: PingPayload) -> Self {
        Self {
            version: value.version,
            nonces: value
                .nonces
                .map(|n| n.into_iter().map(Into::into).collect()),
        }
    }
}

impl TryFrom<OnboardRequestWire> for OnboardRequest {
    type Error = crate::error::CodecError;

    fn try_from(value: OnboardRequestWire) -> Result<Self, Self::Error> {
        Ok(Self {
            share_pk: hexbytes::decode(&value.share_pk)?,
            idx: value.idx,
        })
    }
}

impl From<OnboardRequest> for OnboardRequestWire {
    fn from(value: OnboardRequest) -> Self {
        Self {
            share_pk: hexbytes::encode(&value.share_pk),
            idx: value.idx,
        }
    }
}

impl TryFrom<OnboardResponseWire> for OnboardResponse {
    type Error = crate::error::CodecError;

    fn try_from(value: OnboardResponseWire) -> Result<Self, Self::Error> {
        if value.nonces.len() > MAX_NONCE_PACKAGE {
            return Err(crate::error::CodecError::InvalidPayload(
                "onboard nonces exceed max size",
            ));
        }
        Ok(Self {
            group: value.group.try_into()?,
            nonces: value
                .nonces
                .into_iter()
                .map(TryInto::try_into)
                .collect::<CodecResult<Vec<_>>>()?,
        })
    }
}

impl From<OnboardResponse> for OnboardResponseWire {
    fn from(value: OnboardResponse) -> Self {
        Self {
            group: value.group.into(),
            nonces: value.nonces.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_session_wire_rejects_empty_hashes() {
        let wire = SignSessionPackageWire {
            gid: hex::encode([1u8; 32]),
            sid: hex::encode([2u8; 32]),
            members: vec![1, 2],
            hashes: vec![],
            content: None,
            kind: "message".to_string(),
            stamp: 1,
            nonces: None,
        };
        let err: crate::error::CodecError =
            TryInto::<SignSessionPackage>::try_into(wire).expect_err("must reject");
        assert!(matches!(err, crate::error::CodecError::InvalidPayload(_)));
    }

    #[test]
    fn sign_session_wire_rejects_empty_hash_group() {
        let wire = SignSessionPackageWire {
            gid: hex::encode([1u8; 32]),
            sid: hex::encode([2u8; 32]),
            members: vec![1, 2],
            hashes: vec![vec![]],
            content: None,
            kind: "message".to_string(),
            stamp: 1,
            nonces: None,
        };
        let err: crate::error::CodecError =
            TryInto::<SignSessionPackage>::try_into(wire).expect_err("must reject");
        assert!(matches!(err, crate::error::CodecError::InvalidPayload(_)));
    }

    #[test]
    fn partial_sig_wire_rejects_empty_psigs() {
        let wire = PartialSigPackageWire {
            idx: 1,
            sid: hex::encode([2u8; 32]),
            pubkey: hex::encode([3u8; 33]),
            psigs: Vec::new(),
            nonce_code: None,
            replenish: None,
        };
        let err: crate::error::CodecError =
            TryInto::<PartialSigPackage>::try_into(wire).expect_err("must reject");
        assert!(matches!(err, crate::error::CodecError::InvalidPayload(_)));
    }

    #[test]
    fn ecdh_wire_rejects_empty_entries() {
        let wire = EcdhPackageWire {
            idx: 1,
            members: vec![1, 2],
            entries: Vec::new(),
        };
        let err: crate::error::CodecError =
            TryInto::<EcdhPackage>::try_into(wire).expect_err("must reject");
        assert!(matches!(err, crate::error::CodecError::InvalidPayload(_)));
    }
}
