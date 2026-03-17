use std::collections::HashSet;

use bifrost_core::types::{
    DerivedPublicNonce, EcdhEntry, EcdhPackage, GroupPackage, IndexedPublicNonceCommitment,
    MemberNonceCommitmentSet, MemberPackage, MemberPublicNonce, MethodPolicy, OnboardRequest,
    OnboardResponse, PartialSigEntry, PartialSigPackage, PeerError, PeerScopedPolicyProfile,
    PingPayload, SharePackage, SignSessionPackage,
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
pub struct IndexedPublicNonceCommitmentWire {
    pub hash_index: u16,
    pub binder_pn: String,
    pub hidden_pn: String,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberNonceCommitmentSetWire {
    pub idx: u16,
    pub entries: Vec<IndexedPublicNonceCommitmentWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignSessionPackageWire {
    pub gid: String,
    pub sid: String,
    pub members: Vec<u16>,
    pub hashes: Vec<String>,
    pub content: Option<String>,
    pub kind: String,
    pub stamp: u32,
    pub nonces: Option<Vec<MemberNonceCommitmentSetWire>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSigEntryWire {
    pub hash_index: u16,
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
    pub policy_profile: Option<PeerScopedPolicyProfileWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodPolicyWire {
    pub echo: bool,
    pub ping: bool,
    pub onboard: bool,
    pub sign: bool,
    pub ecdh: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerScopedPolicyProfileWire {
    pub for_peer: String,
    pub revision: u64,
    pub updated: u64,
    pub block_all: bool,
    pub request: MethodPolicyWire,
    pub respond: MethodPolicyWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerErrorWire {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardRequestWire {
    pub version: u16,
    pub nonces: Vec<DerivedPublicNonceWire>,
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

        let mut members: Vec<MemberPackage> = Vec::with_capacity(value.members.len());
        for m in value.members {
            members.push(m.try_into()?);
        }
        if value.threshold == 0 || value.threshold as usize > members.len() {
            return Err(crate::error::CodecError::InvalidPayload(
                "group threshold is out of bounds",
            ));
        }
        let mut seen_indices = HashSet::with_capacity(members.len());
        let mut seen_pubkeys = HashSet::with_capacity(members.len());
        for member in &members {
            if !seen_indices.insert(member.idx) {
                return Err(crate::error::CodecError::InvalidPayload(
                    "group members contain duplicate idx",
                ));
            }
            if !seen_pubkeys.insert(member.pubkey) {
                return Err(crate::error::CodecError::InvalidPayload(
                    "group members contain duplicate pubkey",
                ));
            }
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

impl TryFrom<IndexedPublicNonceCommitmentWire> for IndexedPublicNonceCommitment {
    type Error = crate::error::CodecError;

    fn try_from(value: IndexedPublicNonceCommitmentWire) -> Result<Self, Self::Error> {
        Ok(Self {
            hash_index: value.hash_index,
            binder_pn: hexbytes::decode(&value.binder_pn)?,
            hidden_pn: hexbytes::decode(&value.hidden_pn)?,
            code: hexbytes::decode(&value.code)?,
        })
    }
}

impl From<IndexedPublicNonceCommitment> for IndexedPublicNonceCommitmentWire {
    fn from(value: IndexedPublicNonceCommitment) -> Self {
        Self {
            hash_index: value.hash_index,
            binder_pn: hexbytes::encode(&value.binder_pn),
            hidden_pn: hexbytes::encode(&value.hidden_pn),
            code: hexbytes::encode(&value.code),
        }
    }
}

impl TryFrom<MemberNonceCommitmentSetWire> for MemberNonceCommitmentSet {
    type Error = crate::error::CodecError;

    fn try_from(value: MemberNonceCommitmentSetWire) -> Result<Self, Self::Error> {
        if value.entries.is_empty() {
            return Err(crate::error::CodecError::InvalidPayload(
                "member nonce entries must not be empty",
            ));
        }
        if value.entries.len() > MAX_SIGN_BATCH_SIZE {
            return Err(crate::error::CodecError::InvalidPayload(
                "member nonce entries exceed max size",
            ));
        }
        Ok(Self {
            idx: value.idx,
            entries: value
                .entries
                .into_iter()
                .map(TryInto::try_into)
                .collect::<CodecResult<Vec<_>>>()?,
        })
    }
}

impl From<MemberNonceCommitmentSet> for MemberNonceCommitmentSetWire {
    fn from(value: MemberNonceCommitmentSet) -> Self {
        Self {
            idx: value.idx,
            entries: value.entries.into_iter().map(Into::into).collect(),
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
                "sign session hashes exceed max size",
            ));
        }

        let hashes = value
            .hashes
            .into_iter()
            .map(|h| hexbytes::decode::<32>(&h))
            .collect::<CodecResult<Vec<_>>>()?;

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
            content: value
                .content
                .map(|c| hexbytes::decode_vec(&c))
                .transpose()?,
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
                .map(|h| hexbytes::encode(&h))
                .collect(),
            content: value.content.map(|c| hexbytes::encode(&c)),
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
            hash_index: value.hash_index,
            sighash: hexbytes::decode(&value.sighash)?,
            partial_sig: hexbytes::decode(&value.partial_sig)?,
        })
    }
}

impl From<PartialSigEntry> for PartialSigEntryWire {
    fn from(value: PartialSigEntry) -> Self {
        Self {
            hash_index: value.hash_index,
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
            policy_profile: value.policy_profile.map(TryInto::try_into).transpose()?,
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
            policy_profile: value.policy_profile.map(Into::into),
        }
    }
}

impl TryFrom<MethodPolicyWire> for MethodPolicy {
    type Error = crate::error::CodecError;

    fn try_from(value: MethodPolicyWire) -> Result<Self, Self::Error> {
        Ok(Self {
            echo: value.echo,
            ping: value.ping,
            onboard: value.onboard,
            sign: value.sign,
            ecdh: value.ecdh,
        })
    }
}

impl From<MethodPolicy> for MethodPolicyWire {
    fn from(value: MethodPolicy) -> Self {
        Self {
            echo: value.echo,
            ping: value.ping,
            onboard: value.onboard,
            sign: value.sign,
            ecdh: value.ecdh,
        }
    }
}

impl TryFrom<PeerScopedPolicyProfileWire> for PeerScopedPolicyProfile {
    type Error = crate::error::CodecError;

    fn try_from(value: PeerScopedPolicyProfileWire) -> Result<Self, Self::Error> {
        Ok(Self {
            for_peer: hexbytes::decode(&value.for_peer)?,
            revision: value.revision,
            updated: value.updated,
            block_all: value.block_all,
            request: value.request.try_into()?,
            respond: value.respond.try_into()?,
        })
    }
}

impl From<PeerScopedPolicyProfile> for PeerScopedPolicyProfileWire {
    fn from(value: PeerScopedPolicyProfile) -> Self {
        Self {
            for_peer: hexbytes::encode(&value.for_peer),
            revision: value.revision,
            updated: value.updated,
            block_all: value.block_all,
            request: value.request.into(),
            respond: value.respond.into(),
        }
    }
}

impl From<PeerErrorWire> for PeerError {
    fn from(value: PeerErrorWire) -> Self {
        Self {
            code: value.code,
            message: value.message,
        }
    }
}

impl From<PeerError> for PeerErrorWire {
    fn from(value: PeerError) -> Self {
        Self {
            code: value.code,
            message: value.message,
        }
    }
}

impl TryFrom<OnboardRequestWire> for OnboardRequest {
    type Error = crate::error::CodecError;

    fn try_from(value: OnboardRequestWire) -> Result<Self, Self::Error> {
        if value.nonces.is_empty() {
            return Err(crate::error::CodecError::InvalidPayload(
                "onboard nonces must not be empty",
            ));
        }
        if value.nonces.len() > MAX_NONCE_PACKAGE {
            return Err(crate::error::CodecError::InvalidPayload(
                "onboard nonces exceed max size",
            ));
        }
        Ok(Self {
            version: value.version,
            nonces: value
                .nonces
                .into_iter()
                .map(TryInto::try_into)
                .collect::<CodecResult<Vec<_>>>()?,
        })
    }
}

impl From<OnboardRequest> for OnboardRequestWire {
    fn from(value: OnboardRequest) -> Self {
        Self {
            version: value.version,
            nonces: value.nonces.into_iter().map(Into::into).collect(),
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
    fn sign_session_wire_rejects_invalid_hash_hex() {
        let wire = SignSessionPackageWire {
            gid: hex::encode([1u8; 32]),
            sid: hex::encode([2u8; 32]),
            members: vec![1, 2],
            hashes: vec!["zz".to_string()],
            content: None,
            kind: "message".to_string(),
            stamp: 1,
            nonces: None,
        };
        let err: crate::error::CodecError =
            TryInto::<SignSessionPackage>::try_into(wire).expect_err("must reject");
        assert!(matches!(
            err,
            crate::error::CodecError::Hex | crate::error::CodecError::InvalidLength { .. }
        ));
    }

    #[test]
    fn partial_sig_wire_rejects_empty_psigs() {
        let wire = PartialSigPackageWire {
            idx: 1,
            sid: hex::encode([2u8; 32]),
            pubkey: hex::encode([3u8; 32]),
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

    #[test]
    fn sign_session_wire_content_roundtrip_is_binary_safe() {
        let session = SignSessionPackage {
            gid: [1u8; 32],
            sid: [2u8; 32],
            members: vec![1, 2],
            hashes: vec![[3u8; 32]],
            content: Some(vec![0, 255, 1, 2, 3, 128]),
            kind: "message".to_string(),
            stamp: 1,
            nonces: None,
        };
        let wire = SignSessionPackageWire::from(session.clone());
        let parsed: SignSessionPackage = wire.try_into().expect("content parse");
        assert_eq!(parsed.content, session.content);
    }

    #[test]
    fn sign_session_wire_rejects_non_hex_content() {
        let wire = SignSessionPackageWire {
            gid: hex::encode([1u8; 32]),
            sid: hex::encode([2u8; 32]),
            members: vec![1, 2],
            hashes: vec![hex::encode([3u8; 32])],
            content: Some("not-hex".to_string()),
            kind: "message".to_string(),
            stamp: 1,
            nonces: None,
        };
        let err: crate::error::CodecError =
            TryInto::<SignSessionPackage>::try_into(wire).expect_err("must reject");
        assert!(matches!(err, crate::error::CodecError::Hex));
    }

    #[test]
    fn group_wire_rejects_member_pubkey32_when_verifying_share33_required() {
        let wire = GroupPackageWire {
            group_pk: hex::encode([1u8; 32]),
            threshold: 1,
            members: vec![MemberPackageWire {
                idx: 1,
                pubkey: hex::encode([2u8; 32]),
            }],
        };
        let err: crate::error::CodecError =
            TryInto::<GroupPackage>::try_into(wire).expect_err("must reject member pubkey32");
        assert!(matches!(
            err,
            crate::error::CodecError::InvalidLength { .. }
        ));
    }

    #[test]
    fn onboard_wire_rejects_empty_nonce_package() {
        let wire = OnboardRequestWire {
            version: 1,
            nonces: Vec::new(),
        };
        let err: crate::error::CodecError =
            TryInto::<OnboardRequest>::try_into(wire).expect_err("must reject empty nonces");
        assert!(matches!(
            err,
            crate::error::CodecError::InvalidPayload(_)
        ));
    }

    #[test]
    fn onboard_wire_roundtrips_version_and_nonces() {
        let request = OnboardRequest {
            version: 1,
            nonces: vec![DerivedPublicNonce {
                binder_pn: [1u8; 33],
                hidden_pn: [2u8; 33],
                code: [3u8; 32],
            }],
        };
        let wire = OnboardRequestWire::from(request.clone());
        let decoded = OnboardRequest::try_from(wire).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn group_wire_rejects_duplicate_member_idx() {
        let pubkey_a = hex::encode([2u8; 33]);
        let pubkey_b = hex::encode([3u8; 33]);
        let wire = GroupPackageWire {
            group_pk: hex::encode([1u8; 32]),
            threshold: 1,
            members: vec![
                MemberPackageWire {
                    idx: 1,
                    pubkey: pubkey_a,
                },
                MemberPackageWire {
                    idx: 1,
                    pubkey: pubkey_b,
                },
            ],
        };
        let err: crate::error::CodecError =
            TryInto::<GroupPackage>::try_into(wire).expect_err("must reject duplicate idx");
        assert!(matches!(
            err,
            crate::error::CodecError::InvalidPayload("group members contain duplicate idx")
        ));
    }

    #[test]
    fn group_wire_rejects_duplicate_member_pubkey() {
        let pubkey = hex::encode([2u8; 33]);
        let wire = GroupPackageWire {
            group_pk: hex::encode([1u8; 32]),
            threshold: 1,
            members: vec![
                MemberPackageWire {
                    idx: 1,
                    pubkey: pubkey.clone(),
                },
                MemberPackageWire { idx: 2, pubkey },
            ],
        };
        let err: crate::error::CodecError =
            TryInto::<GroupPackage>::try_into(wire).expect_err("must reject duplicate pubkey");
        assert!(matches!(
            err,
            crate::error::CodecError::InvalidPayload("group members contain duplicate pubkey")
        ));
    }

    #[test]
    fn onboard_response_wire_rejects_oversized_nonce_bundle() {
        let nonce = DerivedPublicNonceWire {
            binder_pn: hex::encode([1u8; 33]),
            hidden_pn: hex::encode([2u8; 33]),
            code: hex::encode([3u8; 32]),
        };
        let wire = OnboardResponseWire {
            group: GroupPackageWire {
                group_pk: hex::encode([1u8; 32]),
                threshold: 1,
                members: vec![MemberPackageWire {
                    idx: 1,
                    pubkey: hex::encode([2u8; 33]),
                }],
            },
            nonces: vec![nonce; 1001],
        };
        let err: crate::error::CodecError =
            TryInto::<OnboardResponse>::try_into(wire).expect_err("must reject oversized nonces");
        assert!(matches!(
            err,
            crate::error::CodecError::InvalidPayload("onboard nonces exceed max size")
        ));
    }
}
