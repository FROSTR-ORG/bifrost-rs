use zeroize::Zeroize;

pub type Bytes32 = [u8; 32];
pub type Bytes33 = [u8; 33];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberPackage {
    pub idx: u16,
    pub pubkey: Bytes33,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPackage {
    pub group_pk: Bytes33,
    pub threshold: u16,
    pub members: Vec<MemberPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct SharePackage {
    pub idx: u16,
    pub seckey: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedPublicNonce {
    pub binder_pn: Bytes33,
    pub hidden_pn: Bytes33,
    pub code: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberPublicNonce {
    pub idx: u16,
    pub binder_pn: Bytes33,
    pub hidden_pn: Bytes33,
    pub code: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignSessionTemplate {
    pub members: Vec<u16>,
    pub hashes: Vec<Vec<Bytes32>>,
    pub content: Option<Vec<u8>>,
    pub kind: String,
    pub stamp: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignSessionPackage {
    pub gid: Bytes32,
    pub sid: Bytes32,
    pub members: Vec<u16>,
    pub hashes: Vec<Vec<Bytes32>>,
    pub content: Option<Vec<u8>>,
    pub kind: String,
    pub stamp: u32,
    pub nonces: Option<Vec<MemberPublicNonce>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub session: SignSessionPackage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSigEntry {
    pub sighash: Bytes32,
    pub partial_sig: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSigPackage {
    pub idx: u16,
    pub sid: Bytes32,
    pub pubkey: Bytes33,
    pub psigs: Vec<PartialSigEntry>,
    pub nonce_code: Option<Bytes32>,
    pub replenish: Option<Vec<DerivedPublicNonce>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntry {
    pub sighash: Bytes32,
    pub pubkey: Bytes33,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhEntry {
    pub ecdh_pk: Bytes33,
    pub keyshare: Bytes33,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhPackage {
    pub idx: u16,
    pub members: Vec<u16>,
    pub entries: Vec<EcdhEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    pub send: bool,
    pub recv: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingPayload {
    pub version: u16,
    pub nonces: Option<Vec<DerivedPublicNonce>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardRequest {
    pub share_pk: Bytes33,
    pub idx: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardResponse {
    pub group: GroupPackage,
    pub nonces: Vec<DerivedPublicNonce>,
}
