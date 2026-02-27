use anyhow::{Result, bail};

#[derive(Debug, Clone)]
pub struct FrostSigningConfig {
    pub threshold: usize,
    pub max_signers: usize,
    pub message: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FrostSession {
    pub threshold: usize,
    pub max_signers: usize,
    pub message: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GroupSignature {
    pub bytes: Vec<u8>,
}

pub fn prepare_session(config: &FrostSigningConfig) -> Result<FrostSession> {
    if config.threshold == 0 || config.max_signers == 0 {
        bail!("threshold/max_signers must be > 0");
    }
    if config.threshold > config.max_signers {
        bail!("threshold must be <= max_signers");
    }

    Ok(FrostSession {
        threshold: config.threshold,
        max_signers: config.max_signers,
        message: config.message.clone(),
    })
}

pub fn run_signing_rounds(session: &FrostSession) -> Result<GroupSignature> {
    if session.message.is_empty() {
        bail!("message must not be empty");
    }

    // TODO: Implement with `frost-secp256k1-tr`:
    // 1) Run distributed keygen (or load signer key packages)
    // 2) Select signing participants >= threshold
    // 3) Round 1: generate commitments/nonces
    // 4) Coordinator creates signing package
    // 5) Round 2: each signer creates signature share
    // 6) Coordinator aggregates shares into group signature
    Ok(GroupSignature { bytes: Vec::new() })
}

pub fn verify_group_signature(_session: &FrostSession) -> Result<()> {
    // TODO: Verify with `frost-secp256k1-tr` against group public key and message.
    Ok(())
}
