use std::collections::HashMap;

use frost_secp256k1_tr_unofficial as frost;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::types::{Bytes32, DerivedPublicNonce, MemberPublicNonce};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoncePoolConfig {
    pub pool_size: usize,
    pub min_threshold: usize,
    pub critical_threshold: usize,
    pub replenish_count: usize,
}

impl Default for NoncePoolConfig {
    fn default() -> Self {
        Self {
            pool_size: 100,
            min_threshold: 20,
            critical_threshold: 5,
            replenish_count: 50,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NoncePool {
    our_idx: u16,
    seckey: Bytes32,
    config: NoncePoolConfig,
    outgoing_public: HashMap<u16, HashMap<Bytes32, DerivedPublicNonce>>,
    outgoing_secret: HashMap<u16, HashMap<Bytes32, frost::round1::SigningNonces>>,
    incoming: HashMap<u16, HashMap<Bytes32, DerivedPublicNonce>>,
}

impl NoncePool {
    pub fn new(our_idx: u16, seckey: Bytes32, config: NoncePoolConfig) -> Self {
        Self {
            our_idx,
            seckey,
            config,
            outgoing_public: HashMap::new(),
            outgoing_secret: HashMap::new(),
            incoming: HashMap::new(),
        }
    }

    pub fn init_peer(&mut self, peer_idx: u16) {
        if peer_idx == self.our_idx {
            return;
        }
        self.outgoing_public.entry(peer_idx).or_default();
        self.outgoing_secret.entry(peer_idx).or_default();
        self.incoming.entry(peer_idx).or_default();
    }

    pub fn generate_for_peer(
        &mut self,
        peer_idx: u16,
        count: usize,
    ) -> CoreResult<Vec<DerivedPublicNonce>> {
        let signing_share = frost::keys::SigningShare::deserialize(&self.seckey)
            .map_err(|e| CoreError::Frost(e.to_string()))?;
        let public_map = self.outgoing_public.entry(peer_idx).or_default();
        let secret_map = self.outgoing_secret.entry(peer_idx).or_default();

        let slots = self.config.pool_size.saturating_sub(public_map.len());
        let generate = slots.min(count);

        let mut out = Vec::with_capacity(generate);
        for _ in 0..generate {
            let (signing_nonces, commitments) = frost::round1::commit(&signing_share, &mut OsRng);
            let mut code = [0u8; 32];
            OsRng.fill_bytes(&mut code);

            let hiding_bytes = commitments
                .hiding()
                .serialize()
                .map_err(|e| CoreError::Frost(e.to_string()))?;
            let binding_bytes = commitments
                .binding()
                .serialize()
                .map_err(|e| CoreError::Frost(e.to_string()))?;
            if hiding_bytes.len() != 33 || binding_bytes.len() != 33 {
                return Err(CoreError::InvalidPubkey);
            }

            let mut hidden_pn = [0u8; 33];
            hidden_pn.copy_from_slice(&hiding_bytes);
            let mut binder_pn = [0u8; 33];
            binder_pn.copy_from_slice(&binding_bytes);

            let derived = DerivedPublicNonce {
                binder_pn,
                hidden_pn,
                code,
            };
            public_map.insert(code, derived.clone());
            secret_map.insert(code, signing_nonces);
            out.push(derived);
        }

        Ok(out)
    }

    pub fn store_incoming(&mut self, peer_idx: u16, nonces: Vec<DerivedPublicNonce>) {
        let map = self.incoming.entry(peer_idx).or_default();
        for nonce in nonces {
            if map.len() >= self.config.pool_size {
                break;
            }
            map.entry(nonce.code).or_insert(nonce);
        }
    }

    pub fn consume_incoming(&mut self, peer_idx: u16) -> Option<MemberPublicNonce> {
        let map = self.incoming.get_mut(&peer_idx)?;
        let first = *map.keys().next()?;
        let nonce = map.remove(&first)?;
        Some(MemberPublicNonce {
            idx: peer_idx,
            binder_pn: nonce.binder_pn,
            hidden_pn: nonce.hidden_pn,
            code: nonce.code,
        })
    }

    pub fn take_outgoing_signing_nonces(
        &mut self,
        peer_idx: u16,
        code: Bytes32,
    ) -> Option<frost::round1::SigningNonces> {
        let secret_map = self.outgoing_secret.get_mut(&peer_idx)?;
        let nonces = secret_map.remove(&code)?;
        if let Some(public_map) = self.outgoing_public.get_mut(&peer_idx) {
            public_map.remove(&code);
        }
        Some(nonces)
    }

    pub fn can_sign(&self, peer_idx: u16) -> bool {
        self.incoming
            .get(&peer_idx)
            .map(|m| m.len() > self.config.critical_threshold)
            .unwrap_or(false)
    }

    pub fn should_send_nonces_to(&self, peer_idx: u16) -> bool {
        self.outgoing_public
            .get(&peer_idx)
            .map(|m| m.len() < self.config.min_threshold)
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_pool_generate_and_consume() {
        let (shares, _) =
            frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, OsRng)
                .expect("dealer");
        let (id, secret_share) = shares.into_iter().next().expect("share");
        let key_package = frost::keys::KeyPackage::try_from(secret_share).expect("key package");
        let mut seckey = [0u8; 32];
        seckey.copy_from_slice(&key_package.signing_share().serialize());

        let mut pool = NoncePool::new(
            id.serialize()[31] as u16,
            seckey,
            NoncePoolConfig::default(),
        );
        pool.init_peer(2);
        let generated = pool.generate_for_peer(2, 4).expect("generate");
        assert!(!generated.is_empty());
        pool.store_incoming(2, generated);
        let consumed = pool.consume_incoming(2);
        assert!(consumed.is_some());
    }
}
