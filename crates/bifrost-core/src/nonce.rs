use std::collections::{HashMap, HashSet, VecDeque};

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
    spent_outgoing: HashMap<u16, HashSet<Bytes32>>,
    incoming: HashMap<u16, HashMap<Bytes32, DerivedPublicNonce>>,
    incoming_order: HashMap<u16, VecDeque<Bytes32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoncePeerStats {
    pub incoming_available: usize,
    pub outgoing_available: usize,
    pub outgoing_spent: usize,
    pub can_sign: bool,
    pub should_send_nonces: bool,
}

impl NoncePool {
    pub fn new(our_idx: u16, seckey: Bytes32, config: NoncePoolConfig) -> Self {
        Self {
            our_idx,
            seckey,
            config,
            outgoing_public: HashMap::new(),
            outgoing_secret: HashMap::new(),
            spent_outgoing: HashMap::new(),
            incoming: HashMap::new(),
            incoming_order: HashMap::new(),
        }
    }

    pub fn init_peer(&mut self, peer_idx: u16) {
        if peer_idx == self.our_idx {
            return;
        }
        self.outgoing_public.entry(peer_idx).or_default();
        self.outgoing_secret.entry(peer_idx).or_default();
        self.spent_outgoing.entry(peer_idx).or_default();
        self.incoming.entry(peer_idx).or_default();
        self.incoming_order.entry(peer_idx).or_default();
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
        let spent_set = self.spent_outgoing.entry(peer_idx).or_default();

        let slots = self.config.pool_size.saturating_sub(public_map.len());
        let generate = slots.min(count);

        let mut out = Vec::with_capacity(generate);
        for _ in 0..generate {
            let (signing_nonces, commitments) = frost::round1::commit(&signing_share, &mut OsRng);
            let code = loop {
                let mut candidate = [0u8; 32];
                OsRng.fill_bytes(&mut candidate);
                if !public_map.contains_key(&candidate)
                    && !secret_map.contains_key(&candidate)
                    && !spent_set.contains(&candidate)
                {
                    break candidate;
                }
            };

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
        let order = self.incoming_order.entry(peer_idx).or_default();
        for nonce in nonces {
            if map.len() >= self.config.pool_size {
                break;
            }
            if map.contains_key(&nonce.code) {
                continue;
            }
            order.push_back(nonce.code);
            map.insert(nonce.code, nonce);
        }
    }

    pub fn consume_incoming(&mut self, peer_idx: u16) -> Option<MemberPublicNonce> {
        let map = self.incoming.get_mut(&peer_idx)?;
        let order = self.incoming_order.get_mut(&peer_idx)?;
        while let Some(code) = order.pop_front() {
            if let Some(nonce) = map.remove(&code) {
                return Some(MemberPublicNonce {
                    idx: peer_idx,
                    binder_pn: nonce.binder_pn,
                    hidden_pn: nonce.hidden_pn,
                    code: nonce.code,
                });
            }
        }
        None
    }

    pub fn take_outgoing_signing_nonces(
        &mut self,
        peer_idx: u16,
        code: Bytes32,
    ) -> CoreResult<frost::round1::SigningNonces> {
        let secret_map = self
            .outgoing_secret
            .get_mut(&peer_idx)
            .ok_or(CoreError::NonceNotFound)?;
        let spent_set = self.spent_outgoing.entry(peer_idx).or_default();

        let Some(nonces) = secret_map.remove(&code) else {
            if spent_set.contains(&code) {
                return Err(CoreError::NonceAlreadyClaimed);
            }
            return Err(CoreError::NonceNotFound);
        };

        if let Some(public_map) = self.outgoing_public.get_mut(&peer_idx) {
            public_map.remove(&code);
        }
        spent_set.insert(code);
        Ok(nonces)
    }

    pub fn take_outgoing_signing_nonces_many(
        &mut self,
        peer_idx: u16,
        codes: &[Bytes32],
    ) -> CoreResult<Vec<frost::round1::SigningNonces>> {
        if codes.is_empty() {
            return Ok(Vec::new());
        }
        // Atomic claim: validate all requested codes first, then consume.
        let secret_map = self
            .outgoing_secret
            .get(&peer_idx)
            .ok_or(CoreError::NonceNotFound)?;
        let spent_set = self
            .spent_outgoing
            .get(&peer_idx)
            .cloned()
            .unwrap_or_default();
        for code in codes {
            if !secret_map.contains_key(code) {
                if spent_set.contains(code) {
                    return Err(CoreError::NonceAlreadyClaimed);
                }
                return Err(CoreError::NonceNotFound);
            }
        }

        let mut out = Vec::with_capacity(codes.len());
        for code in codes {
            out.push(self.take_outgoing_signing_nonces(peer_idx, *code)?);
        }
        Ok(out)
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

    pub fn peer_stats(&self, peer_idx: u16) -> NoncePeerStats {
        let incoming_available = self.incoming.get(&peer_idx).map(|m| m.len()).unwrap_or(0);
        let outgoing_available = self
            .outgoing_public
            .get(&peer_idx)
            .map(|m| m.len())
            .unwrap_or(0);
        let outgoing_spent = self
            .spent_outgoing
            .get(&peer_idx)
            .map(|m| m.len())
            .unwrap_or(0);

        NoncePeerStats {
            incoming_available,
            outgoing_available,
            outgoing_spent,
            can_sign: self.can_sign(peer_idx),
            should_send_nonces: self.should_send_nonces_to(peer_idx),
        }
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

    #[test]
    fn outgoing_signing_nonces_are_single_use() {
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

        let generated = pool.generate_for_peer(2, 1).expect("generate");
        let code = generated.first().expect("nonce").code;

        let first = pool.take_outgoing_signing_nonces(2, code);
        assert!(first.is_ok());

        let second = pool.take_outgoing_signing_nonces(2, code);
        assert!(matches!(second, Err(CoreError::NonceAlreadyClaimed)));
    }

    #[test]
    fn peer_stats_reports_counts() {
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
        let generated = pool.generate_for_peer(2, 3).expect("generate");
        pool.store_incoming(2, generated);

        let stats = pool.peer_stats(2);
        assert!(stats.incoming_available > 0);
        assert!(stats.outgoing_available > 0);
    }

    #[test]
    fn incoming_nonces_are_consumed_fifo() {
        let mut pool = NoncePool::new(1, [1u8; 32], NoncePoolConfig::default());
        pool.init_peer(2);

        let first = DerivedPublicNonce {
            binder_pn: [2u8; 33],
            hidden_pn: [3u8; 33],
            code: [10u8; 32],
        };
        let second = DerivedPublicNonce {
            binder_pn: [4u8; 33],
            hidden_pn: [5u8; 33],
            code: [11u8; 32],
        };
        pool.store_incoming(2, vec![first.clone(), second.clone()]);

        let consumed_first = pool.consume_incoming(2).expect("first nonce");
        let consumed_second = pool.consume_incoming(2).expect("second nonce");
        assert_eq!(consumed_first.code, first.code);
        assert_eq!(consumed_second.code, second.code);
    }
}
