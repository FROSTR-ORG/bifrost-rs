use sha2::{Digest, Sha256};

pub fn message_sighash(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

pub fn bind_sighash(session_id: [u8; 32], sighash: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(session_id);
    h.update(sighash);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_sighash_is_deterministic() {
        let a = bind_sighash([1u8; 32], [2u8; 32]);
        let b = bind_sighash([1u8; 32], [2u8; 32]);
        assert_eq!(a, b);
    }
}
