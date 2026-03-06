use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use k256::ecdh::diffie_hellman;
use k256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

use crate::{Result, SignerError};

pub(crate) fn encrypt_content_for_peer(
    seckey: [u8; 32],
    peer_pubkey32: &str,
    plaintext: &str,
) -> Result<String> {
    let mut nonce32 = [0u8; 32];
    OsRng.fill_bytes(&mut nonce32);
    encrypt_content_for_peer_with_nonce(seckey, peer_pubkey32, plaintext, nonce32)
}

pub(crate) fn encrypt_content_for_peer_with_nonce(
    seckey: [u8; 32],
    peer_pubkey32: &str,
    plaintext: &str,
    nonce32: [u8; 32],
) -> Result<String> {
    let shared_x = event_shared_x(seckey, peer_pubkey32)?;
    let conversation_key = hkdf_extract_sha256(b"nip44-v2", &shared_x)?;
    let (chacha_key, chacha_nonce, hmac_key) = get_message_keys(&conversation_key, &nonce32)?;

    let mut padded = pad_message(plaintext)?;
    let mut chacha = ChaCha20::new((&chacha_key).into(), (&chacha_nonce).into());
    chacha.apply_keystream(&mut padded);
    let mac = hmac_aad(&hmac_key, &nonce32, &padded)?;

    let mut encoded = Vec::with_capacity(1 + 32 + padded.len() + 32);
    encoded.push(2u8);
    encoded.extend_from_slice(&nonce32);
    encoded.extend_from_slice(&padded);
    encoded.extend_from_slice(&mac);

    Ok(STANDARD_NO_PAD.encode(encoded))
}

pub(crate) fn decrypt_content_from_peer(
    seckey: [u8; 32],
    peer_pubkey32: &str,
    payload: &str,
) -> Result<String> {
    if payload.is_empty() || payload.starts_with('#') {
        return Err(SignerError::DecryptFailed(
            "unknown encryption version".to_string(),
        ));
    }
    let data = STANDARD_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|e| SignerError::DecryptFailed(format!("invalid base64: {e}")))?;
    if data.len() < 99 {
        return Err(SignerError::DecryptFailed(
            "invalid payload length".to_string(),
        ));
    }
    if data[0] != 2 {
        return Err(SignerError::DecryptFailed(
            "unknown encryption version marker".to_string(),
        ));
    }

    let mut nonce32 = [0u8; 32];
    nonce32.copy_from_slice(&data[1..33]);
    let ciphertext = &data[33..data.len() - 32];
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&data[data.len() - 32..]);

    let shared_x = event_shared_x(seckey, peer_pubkey32)?;
    let conversation_key = hkdf_extract_sha256(b"nip44-v2", &shared_x)?;
    let (chacha_key, chacha_nonce, hmac_key) = get_message_keys(&conversation_key, &nonce32)?;
    let expected_mac = hmac_aad(&hmac_key, &nonce32, ciphertext)?;
    if !ct_eq_32(&expected_mac, &mac) {
        return Err(SignerError::DecryptFailed("invalid MAC".to_string()));
    }

    let mut padded = ciphertext.to_vec();
    let mut chacha = ChaCha20::new((&chacha_key).into(), (&chacha_nonce).into());
    chacha.apply_keystream(&mut padded);
    unpad_message(&padded)
}

fn event_shared_x(seckey: [u8; 32], peer_pubkey32: &str) -> Result<[u8; 32]> {
    let peer_x = hex::decode(peer_pubkey32)
        .map_err(|e| SignerError::DecryptFailed(format!("invalid peer pubkey hex: {e}")))?;
    if peer_x.len() != 32 {
        return Err(SignerError::DecryptFailed(
            "peer pubkey must be 32 bytes x-only".to_string(),
        ));
    }
    let mut peer_bytes = [0u8; 33];
    peer_bytes[0] = 0x02;
    peer_bytes[1..].copy_from_slice(&peer_x);
    let peer_pk = PublicKey::from_sec1_bytes(&peer_bytes)
        .map_err(|e| SignerError::DecryptFailed(format!("invalid peer pubkey: {e}")))?;
    let local_sk = SecretKey::from_slice(&seckey)
        .map_err(|e| SignerError::DecryptFailed(format!("invalid local seckey: {e}")))?;
    let shared = diffie_hellman(local_sk.to_nonzero_scalar(), peer_pk.as_affine());

    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt)
        .map_err(|e| SignerError::DecryptFailed(format!("hkdf extract init failed: {e}")))?;
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&out);
    Ok(prk)
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let mut okm = Vec::with_capacity(len);
    let mut t = Vec::<u8>::new();
    let mut counter: u8 = 1;
    while okm.len() < len {
        let mut mac = Hmac::<Sha256>::new_from_slice(prk)
            .map_err(|e| SignerError::DecryptFailed(format!("hkdf expand init failed: {e}")))?;
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().to_vec();
        let remaining = len - okm.len();
        if t.len() <= remaining {
            okm.extend_from_slice(&t);
        } else {
            okm.extend_from_slice(&t[..remaining]);
        }
        counter = counter.saturating_add(1);
        if counter == 0 {
            return Err(SignerError::DecryptFailed(
                "hkdf expand overflow".to_string(),
            ));
        }
    }
    Ok(okm)
}

fn get_message_keys(
    conversation_key: &[u8; 32],
    nonce32: &[u8; 32],
) -> Result<([u8; 32], [u8; 12], [u8; 32])> {
    let keys = hkdf_expand_sha256(conversation_key, nonce32, 76)?;
    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];
    chacha_key.copy_from_slice(&keys[0..32]);
    chacha_nonce.copy_from_slice(&keys[32..44]);
    hmac_key.copy_from_slice(&keys[44..76]);
    Ok((chacha_key, chacha_nonce, hmac_key))
}

fn calc_padded_len(unpadded_len: usize) -> Result<usize> {
    if unpadded_len == 0 {
        return Err(SignerError::DecryptFailed(
            "invalid plaintext size".to_string(),
        ));
    }
    if unpadded_len <= 32 {
        return Ok(32);
    }
    let next_power = 1usize << ((usize::BITS - (unpadded_len - 1).leading_zeros()) as usize);
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    Ok(chunk * (((unpadded_len - 1) / chunk) + 1))
}

fn pad_message(plaintext: &str) -> Result<Vec<u8>> {
    let unpadded = plaintext.as_bytes();
    let unpadded_len = unpadded.len();
    if unpadded_len == 0 || unpadded_len > 0xffff {
        return Err(SignerError::DecryptFailed(
            "invalid plaintext size: must be between 1 and 65535 bytes".to_string(),
        ));
    }
    let padded_len = calc_padded_len(unpadded_len)?;
    let mut out = Vec::with_capacity(2 + padded_len);
    out.extend_from_slice(&(unpadded_len as u16).to_be_bytes());
    out.extend_from_slice(unpadded);
    out.resize(2 + padded_len, 0u8);
    Ok(out)
}

fn unpad_message(padded: &[u8]) -> Result<String> {
    if padded.len() < 2 {
        return Err(SignerError::DecryptFailed("invalid padding".to_string()));
    }
    let unpadded_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if unpadded_len == 0 || unpadded_len > 0xffff {
        return Err(SignerError::DecryptFailed("invalid padding".to_string()));
    }
    let expect = 2 + calc_padded_len(unpadded_len)?;
    if padded.len() != expect || padded.len() < 2 + unpadded_len {
        return Err(SignerError::DecryptFailed("invalid padding".to_string()));
    }
    let unpadded = &padded[2..2 + unpadded_len];
    String::from_utf8(unpadded.to_vec())
        .map_err(|e| SignerError::DecryptFailed(format!("invalid utf8 payload: {e}")))
}

fn hmac_aad(hmac_key: &[u8; 32], nonce32: &[u8; 32], ciphertext: &[u8]) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key)
        .map_err(|e| SignerError::DecryptFailed(format!("hmac init failed: {e}")))?;
    mac.update(nonce32);
    mac.update(ciphertext);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    Ok(tag)
}

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::decrypt_content_from_peer;

    #[test]
    fn decrypts_js_generated_nip44_payload() {
        let local_seckey = hex::decode("579689f6508912ed1fc14b656426a1669b1e15510e33304b2c9e62248bd9299e")
            .expect("hex seckey");
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&local_seckey);

        let peer_pubkey32 = "c8d330c2d4cc93bd48e2d865beef3b86c45d80326e53d0f897df055816651dbd";
        let payload = "AgcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHVjH09L8c2jhZOTvj0AILSiZ+7cwhoXDehgU1ieJdokoDSRlLk23Sveljn8K8WcJ/4wPFfu19mxGKiht58B8eQf0C/agzO4RGabcZqH0XwSTBBY07UklU6qnJ06V3ij5NjWXU+XreZRV0Bc/e52u/h6SO4tKELe2OFsh3H6sCjdlNgattHxKHfiO5QQPj+VpjGeXVk1PyThUPsCVVJTjK+IIWedUFXd2cXuPBcT6RzrYtKjnrG7W9KsgqCyaWRneaGAbAbD0G/N8k8lrq6tl8aPmLPyoin4V12s4cwk6+Zd94Sw";
        let plaintext = decrypt_content_from_peer(sk, peer_pubkey32, payload).expect("decrypt");
        assert!(plaintext.contains("\"request_id\":\"vec-1\""));
        assert!(plaintext.contains("\"type\":\"OnboardRequest\""));
        assert!(plaintext.contains("\"idx\":2"));
    }
}
