use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bifrost_codec::wire::{OnboardRequestWire, OnboardResponseWire};
use bifrost_codec::{
    BridgeEnvelope, BridgePayload, decode_bridge_envelope, encode_bridge_envelope,
};
use bifrost_core::types::{
    Bytes32, DerivedPublicNonce, EcdhPackage, GroupPackage, OnboardRequest, OnboardResponse,
    PartialSigPackage, SharePackage, SignSessionPackage, SignatureEntry,
};
use bifrost_core::{
    combine_ecdh_packages, combine_signatures, create_ecdh_package, create_partial_sig_package,
    local_pubkey_from_share, verify_partial_sig_package, verify_session_package,
};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use frost_secp256k1_tr_unofficial as frost;
use hmac::Mac;
use k256::FieldBytes;
use k256::PublicKey;
use k256::SecretKey;
use k256::ecdh::diffie_hellman;
use k256::schnorr::SigningKey;
use nostr::{Alphabet, Event, SingleLetterTag, TagKind};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::errors::{FrostUtilsError, FrostUtilsResult};

pub fn validate_sign_session(
    group: &GroupPackage,
    session: &SignSessionPackage,
) -> FrostUtilsResult<()> {
    verify_session_package(group, session)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))
}

pub fn sign_create_partial(
    group: &GroupPackage,
    session: &SignSessionPackage,
    share: &SharePackage,
    signing_nonces: &[frost::round1::SigningNonces],
    signer_pubkey32: Option<Bytes32>,
) -> FrostUtilsResult<PartialSigPackage> {
    let pubkey = if let Some(v) = signer_pubkey32 {
        v
    } else {
        local_pubkey_from_share(share).map_err(|e| FrostUtilsError::Crypto(e.to_string()))?
    };

    create_partial_sig_package(group, session, share, signing_nonces, pubkey)
        .map_err(|e| FrostUtilsError::Crypto(e.to_string()))
}

pub fn sign_verify_partial(
    group: &GroupPackage,
    session: &SignSessionPackage,
    partial: &PartialSigPackage,
) -> FrostUtilsResult<()> {
    verify_partial_sig_package(group, session, partial)
        .map_err(|e| FrostUtilsError::VerificationFailed(e.to_string()))
}

pub fn sign_finalize(
    group: &GroupPackage,
    session: &SignSessionPackage,
    partials: &[PartialSigPackage],
) -> FrostUtilsResult<Vec<SignatureEntry>> {
    combine_signatures(group, session, partials).map_err(|e| FrostUtilsError::Crypto(e.to_string()))
}

pub fn ecdh_create_from_share(
    members: &[u16],
    share: &SharePackage,
    targets: &[Bytes32],
) -> FrostUtilsResult<EcdhPackage> {
    create_ecdh_package(members, share, targets).map_err(|e| FrostUtilsError::Crypto(e.to_string()))
}

pub fn ecdh_finalize(pkgs: &[EcdhPackage], target: Bytes32) -> FrostUtilsResult<Bytes32> {
    combine_ecdh_packages(pkgs, target).map_err(|e| FrostUtilsError::Crypto(e.to_string()))
}

pub fn generate_opaque_request_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn build_onboard_request_event(
    share_seckey: [u8; 32],
    peer_pubkey32_hex: &str,
    event_kind: u64,
    request_id: &str,
    sent_at: u64,
    nonces: &[DerivedPublicNonce],
) -> FrostUtilsResult<Event> {
    if nonces.is_empty() {
        return Err(FrostUtilsError::InvalidInput(
            "onboard request nonces must not be empty".to_string(),
        ));
    }
    let plaintext = encode_bridge_envelope(&BridgeEnvelope {
        request_id: request_id.to_string(),
        sent_at,
        payload: BridgePayload::OnboardRequest(OnboardRequestWire::from(OnboardRequest {
            version: 1,
            nonces: nonces.to_vec(),
        })),
    })
    .map_err(|e| FrostUtilsError::Codec(e.to_string()))?;
    let ciphertext = encrypt_content_for_peer(share_seckey, peer_pubkey32_hex, &plaintext)?;
    build_signed_event(
        share_seckey,
        event_kind,
        vec![vec!["p".to_string(), peer_pubkey32_hex.to_string()]],
        ciphertext,
        sent_at,
    )
}

pub fn decode_onboard_response_event(
    event: &Event,
    share_seckey: [u8; 32],
    expected_peer_pubkey32_hex: &str,
    expected_local_pubkey32_hex: &str,
    request_id: &str,
) -> FrostUtilsResult<Option<OnboardResponse>> {
    if event.pubkey.to_hex().to_ascii_lowercase() != expected_peer_pubkey32_hex {
        return Ok(None);
    }
    if !has_exact_local_recipient_tag(event, expected_local_pubkey32_hex) {
        return Ok(None);
    }
    let plaintext =
        match decrypt_content_from_peer(share_seckey, expected_peer_pubkey32_hex, &event.content) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
    let envelope = match decode_bridge_envelope(&plaintext) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if envelope.request_id != request_id {
        return Ok(None);
    }
    match envelope.payload {
        BridgePayload::OnboardResponse(wire) => {
            <OnboardResponse as TryFrom<OnboardResponseWire>>::try_from(wire)
                .map(Some)
                .map_err(|e| FrostUtilsError::Codec(e.to_string()))
        }
        BridgePayload::Error(err) => Err(FrostUtilsError::VerificationFailed(err.message)),
        _ => Ok(None),
    }
}

fn has_exact_local_recipient_tag(event: &Event, local_pubkey: &str) -> bool {
    let p_tag = SingleLetterTag::lowercase(Alphabet::P);
    let recipients = event
        .tags
        .iter()
        .filter_map(|tag| match tag.kind() {
            TagKind::SingleLetter(letter) if letter == p_tag => tag.content().map(str::to_string),
            _ => None,
        })
        .collect::<Vec<_>>();
    recipients.len() == 1 && recipients[0] == local_pubkey
}

fn build_signed_event(
    seckey: [u8; 32],
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
    created_at: u64,
) -> FrostUtilsResult<Event> {
    let fb = FieldBytes::from(seckey);
    let signing_key = SigningKey::from_bytes(&fb)
        .map_err(|e| FrostUtilsError::Crypto(format!("invalid signing key: {e}")))?;
    let pubkey = hex::encode(signing_key.verifying_key().to_bytes());
    let preimage = serde_json::json!([0, pubkey, created_at, kind, tags, content]).to_string();
    let digest = Sha256::digest(preimage.as_bytes());
    let id = hex::encode(digest);
    let aux = [0u8; 32];
    let sig = signing_key
        .sign_raw(digest.as_slice(), &aux)
        .map_err(|e| FrostUtilsError::Crypto(format!("failed signing event: {e}")))?;
    serde_json::from_value(serde_json::json!({
        "id": id,
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": hex::encode(sig.to_bytes()),
    }))
    .map_err(|e| FrostUtilsError::Codec(format!("build nostr event: {e}")))
}

fn encrypt_content_for_peer(
    seckey: [u8; 32],
    peer_pubkey32: &str,
    plaintext: &str,
) -> FrostUtilsResult<String> {
    let mut nonce32 = [0u8; 32];
    OsRng.fill_bytes(&mut nonce32);
    let shared_x = event_shared_x(seckey, peer_pubkey32)?;
    let conversation_key = hkdf_extract_sha256(b"nip44-v2", &shared_x)?;
    let (chacha_key, chacha_nonce, hmac_key) = get_message_keys(&conversation_key, &nonce32)?;

    let mut padded = pad_message(plaintext)?;
    let mut chacha = chacha20::ChaCha20::new((&chacha_key).into(), (&chacha_nonce).into());
    chacha.apply_keystream(&mut padded);
    let mac = hmac_aad(&hmac_key, &nonce32, &padded)?;

    let mut encoded = Vec::with_capacity(1 + 32 + padded.len() + 32);
    encoded.push(2u8);
    encoded.extend_from_slice(&nonce32);
    encoded.extend_from_slice(&padded);
    encoded.extend_from_slice(&mac);
    Ok(STANDARD_NO_PAD.encode(encoded))
}

fn decrypt_content_from_peer(
    seckey: [u8; 32],
    peer_pubkey32: &str,
    payload: &str,
) -> FrostUtilsResult<String> {
    let data = STANDARD_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|e| FrostUtilsError::Crypto(format!("invalid base64: {e}")))?;
    if data.len() < 99 {
        return Err(FrostUtilsError::DecryptionFailed);
    }
    if data[0] != 2 {
        return Err(FrostUtilsError::DecryptionFailed);
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
        return Err(FrostUtilsError::DecryptionFailed);
    }

    let mut padded = ciphertext.to_vec();
    let mut chacha = chacha20::ChaCha20::new((&chacha_key).into(), (&chacha_nonce).into());
    chacha.apply_keystream(&mut padded);
    unpad_message(&padded)
}

fn event_shared_x(seckey: [u8; 32], peer_pubkey32: &str) -> FrostUtilsResult<[u8; 32]> {
    let peer_x = hex::decode(peer_pubkey32)
        .map_err(|e| FrostUtilsError::Crypto(format!("invalid peer pubkey hex: {e}")))?;
    if peer_x.len() != 32 {
        return Err(FrostUtilsError::InvalidInput(
            "peer pubkey must be 32 bytes x-only".to_string(),
        ));
    }
    let mut peer_bytes = [0u8; 33];
    peer_bytes[0] = 0x02;
    peer_bytes[1..].copy_from_slice(&peer_x);
    let peer_pk = PublicKey::from_sec1_bytes(&peer_bytes)
        .map_err(|e| FrostUtilsError::Crypto(format!("invalid peer pubkey: {e}")))?;
    let local_sk = SecretKey::from_slice(&seckey)
        .map_err(|e| FrostUtilsError::Crypto(format!("invalid local seckey: {e}")))?;
    let shared = diffie_hellman(local_sk.to_nonzero_scalar(), peer_pk.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> FrostUtilsResult<[u8; 32]> {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(salt)
        .map_err(|e| FrostUtilsError::Crypto(format!("hkdf extract init failed: {e}")))?;
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&out);
    Ok(prk)
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> FrostUtilsResult<Vec<u8>> {
    let mut okm = Vec::with_capacity(len);
    let mut t = Vec::<u8>::new();
    let mut counter: u8 = 1;
    while okm.len() < len {
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(prk)
            .map_err(|e| FrostUtilsError::Crypto(format!("hkdf expand init failed: {e}")))?;
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
            return Err(FrostUtilsError::Crypto("hkdf expand overflow".to_string()));
        }
    }
    Ok(okm)
}

fn get_message_keys(
    conversation_key: &[u8; 32],
    nonce32: &[u8; 32],
) -> FrostUtilsResult<([u8; 32], [u8; 12], [u8; 32])> {
    let keys = hkdf_expand_sha256(conversation_key, nonce32, 76)?;
    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];
    chacha_key.copy_from_slice(&keys[0..32]);
    chacha_nonce.copy_from_slice(&keys[32..44]);
    hmac_key.copy_from_slice(&keys[44..76]);
    Ok((chacha_key, chacha_nonce, hmac_key))
}

fn calc_padded_len(unpadded_len: usize) -> FrostUtilsResult<usize> {
    if unpadded_len == 0 {
        return Err(FrostUtilsError::InvalidInput(
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

fn pad_message(plaintext: &str) -> FrostUtilsResult<Vec<u8>> {
    let unpadded = plaintext.as_bytes();
    let unpadded_len = unpadded.len();
    if unpadded_len == 0 || unpadded_len > 0xffff {
        return Err(FrostUtilsError::InvalidInput(
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

fn unpad_message(padded: &[u8]) -> FrostUtilsResult<String> {
    if padded.len() < 2 {
        return Err(FrostUtilsError::DecryptionFailed);
    }
    let unpadded_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if unpadded_len == 0 || unpadded_len > 0xffff {
        return Err(FrostUtilsError::DecryptionFailed);
    }
    let expect = 2 + calc_padded_len(unpadded_len)?;
    if padded.len() != expect || padded.len() < 2 + unpadded_len {
        return Err(FrostUtilsError::DecryptionFailed);
    }
    let unpadded = &padded[2..2 + unpadded_len];
    String::from_utf8(unpadded.to_vec()).map_err(|_| FrostUtilsError::DecryptionFailed)
}

fn hmac_aad(
    hmac_key: &[u8; 32],
    nonce32: &[u8; 32],
    ciphertext: &[u8],
) -> FrostUtilsResult<[u8; 32]> {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(hmac_key)
        .map_err(|e| FrostUtilsError::Crypto(format!("hmac init failed: {e}")))?;
    mac.update(nonce32);
    mac.update(ciphertext);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    Ok(tag)
}

fn ct_eq_32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for idx in 0..32 {
        diff |= left[idx] ^ right[idx];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use bifrost_core::nonce::NoncePool;
    use bifrost_core::nonce::NoncePoolConfig;
    use bifrost_core::types::{
        IndexedPublicNonceCommitment, MemberNonceCommitmentSet, SignSessionTemplate,
    };
    use bifrost_core::{create_session_package, local_pubkey_from_share};
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    use super::*;
    use crate::keyset::create_keyset;
    use crate::types::CreateKeysetConfig;

    fn two_member_session_fixture() -> (
        GroupPackage,
        SharePackage,
        SharePackage,
        SignSessionPackage,
        Vec<frost::round1::SigningNonces>,
        Vec<frost::round1::SigningNonces>,
    ) {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("bundle");

        let share_a = bundle.shares[0].clone();
        let share_b = bundle.shares[1].clone();

        let mut pool_a = NoncePool::new(share_a.idx, share_a.seckey, NoncePoolConfig::default());
        pool_a.init_peer(share_b.idx);
        let nonce_a = pool_a
            .generate_for_peer(share_b.idx, 1)
            .expect("nonce a")
            .remove(0);
        let nonces_a = pool_a
            .take_outgoing_signing_nonces_many(share_b.idx, &[nonce_a.code])
            .expect("nonces a");

        let mut pool_b = NoncePool::new(share_b.idx, share_b.seckey, NoncePoolConfig::default());
        pool_b.init_peer(share_a.idx);
        let nonce_b = pool_b
            .generate_for_peer(share_a.idx, 1)
            .expect("nonce b")
            .remove(0);
        let nonces_b = pool_b
            .take_outgoing_signing_nonces_many(share_a.idx, &[nonce_b.code])
            .expect("nonces b");

        let mut members = vec![share_a.idx, share_b.idx];
        members.sort_unstable();
        let mut nonces = vec![
            MemberNonceCommitmentSet {
                idx: share_a.idx,
                entries: vec![IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: nonce_a.binder_pn,
                    hidden_pn: nonce_a.hidden_pn,
                    code: nonce_a.code,
                }],
            },
            MemberNonceCommitmentSet {
                idx: share_b.idx,
                entries: vec![IndexedPublicNonceCommitment {
                    hash_index: 0,
                    binder_pn: nonce_b.binder_pn,
                    hidden_pn: nonce_b.hidden_pn,
                    code: nonce_b.code,
                }],
            },
        ];
        nonces.sort_by_key(|m| m.idx);

        let mut session = create_session_package(
            &bundle.group,
            SignSessionTemplate {
                members,
                hashes: vec![[7u8; 32]],
                content: None,
                kind: "message".to_string(),
                stamp: 1,
            },
        )
        .expect("session");
        session.nonces = Some(nonces);

        (bundle.group, share_a, share_b, session, nonces_a, nonces_b)
    }

    #[test]
    fn stateless_sign_flow_roundtrip() {
        let (group, share_a, share_b, session, nonces_a, nonces_b) = two_member_session_fixture();
        validate_sign_session(&group, &session).expect("session valid");

        let partial_a =
            sign_create_partial(&group, &session, &share_a, &nonces_a, None).expect("partial a");
        let partial_b =
            sign_create_partial(&group, &session, &share_b, &nonces_b, None).expect("partial b");

        sign_verify_partial(&group, &session, &partial_a).expect("verify a");
        sign_verify_partial(&group, &session, &partial_b).expect("verify b");

        let sigs = sign_finalize(&group, &session, &[partial_a, partial_b]).expect("finalize");
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn stateless_ecdh_flow_roundtrip() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("bundle");

        let share_a = bundle.shares[0].clone();
        let share_b = bundle.shares[1].clone();
        let target = local_pubkey_from_share(&bundle.shares[2]).expect("target");
        let mut members = vec![share_a.idx, share_b.idx];
        members.sort_unstable();

        let pkg_a = ecdh_create_from_share(&members, &share_a, &[target]).expect("pkg a");
        let pkg_b = ecdh_create_from_share(&members, &share_b, &[target]).expect("pkg b");

        let secret_ab = ecdh_finalize(&[pkg_a.clone(), pkg_b.clone()], target).expect("combine");
        let secret_ba = ecdh_finalize(&[pkg_b, pkg_a], target).expect("combine");
        assert_eq!(secret_ab, secret_ba);
    }

    #[test]
    fn stateless_onboard_exchange_roundtrip() {
        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("bundle");
        let local_share = bundle.shares[0].clone();
        let inviter_share = bundle.shares[1].clone();
        let inviter_secret = SecretKey::from_slice(&inviter_share.seckey).expect("inviter secret");
        let inviter_pubkey32 = hex::encode(
            &inviter_secret
                .public_key()
                .to_encoded_point(false)
                .x()
                .expect("x")[..],
        );
        let local_pubkey32 =
            hex::encode(local_pubkey_from_share(&local_share).expect("local pubkey"));
        let request_id = generate_opaque_request_id();
        let bootstrap_nonces = vec![DerivedPublicNonce {
            binder_pn: [7u8; 33],
            hidden_pn: [8u8; 33],
            code: [9u8; 32],
        }];
        let event = build_onboard_request_event(
            local_share.seckey,
            &inviter_pubkey32,
            20_000,
            &request_id,
            42,
            &bootstrap_nonces,
        )
        .expect("build request");
        let plaintext =
            decrypt_content_from_peer(inviter_share.seckey, &local_pubkey32, &event.content)
                .expect("decrypt request");
        let envelope = decode_bridge_envelope(&plaintext).expect("decode request");
        assert_eq!(envelope.request_id, request_id);
        let response = OnboardResponse {
            group: bundle.group.clone(),
            nonces: vec![],
        };
        let response_plaintext = encode_bridge_envelope(&BridgeEnvelope {
            request_id: request_id.clone(),
            sent_at: 43,
            payload: BridgePayload::OnboardResponse(OnboardResponseWire::from(response.clone())),
        })
        .expect("encode response");
        let response_content =
            encrypt_content_for_peer(inviter_share.seckey, &local_pubkey32, &response_plaintext)
                .expect("encrypt response");
        let response_event = build_signed_event(
            inviter_share.seckey,
            20_000,
            vec![vec!["p".to_string(), local_pubkey32.clone()]],
            response_content,
            43,
        )
        .expect("build response");
        let decoded = decode_onboard_response_event(
            &response_event,
            local_share.seckey,
            &inviter_pubkey32,
            &local_pubkey32,
            &request_id,
        )
        .expect("decode response")
        .expect("matching response");
        assert_eq!(decoded.group, response.group);
    }
}
