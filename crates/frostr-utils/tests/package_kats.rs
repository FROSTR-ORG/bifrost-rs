//! Bucket B B.2 known-answer tests (KATs) for the v2 portable package
//! envelope at the bech32m-string layer.
//!
//! Three pinned vectors — one per package kind (bfshare, bfprofile,
//! bfonboard). Each KAT:
//!
//! 1. Derives a v2 envelope deterministically (fixed password, salt,
//!    nonce, plaintext, and the lighter `minimum_secure` Argon2id params
//!    for fast `cargo test`).
//! 2. Bech32m-wraps the envelope JSON (and, for bfprofile, the leading
//!    profile-id prefix).
//! 3. Pins the resulting bech32m string as a constant.
//! 4. Asserts that `decode_*_package` against the pinned string returns
//!    the original plaintext payload.
//!
//! Any unintentional drift in the v2 envelope shape, AAD construction,
//! KDF, or AEAD primitive will break these tests. Replacing the OLD
//! PBKDF2 + AES-GCM-24 KATs (which were tied to a now-retired scheme),
//! these vectors anchor the byte-level wire format of the new
//! Argon2id + XChaCha20Poly1305 stack.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bech32::{Bech32m, ByteIterExt, Fe32IterExt, Hrp};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frostr_utils::{
    Argon2Params, BF_PACKAGE_VERSION, BF_PACKAGE_XCHACHA_NONCE_BYTES, PACKAGE_KDF_SALT_LEN,
    PREFIX_BFONBOARD, PREFIX_BFPROFILE, PREFIX_BFSHARE, build_aad_package,
    decode_bfonboard_package, decode_bfprofile_package, decode_bfshare_package,
    derive_package_encryption_key_v2, derive_profile_id_from_share_secret,
};
use serde_json::json;

/// Deterministic helper: build a v2 envelope JSON from fixed inputs.
fn build_envelope_json(
    hrp: &str,
    password: &str,
    plaintext: &str,
    outer_id: Option<&str>,
    salt: &[u8; PACKAGE_KDF_SALT_LEN],
    nonce: &[u8; BF_PACKAGE_XCHACHA_NONCE_BYTES],
    params: &Argon2Params,
) -> Vec<u8> {
    let aad = build_aad_package(BF_PACKAGE_VERSION, hrp, salt, outer_id).expect("aad");
    let key = derive_package_encryption_key_v2(password, salt, params).expect("kdf");
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .expect("encrypt");
    let envelope = json!({
        "version": BF_PACKAGE_VERSION,
        "kdf": "argon2id",
        "kdf_m_cost": params.m_cost(),
        "kdf_t_cost": params.t_cost(),
        "kdf_p_cost": params.p_cost(),
        "aead": "xchacha20poly1305",
        "salt_hex": hex::encode(salt),
        "nonce_hex": hex::encode(nonce),
        "ciphertext": URL_SAFE_NO_PAD.encode(&ciphertext),
    });
    serde_json::to_vec(&envelope).expect("ser")
}

fn bech32m_wrap(hrp: &str, payload: &[u8]) -> String {
    let hrp = Hrp::parse(hrp).expect("hrp parse");
    let mut out = String::new();
    out.extend(
        payload
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .chars(),
    );
    out
}

const KAT_PASSWORD: &str = "kat-password-v2";
const KAT_SHARE_SECRET: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const KAT_PEER_PK: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
/// Computed from `derive_profile_id_from_share_secret(KAT_SHARE_SECRET)` and
/// pinned here to keep the bfprofile KAT free of runtime dependencies on the
/// derivation function. The pin is checked at test-time.
const KAT_PROFILE_ID: &str =
    "a62c6e300a1d759cafa27aabf212d2d7675c1e1eadfa48448e1406744fbe3830";

/// 16-byte fixed salt, all 0xAB.
const KAT_SALT: [u8; PACKAGE_KDF_SALT_LEN] = [0xABu8; PACKAGE_KDF_SALT_LEN];
/// 24-byte fixed XChaCha20 nonce, all 0xCD.
const KAT_NONCE: [u8; BF_PACKAGE_XCHACHA_NONCE_BYTES] = [0xCDu8; BF_PACKAGE_XCHACHA_NONCE_BYTES];

#[test]
fn bfshare_kat_pins_bech32m_string() {
    let plaintext_payload = format!("{KAT_SHARE_SECRET}?relay=wss%3A%2F%2Frelay.one");
    let bytes = build_envelope_json(
        PREFIX_BFSHARE,
        KAT_PASSWORD,
        &plaintext_payload,
        None,
        &KAT_SALT,
        &KAT_NONCE,
        &Argon2Params::minimum_secure(),
    );
    let kat = bech32m_wrap(PREFIX_BFSHARE, &bytes);

    // Pinned bech32m string captured from a deterministic run with
    // KAT_PASSWORD / KAT_SALT / KAT_NONCE / minimum_secure Argon2id params.
    const EXPECTED: &str = "bfshare10v3xzetpvs3r5gncvd5xzcmgvyerqur0d3unzvesx53zcgnrd9cxsetjw3jhsapz8g3rvvrhxaey7unpdskkzvfnw9jr2upktam9zd2d2afyjctcdv6x5wz58qc9yunvxaf4q3ejv3hrqvph8ye9wwfjtum5ywzgfcu9v42wdycku7p3fpdr253e2ez8vd2wxeu5ve6n0f2nwv352px56jzh090hwc2j2f3kxun9f4c9q4msfdcyccfkf3kkz6f3xguk5kzgw4r45d6v2suywt2kdf2hxnt6fvm5k33j8y3zcgntv3nzyw3zv9exwmmwxf5kgg3vyf4kgejld40kxmmnws3r5d34x5envtpzddjxvhmsta3k7um5ygarztpzddjxvhm5ta3k7um5ygarxtpzdehkucm9ta5x27pz8g3xxerrv33kgcmyvdjxxerrv33kgcmyvdjxxerrv33kgcmyvdjxxerrv33kgcmyvdjxxerrv33kgcmyygkzyumpd36976r90q3r5gnpvfskyctzv93xzcnpvfskyctzv93xzcnpvfskyctzv93xzcnpvg3zcgnkv4e8x6t0dc3r5vna4rw6q2";

    if kat != EXPECTED {
        eprintln!("BFSHARE KAT (capture):\n{kat}");
    }
    assert_eq!(
        kat, EXPECTED,
        "bfshare KAT drift — re-pin only after deliberately changing the v2 wire format"
    );

    let decoded = decode_bfshare_package(&kat, KAT_PASSWORD).expect("kat decode");
    assert_eq!(decoded.share_secret, KAT_SHARE_SECRET);
    assert_eq!(decoded.relays, vec!["wss://relay.one".to_string()]);
}

#[test]
fn bfonboard_kat_pins_bech32m_string() {
    let plaintext_payload =
        format!("{KAT_SHARE_SECRET}?relay=wss%3A%2F%2Frelay.one&peer_pk={KAT_PEER_PK}");
    let bytes = build_envelope_json(
        PREFIX_BFONBOARD,
        KAT_PASSWORD,
        &plaintext_payload,
        None,
        &KAT_SALT,
        &KAT_NONCE,
        &Argon2Params::minimum_secure(),
    );
    let kat = bech32m_wrap(PREFIX_BFONBOARD, &bytes);

    const EXPECTED: &str = "bfonboard10v3xzetpvs3r5gncvd5xzcmgvyerqur0d3unzvesx53zcgnrd9cxsetjw3jhsapz8g3rvvrhxaey7unpdskkzvfnw9jr2upktam9zd2d2afyjctcdv6x5wz58qc9yunvxaf4q3ejv3hrqvph8ye9wwfjtum5ywzgfcu9v42wdycku7p3fpdr253e2ez8vd2wxeu5ve6n0f2nwv352px56jzh090hwc2j2f3kxun9f4c9q4msfdcyccfkf3kkz6f3xguk5kzxf3qnj46jvce5svzrxa5k7j2gta6hv53eva4h2a6sw34k6wrr0p3xu6nyw3q5w3rr8y65znz0dfa853rtwa0kyum32djyvvz6x3h5wvzsdfpywempgce5ve3jxee42smg0guh2sf50f35ghecvenywe6t2fd85c2nwp24juzyv9q4y7zs894yznr4veu4q5fz9s3xkerxygazyctjvahkuvnfvs3zcgntv3n97m2lvdhhxapz8gmr2dfnxckzy6myve0hqhmrdaehgg36xykzy6myve0hghmrdaehgg36xvkzymn0de3k2hmgv4uzyw3zvdjxxerrv33kgcmyvdjxxerrv33kgcmyvdjxxerrv33kgcmyvdjxxerrv33kgcmyvdjxxerrv33kgg3vyfekzmr5ta5x27pz8g3xzcnpvfskyctzv93xzcnpvfskyctzv93xzcnpvfskyctzv93xzc3z9s38vetjwd5k7m3z8ge86l65yg6";

    if kat != EXPECTED {
        eprintln!("BFONBOARD KAT (capture):\n{kat}");
    }
    assert_eq!(
        kat, EXPECTED,
        "bfonboard KAT drift — re-pin only after deliberately changing the v2 wire format"
    );

    let decoded = decode_bfonboard_package(&kat, KAT_PASSWORD).expect("kat decode");
    assert_eq!(decoded.share_secret, KAT_SHARE_SECRET);
    assert_eq!(decoded.peer_pk, KAT_PEER_PK);
    assert_eq!(decoded.relays, vec!["wss://relay.one".to_string()]);
}

#[test]
fn kat_profile_id_matches_share_secret() {
    let derived = derive_profile_id_from_share_secret(KAT_SHARE_SECRET).expect("derive");
    assert_eq!(
        derived, KAT_PROFILE_ID,
        "KAT_PROFILE_ID drifted from derive_profile_id_from_share_secret(KAT_SHARE_SECRET); \
         re-pin KAT_PROFILE_ID to {derived:?}"
    );
}

#[test]
fn bfprofile_kat_pins_bech32m_string() {
    // Compact JSON plaintext for the bfprofile package. The exact
    // serialization here is what the production normalizer would produce on
    // a round-trip, so the KAT plaintext stays in lockstep with the writer.
    let plaintext_payload = serde_json::json!({
        "profile_id": KAT_PROFILE_ID,
        "version": BF_PACKAGE_VERSION,
        "device": {
            "name": "Alice Laptop",
            "share_secret": KAT_SHARE_SECRET,
            "manual_peer_policy_overrides": [],
            "relays": ["wss://relay.one"]
        },
        "group_package": {
            "group_name": "Alpha",
            "group_pk": "3333333333333333333333333333333333333333333333333333333333333333",
            "threshold": 2,
            "members": [
                { "idx": 1, "pubkey": "024444444444444444444444444444444444444444444444444444444444444444" },
                { "idx": 2, "pubkey": "035555555555555555555555555555555555555555555555555555555555555555" },
                { "idx": 3, "pubkey": "026666666666666666666666666666666666666666666666666666666666666666" }
            ]
        }
    });
    let plaintext_str = serde_json::to_string(&plaintext_payload).expect("plaintext");
    let envelope_bytes = build_envelope_json(
        PREFIX_BFPROFILE,
        KAT_PASSWORD,
        &plaintext_str,
        Some(KAT_PROFILE_ID),
        &KAT_SALT,
        &KAT_NONCE,
        &Argon2Params::minimum_secure(),
    );

    // bfprofile prepends the 64-byte ascii profile id prefix to the envelope JSON.
    let mut payload = Vec::with_capacity(64 + envelope_bytes.len());
    payload.extend_from_slice(KAT_PROFILE_ID.as_bytes());
    payload.extend_from_slice(&envelope_bytes);
    let kat = bech32m_wrap(PREFIX_BFPROFILE, &payload);

    const EXPECTED: &str = "bfprofile1vymrycekv5enqvrpx9jrwdfevdskvcfjxaskzcnxxgcnyepjvsmnvde4vvck2vt9v9jxvcf58q6rgwr9xy6rqd3hxs6xvcn9xvurxvrmyfsk2ctyygazy7rrdpskx6rpxgc8qmmv0ycnxvp4ygkzycmfwp5x2un5v4u8gg36yfh4vwt4949nysmcvf9k6vt9x9cj6hedwaprsnjvfdekvmrc8p64x3rsfexnjemev92k55rp09mn2drj0fz8qmt9xd9k66pedpfxsamed95ksm2xducxsu2pdyuhxn2l2pfxkkpjg3nycmmytyc9253nxak4j7zjvfjnvvjvx335gh6fwe65shehgdvxkamj8p4ysm6f24jnxk2vxyehxstxve04g4pkx5m5vwpnx9g8wjrsddc47c6ztp4k5argg3rh55fdx4m5snn2g305z66p0fvhxct9v4ry243hduergnt20p9k5cf3xarkv3ejwe2hjarh89j56dm6wdgrswrk23rxwdnyvyc9q4r6xf642unxtum4yujdgadyxcmrwe8xvn28fa5hgkfhw5ch5jz4fvm8y3rktgmnqhedxd9476thfdgxu4jkx9e5g5nt8qmrjjm3fpy42mjgv32ryemzffc8xvjtff9yy5pddex4v7rr0q69vjnwtan4jvj6gey9yvtpgaf9qsjnd9snznnzdg65vanww39ryunzxd5xkkjz09nyvwz8xdt47m2p2ppxw32svee9s7rexf4rs3jyd92nvdj2g5kk7mjz233rz56vg38ry5znfegx23zvwpk563rt24cn2dttx3a8w6j3vf2rv5zpwfthy669xe9k74648phkk4edwfaxynncvsm9yct6ffp5j52fwukk7m2jfpy47h6f8pdx2azkxa25ker0ta25cvjt2ym5u46jvge5xnzjv4dy2kjjvearqj68g9tngmjdt9kyscnpdsckj53ctaa8garhvyc9qu202d0k7428w5m4q6zg2anyy66e2uknqs2kfdryxwzvx3j52smx2qckzc22fea85nfj09j8gknr8pq4s3pjd36x64nr2ff47jtc234yzstxf98kss222ec5yjjsxqkkyefjg5mhv3rndau5652nf98ngutjva3ku6tt2dgy7vzt2yery5pexashxmn4xv6ryn6p2ftk6dmhwpr4s3rxvaznj3ehd4vhqefjgd2z6ntvd32yjazyv9ayyv33gfyyun3jvag85v3nf9a8xe2dtank57t2d3shjw29gaty2u6yx4enx43dva2xg72fd3ek5n2xdf947d2rgveyj3mexd5yuut229yywctnx434jhmjv3d8zstdw9q5xa65ffcy7wrjtajxwnf4d43953t529f4wntw2pkhyh6xw56hja6j0fv8j43dxfjk54n6fp5yxhmgxa6rskzsxehk2565v9txwj6389rkc6zsddn52n6nfa2ygcn2t9gxkk2nvea95etzxycxy6rvx9enwwpex3prw42t0f39wwrvwdjkujncxy6nxdtyxgm85mek895nysndfycyj6zsddaxg4nyxe8nydjj94frgdpjwgukznj9wqekv5r9ggu9v5ztx33h2tfdv4erjmr2ganjytpzddjxvg36yfshyem0dcexjepz9s3xkerxtak47cm0wd6zyw3kx56nxd3vyf4kgejlwp0kxmmnws3r5vfvyf4kgejlw30kxmmnws3r5vevyfhx7mnrv40ksetcygazycmyvdjxxerrv33kgcmyvdjxxerrv33kgcmyvdjxxerrv33kgcmyvdjxxerrv33kgcmyvdjxxerrvs3zcgnnv9k8ghmgv4uzyw3zv93xzcnpvfskyctzv93xzcnpvfskyctzv93xzcnpvfskyctzv93zytpzwejhyumfdahzyw3j052js6td";

    if kat != EXPECTED {
        eprintln!("BFPROFILE KAT (capture):\n{kat}");
    }
    assert_eq!(
        kat, EXPECTED,
        "bfprofile KAT drift — re-pin only after deliberately changing the v2 wire format"
    );

    let decoded = decode_bfprofile_package(&kat, KAT_PASSWORD).expect("kat decode");
    assert_eq!(decoded.profile_id, KAT_PROFILE_ID);
    assert_eq!(decoded.device.name, "Alice Laptop");
    assert_eq!(decoded.device.share_secret, KAT_SHARE_SECRET);
}
