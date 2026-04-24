//! B.3 adversarial test coverage for the host-local encrypted-profile
//! envelope v2 (bucket-b-kdf-aad.md, 2026-04-22 remediation track).
//!
//! Each test models a specific tampering scenario against the v2 envelope
//! produced by `FilesystemEncryptedProfileStore::store_encrypted_profile`.
//! Where the scenario requires a malformed envelope, the test fabricates
//! bytes directly and writes them to disk, bypassing the writer.

use std::fs;
use std::path::PathBuf;

use bifrost_profile::{
    ARGON2_MAX_M_COST, Argon2Params, ENCRYPTED_PROFILE_VERSION, EncryptedProfileRecord,
    FilesystemEncryptedProfileStore, KDF_ID_ARGON2ID, StateError, build_aad_hostlocal,
};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ENVELOPE_MIN_LEN: usize = 1 + 1 + 4 + 4 + 1 + NONCE_LEN + TAG_LEN;

fn temp_dir(label: &str) -> PathBuf {
    let id = format!(
        "bifrost-profile-pr7-{label}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    );
    std::env::temp_dir().join(id)
}

fn make_store(label: &str) -> (FilesystemEncryptedProfileStore, PathBuf) {
    let root = temp_dir(label);
    fs::create_dir_all(&root).expect("create temp dir");
    let store = FilesystemEncryptedProfileStore::new(&root, &root);
    (store, root)
}

fn base_record() -> EncryptedProfileRecord {
    EncryptedProfileRecord {
        id: "encrypted-profile-42-abcd".to_string(),
        kind: "share_package".to_string(),
        source: "file_import".to_string(),
        ciphertext_path: "/tmp/ignored.enc".to_string(),
        key_source: "passphrase".to_string(),
        salt_hex: "000102030405060708090a0b0c0d0e0f".to_string(),
        created_at: 0x0102_0304_0506_0708,
        updated_at: 0x0102_0304_0506_0708,
    }
}

fn downcast_state_error(err: &anyhow::Error) -> &StateError {
    err.downcast_ref::<StateError>().unwrap_or_else(|| {
        panic!("expected StateError, got: {err:?}");
    })
}

#[test]
fn decrypt_rejects_wrong_passphrase() {
    let (store, root) = make_store("wrong-pass");
    let record = store
        .store_encrypted_profile(
            "share_package",
            "file_import",
            "{\"share\":1}",
            "correct-passphrase",
            42,
        )
        .expect("store encrypted profile");

    let err = store
        .decrypt_encrypted_profile(&record, "wrong-passphrase")
        .expect_err("wrong passphrase must fail");

    // MAC failure surfaces as the generic decrypt error message.
    assert!(
        err.to_string().contains("decryption failure"),
        "unexpected error: {err:?}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn decrypt_rejects_corrupted_ciphertext_byte_flip() {
    let (store, root) = make_store("byte-flip");
    let record = store
        .store_encrypted_profile(
            "share_package",
            "file_import",
            "{\"share\":1}",
            "passphrase",
            42,
        )
        .expect("store encrypted profile");

    // Flip a byte in the Poly1305 tag region — last 16 bytes of the file.
    let mut envelope = fs::read(&record.ciphertext_path).expect("read envelope");
    let tag_start = envelope.len() - TAG_LEN;
    envelope[tag_start] ^= 0x01;
    fs::write(&record.ciphertext_path, &envelope).expect("write tampered envelope");

    let err = store
        .decrypt_encrypted_profile(&record, "passphrase")
        .expect_err("tag flip must fail AEAD");

    assert!(
        err.to_string().contains("decryption failure"),
        "unexpected error: {err:?}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn decrypt_rejects_unsupported_version() {
    let (store, root) = make_store("unsupported-version");
    // First produce a valid v2 envelope so sidecar metadata exists.
    let record = store
        .store_encrypted_profile(
            "share_package",
            "file_import",
            "{\"share\":1}",
            "passphrase",
            42,
        )
        .expect("store encrypted profile");

    // Fabricate a v1-shaped envelope: [version=1][nonce:12][ciphertext+tag].
    // Shape it long enough to pass the length check (so version rejection
    // fires first) — use ENVELOPE_MIN_LEN bytes.
    let mut v1_envelope = vec![0u8; ENVELOPE_MIN_LEN];
    v1_envelope[0] = 1;
    fs::write(&record.ciphertext_path, &v1_envelope).expect("write fake v1 envelope");

    let err = store
        .decrypt_encrypted_profile(&record, "passphrase")
        .expect_err("v1 envelope must fail");
    assert_eq!(
        downcast_state_error(&err),
        &StateError::UnsupportedVersion(1)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn decrypt_rejects_tampered_metadata_aad() {
    let (store, root) = make_store("metadata-aad");
    let record = store
        .store_encrypted_profile(
            "share_package",
            "file_import",
            "{\"share\":1}",
            "passphrase",
            42,
        )
        .expect("store encrypted profile");

    // Baseline: decrypt succeeds with the stored metadata.
    let plaintext = store
        .decrypt_encrypted_profile(&record, "passphrase")
        .expect("baseline decrypt must succeed");
    assert_eq!(plaintext, "{\"share\":1}");

    // Mutate `kind` after encrypt — rebuilt AAD will not match the AEAD's
    // pinned AAD, so MAC verification must fail.
    let mut mutated = record.clone();
    mutated.kind = "tampered_kind".to_string();

    let err = store
        .decrypt_encrypted_profile(&mutated, "passphrase")
        .expect_err("mutated kind must fail MAC");
    assert!(
        err.to_string().contains("decryption failure"),
        "unexpected error: {err:?}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn decrypt_rejects_params_below_floor() {
    let (store, root) = make_store("params-below");
    let record = store
        .store_encrypted_profile(
            "share_package",
            "file_import",
            "{\"share\":1}",
            "passphrase",
            42,
        )
        .expect("store encrypted profile");

    // Fabricate an envelope with m_cost = 32_768 (below the 65_536 floor).
    let mut envelope = vec![0u8; ENVELOPE_MIN_LEN];
    envelope[0] = ENCRYPTED_PROFILE_VERSION;
    envelope[1] = KDF_ID_ARGON2ID;
    envelope[2..6].copy_from_slice(&32_768u32.to_be_bytes());
    envelope[6..10].copy_from_slice(&4u32.to_be_bytes());
    envelope[10] = 1;
    // Bytes 11..39 left zero; they'll never be reached.
    fs::write(&record.ciphertext_path, &envelope).expect("write below-floor envelope");

    let err = store
        .decrypt_encrypted_profile(&record, "passphrase")
        .expect_err("below-floor params must fail");
    assert_eq!(
        downcast_state_error(&err),
        &StateError::UnsupportedParams {
            m_cost: 32_768,
            t_cost: 4,
            p_cost: 1,
        }
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn decrypt_rejects_params_above_ceiling() {
    let (store, root) = make_store("params-above");
    let record = store
        .store_encrypted_profile(
            "share_package",
            "file_import",
            "{\"share\":1}",
            "passphrase",
            42,
        )
        .expect("store encrypted profile");

    // Fabricate an envelope with m_cost = u32::MAX (above the 1 GiB ceiling).
    let mut envelope = vec![0u8; ENVELOPE_MIN_LEN];
    envelope[0] = ENCRYPTED_PROFILE_VERSION;
    envelope[1] = KDF_ID_ARGON2ID;
    envelope[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
    envelope[6..10].copy_from_slice(&4u32.to_be_bytes());
    envelope[10] = 1;
    fs::write(&record.ciphertext_path, &envelope).expect("write above-ceiling envelope");

    let err = store
        .decrypt_encrypted_profile(&record, "passphrase")
        .expect_err("above-ceiling params must fail");
    match downcast_state_error(&err) {
        StateError::UnsupportedParams { m_cost, .. } => {
            assert_eq!(*m_cost, u32::MAX);
            // The ceiling is u32::MAX is obviously > ARGON2_MAX_M_COST.
            assert!(*m_cost > ARGON2_MAX_M_COST);
        }
        other => panic!("expected UnsupportedParams, got {other:?}"),
    }

    let _ = fs::remove_dir_all(root);
}

#[test]
fn decrypt_rejects_short_envelope() {
    let (store, root) = make_store("short");
    let record = store
        .store_encrypted_profile(
            "share_package",
            "file_import",
            "{\"share\":1}",
            "passphrase",
            42,
        )
        .expect("store encrypted profile");

    // Truncate to 20 bytes — below the 39-byte minimum.
    fs::write(&record.ciphertext_path, vec![0u8; 20]).expect("write short envelope");

    let err = store
        .decrypt_encrypted_profile(&record, "passphrase")
        .expect_err("short envelope must fail");
    assert_eq!(
        downcast_state_error(&err),
        &StateError::Truncated {
            actual: 20,
            minimum: ENVELOPE_MIN_LEN,
        }
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn argon2_params_round_trip() {
    let (store, root) = make_store("params-round-trip");
    // Use minimum_secure() — still exercises the parameterized code path
    // without the 400-600 ms cost of high_security() across multiple
    // re-derivations per test.
    let record = store
        .store_encrypted_profile_with_params(
            "share_package",
            "file_import",
            "{\"share\":1}",
            "passphrase",
            42,
            &Argon2Params::minimum_secure(),
        )
        .expect("store with minimum_secure params");

    let plaintext = store
        .decrypt_encrypted_profile(&record, "passphrase")
        .expect("decrypt with embedded minimum_secure params must succeed");
    assert_eq!(plaintext, "{\"share\":1}");

    // Verify the envelope actually embedded the minimum_secure triple.
    let envelope = fs::read(&record.ciphertext_path).expect("read envelope");
    assert_eq!(envelope[0], ENCRYPTED_PROFILE_VERSION);
    assert_eq!(envelope[1], KDF_ID_ARGON2ID);
    let m_cost = u32::from_be_bytes([envelope[2], envelope[3], envelope[4], envelope[5]]);
    let t_cost = u32::from_be_bytes([envelope[6], envelope[7], envelope[8], envelope[9]]);
    let p_cost = envelope[10];
    assert_eq!(m_cost, Argon2Params::minimum_secure().m_cost());
    assert_eq!(t_cost, Argon2Params::minimum_secure().t_cost());
    assert_eq!(p_cost, Argon2Params::minimum_secure().p_cost());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn aad_bytes_are_deterministic() {
    // Identical records produce identical AAD bytes.
    let record = base_record();
    let first = build_aad_hostlocal(&record).expect("build aad");
    let second = build_aad_hostlocal(&record).expect("build aad");
    assert_eq!(first, second);

    // Mutating `updated_at` (excluded from AAD per plan) must not change
    // the AAD bytes — this is what lets the writer rewrite sidecar
    // timestamps without invalidating the ciphertext.
    let mut mutated = record.clone();
    mutated.updated_at = record.updated_at.wrapping_add(0xdead_beef);
    let after = build_aad_hostlocal(&mutated).expect("build aad after updated_at mutation");
    assert_eq!(first, after);
}

#[test]
fn aad_rejects_interior_nul() {
    let mut record = base_record();
    record.kind = "a\x00b".to_string();
    let err = build_aad_hostlocal(&record).expect_err("interior NUL in kind must reject");
    assert_eq!(
        err,
        StateError::InvalidMetadata {
            reason: StateError::KIND_INTERIOR_NUL,
        }
    );
}
