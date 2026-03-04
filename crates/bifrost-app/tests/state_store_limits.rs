use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use bifrost_app::runtime::EncryptedFileStore;
use bifrost_core::types::SharePackage;
use bifrost_signer::{DeviceState, DeviceStore, SignerError};

fn temp_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bifrost-app-{name}-{}-{nonce}.bin",
        std::process::id()
    ))
}

fn test_share() -> SharePackage {
    SharePackage {
        idx: 1,
        seckey: [7u8; 32],
    }
}

#[test]
fn encrypted_file_store_rejects_oversized_ciphertext_on_load() {
    let path = temp_path("oversized-ciphertext");
    let _ = fs::remove_file(&path);
    let store = EncryptedFileStore::new(path.clone(), test_share());
    fs::write(&path, vec![0u8; 5 * 1024 * 1024]).expect("write oversized ciphertext fixture");

    let err = store.load().expect_err("oversized ciphertext must fail");
    match err {
        SignerError::StateCorrupted(message) => {
            assert!(message.contains("state ciphertext exceeds maximum size"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    let _ = fs::remove_file(path);
}

#[test]
fn encrypted_file_store_rejects_oversized_plaintext_on_save() {
    let path = temp_path("oversized-plaintext");
    let _ = fs::remove_file(&path);
    let store = EncryptedFileStore::new(path.clone(), test_share());
    let mut state = DeviceState::new(1, [9u8; 32]);
    state.replay_cache.insert("x".repeat(5 * 1024 * 1024), 0);

    let err = store
        .save(&state)
        .expect_err("oversized plaintext must fail");
    match err {
        SignerError::StateCorrupted(message) => {
            assert!(
                message.contains("state plaintext exceeds maximum size")
                    || message.contains("size limit has been reached")
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    let _ = fs::remove_file(path);
}
