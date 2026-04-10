use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use bifrost_core::types::SharePackage;
use bifrost_signer::{DeviceState, DeviceStore};
use bincode::{DefaultOptions, Options};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub struct EncryptedFileStore {
    path: PathBuf,
    key: [u8; 32],
}

const MAX_STATE_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_STATE_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024 + 1 + 12 + 16;

impl EncryptedFileStore {
    pub fn new(path: PathBuf, share: SharePackage) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(share.seckey);
        hasher.update(b"bifrost-device-state");
        let key_bytes = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Self { path, key }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| anyhow!("state encryption failure"))?;

        let mut out = Vec::with_capacity(1 + 12 + ciphertext.len());
        out.push(1u8);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 1 + 12 + 16 {
            return Err(anyhow!("state ciphertext is too short"));
        }
        let version = ciphertext[0];
        if version != 1 {
            return Err(anyhow!("unsupported state ciphertext version"));
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&ciphertext[1..13]);
        let payload = &ciphertext[13..];

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), payload)
            .map_err(|_| anyhow!("state decryption failure"))
    }
}

impl DeviceStore for EncryptedFileStore {
    fn load(&self) -> bifrost_signer::Result<DeviceState> {
        let ciphertext = fs::read(&self.path)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        if ciphertext.len() > MAX_STATE_CIPHERTEXT_BYTES {
            return Err(bifrost_signer::SignerError::StateCorrupted(
                "state ciphertext exceeds maximum size".to_string(),
            ));
        }
        let plaintext = self
            .decrypt(&ciphertext)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        if plaintext.len() > MAX_STATE_PLAINTEXT_BYTES {
            return Err(bifrost_signer::SignerError::StateCorrupted(
                "state plaintext exceeds maximum size".to_string(),
            ));
        }
        DefaultOptions::new()
            .with_limit(MAX_STATE_PLAINTEXT_BYTES as u64)
            .deserialize(&plaintext)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))
    }

    fn save(&self, state: &DeviceState) -> bifrost_signer::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        }
        let plaintext = DefaultOptions::new()
            .with_limit(MAX_STATE_PLAINTEXT_BYTES as u64)
            .serialize(state)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        if plaintext.len() > MAX_STATE_PLAINTEXT_BYTES {
            return Err(bifrost_signer::SignerError::StateCorrupted(
                "state plaintext exceeds maximum size".to_string(),
            ));
        }
        let ciphertext = self
            .encrypt(&plaintext)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        write_bytes_atomic(&self.path, &ciphertext)
            .map_err(|e| bifrost_signer::SignerError::StateCorrupted(e.to_string()))?;
        Ok(())
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }
}

pub struct DeviceLock {
    _file: File,
}

impl DeviceLock {
    pub fn acquire_exclusive(state_path: &Path) -> Result<Self> {
        let lock_path = state_path.with_extension("lock");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open lock {}", lock_path.display()))?;

        match file.try_lock_exclusive() {
            Ok(()) => {
                file.set_len(0)?;
                write!(&mut file, "{}", std::process::id())?;
                Ok(Self { _file: file })
            }
            Err(_) => {
                let pid = read_lock_holder(&lock_path);
                Err(anyhow!("device is locked by another process (PID: {pid})"))
            }
        }
    }

    pub fn acquire_shared(state_path: &Path) -> Result<Self> {
        let lock_path = state_path.with_extension("lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open lock {}", lock_path.display()))?;

        match file.try_lock_shared() {
            Ok(()) => Ok(Self { _file: file }),
            Err(_) => {
                let pid = read_lock_holder(&lock_path);
                Err(anyhow!("device is locked by another process (PID: {pid})"))
            }
        }
    }
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = temp_sibling_path(path);
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_parent_dir(path)?;
    Ok(())
}

fn temp_sibling_path(path: &Path) -> PathBuf {
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    path.with_extension(format!("tmp-{}", hex::encode(suffix)))
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

fn read_lock_holder(lock_path: &Path) -> String {
    fs::read_to_string(lock_path)
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

use anyhow::Context;
