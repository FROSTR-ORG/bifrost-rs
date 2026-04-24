//! Associated-data construction for the host-local encrypted-profile
//! envelope v2.
//!
//! Bucket B B.1 binds the AEAD to the sidecar metadata via a deterministic,
//! length-prefixed byte string. Canonical layout:
//!
//! ```text
//! AAD_hostlocal = b"bfrstprof\x00"           // 10-byte domain separator
//!               || version:u8                  // 1 byte, equals envelope_version
//!               || record_id_len:u16_be        // 2 bytes
//!               || record_id_utf8              // N bytes
//!               || kind_len:u16_be             // 2 bytes
//!               || kind_utf8                   // N bytes
//!               || source_len:u16_be           // 2 bytes
//!               || source_utf8                 // N bytes
//!               || salt:16                     // 16 raw bytes (NOT hex)
//!               || created_at:u64_be           // 8 bytes
//! ```
//!
//! Any of `record_id`, `kind`, or `source` containing an interior NUL
//! (`0x00`) is rejected with [`StateError::InvalidMetadata`] — the domain
//! separator terminates with a NUL and interior NULs in sidecar fields could
//! otherwise obscure which section of the AAD the attacker is poking at.

use crate::ENCRYPTED_PROFILE_VERSION_V2;
use crate::models::EncryptedProfileRecord;
use crate::state_error::StateError;

/// Domain separator written at the start of every AAD byte string.
/// Nine ASCII bytes (`b"bfrstprof"`) plus a trailing NUL, 10 bytes total.
pub const AAD_DOMAIN_SEPARATOR: &[u8; 10] = b"bfrstprof\x00";

/// Required salt length in raw bytes.
pub const AAD_SALT_LEN: usize = 16;

/// Build the canonical AAD byte string for the host-local envelope from the
/// sidecar metadata.
///
/// The `version` byte is pinned to [`ENCRYPTED_PROFILE_VERSION_V2`]; PR7 will
/// use this helper from the v2 writer and reader. Callers for later envelope
/// versions should introduce a sibling helper rather than mutating this one —
/// reusing the same function for a new version risks a silent MAC-swap.
pub fn build_aad_hostlocal(record: &EncryptedProfileRecord) -> Result<Vec<u8>, StateError> {
    if record.id.as_bytes().contains(&0u8) {
        return Err(StateError::InvalidMetadata {
            reason: StateError::RECORD_ID_INTERIOR_NUL,
        });
    }
    if record.kind.as_bytes().contains(&0u8) {
        return Err(StateError::InvalidMetadata {
            reason: StateError::KIND_INTERIOR_NUL,
        });
    }
    if record.source.as_bytes().contains(&0u8) {
        return Err(StateError::InvalidMetadata {
            reason: StateError::SOURCE_INTERIOR_NUL,
        });
    }

    let salt = decode_salt_hex(&record.salt_hex)?;

    let record_id = record.id.as_bytes();
    let kind = record.kind.as_bytes();
    let source = record.source.as_bytes();

    let record_id_len: u16 =
        record_id
            .len()
            .try_into()
            .map_err(|_| StateError::InvalidMetadata {
                reason: "record_id exceeds u16::MAX bytes",
            })?;
    let kind_len: u16 = kind
        .len()
        .try_into()
        .map_err(|_| StateError::InvalidMetadata {
            reason: "kind exceeds u16::MAX bytes",
        })?;
    let source_len: u16 = source
        .len()
        .try_into()
        .map_err(|_| StateError::InvalidMetadata {
            reason: "source exceeds u16::MAX bytes",
        })?;

    let mut out = Vec::with_capacity(
        AAD_DOMAIN_SEPARATOR.len()
            + 1
            + 2
            + record_id.len()
            + 2
            + kind.len()
            + 2
            + source.len()
            + AAD_SALT_LEN
            + 8,
    );

    out.extend_from_slice(AAD_DOMAIN_SEPARATOR);
    out.push(ENCRYPTED_PROFILE_VERSION_V2);
    out.extend_from_slice(&record_id_len.to_be_bytes());
    out.extend_from_slice(record_id);
    out.extend_from_slice(&kind_len.to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(&source_len.to_be_bytes());
    out.extend_from_slice(source);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&record.created_at.to_be_bytes());

    Ok(out)
}

fn decode_salt_hex(salt_hex: &str) -> Result<[u8; AAD_SALT_LEN], StateError> {
    let bytes = hex::decode(salt_hex).map_err(|_| StateError::InvalidMetadata {
        reason: "salt_hex is not valid hex",
    })?;
    if bytes.len() != AAD_SALT_LEN {
        return Err(StateError::InvalidMetadata {
            reason: "salt_hex does not decode to 16 bytes",
        });
    }
    let mut out = [0u8; AAD_SALT_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn aad_is_deterministic_on_identical_input() {
        let record = base_record();
        let first = build_aad_hostlocal(&record).expect("build aad");
        let second = build_aad_hostlocal(&record).expect("build aad");
        assert_eq!(first, second);
    }

    #[test]
    fn aad_starts_with_domain_separator_and_version() {
        let record = base_record();
        let aad = build_aad_hostlocal(&record).expect("build aad");
        assert_eq!(&aad[..10], AAD_DOMAIN_SEPARATOR);
        assert_eq!(aad[10], ENCRYPTED_PROFILE_VERSION_V2);
    }

    #[test]
    fn aad_uses_big_endian_record_id_length() {
        let record = base_record();
        let aad = build_aad_hostlocal(&record).expect("build aad");
        let len_bytes = [aad[11], aad[12]];
        assert_eq!(u16::from_be_bytes(len_bytes) as usize, record.id.len());
    }

    #[test]
    fn aad_embeds_raw_salt_not_hex() {
        let record = base_record();
        let aad = build_aad_hostlocal(&record).expect("build aad");
        // Locate the salt: after domain(10) + version(1) + 2+record_id + 2+kind + 2+source
        let mut cursor = 11;
        let rid_len = u16::from_be_bytes([aad[cursor], aad[cursor + 1]]) as usize;
        cursor += 2 + rid_len;
        let kind_len = u16::from_be_bytes([aad[cursor], aad[cursor + 1]]) as usize;
        cursor += 2 + kind_len;
        let src_len = u16::from_be_bytes([aad[cursor], aad[cursor + 1]]) as usize;
        cursor += 2 + src_len;
        let expected_salt: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        assert_eq!(&aad[cursor..cursor + 16], &expected_salt);
    }

    #[test]
    fn aad_ends_with_big_endian_created_at() {
        let record = base_record();
        let aad = build_aad_hostlocal(&record).expect("build aad");
        let tail = &aad[aad.len() - 8..];
        assert_eq!(tail, &record.created_at.to_be_bytes());
    }

    #[test]
    fn aad_differs_when_kind_changes() {
        let mut record = base_record();
        let before = build_aad_hostlocal(&record).expect("build aad");
        record.kind = "other_kind".to_string();
        let after = build_aad_hostlocal(&record).expect("build aad");
        assert_ne!(before, after);
    }

    #[test]
    fn aad_differs_when_record_id_changes() {
        let mut record = base_record();
        let before = build_aad_hostlocal(&record).expect("build aad");
        record.id = "encrypted-profile-42-ffff".to_string();
        let after = build_aad_hostlocal(&record).expect("build aad");
        assert_ne!(before, after);
    }

    #[test]
    fn aad_differs_when_source_changes() {
        let mut record = base_record();
        let before = build_aad_hostlocal(&record).expect("build aad");
        record.source = "bfprofile_import".to_string();
        let after = build_aad_hostlocal(&record).expect("build aad");
        assert_ne!(before, after);
    }

    #[test]
    fn aad_differs_when_salt_changes() {
        let mut record = base_record();
        let before = build_aad_hostlocal(&record).expect("build aad");
        record.salt_hex = "0f0e0d0c0b0a09080706050403020100".to_string();
        let after = build_aad_hostlocal(&record).expect("build aad");
        assert_ne!(before, after);
    }

    #[test]
    fn aad_differs_when_created_at_changes() {
        let mut record = base_record();
        let before = build_aad_hostlocal(&record).expect("build aad");
        record.created_at += 1;
        let after = build_aad_hostlocal(&record).expect("build aad");
        assert_ne!(before, after);
    }

    #[test]
    fn aad_ignores_updated_at_changes() {
        // `updated_at` is explicitly excluded from the AAD because it moves
        // without invalidating the ciphertext.
        let mut record = base_record();
        let before = build_aad_hostlocal(&record).expect("build aad");
        record.updated_at += 1;
        let after = build_aad_hostlocal(&record).expect("build aad");
        assert_eq!(before, after);
    }

    #[test]
    fn aad_ignores_ciphertext_path_changes() {
        let mut record = base_record();
        let before = build_aad_hostlocal(&record).expect("build aad");
        record.ciphertext_path = "/elsewhere/path.enc".to_string();
        let after = build_aad_hostlocal(&record).expect("build aad");
        assert_eq!(before, after);
    }

    #[test]
    fn aad_rejects_interior_nul_in_record_id() {
        let mut record = base_record();
        record.id = "abc\0def".to_string();
        let err = build_aad_hostlocal(&record).expect_err("interior nul in id rejects");
        assert!(matches!(
            err,
            StateError::InvalidMetadata {
                reason: StateError::RECORD_ID_INTERIOR_NUL
            }
        ));
    }

    #[test]
    fn aad_rejects_interior_nul_in_kind() {
        let mut record = base_record();
        record.kind = "share\0package".to_string();
        let err = build_aad_hostlocal(&record).expect_err("interior nul in kind rejects");
        assert!(matches!(
            err,
            StateError::InvalidMetadata {
                reason: StateError::KIND_INTERIOR_NUL
            }
        ));
    }

    #[test]
    fn aad_rejects_interior_nul_in_source() {
        let mut record = base_record();
        record.source = "file\0import".to_string();
        let err = build_aad_hostlocal(&record).expect_err("interior nul in source rejects");
        assert!(matches!(
            err,
            StateError::InvalidMetadata {
                reason: StateError::SOURCE_INTERIOR_NUL
            }
        ));
    }

    #[test]
    fn aad_rejects_bad_salt_hex() {
        let mut record = base_record();
        record.salt_hex = "not-hex-at-all".to_string();
        let err = build_aad_hostlocal(&record).expect_err("non-hex salt rejects");
        assert!(matches!(err, StateError::InvalidMetadata { .. }));
    }

    #[test]
    fn aad_rejects_salt_wrong_length() {
        let mut record = base_record();
        record.salt_hex = "00112233".to_string(); // 4 bytes, not 16
        let err = build_aad_hostlocal(&record).expect_err("short salt rejects");
        assert!(matches!(err, StateError::InvalidMetadata { .. }));
    }

    #[test]
    fn aad_length_is_predictable() {
        let record = base_record();
        let aad = build_aad_hostlocal(&record).expect("build aad");
        let expected = AAD_DOMAIN_SEPARATOR.len()
            + 1 // version
            + 2 + record.id.len()
            + 2 + record.kind.len()
            + 2 + record.source.len()
            + AAD_SALT_LEN
            + 8;
        assert_eq!(aad.len(), expected);
    }
}
