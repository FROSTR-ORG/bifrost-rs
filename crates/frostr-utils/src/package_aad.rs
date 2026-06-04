//! Associated-data construction for portable bech32m package envelope v2.
//!
//! Bucket B B.2 binds the AEAD to envelope metadata (HRP + salt + outer-id)
//! via a deterministic, length-prefixed byte string. Canonical layout:
//!
//! ```text
//! AAD_package = b"bfrstpkg\x00"           // 10-byte domain separator
//!             || envelope_version:u8       // 1 byte
//!             || hrp_len:u8                // 1 byte
//!             || hrp_utf8                  // "bfshare" | "bfprofile" | "bfonboard"
//!             || salt:16                   // 16 raw bytes
//!             || outer_id_len:u16_be       // 2 bytes; 0 if no outer id
//!             || outer_id_utf8             // N bytes; empty for bfshare/bfonboard
//! ```
//!
//! `outer_id` containing an interior NUL (`0x00`) is rejected with
//! [`FrostUtilsError::InvalidMetadata`] — interior NULs in attacker-controlled
//! sidecar fields could otherwise obscure which AAD region the attacker is
//! poking at.

use crate::argon2_params::PACKAGE_KDF_SALT_LEN;
use crate::errors::FrostUtilsError;

/// Domain separator written at the start of every package AAD byte string.
/// Eight ASCII bytes (`b"bfrstpkg"`) plus a trailing NUL — 9 bytes total.
///
/// (Header comment elsewhere references "10-byte domain separator" for parity
/// with the host-local AAD; `bfrstpkg` is one byte shorter than `bfrstprof`,
/// so the package AAD prefix is 9 bytes including the trailing NUL.)
pub const AAD_PACKAGE_DOMAIN_SEPARATOR: &[u8] = b"bfrstpkg\x00";

/// Build the canonical AAD byte string for the portable-package envelope.
///
/// `outer_id_opt` is `Some` for `bfprofile` (carries the outer hex profile id)
/// and `None` for `bfshare` / `bfonboard`.
pub fn build_aad_package(
    envelope_version: u8,
    hrp: &str,
    salt: &[u8; PACKAGE_KDF_SALT_LEN],
    outer_id_opt: Option<&str>,
) -> Result<Vec<u8>, FrostUtilsError> {
    let hrp_bytes = hrp.as_bytes();
    let hrp_len: u8 = hrp_bytes
        .len()
        .try_into()
        .map_err(|_| FrostUtilsError::InvalidMetadata("hrp exceeds 255 bytes"))?;
    if hrp_bytes.contains(&0u8) {
        return Err(FrostUtilsError::InvalidMetadata(
            "hrp contains interior NUL",
        ));
    }

    let outer_id_bytes = outer_id_opt.map(|s| s.as_bytes()).unwrap_or(&[]);
    if outer_id_bytes.contains(&0u8) {
        return Err(FrostUtilsError::InvalidMetadata(
            "outer_id contains interior NUL",
        ));
    }
    let outer_id_len: u16 = outer_id_bytes
        .len()
        .try_into()
        .map_err(|_| FrostUtilsError::InvalidMetadata("outer_id exceeds u16::MAX bytes"))?;

    let mut out = Vec::with_capacity(
        AAD_PACKAGE_DOMAIN_SEPARATOR.len()
            + 1 // envelope_version
            + 1 // hrp_len
            + hrp_bytes.len()
            + PACKAGE_KDF_SALT_LEN
            + 2 // outer_id_len
            + outer_id_bytes.len(),
    );
    out.extend_from_slice(AAD_PACKAGE_DOMAIN_SEPARATOR);
    out.push(envelope_version);
    out.push(hrp_len);
    out.extend_from_slice(hrp_bytes);
    out.extend_from_slice(salt);
    out.extend_from_slice(&outer_id_len.to_be_bytes());
    out.extend_from_slice(outer_id_bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt() -> [u8; PACKAGE_KDF_SALT_LEN] {
        *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    }

    #[test]
    fn bfshare_aad_omits_outer_id() {
        let aad = build_aad_package(2, "bfshare", &salt(), None).expect("aad");
        // domain(9) + version(1) + hrp_len(1) + hrp(7) + salt(16) + outer_id_len(2) + outer_id(0) = 36
        assert_eq!(aad.len(), 9 + 1 + 1 + 7 + 16 + 2);
        assert!(aad.starts_with(AAD_PACKAGE_DOMAIN_SEPARATOR));
        assert_eq!(aad[9], 2); // version
        assert_eq!(aad[10], 7); // hrp len
        assert_eq!(&aad[11..18], b"bfshare");
    }

    #[test]
    fn bfprofile_aad_includes_outer_id() {
        let outer = "ab".repeat(32);
        let aad = build_aad_package(2, "bfprofile", &salt(), Some(&outer)).expect("aad");
        assert!(aad.ends_with(outer.as_bytes()));
    }

    #[test]
    fn aad_rejects_interior_nul_in_outer_id() {
        let err = build_aad_package(2, "bfprofile", &salt(), Some("a\0b"))
            .expect_err("interior nul rejects");
        assert!(matches!(err, FrostUtilsError::InvalidMetadata(_)));
    }

    #[test]
    fn aad_rejects_interior_nul_in_hrp() {
        let err =
            build_aad_package(2, "bfsh\0are", &salt(), None).expect_err("interior nul rejects");
        assert!(matches!(err, FrostUtilsError::InvalidMetadata(_)));
    }

    #[test]
    fn aad_is_deterministic() {
        let a = build_aad_package(2, "bfshare", &salt(), None).expect("aad");
        let b = build_aad_package(2, "bfshare", &salt(), None).expect("aad");
        assert_eq!(a, b);
    }

    #[test]
    fn aad_differs_on_hrp_change() {
        let a = build_aad_package(2, "bfshare", &salt(), None).expect("aad");
        let b = build_aad_package(2, "bfprofile", &salt(), None).expect("aad");
        assert_ne!(a, b);
    }
}
