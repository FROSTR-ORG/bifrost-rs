//! Argon2id parameter helpers for portable bech32m package encryption.
//!
//! Bucket B B.2 (remediation 2026-04-22) migrates the portable package
//! encryption from `SHA-256(pw) || PBKDF2-600k` to Argon2id. The
//! `Argon2Params` type duplicates `bifrost_profile::Argon2Params` deliberately:
//! `bifrost-profile` already depends on `frostr-utils`, so importing the type
//! the other way would introduce a dependency cycle. Both types are kept in
//! lockstep — same defaults, same floor, same ceiling — and any change here
//! must mirror the host-local copy.
//!
//! See `bucket-b-kdf-aad.md` for the unified parameter discipline.
//!
//! NOTE: if a future refactor moves the type into `bifrost-core::secret`, both
//! crates can re-export it from there and the duplication goes away.

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};

use crate::errors::FrostUtilsError;

/// Argon2id memory-cost floor in KiB (64 MiB).
pub const ARGON2_MIN_M_COST: u32 = 65_536;

/// Argon2id memory-cost ceiling in KiB (1 GiB).
pub const ARGON2_MAX_M_COST: u32 = 1_048_576;

/// Argon2id iteration-count floor.
pub const ARGON2_MIN_T_COST: u32 = 3;

/// Argon2id parallelism floor.
pub const ARGON2_MIN_P_COST: u8 = 1;

const DEFAULT_M_COST: u32 = 262_144; // 256 MiB
const DEFAULT_T_COST: u32 = 4;
const DEFAULT_P_COST: u8 = 1;

const MINIMUM_SECURE_M_COST: u32 = 65_536; // 64 MiB (== floor)
const MINIMUM_SECURE_T_COST: u32 = 3;
const MINIMUM_SECURE_P_COST: u8 = 1;

const HIGH_SECURITY_M_COST: u32 = 524_288; // 512 MiB
const HIGH_SECURITY_T_COST: u32 = 4;
const HIGH_SECURITY_P_COST: u8 = 1;

/// Validated Argon2id parameter triple. Mirrors
/// `bifrost_profile::Argon2Params`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Argon2Params {
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
}

/// Errors produced when an `Argon2Params` triple is outside the allowed
/// envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamsError {
    BelowFloor {
        m_cost: u32,
        t_cost: u32,
        p_cost: u8,
    },
    AboveCeiling {
        m_cost: u32,
    },
}

impl fmt::Display for ParamsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamsError::BelowFloor {
                m_cost,
                t_cost,
                p_cost,
            } => write!(
                f,
                "argon2 parameters below floor: m_cost={m_cost}, t_cost={t_cost}, p_cost={p_cost}; \
                 require m_cost>={ARGON2_MIN_M_COST}, t_cost>={ARGON2_MIN_T_COST}, \
                 p_cost>={ARGON2_MIN_P_COST}"
            ),
            ParamsError::AboveCeiling { m_cost } => write!(
                f,
                "argon2 parameters above ceiling: m_cost={m_cost}; require m_cost<={ARGON2_MAX_M_COST}"
            ),
        }
    }
}

impl std::error::Error for ParamsError {}

impl From<ParamsError> for FrostUtilsError {
    fn from(err: ParamsError) -> Self {
        match err {
            ParamsError::BelowFloor {
                m_cost,
                t_cost,
                p_cost,
            } => FrostUtilsError::UnsupportedParams {
                m_cost,
                t_cost,
                p_cost,
            },
            ParamsError::AboveCeiling { m_cost } => FrostUtilsError::UnsupportedParams {
                m_cost,
                t_cost: 0,
                p_cost: 0,
            },
        }
    }
}

impl Argon2Params {
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u8) -> Result<Self, ParamsError> {
        if m_cost > ARGON2_MAX_M_COST {
            return Err(ParamsError::AboveCeiling { m_cost });
        }
        if m_cost < ARGON2_MIN_M_COST || t_cost < ARGON2_MIN_T_COST || p_cost < ARGON2_MIN_P_COST {
            return Err(ParamsError::BelowFloor {
                m_cost,
                t_cost,
                p_cost,
            });
        }
        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
        })
    }

    #[allow(clippy::should_implement_trait)]
    pub const fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }

    pub const fn minimum_secure() -> Self {
        Self {
            m_cost: MINIMUM_SECURE_M_COST,
            t_cost: MINIMUM_SECURE_T_COST,
            p_cost: MINIMUM_SECURE_P_COST,
        }
    }

    pub const fn high_security() -> Self {
        Self {
            m_cost: HIGH_SECURITY_M_COST,
            t_cost: HIGH_SECURITY_T_COST,
            p_cost: HIGH_SECURITY_P_COST,
        }
    }

    pub const fn m_cost(&self) -> u32 {
        self.m_cost
    }

    pub const fn t_cost(&self) -> u32 {
        self.t_cost
    }

    pub const fn p_cost(&self) -> u8 {
        self.p_cost
    }

    pub(crate) fn to_argon2_params(self) -> Params {
        Params::new(self.m_cost, self.t_cost, u32::from(self.p_cost), None)
            .expect("validated Argon2Params must translate to argon2::Params")
    }

    pub(crate) fn to_argon2(self) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.to_argon2_params())
    }
}

/// Salt length in raw bytes used by the portable-package KDF.
pub const PACKAGE_KDF_SALT_LEN: usize = 16;

/// Derived key length in bytes (XChaCha20Poly1305 key).
pub const PACKAGE_KDF_OUTPUT_LEN: usize = 32;

/// Derive a 32-byte XChaCha20Poly1305 key from a passphrase and salt using
/// Argon2id v0x13 with the operator-selected [`Argon2Params`].
pub fn derive_package_encryption_key_v2(
    passphrase: &str,
    salt: &[u8; PACKAGE_KDF_SALT_LEN],
    params: &Argon2Params,
) -> Result<[u8; PACKAGE_KDF_OUTPUT_LEN], FrostUtilsError> {
    let argon2 = params.to_argon2();
    let mut key = [0u8; PACKAGE_KDF_OUTPUT_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_err| FrostUtilsError::UnsupportedParams {
            m_cost: params.m_cost(),
            t_cost: params.t_cost(),
            p_cost: params.p_cost(),
        })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_256_mib_t4_p1() {
        let p = Argon2Params::default();
        assert_eq!(p.m_cost(), 262_144);
        assert_eq!(p.t_cost(), 4);
        assert_eq!(p.p_cost(), 1);
    }

    #[test]
    fn minimum_secure_is_the_floor() {
        let p = Argon2Params::minimum_secure();
        assert_eq!(p.m_cost(), ARGON2_MIN_M_COST);
        assert_eq!(p.t_cost(), ARGON2_MIN_T_COST);
        assert_eq!(p.p_cost(), ARGON2_MIN_P_COST);
    }

    #[test]
    fn new_rejects_below_floor() {
        let err = Argon2Params::new(ARGON2_MIN_M_COST - 1, 4, 1).expect_err("below floor rejects");
        assert!(matches!(err, ParamsError::BelowFloor { .. }));
    }

    #[test]
    fn new_rejects_above_ceiling() {
        let err =
            Argon2Params::new(ARGON2_MAX_M_COST + 1, 4, 1).expect_err("above ceiling rejects");
        assert!(matches!(err, ParamsError::AboveCeiling { .. }));
    }
}
