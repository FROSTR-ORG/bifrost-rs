//! Argon2id parameter helpers for host-local encrypted profiles.
//!
//! Bucket B (remediation 2026-04-22) centralizes the parameter discipline for
//! Argon2id-based key derivation used by the host-local `.enc` envelope. The
//! same `Argon2Params` type is also the target for the Bucket B portable
//! package migration so that a single KDF contract exists across the codebase.
//!
//! This module is crate-internal to PR6 and is not yet wired into the writer
//! or reader. PR7 will perform the envelope v2 cutover.

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id memory-cost floor in KiB (64 MiB). Envelopes recording anything
/// weaker are rejected on decrypt.
pub const ARGON2_MIN_M_COST: u32 = 65_536;

/// Argon2id memory-cost ceiling in KiB (1 GiB). Caps malformed or malicious
/// metadata before they reach the Argon2 engine.
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

/// Validated Argon2id parameter triple, pinned to the operator-facing profile
/// of choice (default / minimum_secure / high_security) or constructed via
/// [`Argon2Params::new`] with floor/ceiling enforcement.
///
/// `#[non_exhaustive]` keeps the field layout an implementation detail so we
/// can add additional knobs (e.g. `keyid`) in a future bump without a breaking
/// change.
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
    /// `m_cost`, `t_cost`, or `p_cost` was below the Bucket B floor.
    BelowFloor {
        m_cost: u32,
        t_cost: u32,
        p_cost: u8,
    },
    /// `m_cost` was above the `ARGON2_MAX_M_COST` ceiling.
    AboveCeiling { m_cost: u32 },
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

impl Argon2Params {
    /// Construct an `Argon2Params` after validating against the Bucket B
    /// floor/ceiling. Returns [`ParamsError`] on reject.
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

    /// Recommended parameters: `m = 256 MiB`, `t = 4`, `p = 1`.
    ///
    /// Roughly 400-600 ms unlock on 2020-era desktop hardware; threat model
    /// assumes keys protecting crypto assets.
    #[allow(clippy::should_implement_trait)]
    pub const fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }

    /// Decrypt-side floor: `m = 64 MiB`, `t = 3`, `p = 1`. Envelopes recording
    /// anything weaker are rejected.
    pub const fn minimum_secure() -> Self {
        Self {
            m_cost: MINIMUM_SECURE_M_COST,
            t_cost: MINIMUM_SECURE_T_COST,
            p_cost: MINIMUM_SECURE_P_COST,
        }
    }

    /// High-security profile: `m = 512 MiB`, `t = 4`, `p = 1`. Sub-2s unlock
    /// latency in exchange for ~3x attacker cost.
    pub const fn high_security() -> Self {
        Self {
            m_cost: HIGH_SECURITY_M_COST,
            t_cost: HIGH_SECURITY_T_COST,
            p_cost: HIGH_SECURITY_P_COST,
        }
    }

    /// Memory cost in KiB.
    pub const fn m_cost(&self) -> u32 {
        self.m_cost
    }

    /// Iteration count.
    pub const fn t_cost(&self) -> u32 {
        self.t_cost
    }

    /// Parallelism degree.
    pub const fn p_cost(&self) -> u8 {
        self.p_cost
    }

    /// Convert to the underlying `argon2::Params` struct.
    ///
    /// Crate-internal: callers that actually run Argon2id should go through
    /// `derive_profile_encryption_key_v2` so the algorithm/version pins stay
    /// in one place.
    #[allow(dead_code)] // consumed by `kdf::derive_profile_encryption_key_v2`
    pub(crate) fn to_argon2_params(self) -> Params {
        Params::new(self.m_cost, self.t_cost, u32::from(self.p_cost), None)
            .expect("validated Argon2Params must translate to argon2::Params")
    }

    /// Build an `argon2::Argon2` engine pinned to Argon2id + v0x13.
    #[allow(dead_code)] // consumed by `kdf::derive_profile_encryption_key_v2`
    pub(crate) fn to_argon2(self) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.to_argon2_params())
    }
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
    fn high_security_is_512_mib() {
        let p = Argon2Params::high_security();
        assert_eq!(p.m_cost(), 524_288);
        assert_eq!(p.t_cost(), 4);
        assert_eq!(p.p_cost(), 1);
    }

    #[test]
    fn new_accepts_default_params() {
        let p = Argon2Params::new(262_144, 4, 1).expect("default must validate");
        assert_eq!(p, Argon2Params::default());
    }

    #[test]
    fn new_accepts_floor_params() {
        let p = Argon2Params::new(ARGON2_MIN_M_COST, ARGON2_MIN_T_COST, ARGON2_MIN_P_COST)
            .expect("floor must validate");
        assert_eq!(p, Argon2Params::minimum_secure());
    }

    #[test]
    fn new_rejects_m_cost_below_floor() {
        let err =
            Argon2Params::new(ARGON2_MIN_M_COST - 1, 4, 1).expect_err("m_cost below floor rejects");
        assert!(matches!(err, ParamsError::BelowFloor { .. }));
    }

    #[test]
    fn new_rejects_t_cost_below_floor() {
        let err = Argon2Params::new(ARGON2_MIN_M_COST, ARGON2_MIN_T_COST - 1, 1)
            .expect_err("t_cost below floor rejects");
        assert!(matches!(err, ParamsError::BelowFloor { .. }));
    }

    #[test]
    fn new_rejects_p_cost_below_floor() {
        let err = Argon2Params::new(ARGON2_MIN_M_COST, ARGON2_MIN_T_COST, 0)
            .expect_err("p_cost below floor rejects");
        assert!(matches!(err, ParamsError::BelowFloor { .. }));
    }

    #[test]
    fn new_rejects_m_cost_above_ceiling() {
        let err = Argon2Params::new(ARGON2_MAX_M_COST + 1, 4, 1)
            .expect_err("m_cost above ceiling rejects");
        assert!(matches!(err, ParamsError::AboveCeiling { .. }));
    }

    #[test]
    fn new_rejects_u32_max_m_cost() {
        let err =
            Argon2Params::new(u32::MAX, 4, 1).expect_err("u32::MAX m_cost rejects via ceiling");
        assert!(matches!(err, ParamsError::AboveCeiling { .. }));
    }

    #[test]
    fn new_accepts_ceiling() {
        let p = Argon2Params::new(ARGON2_MAX_M_COST, 4, 1).expect("ceiling must validate");
        assert_eq!(p.m_cost(), ARGON2_MAX_M_COST);
    }

    #[test]
    fn to_argon2_params_round_trips_triple() {
        let p = Argon2Params::default();
        let native = p.to_argon2_params();
        assert_eq!(native.m_cost(), p.m_cost());
        assert_eq!(native.t_cost(), p.t_cost());
        assert_eq!(native.p_cost(), u32::from(p.p_cost()));
    }
}
