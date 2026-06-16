use frost_secp256k1_tr_unofficial as frost;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, SecretKey};

use crate::error::{CoreError, CoreResult};
use crate::types::{Bytes32, Bytes33, EcdhEntry, EcdhPackage, SharePackage};

pub fn create_ecdh_package(
    members: &[u16],
    share: &SharePackage,
    ecdh_pks: &[Bytes32],
) -> CoreResult<EcdhPackage> {
    let sk =
        SecretKey::from_slice(share.seckey.expose_bytes()).map_err(|_| CoreError::InvalidScalar)?;
    // Weight this share by its Lagrange coefficient over the participating quorum
    // (`members`) before the ECDH point-multiply, so the summed threshold
    // contributions in `combine_ecdh_packages` reconstruct `group_secret · target`
    // (the real group-key ECDH) rather than a merely self-consistent sum. This
    // mirrors FROSTR V1 (`@vbyte/frost` `calc_lagrange_coeff`); without it the
    // derived secret can't interop with standard NIP-44 peers for any t-of-n, t > 1.
    let lambda = lagrange_coeff_at_zero(members, share.idx)?;
    let scalar = (*sk.to_nonzero_scalar().as_ref()) * lambda;
    let mut entries = Vec::with_capacity(ecdh_pks.len());

    for ecdh_pk in ecdh_pks {
        let point = point_from_pubkey32(*ecdh_pk)?;
        let shared = (ProjectivePoint::from(point) * scalar).to_affine();

        let mut keyshare = [0u8; 33];
        keyshare.copy_from_slice(shared.to_encoded_point(true).as_bytes());

        entries.push(EcdhEntry {
            ecdh_pk: *ecdh_pk,
            keyshare,
        });
    }

    Ok(EcdhPackage {
        idx: share.idx,
        members: members.to_vec(),
        entries,
    })
}

pub fn combine_ecdh_packages(pkgs: &[EcdhPackage], ecdh_pk: Bytes32) -> CoreResult<Bytes32> {
    if pkgs.is_empty() {
        return Err(CoreError::EmptyMembers);
    }

    let mut acc = ProjectivePoint::IDENTITY;
    let mut count = 0usize;

    for pkg in pkgs {
        if let Some(entry) = pkg.entries.iter().find(|e| e.ecdh_pk == ecdh_pk) {
            let point = point_from_bytes(entry.keyshare)?;
            acc += ProjectivePoint::from(point);
            count += 1;
        }
    }

    if count == 0 {
        return Err(CoreError::InvalidPubkey);
    }

    // Standard NIP-44 / ECDH shared secret = the raw X-coordinate of the combined
    // point (NOT a hash of it). The combined threshold point equals the point a
    // normal ECDH with the group key produces, so taking its X here makes the
    // app-facing `window.nostr.nip44` conversation key interoperate with standard
    // nostr clients — and matches the single-key `nip44::event_shared_x` path.
    let point = acc.to_affine().to_encoded_point(false);
    let x = point.x().ok_or(CoreError::InvalidPubkey)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x);
    Ok(out)
}

pub fn local_pubkey_from_share(share: &SharePackage) -> CoreResult<Bytes32> {
    let sk =
        SecretKey::from_slice(share.seckey.expose_bytes()).map_err(|_| CoreError::InvalidScalar)?;
    let ep = sk.public_key().to_encoded_point(false);
    let x = ep.x().ok_or(CoreError::InvalidPubkey)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x);
    Ok(out)
}

// Lagrange interpolation coefficient for member `idx`, evaluated at x = 0, over the
// participating quorum `members` (the share x-coordinates). `λ_i = Π_{j≠i} x_j /
// (x_j - x_i)`, so `Σ λ_i · share_i = f(0) = group_secret` for the quorum's shares of
// the degree-(t-1) sharing polynomial `f`. The member index is the share's
// x-coordinate (matching the `frost` keygen identifiers). For a singleton/empty
// `members` (threshold-1) this is `1`, so the threshold-1 path is unchanged.
fn lagrange_coeff_at_zero(members: &[u16], idx: u16) -> CoreResult<Scalar> {
    let xi = member_scalar(idx)?;
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &member in members {
        if member == idx {
            continue;
        }
        let xj = member_scalar(member)?;
        num *= xj;
        den *= xj - xi;
    }
    let den_inv = Option::<Scalar>::from(den.invert()).ok_or(CoreError::InvalidScalar)?;
    Ok(num * den_inv)
}

// The member index's x-coordinate in the sharing polynomial, derived from the SAME
// `frost` Identifier mapping that signing uses (`Identifier::try_from(idx)`), so the
// ECDH Lagrange basis can't drift from the keygen/signing identifier encoding. The
// Lagrange formula above stays hand-rolled because frost-core exposes no public
// per-identifier coefficient API (only `keys::reconstruct`, which needs every share
// on one device and so can't serve the distributed ECDH protocol).
fn member_scalar(idx: u16) -> CoreResult<Scalar> {
    let id = frost::Identifier::try_from(idx).map_err(|e| CoreError::Frost(e.to_string()))?;
    let bytes = id.serialize();
    let sk = SecretKey::from_slice(&bytes).map_err(|_| CoreError::InvalidScalar)?;
    Ok(*sk.to_nonzero_scalar().as_ref())
}

fn point_from_pubkey32(bytes: Bytes32) -> CoreResult<AffinePoint> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&bytes);
    point_from_bytes(compressed)
}

fn point_from_bytes(bytes: Bytes33) -> CoreResult<AffinePoint> {
    let ep = EncodedPoint::from_bytes(bytes).map_err(|_| CoreError::InvalidPubkey)?;
    AffinePoint::from_encoded_point(&ep)
        .into_option()
        .ok_or(CoreError::InvalidPubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_pubkey_derives() {
        let share = SharePackage {
            idx: 1,
            seckey: crate::secret::SharePrivateKey::new([11; 32]),
        };
        let pk = local_pubkey_from_share(&share).expect("pubkey");
        assert_eq!(pk.len(), 32);
    }

    // The threshold ECDH secret must be the raw X-coordinate of the shared point
    // (standard NIP-44), NOT a hash of it — so the app-facing window.nostr.nip44
    // conversation key interoperates with standard nostr clients. Here a standard
    // counterparty holds the peer key and does a normal ECDH with the group key;
    // the threshold combine must produce the identical secret.
    #[test]
    fn combine_returns_standard_raw_x_ecdh_secret() {
        // threshold-1 "group" = a single share; the peer is a normal keypair.
        let share = SharePackage {
            idx: 1,
            seckey: crate::secret::SharePrivateKey::new([11; 32]),
        };
        let peer = SharePackage {
            idx: 2,
            seckey: crate::secret::SharePrivateKey::new([22; 32]),
        };
        let peer_xonly = local_pubkey_from_share(&peer).expect("peer pubkey");
        let group_xonly = local_pubkey_from_share(&share).expect("group pubkey");

        // FROSTR side: build + combine the ECDH package for the peer.
        let pkg = create_ecdh_package(&[share.idx], &share, &[peer_xonly]).expect("package");
        let frostr_secret = combine_ecdh_packages(&[pkg], peer_xonly).expect("combine");

        // Standard counterparty: ECDH(peer_seckey, group_pubkey), raw X-coordinate.
        let peer_sk = SecretKey::from_slice(peer.seckey.expose_bytes()).expect("peer scalar");
        let peer_scalar = *peer_sk.to_nonzero_scalar().as_ref();
        let group_point = point_from_pubkey32(group_xonly).expect("group point");
        let shared = (ProjectivePoint::from(group_point) * peer_scalar).to_affine();
        let ep = shared.to_encoded_point(false);
        let standard_x = ep.x().expect("x coordinate");

        assert_eq!(&frostr_secret[..], standard_x.as_slice());
    }

    // The threshold case that the prior tests miss: a real t-of-n (t > 1) quorum must
    // also reconstruct the *group-key* ECDH secret (raw X of `group_secret · target`),
    // not just a self-consistent sum. This requires the Lagrange weighting in
    // `create_ecdh_package`; without it a 2-of-3 combine yields `(Σ shares)·target`,
    // which is undecryptable by a standard NIP-44 peer (the "invalid MAC" the @live
    // interop test caught). Here a degree-1 polynomial gives explicit 2-of-3 shares.
    #[test]
    fn combine_reconstructs_group_key_ecdh_for_threshold_quorum() {
        let scalar_bytes = |s: Scalar| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&s.to_bytes());
            out
        };

        // f(x) = a0 + a1*x; a0 is the group secret, shares are f(1), f(2), f(3).
        let a0 = Scalar::from(1_234_567u64);
        let a1 = Scalar::from(7_654_321u64);
        let f = |x: u64| a0 + a1 * Scalar::from(x);
        let share = |idx: u16| SharePackage {
            idx,
            seckey: crate::secret::SharePrivateKey::new(scalar_bytes(f(u64::from(idx)))),
        };

        // External counterparty with secret `c`; target = its x-only pubkey.
        let c = Scalar::from(99u64);
        let counterparty = SharePackage {
            idx: 7,
            seckey: crate::secret::SharePrivateKey::new(scalar_bytes(c)),
        };
        let target = local_pubkey_from_share(&counterparty).expect("target pubkey");
        let group_xonly = local_pubkey_from_share(&SharePackage {
            idx: 1,
            seckey: crate::secret::SharePrivateKey::new(scalar_bytes(a0)),
        })
        .expect("group pubkey");

        // FROSTR side: the {1,2} quorum builds + combines its ECDH packages.
        let members = vec![1u16, 2u16];
        let pkg1 = create_ecdh_package(&members, &share(1), &[target]).expect("pkg1");
        let pkg2 = create_ecdh_package(&members, &share(2), &[target]).expect("pkg2");
        let frostr_secret = combine_ecdh_packages(&[pkg1, pkg2], target).expect("combine");

        // Standard counterparty: ECDH(c, group_pubkey), raw X-coordinate.
        let group_point = point_from_pubkey32(group_xonly).expect("group point");
        let shared = (ProjectivePoint::from(group_point) * c).to_affine();
        let ep = shared.to_encoded_point(false);
        let standard_x = ep.x().expect("x coordinate");

        assert_eq!(&frostr_secret[..], standard_x.as_slice());

        // Sanity: a different quorum {2,3} must reconstruct the same group secret.
        let members_b = vec![2u16, 3u16];
        let pkg2b = create_ecdh_package(&members_b, &share(2), &[target]).expect("pkg2b");
        let pkg3b = create_ecdh_package(&members_b, &share(3), &[target]).expect("pkg3b");
        let frostr_secret_b = combine_ecdh_packages(&[pkg2b, pkg3b], target).expect("combine b");
        assert_eq!(frostr_secret_b, frostr_secret);
    }

    // Spec-anchored known-answer test: pins a fixed-input threshold ECDH to a stable
    // raw-X output, so any future change to the Lagrange / point math is caught — not
    // just internal inconsistency. The pinned answer is cross-checked in-test against an
    // independent k256 computation of the standard group-key ECDH, and must hold across
    // every threshold quorum. Re-pin EXPECTED_SECRET_HEX only after a deliberate,
    // reviewed change to the ECDH derivation.
    #[test]
    fn ecdh_threshold_kat() {
        const EXPECTED_SECRET_HEX: &str =
            "044cb5cb96a3459b171e913b34b8e85c3bb17ca228aa608d37151ec7e478e8ac";

        let scalar_bytes = |s: Scalar| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&s.to_bytes());
            out
        };

        // Fixed degree-1 sharing polynomial f(x) = a0 + a1*x (a0 = group secret), with
        // shares at x = 1,2,3; fixed external counterparty secret c, target = x-only(c·G).
        let a0 = Scalar::from(0x1234_5678_9abc_def0u64);
        let a1 = Scalar::from(0x0fed_cba9_8765_4321u64);
        let c = Scalar::from(0x00de_ad00_beef_0042u64);
        let f = |x: u64| a0 + a1 * Scalar::from(x);
        let share = |idx: u16| SharePackage {
            idx,
            seckey: crate::secret::SharePrivateKey::new(scalar_bytes(f(u64::from(idx)))),
        };
        let target = local_pubkey_from_share(&SharePackage {
            idx: 9,
            seckey: crate::secret::SharePrivateKey::new(scalar_bytes(c)),
        })
        .expect("target pubkey");
        let group_xonly = local_pubkey_from_share(&SharePackage {
            idx: 1,
            seckey: crate::secret::SharePrivateKey::new(scalar_bytes(a0)),
        })
        .expect("group pubkey");

        // Independent k256 anchor: standard ECDH(c, group_pubkey), raw X-coordinate.
        let group_point = point_from_pubkey32(group_xonly).expect("group point");
        let shared = (ProjectivePoint::from(group_point) * c).to_affine();
        let ep = shared.to_encoded_point(false);
        let standard_x = ep.x().expect("x coordinate");
        assert_eq!(
            hex::encode(standard_x),
            EXPECTED_SECRET_HEX,
            "ECDH KAT drift — re-pin EXPECTED_SECRET_HEX only after a deliberate ECDH change"
        );

        // Every threshold quorum must reconstruct exactly the pinned secret.
        for members in [vec![1u16, 2], vec![1, 3], vec![2, 3]] {
            let pkgs: Vec<_> = members
                .iter()
                .map(|&idx| create_ecdh_package(&members, &share(idx), &[target]).expect("package"))
                .collect();
            let secret = combine_ecdh_packages(&pkgs, target).expect("combine");
            assert_eq!(
                hex::encode(secret),
                EXPECTED_SECRET_HEX,
                "quorum {members:?} diverged from the pinned ECDH secret"
            );
        }
    }
}
