use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, SecretKey};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::types::{Bytes32, Bytes33, EcdhEntry, EcdhPackage, SharePackage};

pub fn create_ecdh_package(
    members: &[u16],
    share: &SharePackage,
    ecdh_pks: &[Bytes32],
) -> CoreResult<EcdhPackage> {
    let sk = SecretKey::from_slice(&share.seckey).map_err(|_| CoreError::InvalidScalar)?;
    let scalar = *sk.to_nonzero_scalar().as_ref();
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

    let point = acc.to_affine().to_encoded_point(true);
    let mut hasher = Sha256::new();
    hasher.update(point.as_bytes());
    Ok(hasher.finalize().into())
}

pub fn local_pubkey_from_share(share: &SharePackage) -> CoreResult<Bytes32> {
    let sk = SecretKey::from_slice(&share.seckey).map_err(|_| CoreError::InvalidScalar)?;
    let ep = sk.public_key().to_encoded_point(false);
    let x = ep.x().ok_or(CoreError::InvalidPubkey)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x);
    Ok(out)
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
            seckey: [11; 32],
        };
        let pk = local_pubkey_from_share(&share).expect("pubkey");
        assert_eq!(pk.len(), 32);
    }
}
