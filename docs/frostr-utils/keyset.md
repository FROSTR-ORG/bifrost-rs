# Keyset Utilities

`frostr-utils` keyset helpers:

- `create_keyset(CreateKeysetConfig)`
- `verify_keyset(&KeysetBundle)`
- `verify_group_config(&GroupPackage)`
- `verify_share(&SharePackage, &GroupPackage)`
- `rotate_keyset_dealer(&GroupPackage, RotateKeysetRequest)`
- `recover_key(&RecoverKeyInput)`

## Rotation Model

`rotate_keyset_dealer` performs a trusted-dealer rotation of an existing FROSTR keyset:

- threshold shares from the current group are used to reconstruct the signing key
- that same signing key is re-split into a new share set
- the resulting keyset preserves the same group public key
- the resulting group configuration can change threshold and member count

Because the member verifying shares can change, the derived `group_id` can also change even when the group public key stays the same.

If the group public key changes, that is not rotation. It is a brand-new keyset and should use key generation, not rotation.

## Recovery Model

Recovery reconstructs the current group signing key from threshold shares using FROST key reconstruction.
