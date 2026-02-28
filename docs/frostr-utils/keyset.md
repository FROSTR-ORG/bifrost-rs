# Keyset Utilities

`frostr-utils` keyset helpers:

- `create_keyset(CreateKeysetConfig)`
- `verify_keyset(&KeysetBundle)`
- `verify_group_config(&GroupPackage)`
- `verify_share(&SharePackage, &GroupPackage)`
- `rotate_keyset_dealer(&GroupPackage, RotateKeysetRequest)`
- `recover_key(&RecoverKeyInput)`

## Rotation Model

Rotation is dealer reissue in alpha:
- a new keyset is generated with requested threshold/member count
- previous group id is returned for audit linkage

## Recovery Model

Recovery reconstructs the group signing key from threshold shares using FROST key reconstruction.
