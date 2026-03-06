# Plan A: Pubkey32 Normalization (Hard Cut)

## Summary
Normalize Bifrost public-key identity surfaces to canonical 32-byte x-only keys (64 lowercase hex chars) with no compatibility shims.

This plan is the prerequisite for multi-device routing.

## Decisions (Locked)
- Canonical public-key identity format is `pubkey32` (x-only, 32 bytes, hex-encoded).
- Legacy compressed identity keys (`33-byte`, `02/03 + x`) are removed from public APIs, wire schemas, config surfaces, and tests.
- Hard cut only: no dual parsing, no fallback, no migration aliases.
- Curve point fields that are not identity keys (for example FROST nonce points like `binder_pn`/`hidden_pn`) remain in their cryptographically required encoding.
- `MemberPackage.pubkey` remains a 33-byte FROST verifying-share point (cryptographic material, not peer identity).
- No existing keysets are supported. Fresh alpha key material only.
- FROST key material must be normalized with `EvenY` semantics before any x-only export/storage; naive x-only truncation is invalid.

## Key Implementation Changes

### 1) Core domain and wire types
- Replace identity key fields in `bifrost-core` types from `Bytes33` to `Bytes32`:
  - `GroupPackage.group_pk`
  - `OnboardRequest.share_pk`
  - Any peer identity fields used for sender/member binding.
- Keep `MemberPackage.pubkey` as 33-byte verifying-share material required for FROST verification.
- Keep non-identity curve-point fields unchanged where required by cryptographic primitives.
- Update validation helpers:
  - remove `decode_hex33` for identity surfaces
  - add/standardize `decode_hex32_pubkey` (strict lowercase canonicalization where applicable)
  - enforce exact 32-byte length and secp256k1 x-only validity.
- Key generation/bootstrap rule:
  - normalize group and participant key packages with `into_even_y(None)` before persisting/exporting identity keys
  - export identity keys as x-only 32-byte values only.

### 2) Codec schema updates
- Update `bifrost-codec` wire structs so identity fields serialize as `pubkey32` hex strings.
- Update parsing/conversion for all affected request/response packages.
- Keep envelope shape unchanged (`BridgeEnvelope` remains unversioned alpha hard-cut).

### 3) Signer normalization
- Refactor signer identity handling to native x-only maps:
  - remove compressed-to-xonly indirection for identity tracking
  - peer lookup, sender binding, and policy maps keyed by `pubkey32`.
- Update crypto IO boundaries:
  - API inputs/outputs use `pubkey32`
  - internal conversion to compressed form is permitted only inside crypto helpers where required.
- Update signer command inputs that currently carry `33-byte` identity keys (for example `BeginEcdh`) to `32-byte` key inputs.
- Do not accept compressed identity keys at signer boundaries.

### 3.1) ECDH hard-cut normalization
- Migrate ECDH identity fields (`ecdh_pk`, peer targeting, related wire fields) from 33-byte compressed keys to `pubkey32`.
- For x-only ECDH inputs:
  - lift x-coordinate to curve point with fixed even-Y rule
  - use normalized/x-only representation for secret derivation input hashing (not raw compressed 33-byte bytes).
- Remove parity-dependent behavior from ECDH output derivation by standardizing on x-only/even-Y normalization.

### 4) Router/bridge/app/dev surfaces
- Update router command and status surfaces to `pubkey32`.
- Update `bifrost-bridge-tokio` typed APIs to `pubkey32` targeting.
- Update app/dev CLI and config JSON examples to use `pubkey32` everywhere identity keys are supplied.

### 5) Fixtures and docs hard cut
- Rewrite all fixtures/golden vectors/config examples to `pubkey32`.
- Update docs to state explicit canonical rule: identity pubkeys are x-only 32-byte hex.

## Test Plan

### Unit
- Core validation:
  - accepts valid x-only 32-byte keys
  - rejects 33-byte compressed keys
  - rejects malformed/non-canonical hex.
- Codec roundtrip:
  - all identity fields preserve exact `pubkey32` values.
- Signer:
  - sender/member binding still enforced with `pubkey32`
  - ECDH/sign workflows still pass with normalized inputs.
- FROST parity normalization:
  - `into_even_y(None)` normalized key packages sign/verify successfully
  - naive x-only truncation/relift path is rejected or fails tests by design.

### Integration
- App/dev config parsing with `pubkey32` peers succeeds.
- Any config using 33-byte identity keys fails fast with clear errors.
- Freshly generated keysets (post-hard-cut) produce only x-only identity keys and pass sign + ECDH flows.

### Regression
- Full workspace tests pass with no 33-byte identity key assumptions.
- Repo grep contains no active public identity API requiring 33-byte keys.

## Acceptance Criteria
- All public identity key surfaces are `pubkey32` only.
- No compatibility fallback for 33-byte identity keys exists.
- Test suite passes with updated fixtures and docs.
- This plan is complete and enables Plan B routing without another key-shape refactor.
- ECDH operates correctly with x-only keys under fixed even-Y normalization, with no parity-dependent ambiguity.
