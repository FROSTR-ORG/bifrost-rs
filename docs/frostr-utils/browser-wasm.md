# Browser WASM Package API

`bifrost-bridge-wasm` is the canonical browser-facing export surface for Rust-owned FROSTR package and encrypted-backup semantics.

The browser host layer does not reimplement these semantics in JavaScript. Browser apps and shared browser host code should consume the generated WASM module for:

- `bfshare` encode/decode
- `bfonboard` encode/decode
- `bfprofile` encode/decode
- profile package pair creation
- encrypted profile backup creation
- backup key derivation
- backup content encrypt/decrypt
- backup event build/parse

## Required browser exports

The generated browser module must expose:

- `WasmBridgeRuntime`
- `bf_package_version`
- `bfshare_prefix`
- `bfonboard_prefix`
- `bfprofile_prefix`
- `profile_backup_event_kind`
- `profile_backup_key_domain`
- `encode_bfshare_package`
- `decode_bfshare_package`
- `encode_bfonboard_package`
- `decode_bfonboard_package`
- `encode_bfprofile_package`
- `decode_bfprofile_package`
- `create_profile_package_pair`
- `create_encrypted_profile_backup`
- `derive_profile_backup_conversation_key_hex`
- `encrypt_profile_backup_content`
- `decrypt_profile_backup_content`
- `build_profile_backup_event`
- `parse_profile_backup_event`

## Ownership boundary

- `frostr-utils` owns the package and backup spec.
- `bifrost-bridge-wasm` exposes that spec to browser hosts.
- Browser host layers such as `igloo-shared` own relay transport, storage, and app-state orchestration only.
- Browser apps should treat the WASM bridge as the authoritative package/backup API and should not maintain parallel JS codecs.
