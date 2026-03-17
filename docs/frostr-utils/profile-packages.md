# Profile Packages And Encrypted Backups

`frostr-utils` is the canonical Rust owner of the browser/native package and backup spec:

- `bfshare`
- `bfonboard`
- `bfprofile`
- encrypted profile backup `kind: 10000`

## Scope

`frostr-utils` owns:

- payload types
- encode/decode
- payload validation
- password-based package encryption/decryption
- backup conversation-key derivation
- backup content encryption/decryption
- backup event construction/parsing

`frostr-utils` does not own:

- relay publish
- relay query/subscriptions
- latest-event selection across relays
- host storage
- host lifecycle or UI state

Those responsibilities belong to host layers such as `igloo-shared` and `igloo-shell`.

## Package Shapes

### `bfshare`

Compact URI-like plaintext before encryption:

```text
<secret_share>?relay=<url>&relay=<url>...
```

### `bfonboard`

Compact URI-like plaintext before encryption:

```text
<secret_share>?relay=<url>&relay=<url>...&peer_pk=<pubkey>
```

### `bfprofile`

Bech32m-decoded bytes are:

```text
<profile_id_ascii_hex_64><protected_envelope_json_bytes>
```

The outer 64-byte ASCII-hex prefix is the canonical `profile_id`.

Canonical JSON before encryption with:

- profile id
- device name
- share secret
- manual peer policy overrides
- remote peer policy observations
- relays
- keyset name
- group public key
- threshold / total count
- member index/share-pubkey list

The canonical profile id is:

```text
hex(sha256("frostr:profile-id:v1" || share_pubkey32))
```

Decoders reject the package unless:

- the outer profile-id prefix is valid lowercase 64-char hex
- the outer prefix matches the inner plaintext `profileId`
- the inner `profileId` matches the id derived from the contained share secret

## Encrypted Backup

Encrypted profile backups are Nostr `kind: 10000` events.

- author pubkey: derived from the share secret
- content: encrypted backup JSON
- backup JSON excludes the share secret

The backup conversation key is derived from the share secret alone with the domain string:

```text
frostr-profile-backup/v1
```

That derived 32-byte symmetric key is then used for NIP-44-compatible backup content encryption.
