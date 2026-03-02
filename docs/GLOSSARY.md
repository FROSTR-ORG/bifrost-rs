# Glossary

## FROST

Flexible Round-Optimized Schnorr Threshold protocol used for threshold signatures.

## FROSTR

FROST operations coordinated over Nostr-style relay transport.

## Group Package

Threshold group metadata (`group_pk`, `threshold`, member set).

## Share Package

Per-member secret key share with signer index.

## Sign Session

A signing context that binds group, members, hashes/content, and nonce state.

## Partial Signature

A member's threshold signing contribution for one or more sighashes.

## Nonce Pool

Stateful store for outgoing/incoming signing nonces with safety controls.

## Onboarding

Peer handshake flow used to exchange group context and nonce material.

## Daemon RPC

Local Unix-socket JSON RPC interface exposed by `bifrostd`.

## Devnet

Local multi-node runtime setup generated under the configured runtime data directory.
