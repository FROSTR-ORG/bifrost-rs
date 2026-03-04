# Glossary

## FROST

Flexible Round-Optimized Schnorr Threshold protocol used for threshold signatures.

## FROSTR

FROST operations coordinated over relay transport.

## Group Package

Threshold group metadata (`group_pk`, `threshold`, member set).

## Share Package

Per-member secret key share with signer index.

## Sign Session

A signing context binding group, members, hashes/content, and nonce state.

## Partial Signature

A member's threshold signing contribution.

## Nonce Pool

Stateful store for outgoing/incoming signing nonces with one-time-use controls.

## Onboarding

Peer bootstrap flow used to exchange group context and nonce material.

## Signing Device

Stateful cryptographic engine that decrypts peer events, executes protocol logic, and emits encrypted responses.

## Bridge

Runtime orchestration layer that connects a signing device to a relay adapter and exposes command APIs.
