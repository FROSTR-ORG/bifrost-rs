# Batch Signing Nonce Model (PR-01)

## Purpose

Define a safe, decision-complete nonce lifecycle for enabling batch signing in `bifrost-core` and `bifrost-node` without nonce reuse risk.

## Security Invariants

1. A signing nonce pair must be consumed exactly once.
2. A signing nonce pair must bind to one signer + one session + one message hash index.
3. Failed/aborted sign attempts must never reintroduce consumed nonces.
4. Aggregation must reject shares produced from nonce/commitment mismatch.

## Current State

- Nonce pool stores:
- outbound public commitments by peer/code.
- outbound secret `SigningNonces` by peer/code.
- inbound commitments by peer/code.
- Sign path currently supports one hash (`1x1` shape), which avoids multi-hash nonce scheduling.

## Target State For Batch Signing

## Data Model

Introduce explicit consumed-claim bookkeeping in `NoncePool`:

- `claimed_outgoing`: map of `{peer_idx, code} -> claim_context`.
- `claim_context` includes:
- `sid`
- `hash_index`
- `claimed_at`

Required API additions (core):

- `claim_outgoing_signing_nonces(peer_idx, code, sid, hash_index) -> SigningNonces`
- Fails if the code is missing or already claimed.
- `finalize_claim(peer_idx, code)`
- Makes claim terminal (default behavior after successful sign share generation).
- `abort_claim(peer_idx, code)`
- Optional and only allowed before any signature-share generation; default policy is to keep consumed for safety.

## Coordinator/Signer Flow

For each signer in a batch of `N` hashes:

1. Coordinator provides `N` commitment sets per signer (or one session-per-hash fallback).
2. Signer claims exactly one nonce pair per hash index.
3. Signer produces one signature share per hash index.
4. Claims are finalized immediately after share creation.

## Session Shape

Option A (preferred for parity): one sign session containing `N` hashes and `N` nonce commitments per signer.

Option B (safe fallback): coordinator internally expands batch into `N` independent single-hash sessions.

Implementation plan:

- Start with Option B in `bifrost-node` orchestration if Option A introduces wire churn.
- Keep public API batch-capable while internal implementation can multiplex sessions safely.

## Failure Policy

- If any hash-index signing step fails for a claimed nonce:
- mark that nonce terminally spent.
- do not return it to pool.
- trigger replenish behavior for affected peer.

Rationale: safety over nonce utilization.

## Validation Rules

1. Reject batch sign request when nonce material count per signer does not match hash count.
2. Reject duplicate nonce codes within same session.
3. Reject signature share if signer identifier/commitment mapping mismatches.
4. Reject aggregation if shares do not cover required threshold for each hash index.

## Test Requirements (PR-01/PR-04/PR-05)

1. Claim-once test:
- second claim of same `{peer, code}` fails.
2. Abort policy test:
- claimed nonce is not reusable by default after failed signing path.
3. Batch mapping test:
- each hash index uses distinct nonce/claim context.
4. Mismatch test:
- reused or swapped nonce commitments cause share verification failure.
5. Replenish test:
- failed/consumed claims trigger low-water replenishment behavior.

## Rollout Plan

1. PR-01:
- Lock this model and add guardrail tests for claim semantics.
2. PR-04:
- Implement batch signing using claim API.
3. PR-05:
- Add adversarial/mismatch tests validating non-reuse and commitment binding.

## Open Notes

- If wire compatibility pressure is high, implement Option B first and document as temporary strategy in parity matrix.
