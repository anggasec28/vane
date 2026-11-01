---
name: security-evidence-integrity
description: Verify hashes, provenance, and event-chain consistency.
version: 0.2.0
metadata:
  hermes:
    tags: [security, integrity, cryptography]
    category: security
---
# Security Evidence Integrity

## When to Use
Use when validating evidence digests, event history, signing boundaries, or custody claims.

## Procedure
1. Hash exact evidence bytes with SHA-256 and retain the digest with provenance.
2. Verify exported event chains with `mcp__vane_engine__vane_verify_event_chain`.
3. Verify the profile-local project database with `mcp__vane_engine__vane_verify_project_integrity`.
3. Treat local hash chaining as tamper evidence, not as external anchoring.
4. Keep signing authority in the external Ed25519 signing service.
5. Keep verifier material public and independent of the signing private key.
6. Record any missing anchor, signature, timestamp, or custody proof as an explicit gap.

## Pitfalls
- Do not place private keys in the repository, Hermes profile, or Python engine.
- HMAC under a shared secret does not establish independent verification.
- L3/R-12 external anchor and reset-ledger requirements remain open.

## Verification
Report digest results, provenance gaps, signer/verifier separation, and whether external anchoring is actually present.
