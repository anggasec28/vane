---
name: evidence-management
description: Preserve evidence provenance, integrity, and sufficiency.
version: 0.2.0
metadata:
  hermes:
    tags: [security, evidence, provenance]
    category: security
---
# Evidence Management

## When to Use
Use whenever observations, logs, screenshots, code excerpts, or derived artifacts support an assessment or finding.

## Procedure
1. Assign a stable evidence ID and link it to project, mission, source, method, timestamp, and authorization.
2. Compute SHA-256 over the exact retained bytes. Do not hash a re-rendered or edited substitute.
3. Record collection limitations, parent evidence IDs, and whether the record is observed or derived.
4. Use `mcp__vane_engine__vane_validate_evidence` to validate record structure and digest shape.
5. Use `mcp__vane_engine__vane_verify_event_chain` to verify exported event sequences.
6. Distinguish evidence presence from evidence sufficiency. Preserve disputed and insufficient records without treating them as proof.

## Pitfalls
- A digest proves byte identity, not truth, origin, or authorization.
- An artifact's existence does not prove it supports a finding.
- Do not overwrite original evidence with normalized or redacted copies.

## Verification
Every evidence record must resolve to its source, time, method, authorization, digest, and limitations.
