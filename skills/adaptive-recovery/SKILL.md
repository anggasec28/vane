---
name: adaptive-recovery
description: Recover from observation failures without bypassing policy.
version: 0.2.0
metadata:
  hermes:
    tags: [security, recovery, evidence]
    category: security
---
# Adaptive Evidence-Driven Recovery

## When to Use
Use when an observation is blocked, incomplete, inconsistent, or unavailable.

## Procedure
1. Classify the failure: transient, policy denial, unavailable dependency, rate limit, or evidence insufficiency.
2. Identify the missing evidence and the exact reason it is missing.
3. Retry only the same in-scope observation when the failure is transient, using bounded backoff.
4. Use an alternate method only if it is already authorized.
5. If a new method or asset is required, request explicit approval before proceeding.
6. If no compliant recovery exists, preserve the blocker and report the evidence gap.
7. Re-evaluate closure criteria after recovery.

## Engine Tool

Use `mcp__vane_engine__vane_plan_recovery` to classify a recovery option. Follow its approval requirement; never convert a recommendation into permission.

## Pitfalls
- Never bypass a block page, rate limit, authentication gate, or scope denial.
- Never silently expand to related assets.
- A blocked observation is not proof of absence or a pass.

## Verification
Record failure class, recovery action, approval reference if needed, and resulting evidence delta.
