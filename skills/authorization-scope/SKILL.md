---
name: authorization-scope
description: Resolve every asset and method against explicit approval.
version: 0.2.0
metadata:
  hermes:
    tags: [security, authorization, scope]
    category: security
---
# Authorization and Scope

## When to Use
Use before any assessment action, tool call, asset mapping, recovery attempt, or scope change.

## Procedure
1. Obtain the exact authorization envelope from the Master. Do not infer it from previous access or discovery.
2. Confirm principal, project, validity window, approval reference, asset rules, allowed methods, and prohibited methods.
3. Call `mcp__vane_engine__vane_scope_check` with the exact envelope JSON, locator, and method.
4. Treat any denial, malformed envelope, missing approval reference, expired envelope, or ambiguous locator as DENY.
5. For a mission, verify its Ed25519 approval with `mcp__vane_engine__vane_verify_mission_approval`. For any separately gated action, verify the action-bound approval with `mcp__vane_engine__vane_verify_action_approval`.
6. Record out-of-scope discoveries as NOT_INSPECTED. Do not resolve them by probing.
7. Re-check authorization when the method, asset, project, or time window changes.

## Pitfalls
- A hostname permission does not imply permission for every method.
- A related domain, redirect, IP, repository, contract, symlink target, or dependency is not implicitly in scope.
- Approval for one action does not approve a different action.

## Verification
Retain the exact envelope ID, approval reference, locator, method, decision, and denial reason where applicable.
