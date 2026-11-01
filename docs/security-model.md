# Security Model

## Mandatory invariants
1. Default deny. Missing, expired, revoked, malformed, or mismatched authorization denies action.
2. Scope is explicit. Discovered assets and dependencies are not implicitly authorized.
3. Method allowlisting is exact. An allowed hostname does not imply permission for every technique.
4. Central policy evaluation precedes capability execution.
5. Every mission requires a signed Ed25519 approval bound to its exact authorization envelope. High-risk methods additionally require a separate signed approval bound to the exact asset and method. Mission closure requires independent validation followed by a separate signed approval bound to the completed mission snapshot.
6. Worker authority is a strict subset of the parent mission.
7. Evidence records retain source, time, digest, method, and authorization linkage.
8. Findings require resolvable evidence and cannot validate on disputed/insufficient evidence.
9. Unknown ownership, disputed status, or preservation holds prevent automatic disposal.
10. Signing private keys remain outside the engine; verifier receives public material only.
11. Missing public-key configuration, unknown key IDs, malformed signatures, and signature mismatch deny approval.
12. Master-only emergency suspension is a separate global control. Suspend and release require an Ed25519 approval signed by a configured Master key, bound to the exact operation, revision, reason, authority reference, and trigger.
13. Every emergency-control read verifies the complete event chain and every historical Master signature. Unknown events, invalid signatures, identity mismatch, or unavailable state fail closed.
14. When `VANE_REQUIRE_EMERGENCY_CONTROL=true` (the Hermes bootstrap default), the central policy engine denies actions if the control is not configured, cannot be read, or is suspended. Only the configured Master authority can release it; the agent and specialists cannot.

## Explicit non-capabilities
The baseline does not include exploit execution, credential attacks, persistence, stealth, data exfiltration, transaction submission, key management, or automatic scope expansion. It includes planners, models, validators, and adapter contracts. Concrete active capabilities require separate review, explicit authorization, and independent tests.


## Master emergency control bootstrap

The Hermes-native bootstrap uses these profile-local environment variables:

- `VANE_REQUIRE_EMERGENCY_CONTROL`: defaults to `true`; only an explicit `false`, `no`, or `0` disables the required-control gate.
- `VANE_MASTER_PRINCIPAL`: canonical Master principal identifier.
- `VANE_MASTER_KEY_IDS`: comma-separated key IDs in the public-only Ed25519 keyring that are authorized for Master emergency control.

If the Master principal or key IDs are missing while the gate is required, target-facing policy decisions fail closed. The principal must be populated only after the operator-owned Hermes Telegram identity binding and signing authority have been verified. The repository does not infer a Telegram user ID or configure the live gateway.

The control history is stored in a dedicated global hash-linked event chain. It is separate from project data and does not grant ordinary mission or target authorization. A suspension blocks all actions routed through the central policy engine. Release is a separate signed Master decision.
