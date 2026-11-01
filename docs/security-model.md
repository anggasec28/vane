# Security Model

## Mandatory invariants
1. Default deny. Missing, expired, revoked, malformed, or mismatched authorization denies action.
2. Scope is explicit. Discovered assets and dependencies are not implicitly authorized.
3. Method allowlisting is exact. An allowed hostname does not imply permission for every technique.
4. Central policy evaluation precedes capability execution.
5. Human approval is bound to a specific action digest and validity window.
6. Worker authority is a strict subset of the parent mission.
7. Evidence records retain source, time, digest, method, and authorization linkage.
8. Findings require resolvable evidence and cannot validate on disputed/insufficient evidence.
9. Unknown ownership, disputed status, or preservation holds prevent automatic disposal.
10. Signing private keys remain outside the engine; verifier receives public material only.

## Explicit non-capabilities
The baseline does not include exploit execution, credential attacks, persistence, stealth, data exfiltration, transaction submission, key management, or automatic scope expansion. It includes planners, models, validators, and adapter contracts. Concrete active capabilities require separate review, explicit authorization, and independent tests.
