# Security Controls

Central policy decision point evaluates every consequential action. Enforcement points apply at orchestrator, worker, MCP adapter, evidence operation, and lifecycle boundaries.

Required checks: current signed mission authorization; exact target/action coverage; allowed tool/method; exclusions and limits; separate high-risk action approval; data class; worker delegation; active stop conditions. Revalidate stored authorization before start/resume and against the evidence observation timestamp.

Deny on missing, stale, conflicting, or unverifiable authorization. Mission closure requires independent evidence validation and signed Master closure approval. Tool availability is not authorization. No silent fallback to broader permissions.

Record policy version, decision, reason code, authorization reference, principal, worker, tool/action, target, timestamp, and artifact reference. Protect sensitive reason fields separately where required.


## Master emergency suspension

The global emergency control is not a specialist capability and is not delegated to VANE. The human Master principal alone can issue signed SUSPEND and RELEASE transitions. Each approval binds the exact operation, expected revision, Master principal, reason, authority reference, and trigger. Stale revisions, wrong Master identity, unauthorized key IDs, expired approvals, altered payloads, or invalid event history are rejected.

Hermes bootstrap requires the control by default. Set `VANE_MASTER_PRINCIPAL` and `VANE_MASTER_KEY_IDS` only after the operator-owned Telegram identity and signing authority are bound correctly. If required configuration is missing, state is unavailable, or the control chain cannot be verified, central enforcement denies actions. The global control does not replace mission-specific signed authorization.

The emergency control implementation is a repository capability foundation. Live Telegram identity binding, production public-key provisioning, external signing-service operation, and end-to-end runtime validation remain NOT_VERIFIED.
