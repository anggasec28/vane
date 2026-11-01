# Security Controls

Central policy decision point evaluates every consequential action. Enforcement points apply at orchestrator, worker, MCP adapter, evidence operation, and lifecycle boundaries.

Required checks: current authorization; exact target/action coverage; allowed tool/method; exclusions and limits; required approval; data class; worker delegation; active stop conditions.

Deny on missing, stale, conflicting, or unverifiable authorization. Tool availability is not authorization. No silent fallback to broader permissions.

Record policy version, decision, reason code, authorization reference, principal, worker, tool/action, target, timestamp, and artifact reference. Protect sensitive reason fields separately where required.
