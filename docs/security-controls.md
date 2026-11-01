# Security Controls

Central policy decision point evaluates every consequential action. Enforcement points apply at orchestrator, worker, MCP adapter, evidence operation, and lifecycle boundaries.

Required checks: current signed mission authorization; exact target/action coverage; allowed tool/method; exclusions and limits; separate high-risk action approval; data class; worker delegation; active stop conditions. Revalidate stored authorization before start/resume and against the evidence observation timestamp.

Deny on missing, stale, conflicting, or unverifiable authorization. Mission closure requires independent evidence validation and signed Master closure approval. Tool availability is not authorization. No silent fallback to broader permissions.

Record policy version, decision, reason code, authorization reference, principal, worker, tool/action, target, timestamp, and artifact reference. Protect sensitive reason fields separately where required.
