# Build Status

Repository: https://github.com/anggasec28/vane  
Architecture: Hybrid modular Python engine + VANE profile + Hermes runtime boundary.  
Package version: 0.2.0 development baseline.

## Source implemented
- Python package metadata, CLI, domain models, and typed domain exceptions.
- Authorization envelope, exact asset/method scope checks, action-digest-bound approval records, central policy engine and enforcement facade.
- Mission lifecycle with evidence-gated completion and orchestration facade.
- Web2/Web3 planning, asset disposition, dependency graph, and authorization envelope review.
- Evidence record validation, SHA-256 helpers, canonical provenance, and event-chain verification.
- Finding validation linked to usable evidence.
- Adaptive recovery planner and hybrid lifecycle policy.
- Project registry, SQLite event persistence, MCP capability allowlist.
- Worker delegation contracts and independent mission closure validator.
- External Ed25519 signing interface, public-only approval verifier/keyring, and inert Hermes adapter.
- Local stdio MCP server exposing policy, planning, evidence, and event-chain utilities only.
- JSON schemas and initial unit tests, including skill metadata, approval signatures, scoped planners, and SQLite event integrity.

## Remaining implementation and verification
- Complete durable repositories for all domain objects and schema migrations; the SQLite event chain is implemented as a foundation.
- Add external anchoring and trusted-head publication for tamper evidence; L3/R-12 remains unimplemented.
- Complete all JSON schemas and validation wiring.
- Verify Hermes profile installation and MCP discovery on the target Hermes runtime version; no target runtime has been inspected or changed.
- Add worker execution orchestration and independent verifier workflow.
- Execute and review CI results, expand test coverage, and complete packaging/security review and release artifacts.
- Map every Master decision and historical requirement to code-level acceptance tests.
- Perform holistic consistency review and manifest reconciliation.

## Authority status
Hermes runtime/server inspection or mutation: **NOT AUTHORIZED**. Installation into Hermes, deployment, live target assessment, signing-key provisioning, and production activation are not authorized by this repository build. L3/R-12 remains **OPEN**; Gate 0b **NOT PASSED**; Phase 1 **LOCKED**; Production **NOT AUTHORIZED**.

## Completion rule
This is an active development baseline, not a production-ready release. Do not mark complete until remaining implementation items, isolated tests, manifest/traceability audits, package installation checks, and separate Hermes compatibility approval are complete.
