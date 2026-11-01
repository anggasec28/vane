# Build Status

Repository: https://github.com/anggasec28/vane  
Architecture: Hybrid modular Python engine + VANE profile + Hermes runtime boundary.  
Package version: 0.2.0 development baseline.

## Current repository inventory
- 173 paths registered in `FILE-MANIFEST.json` (unique manifest entries).
- 13 Hermes skills with valid frontmatter and descriptions within the documented length limit.
- 47 MCP tools defined in the server and exactly matched by the profile tool allowlist.
- 10 JSON configuration/schema documents parsed successfully during structural checks.
- A GitHub Actions workflow is configured for push and pull-request CI; test execution/results have not yet been verified.

## Source implemented
- Python package metadata, CLI, domain models, and typed domain exceptions.
- Authorization envelope, exact asset/method scope checks, signed mission approval, separate action-bound approval for high-risk methods, observation-time approval verification and signed authorization revalidation on resume/delegation, public-only Ed25519 verification, and central policy enforcement.
- Mission lifecycle with evidence-gated completion and orchestration facade.
- Web2/Web3 planning, asset disposition, dependency graph, and authorization envelope review.
- Evidence record validation, SHA-256 helpers, canonical provenance, and event-chain verification.
- Finding validation linked to usable evidence.
- Adaptive recovery planner and hybrid lifecycle policy.
- Project registry, typed SQLite repositories for projects/authorization envelopes/missions/evidence/findings/assets/approvals/worker tasks, versioned domain records, atomic hash-linked audit events, and current-row integrity verification.
- Explicit engine bootstrap with profile-local SQLite and public-only Ed25519 verifier.
- Bounded worker delegation lifecycle, strict result validation, durable task-contract and assignment-state persistence, restore-on-demand for delegated assignments, and completion/revocation audit history. Hermes worker-session spawning remains outside this repository runtime boundary.
- One VANE Master profile and eight specialist role contracts with a central registry, explicit input/output contracts, allowed/prohibited activities, handoff ownership, and stop conditions. These are repository-side definitions; Hermes profile loading is not yet verified.
- Evidence-aware dependency graph primitives with bounded traversal, evidence-link checks, and explicit separation between graph relationships and authorization scope.
- Deterministic report bundle assembly linking findings to evidence, preserving limitations and blockers, with an engine-level mission report facade and cross-mission evidence rejection.
- Remediation action contracts with finding-state, dependency, priority, and verification-evidence checks, including whole-plan cycle detection and engine-level plan validation.
- Threat-intelligence record normalization, source provenance, expiry handling, confidence-weighted relevance scoring, and explicit distinction between relevance and exploitability.
- Case work-item and timeline contracts with ownership, due-date, dependency-cycle, and escalation-level validation, now persisted in the project event store. Read-only SLA evaluation identifies due-soon, overdue, blocked, and complete work without auto-changing state.
- Durable persistence for remediation actions, supplied threat-intelligence records, and generated report bundles through a typed governance repository. Verified remediation now requires existing, usable evidence; the internal global-intelligence ledger is excluded from user project listings.
- JSON Schema enforcement on typed writes for project, authorization, approval, mission, asset, evidence, finding, and worker-task records, plus repository-wide schema meta-validation.
- Auditable lifecycle review records are persisted through the governance repository and exposed through two MCP tools.
- Engine-level report assembly and remediation-plan validation, plus MCP tools for specialist listing, mission reports, remediation, case operations, and supplied threat-intelligence ingestion.
- Expanded tests for graph scope boundaries, threat-intelligence time validation, case/remediation dependency cycles, report evidence binding, specialist registry, and worker assignment restoration.
- External Ed25519 signing contract, public-only approval verifier/keyring, and inert Hermes adapter.
- Local stdio MCP server exposing project/mission lifecycle, asset/evidence/finding persistence, approval verification, planning, and integrity utilities; no live target execution.
- JSON schemas and initial unit tests, including skill metadata, approval signatures, scoped planners, and SQLite event integrity.

## Remaining implementation and verification
- Add forward SQLite schema migrations; forward-only transactional SQLite migrations are implemented through schema version 2. Durable worker assignment/completion state is now persisted, but concurrent worker lifecycle and crash-recovery behavior still require isolated validation.
- Add external anchoring and trusted-head publication for tamper evidence; L3/R-12 remains unimplemented.
- Extend schema-to-model coverage to case, remediation, threat-intelligence, report, worker-assignment, and event records; current enforcement covers the eight core typed record families.
- Verify Hermes profile installation and MCP discovery on the target Hermes runtime version; no target runtime has been inspected or changed.
- Add Hermes worker-session spawning and a separately hosted independent verifier workflow through the operator's Hermes agent; VANE repository role contracts are now present.
- Continue expanding test coverage for schema-to-model mappings, lifecycle failure recovery, and all governance edge cases; complete packaging/security review and release artifacts.
- Complete case SLA/escalation automation and map every Master decision and historical requirement to code-level acceptance tests.
- Finish end-to-end consistency review, compare the manifest against the live Git tree, and resolve remaining acceptance-test gaps.

## Authority status
Hermes runtime/server inspection or mutation: **NOT AUTHORIZED**. Installation into Hermes, deployment, live target assessment, signing-key provisioning, and production activation are not authorized by this repository build. L3/R-12 remains **OPEN**; Gate 0b **NOT PASSED**; Phase 1 **LOCKED**; Production **NOT AUTHORIZED**.

## Completion rule
This is an active development baseline, not a production-ready release. Do not mark complete until remaining implementation items, isolated tests, manifest/traceability audits, package installation checks, and separate Hermes compatibility approval are complete.
