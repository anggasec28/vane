# Build Status

Repository: https://github.com/anggasec28/vane  
Architecture: Hybrid modular Python engine + VANE profile + Hermes runtime boundary.  
Package version: 0.2.0 development baseline.

## Current repository inventory
- 150 paths registered in `FILE-MANIFEST.json` (unique manifest entries).
- 13 Hermes skills with valid frontmatter and descriptions within the documented length limit.
- 33 MCP tools defined in the server and exactly matched by the profile tool allowlist.
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
- Bounded worker delegation lifecycle, strict result validation, durable task-contract persistence, evidence-led mission workflow, independent validation, and signed Master closure gate. Worker session spawning and durable completion-state storage remain open.
- External Ed25519 signing contract, public-only approval verifier/keyring, and inert Hermes adapter.
- Local stdio MCP server exposing project/mission lifecycle, asset/evidence/finding persistence, approval verification, planning, and integrity utilities; no live target execution.
- JSON schemas and initial unit tests, including skill metadata, approval signatures, scoped planners, and SQLite event integrity.

## Remaining implementation and verification
- Add forward SQLite schema migrations and durable worker assignment/completion-state storage; current domain-record persistence and schema version 1 are implemented.
- Add external anchoring and trusted-head publication for tamper evidence; L3/R-12 remains unimplemented.
- Complete schema-to-model validation coverage and verify all serialized record types against their schemas.
- Verify Hermes profile installation and MCP discovery on the target Hermes runtime version; no target runtime has been inspected or changed.
- Add Hermes worker-session spawning and a separately hosted independent verifier workflow.
- Execute and review CI results, expand test coverage, and complete packaging/security review and release artifacts.
- Map every Master decision and historical requirement to code-level acceptance tests.
- Finish end-to-end consistency review, compare the manifest against the live Git tree, and resolve remaining acceptance-test gaps.

## Authority status
Hermes runtime/server inspection or mutation: **NOT AUTHORIZED**. Installation into Hermes, deployment, live target assessment, signing-key provisioning, and production activation are not authorized by this repository build. L3/R-12 remains **OPEN**; Gate 0b **NOT PASSED**; Phase 1 **LOCKED**; Production **NOT AUTHORIZED**.

## Completion rule
This is an active development baseline, not a production-ready release. Do not mark complete until remaining implementation items, isolated tests, manifest/traceability audits, package installation checks, and separate Hermes compatibility approval are complete.
