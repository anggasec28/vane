# Build Status

Repository: https://github.com/anggasec28/vane  
Architecture: One primary VANE Hermes profile + seven logical domains + supporting modular Python engine + Hermes native runtime boundary.  
Package version: 0.2.0 development baseline.

## Current repository inventory
- 205 paths registered in `FILE-MANIFEST.json` (unique manifest entries).
- 13 Hermes skills with valid frontmatter and descriptions within the documented length limit.
- 58 MCP tools defined in the server and exactly matched by the profile tool allowlist.
- 18 JSON configuration/schema documents are present; schema meta-validation passed in CI.
- GitHub Actions run #478 on commit `75ec83a` completed successfully: compileall passed, **110 tests passed**, and the CLI version/config check passed. The latest branch-head workflow #484 on commit `109d9d1` completed successfully: compileall passed, **118 tests passed**, and CLI version/config validation passed.

## Assessment workflow planner
- Added an eleven-phase adaptive assessment plan builder and `vane_build_assessment_plan` MCP tool. It requires a current approved authorization envelope and explicitly IN_SCOPE assets, rejects out-of-scope assets, and labels every phase PLANNED. The planner performs no network requests, invokes no scanner, and does not spawn Hermes sessions.

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
- Bounded worker delegation lifecycle, strict task/result validation, durable task-contract and assignment-state persistence, restore-on-demand, and completion/revocation audit history. Four MCP tools now expose specialist handoff, completion, revocation, and listing; they return structured handoff contracts while actual Hermes worker-session spawning remains outside this repository runtime boundary.
- One primary VANE Hermes profile with eight subordinate specialist role contracts. Master is the human authority principal, not an agent/profile/runtime. The specialist registry defines explicit input/output contracts, allowed/prohibited activities, handoff ownership, and stop conditions; Hermes profile loading is not yet verified.
- Evidence-aware dependency graph primitives with bounded traversal, evidence-link checks, and explicit separation between graph relationships and authorization scope.
- Deterministic report bundle assembly linking findings to evidence, preserving limitations and blockers, with an engine-level mission report facade and cross-mission evidence rejection.
- Remediation action contracts with finding-state, dependency, priority, and verification-evidence checks, including whole-plan cycle detection and engine-level plan validation.
- Threat-intelligence record normalization, source provenance, expiry handling, confidence-weighted relevance scoring, and explicit distinction between relevance and exploitability.
- Case work-item and timeline contracts with ownership, due-date, dependency-cycle, and escalation-level validation, now persisted in the project event store.
- Durable persistence for remediation actions, supplied threat-intelligence records, and generated report bundles through a typed governance repository. Verified remediation now requires existing, usable evidence; the internal global-intelligence ledger is excluded from user project listings.
- JSON Schema enforcement on all 15 persisted domain record types plus every hash-linked event record; canonical schemas now cover case operations, threat intelligence, remediation, report bundles, worker assignments, and lifecycle reviews as well as core records.
- Auditable lifecycle review records are persisted through the governance repository and exposed through two MCP tools.
- Append-only Central Decision Ledger foundation: immutable full decision snapshots in the central ledger event chain, explicit decision status transitions, authority/evidence/dependency references, revision checks, event-head compare-and-swap for concurrent append safety, and JSON Schema validation on every append. Exposed through the VANE engine facade and four allowlisted MCP tools.
- Conservative hierarchical evidence-weighted arbitration: six evidence-quality dimensions, strict Pareto dominance without arbitrary weights, hard scope/policy/authority gates, and explicit UNRESOLVED outcomes for ties, incomparable evidence, or material contradictions. Exposed through an allowlisted MCP tool.
- Rebuildable project-scoped Decision Relationship Index for dependency, supersession, and shared-evidence links; retrieval is bounded and derived from the authoritative ledger, not persisted as an authority source.
- Master-only Emergency Suspension Authority: signed operation-bound SUSPEND/RELEASE, configured Master principal and key-ID allowlist, revision/CAS protection, full event-chain and historical signature verification, and fail-closed central enforcement. Hermes bootstrap requires this control by default; missing identity/key configuration or unverifiable state denies actions.
- Governed cross-mission knowledge reuse gate: only PUBLIC or reviewed SANITIZED_GENERALIZED INTERNAL material can be reused after provenance, ownership, quality, authorization, applicability, expiry, and revocation checks. Raw, confidential, secret, evidence-class, unknown, or cross-project restricted data is denied. Allowed knowledge is explicitly a lead, never target-specific evidence or authorization. Exposed through one allowlisted MCP evaluation tool; full sanitization pipeline remains open.
- Engine-level report assembly and remediation-plan validation, plus MCP tools for specialist listing, mission reports, remediation, case operations, and supplied threat-intelligence ingestion.
- Expanded tests for graph scope boundaries, threat-intelligence time validation, case/remediation dependency cycles, report evidence binding, specialist registry, and worker assignment restoration.
- External Ed25519 signing contract, public-only approval verifier/keyring, and inert Hermes adapter.
- Local stdio MCP server exposing project/mission lifecycle, Decision Ledger operations, asset/evidence/finding persistence, approval verification, planning, and integrity utilities; no live target execution.
- JSON schemas and initial unit tests, including skill metadata, approval signatures, scoped planners, and SQLite event integrity.

## Remaining implementation and verification
- Add forward SQLite schema migrations; forward-only transactional SQLite migrations are implemented through schema version 2. Durable worker assignment/completion state is now persisted, but concurrent worker lifecycle and crash-recovery behavior still require isolated validation.
- Add external anchoring and trusted-head publication for tamper evidence; L3/R-12 remains unimplemented.
- Expand schema round-trip and adversarial tests across all 15 persisted record types, including migration/restart compatibility and invalid-record rejection.
- Verify Hermes profile installation and MCP discovery on the target Hermes runtime version; no target runtime has been inspected or changed.
- Hermes worker-session spawning and separately hosted independent-verifier orchestration remain host-runtime responsibilities; the repository now supplies typed, bounded handoff/result contracts.
- Continue expanding test coverage for schema-to-model mappings, lifecycle failure recovery, and all governance edge cases; complete packaging/security review and release artifacts.
- Add and execute concurrency/failure-injection tests for Decision Ledger append races, stale revisions, replay, and recovery.
- Align all seven logical domains and cross-domain dependency/acceptance criteria in a source-decision-to-code traceability matrix.
- Adjudicate CF-01 through CF-07 in `docs/architecture-conflicts.md` without silently changing recorded Master choices.
- Complete case SLA/escalation automation and map every Master decision and historical requirement to code-level acceptance tests.
- Complete context-sensitive Decision Ledger arbitration, appeals/reversals, durable projections, authority continuity, and causal reconciliation.
- Bind the canonical Master principal to the actual operator-owned Hermes Telegram identity and provision the external Master signing key through the separate signing authority; until then the bootstrap emergency-control gate intentionally fails closed.
- Build the full sanitization/generalization pipeline, independent reviewer workflow, and governed cross-mission knowledge artifact lifecycle.
- Finish end-to-end consistency review, compare the manifest against the live Git tree, and resolve remaining acceptance-test gaps.

## Architecture identity correction
The obsolete separate `profiles/vane-master.yaml` has been removed. Master is represented as the human authority principal who interacts directly with the single VANE orchestrator through Telegram. `profiles/registry.yaml` now registers VANE as the orchestrator and lists subordinate specialists only. This repository change does not configure or verify the live Hermes Telegram gateway.

## Authority status
Hermes runtime/server inspection or mutation: **NOT AUTHORIZED**. Installation into Hermes, deployment, live target assessment, signing-key provisioning, and production activation are not authorized by this repository build. L3/R-12 remains **OPEN**; Gate 0b **NOT PASSED**; Phase 1 **LOCKED**; Production **NOT AUTHORIZED**.

## Completion rule
This is an active development baseline, not a production-ready release. Do not mark complete until remaining implementation items, isolated tests, manifest/traceability audits, package installation checks, and separate Hermes compatibility approval are complete.
