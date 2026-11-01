# VANE Requirements and Seven-Domain Traceability

This matrix maps the seven logical domains in **05 — VANE Final Architecture Blueprint** to repository artifacts. A package mapping identifies a candidate implementation location; it does not prove that the complete domain responsibility is implemented or accepted.

## Identity and authority baseline

- Master is the human authority principal who interacts directly with VANE through Telegram.
- VANE is the single primary governed Hermes profile and orchestrator.
- Hermes Agent is the native runtime and owns gateway/Telegram integration, profile execution, sessions, and tool execution.
- Specialist profiles are subordinate role contracts, not peer orchestrators.
- The Python engine provides supporting domain capabilities, not a competing agent runtime.

## Seven logical domains

| Domain | Blueprint responsibility | Repository mapping | Current implementation posture |
|---|---|---|---|
| D1 — Authority & Governance | Master authority, effective authority, delegation, approvals, policy, emergency suspension, authority continuity | `SOUL.md`, `profiles/registry.yaml`, `vane/security/`, `policies/`, `vane/core/` | PARTIAL: human authority contract, signed approvals, central policy enforcement, bounded delegation, and a Master-only signed emergency-control ledger with fail-closed enforcement are implemented; live Telegram identity binding, production key provisioning, and runtime acceptance remain unverified |
| D2 — Decision & Arbitration | Decision lifecycle, Decision Ledger, conflicts, appeals, reversals, cross-domain arbitration | `vane/decisions/ledger.py`, `vane/decisions/arbitration.py`, `vane/decisions/relationships.py`, `vane/storage/sqlite_store.py`, `vane/engine.py`, `vane/mcp/server.py`, `docs/master-decisions.md` | PARTIAL: append-only central Decision Ledger with schema enforcement, dependency/supersession integrity, strict Pareto evidence arbitration, and rebuildable project-scoped relationship retrieval are implemented; full context-sensitive arbitration, appeals/reversals, durable projections, authority continuity, and causal reconciliation remain gaps |
| D3 — Evidence & Intelligence | Discovery intelligence, evidence provenance, fusion, hypotheses, uncertainty, validation inputs | `vane/evidence/`, `vane/intelligence/`, `vane/assessment/graph.py`, `vane/validation/`, evidence skills | PARTIAL: evidence integrity/provenance and supplied threat-intelligence normalization exist; cross-source fusion, hypothesis lifecycle, confidence calibration, and independent evidence acquisition require further implementation and validation |
| D4 — Mission & Workflow | Mission lifecycle, adaptive planning, specialist orchestration, investigation depth, resume, mission adaptation | `vane/core/`, `vane/assessment/`, `vane/workers/`, `vane/recovery/`, assessment skills | PARTIAL: adaptive mission state machine, Web2/Web3 planning, bounded worker assignments, and recovery recommendations exist; Hermes session dispatch, full resume/revalidation semantics, and end-to-end adaptive workflow remain unverified |
| D5 — Data & State Management | Data identity, ownership, versioning, lifecycle, consistency, recovery, reconciliation | `vane/storage/`, `vane/lifecycle/`, `vane/recovery/`, `schemas/` | PARTIAL: SQLite repositories, schema validation, hash-linked events, migrations, and policy-driven lifecycle foundations exist; cross-domain consistency, authoritative reconciliation, corruption recovery, and lifecycle acceptance need more proof |
| D6 — Security & Validation | Identity, access, secrets, central enforcement, signing/verifier separation, security controls, independent validation | `vane/security/`, `vane/crypto/`, `vane/validation/`, `policies/` | PARTIAL: central policy enforcement, public-only Ed25519 verification, external signer contract, and deterministic validation foundations exist; signing-service deployment, key custody, meaningful independence, and failure-mode acceptance are unverified |
| D7 — Project & Case Operations | Project/case identity, ownership, workspace, reporting, closure, retention | `vane/projects/`, `vane/findings/`, `vane/storage/governance_repository.py`, project/case skills | PARTIAL: project/mission records, case work items/timeline, reporting, remediation, and lifecycle review foundations exist; workspace governance, SLA/escalation automation, complete case closure, and retention orchestration remain gaps |

Decision Ledger, arbitration, and relationship sources: `vane/decisions/ledger.py`, `vane/decisions/arbitration.py`, `vane/decisions/relationships.py`; storage CAS: `vane/storage/sqlite_store.py`; engine facade: `vane/engine.py`; schema: `schemas/decision-snapshot.schema.json`; tests: `tests/test_decision_ledger.py`, `tests/test_decision_arbitration.py`. The Decision Ledger, arbitration, and relationship-index tests have executed in GitHub Actions; run #429 passed all 84 tests, and run #430 passed after manifest registration. A VALID decision record is a governance record only; it does not replace or grant a signed mission authorization envelope or action-bound approval.

## Cross-domain requirements

| Requirement / decision | Primary artifact | Validation target | Status |
|---|---|---|---|
| VANE is the primary Hermes profile, not a competing runtime | `SOUL.md`, `config.yaml`, `README.md`, `docs/architecture.md` | Hermes profile compatibility and runtime boundary review | DOCUMENTED; runtime NOT_VERIFIED |
| Master is a human principal, not an agent/profile | `SOUL.md`, `profiles/registry.yaml`, `profiles/README.md` | Identity and authority consistency review | DOCUMENTED |
| Master interacts with VANE through Telegram | `docs/operating-model.md`, `README.md` | Operator-side Hermes gateway/profile check | NOT_VERIFIED |
| Adaptive Delegated Autonomy (ODA C) | `docs/architecture.md`, `vane/core/`, `vane/workers/` | Autonomy bounded by mission ∩ approval ∩ parent ∩ policy | PARTIAL |
| Hierarchical evidence-weighted arbitration (C) | `vane/decisions/`, `vane/evidence/`, `docs/architecture.md` | Multi-factor evidence comparison; dissent and uncertainty preserved; no majority vote | PARTIAL / GAP |
| Hybrid Decision Memory (C) | `vane/decisions/`, `vane/storage/`, `docs/architecture.md` | Authoritative ledger, bounded working memory, relationship index, rebuildable projections, provenance-aware retrieval | PARTIAL / GAP |
| Governed cross-mission knowledge (C) | `vane/intelligence/`, `vane/lifecycle/`, `docs/architecture.md` | Classification, sanitization, provenance, ownership, quality, authorization, applicability, no cross-project leakage | GAP |
| Emergency Suspension Authority (Master-only A) | `docs/architecture.md`, `profiles/registry.yaml`, `vane/security/emergency_suspension.py`, `vane/bootstrap.py` | Signed Master-only suspend/release; full history verification; fail-closed central enforcement | IMPLEMENTED FOUNDATION; Telegram identity binding/runtime NOT_VERIFIED |
| Eleven-phase adaptive workflow and frontier states | `docs/operating-model.md`, `vane/core/`, `vane/assessment/` | Phase traceability, L1-L5 depth, explicit frontier states, evidence-based exhaustion | PARTIAL / GAP |
| Capability maturity L0-L4 | `docs/build-status.md`, `docs/validation-plan.md` | UNDECLARED → DECLARED → CONFIGURED → OPERATIONAL → VERIFIED, each evidence-backed | NOT_IMPLEMENTED
| Authorization before action | authorization, enforcement, approval policy | deny-path and approval-binding scenarios | PARTIAL |
| Deep root cause within approved scope | operating model, assessment graph, root-cause module | bounded dependency tracing and causal evidence | PARTIAL |
| Adaptive hybrid workflow | operating model, orchestrator, state machine | evidence/risk/dependency-driven workflow scenarios | PARTIAL |
| Recovery C | recovery policy and planner | no-scope-expansion and deterministic recovery scenarios | PARTIAL |
| Finding Governance 56-C | finding governance docs/module/skill | lifecycle consistency and evidence binding | PARTIAL |
| Evidence Management 57-C | evidence model, evidence module, storage | provenance, integrity, access, lifecycle review | PARTIAL |
| Project & Case 58-C | project/case docs, project module, repositories | hierarchy, ownership, handoff, closure, retention | PARTIAL |
| Central enforcement 59-A | enforcement and policy modules | fail-closed and capability mediation scenarios | PARTIAL |
| Independent validation 60-C | validation module and validation plan | independence by actor, evidence, method, and infrastructure | PARTIAL |
| Data lifecycle C | lifecycle docs/policy/skill | hold, unclear ownership, preservation, exception cases | PARTIAL |
| Q-3 C | authorization and asset mapping | in-scope/out-of-scope symlink target handling | PARTIAL |
| MK-4 A | cryptographic policy and verifier | signer/verifier separation and custody review | PARTIAL |
| L3/R-12 unresolved | decision register and cryptographic trust policy | no false implementation claim | OPEN / NOT IMPLEMENTED |

Conflict and adjudication register: `docs/architecture-conflicts.md`. CF-01 through CF-07 remain OPEN; Operational Intelligence architecture remains unresolved; L3/R-12 and the listed audit dependencies retain their existing OPEN/NOT_READY states.

## Mandatory traceability rules

1. Every blueprint requirement must map to a code artifact, policy/documentation artifact, or an explicit NOT_IMPLEMENTED / NOT_VERIFIED gap.
2. Every claimed implementation must map to objective acceptance criteria and reproducible validation evidence.
3. A design statement, type definition, test plan, or passing unit test alone does not establish operational acceptance.
4. Independence must be assessed against common-mode exposure, not inferred from a separate profile name.
5. A discovered technical relationship never expands authorization scope.
6. Unresolved Master decisions and L3/R-12 requirements remain explicit and cannot be silently treated as approved or implemented.
7. Domain-level PASS requires all mandatory criteria for that domain; a strong result elsewhere cannot compensate for a failed mandatory control.

## Remaining work

- Expand each domain row into requirement-level traceability against the full blueprint and documents 00–07.
- Define objective acceptance criteria and evidence records for each mandatory requirement.
- Extend the first evidence-weighted arbitration and rebuildable relationship-retrieval slices into full hybrid decision memory; implement governed cross-mission knowledge gates, Master-only emergency suspension, and explicit frontier lifecycle/maturity tracking.
- Complete context-sensitive Decision Ledger arbitration, appeals/reversals, authoritative projections, authority continuity, dependency-health, cross-domain reconciliation, and recovery mechanisms.
- Validate meaningful independent verification and signing-service boundaries; bind the Master Telegram identity to the configured canonical principal and signing authority before enabling the emergency-control gate in Hermes.
- Complete worker orchestration handoff to the operator-owned Hermes agent without creating a second runtime.
- Complete isolated unit, integration, failure-injection, concurrency, and recovery tests.
- Obtain operator-side Hermes compatibility, profile loading, Telegram interaction, MCP discovery, and worker-session validation.
- Keep L3/R-12 OPEN until its separate requirements, implementation, and acceptance gates are satisfied.

A domain marked PARTIAL is not production-ready. Repository presence is not proof of runtime behavior.
