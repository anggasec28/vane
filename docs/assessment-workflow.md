# Assessment Workflow

## Purpose
This document defines the operational contract from a Master request to a validated report. It describes the intended workflow and distinguishes planning from execution.

## Example intake
For a request such as `Assess example.com`, VANE creates a project/mission draft and asks for the missing authorization facts. The domain string is an objective hint, not proof of ownership or permission.

Before target-facing work, the Master must provide a signed, time-bounded authorization envelope that binds:
- project and authorized principal;
- exact hostname/domain scope and subdomain policy;
- permitted and prohibited methods;
- validity window and request/concurrency limits;
- excluded systems, data handling, and stop conditions;
- approval identity and signature.

## Eleven phases
1. Mission comprehension: resolve objective, ownership, exact scope, constraints, and success criteria.
2. Strategic intelligence: assess permitted context, source provenance, freshness, and confidence.
3. Ecosystem discovery: inventory only assets covered by the authorization; discoveries do not inherit authorization.
4. Adversarial modeling: map trust boundaries, attack surfaces, hypotheses, and evidence-backed dependencies.
5. Adaptive investigation planning: prioritize evidence objectives, methods, dependencies, and stop conditions.
6. Specialist orchestration: dispatch finite tasks with asset/method allowlists and deadlines.
7. Deep technical investigation: use reviewed adapters and per-action enforcement; preserve provenance.
8. Exploitability and impact: perform only separately authorized high-risk validation.
9. Evidence fusion and independent validation: correlate, challenge, and independently verify claims.
10. Strategic reassessment: adapt priorities without expanding the authorization envelope.
11. Reporting and knowledge extraction: produce evidence-linked findings, limitations, remediation, and closure recommendation.

The order is adaptive. Evidence may send the mission back to planning or investigation. Scope changes always require renewed Master authorization.

## Execution contract
Each phase must expose: phase ID, objective, prerequisites, input references, output references, execution status, blockers, and acceptance criteria. Use explicit frontier statuses: NOT_ENUMERATED, ENUMERATED, INSTRUMENTED, TESTED, EXHAUSTED, BLOCKED, NOT_APPLICABLE, NOT_INSPECTED, UNKNOWN.

A task is not a phase acceptance. A tool response is not a validated finding. A report is not closure. Closure requires evidence objectives, independent validation, and separate signed Master approval.

## Current implementation boundary
`vane.assessment.workflow.build_assessment_workflow` creates a deterministic eleven-phase plan from a valid authorization envelope and explicitly IN_SCOPE assets. The `vane_build_assessment_plan` MCP tool exposes that plan. Both are planning-only: they do not execute tools, issue network requests, spawn Hermes sessions, or change target state.

Live adapters, persistent phase execution state, Hermes worker spawning, and end-to-end runtime validation remain separate implementation work.
