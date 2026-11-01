# VANE Architecture

## Boundary
Hermes Agent provides runtime, sessions, tool execution, and profile loading. VANE supplies identity, policies, skills, orchestration, schemas, and governance. VANE is not a fork or replacement runtime.

## Layers
1. Identity and Master authority.
2. Authorization envelope and scope resolution.
3. Adaptive orchestration and mission/task state.
4. Web2/Web3 assessment and root-cause tracing.
5. Evidence, findings, provenance, integrity, and lifecycle.
6. Central policy decision point and enforcement points.
7. Project/case/mission/task operations.
8. Independent hybrid validation.
9. MCP capability registry and governed skills.

## Trust boundaries
Master↔VANE; orchestrator↔workers; VANE↔Hermes tools; target↔observation channel; evidence producer↔store; signer↔verifier; internal ledger↔external anchor.

## Invariants
- No consequential action without valid authorization.
- Discovery, redirects, DNS, certificates, and links do not grant scope.
- Blocked observation is not proof of absence.
- Task completion does not imply assessment closure.
- Evidence state and finding state are distinct.
- Signing and verification authority are separated.
- Unclear ownership or preservation status blocks automatic destructive lifecycle action.

Recorded decisions and unresolved items are in master-decisions.md. L3/R-12 remains open and is not represented as implemented.
