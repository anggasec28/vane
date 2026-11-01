# VANE Architecture

## System boundary
Hermes Agent provides runtime, sessions, profile loading, and tool execution. VANE is the agent profile and modular Python engine hosted by Hermes. VANE does not replace or fork Hermes.

## Layers
1. Protected identity and Master authority.
2. Authorization envelope and scope resolution.
3. Central security enforcement and approval binding.
4. Adaptive mission orchestration and explicit state machine.
5. Web2/Web3 planning, asset mapping, evidence-aware dependency graph, and root-cause analysis.
6. Evidence provenance, integrity, storage, and lifecycle.
7. Finding governance and project/case operations.
8. Specialist registry, durable worker delegation, reporting/remediation governance, and independent hybrid validation.
9. MCP capability registry and governed skills.
10. Hermes adapter boundary and external signing service.

## Python package map
`core` orchestration; `security` policy and authorization; `assessment` Web2/Web3 planning and evidence graph; `evidence` integrity/provenance; `findings` governance, report assembly, and remediation validation; `projects` registry and case operations; `intelligence` supplied threat-intelligence normalization; `recovery` adaptive recovery; `lifecycle` data lifecycle; `storage` versioned SQLite domain records, case/remediation/intelligence/report repositories, and hash-linked events; `workers` specialist catalog, typed contracts, and durable delegation lifecycle; `validation` independent checks and JSON Schema validation; `mcp` local stdio workflow server and capability registry; `crypto` public-only Ed25519 approval verifier/keyring; `integrations/hermes` runtime boundary.

## Trust boundaries
Master↔VANE; orchestrator↔worker; VANE↔Hermes host; policy engine↔capability adapter; target↔observation channel; evidence producer↔store; signer↔verifier; local event store↔external anchor.

## Invariants
- Every mission requires a signed Ed25519 approval bound to its authorization envelope; high-risk methods require a second approval bound to the exact locator/method.
- Asset and method permissions are both explicit.
- Discovery, redirects, DNS, certificates, links, and dependency edges do not grant scope.
- Out-of-scope assets remain uninspected and are recorded as such.
- Blocked observation is not proof of absence.
- Task completion does not imply assessment closure.
- Evidence state and finding state are distinct.
- Workers cannot exceed delegated asset/method constraints.
- Evidence is rechecked against the stored signed authorization at observation time; mission closure requires independent validation and a separate signed Master approval.
- Signing and verification authority are separated.
- Unclear ownership or preservation status blocks automatic destructive lifecycle action.
- Runtime and production activation require separate explicit approval.

L3/R-12 and external-anchor design remain open and are not represented as implemented.
