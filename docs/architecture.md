# VANE Architecture

## System boundary
Hermes Agent provides runtime, sessions, profile loading, and tool execution. VANE is the agent profile and modular Python engine hosted by Hermes. VANE does not replace or fork Hermes.

## Layers
1. Protected identity and Master authority.
2. Authorization envelope and scope resolution.
3. Central security enforcement and approval binding.
4. Adaptive mission orchestration and explicit state machine.
5. Web2/Web3 planning, asset mapping, and root-cause dependency analysis.
6. Evidence provenance, integrity, storage, and lifecycle.
7. Finding governance and project/case operations.
8. Worker delegation and independent hybrid validation.
9. MCP capability registry and governed skills.
10. Hermes adapter boundary and external signing service.

## Python package map
`core` orchestration; `security` policy and authorization; `assessment` Web2/Web3 planning; `evidence` integrity/provenance; `findings` governance; `projects` registry; `recovery` adaptive recovery; `lifecycle` data lifecycle; `storage` SQLite persistence; `workers` delegation contracts; `validation` independent checks; `mcp` capability registry; `crypto` signer interface; `integrations/hermes` runtime boundary.

## Trust boundaries
Master↔VANE; orchestrator↔worker; VANE↔Hermes host; policy engine↔capability adapter; target↔observation channel; evidence producer↔store; signer↔verifier; local event store↔external anchor.

## Invariants
- No consequential action without a valid authorization envelope.
- Asset and method permissions are both explicit.
- Discovery, redirects, DNS, certificates, links, and dependency edges do not grant scope.
- Out-of-scope assets remain uninspected and are recorded as such.
- Blocked observation is not proof of absence.
- Task completion does not imply assessment closure.
- Evidence state and finding state are distinct.
- Workers cannot exceed delegated asset/method constraints.
- Signing and verification authority are separated.
- Unclear ownership or preservation status blocks automatic destructive lifecycle action.
- Runtime and production activation require separate explicit approval.

L3/R-12 and external-anchor design remain open and are not represented as implemented.
