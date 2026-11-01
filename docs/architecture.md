# VANE Architecture

## System identity and runtime boundary
VANE is an advanced Red Team Orchestrator and Intelligence Entity for authorized Web2, Web3, and hybrid security assessments. Hermes Agent is the native runtime foundation. VANE is one governed Hermes profile and does not replace, fork, or compete with Hermes.

Master is the human authority principal who interacts directly with VANE through Telegram. Master is not an agent, profile, or runtime. VANE is the primary orchestrator; it interprets Master's authority, coordinates work, and dispatches bounded specialists. Hermes owns the runtime, gateway/Telegram integration, sessions, profile loading, and tool execution.

The Python engine is a supporting domain capability layer exposed through governed MCP tools. It is not a second agent runtime or an alternate session manager.

## Seven logical domains
1. **D1 — Authority & Governance:** human Master authority, effective authority, delegation, approvals, policy, emergency suspension, and authority continuity.
2. **D2 — Decision & Arbitration:** decision lifecycle, Decision Ledger, conflicts, appeals, reversals, and cross-domain arbitration.
3. **D3 — Evidence & Intelligence:** discovery intelligence, evidence provenance and lifecycle, evidence fusion, hypotheses, uncertainty, and validation inputs.
4. **D4 — Mission & Workflow:** mission lifecycle, adaptive hybrid planning, specialist orchestration, investigation depth, resume, and mission adaptation.
5. **D5 — Data & State Management:** data identity, ownership, versioning, consistency, lifecycle, recovery, and reconciliation.
6. **D6 — Security & Validation:** identity, access, secrets, central enforcement, signing/verifier separation, security controls, and independent validation.
7. **D7 — Project & Case Operations:** project/case identity, ownership, workspace, reporting, closure, and retention.

These are logical responsibility domains, not a requirement to create seven separate agents or services. Central governance defines authoritative cross-domain policy; each domain remains accountable for its own operations and state transitions.

## Layers and implementation mapping
1. Human authority principal and protected VANE identity.
2. Authorization envelope, scope resolution, and effective-authority calculation.
3. Central security enforcement, approval binding, and capability mediation.
4. Adaptive mission orchestration and explicit state machine.
5. Web2/Web3 planning, asset mapping, evidence-aware dependency graph, and root-cause analysis.
6. Evidence provenance, integrity, storage, lifecycle, and intelligence correlation.
7. Finding governance, Decision Ledger, and project/case operations.
8. Specialist registry, durable worker delegation, reporting/remediation governance, and independent hybrid validation.
9. MCP capability registry and governed Hermes skills.
10. Hermes profile/runtime boundary and external signing service.

## Python package map
- `core`: orchestration and mission lifecycle.
- `decisions`: append-only Central Decision Ledger snapshots and governed state transitions.
- `security`: authorization, policy decisions, approval verification, and enforcement.
- `assessment`: Web2/Web3 planning, asset mapping, dependency graph, and root-cause support.
- `evidence`: integrity, provenance, and evidence handling.
- `findings`: finding governance, reporting, and remediation validation.
- `projects`: project registry and case operations.
- `intelligence`: supplied threat-intelligence normalization and relevance.
- `recovery`: adaptive recovery planning.
- `lifecycle`: policy-driven data lifecycle.
- `storage`: versioned SQLite domain records, repositories, and hash-linked events.
- `workers`: specialist catalog, typed contracts, and bounded delegation lifecycle.
- `validation`: independent checks and JSON Schema validation.
- `mcp`: local stdio workflow server and capability registry.
- `crypto`: public-only Ed25519 approval verifier/keyring.
- `integrations/hermes`: inert runtime boundary adapter.

## Trust boundaries
Master↔VANE; VANE↔specialist; VANE↔Hermes host; policy engine↔capability adapter; target↔observation channel; evidence producer↔store; signer↔verifier; local event store↔external anchor.

## Invariants
- Master is the ultimate human authority; VANE cannot self-approve or expand scope.
- Every mission requires a signed Ed25519 approval bound to its authorization envelope; high-risk methods require a second approval bound to the exact locator/method.
- Asset and method permissions are both explicit.
- Discovery, redirects, DNS, certificates, links, and dependency edges do not grant scope.
- Out-of-scope assets remain uninspected and are recorded as such.
- Blocked observation is not proof of absence.
- Task completion does not imply assessment closure.
- Evidence state and finding state are distinct.
- Specialists cannot exceed delegated asset/method constraints.
- Evidence is rechecked against stored signed authorization at observation time; mission closure requires independent validation and a separate signed Master approval.
- Signing and verification authority are separated.
- Unclear ownership or preservation status blocks automatic destructive lifecycle action.
- Runtime and production activation require separate explicit approval.

L3/R-12 and external-anchor design remain open and are not represented as implemented. Hermes runtime compatibility and Telegram integration are not verified by repository-only checks.
