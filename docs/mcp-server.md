# VANE MCP Server

VANE ships a local stdio MCP server for local governance and workflow operations. It exposes:
- `vane_status`: reports version and safe capability flags.
- `vane_scope_check`: checks scope coverage only; it does not grant execution authority.
- `vane_verify_mission_approval`: verifies an Ed25519 approval bound to an authorization envelope.
- `vane_verify_action_approval`: verifies an Ed25519 approval bound to one exact asset and method.
- `vane_verify_closure_approval`: verifies a Master approval bound to a completed mission snapshot.
- `vane_plan_web2`: classifies supplied assets and creates passive review work items; it performs no requests.
- `vane_plan_web3`: creates read-only smart-contract review tracks for an explicitly scoped address.
- `vane_validate_finding`: validates a finding against supplied evidence.
- `vane_validate_mission_closure`: checks evidence completeness, blockers, references, and mission state.
- `vane_plan_recovery`: recommends a bounded recovery action.
- `vane_lifecycle_decision`: recommends retention/preservation action without deleting data.
- `vane_validate_evidence`: validates evidence record fields and digest shape.
- `vane_verify_event_chain`: verifies a supplied event chain.
- `vane_verify_project_integrity`: verifies the local SQLite event chain and current domain records for a project.
- `vane_create_decision`, `vane_get_decision`, and `vane_list_decisions`: create and inspect immutable decision snapshots in the Central Decision Ledger.
- `vane_transition_decision`: append an allowed decision-state transition with authority references, evidence references, optimistic revision checking, and event-head compare-and-swap.
- `vane_arbitrate_claims`: compare competing claims through provenance, integrity, independence, reproducibility, freshness, relevance, and hard scope/policy/authority gates. It uses strict Pareto dominance, not numeric weighted scores or majority voting; ties and incomparable evidence remain UNRESOLVED.
- `vane_get_decision_relationships`: rebuild a bounded project-scoped relationship view from the authoritative ledger, including dependencies, supersession, and shared evidence. The projection is disposable and is not persisted as an authority source.
- `vane_evaluate_knowledge_reuse`: evaluate classification, provenance, ownership, quality, reuse authorization, sanitization, expiry/revocation, and target applicability before cross-project reuse. Allowed results are contextual leads only, never target-specific evidence or authorization.
- `vane_delegate_worker_task`: persist a bounded specialist assignment after verifying the parent mission's signed authorization, task deadline, finite asset allowlist, method subset, and specialist profile. Returns a structured handoff contract for the primary Hermes profile; it does not spawn a session.
- `vane_complete_worker_task`: validate and persist a worker result against task identity, asset/method confinement, and the specialist's typed output contract.
- `vane_revoke_worker_task`: revoke an outstanding delegated assignment.
- `vane_list_worker_tasks`: list persisted assignments and their lifecycle history for one project.

It does not expose live scanners, exploit execution, credential attacks, transaction submission, private-key operations, or target mutation.

## Install
Install the optional MCP extra into the VANE profile's virtual environment:

```bash
python -m pip install -e '.[mcp,crypto]'
```

Hermes connects to the local stdio server using the `mcp_servers.vane_engine` entry in the profile's `config.yaml`. The server is local to that profile. After changing MCP configuration, use `/reload-mcp` or restart the profile session and verify the discovered tools.

## Project and mission operations

The local server also exposes a Central Decision Ledger. New decisions begin as UNRESOLVED; permitted transitions are appended as complete snapshots to the central ledger event chain. The event chain is the authoritative history, with explicit actor, authority reference, trigger, rationale, evidence/dependency references, policy version, and revision. Dependencies must resolve to an existing decision in the same project and cannot point to a superseded decision. Supersession must reference an existing current decision revision; a decision with VALID or UNRESOLVED dependents cannot be superseded until those dependents are revalidated or suspended. Stale revisions and stale event-chain heads are rejected. This is a ledger foundation, not yet the complete blueprint arbitration, appeals, reversals, continuity, or reconciliation system.

The local server also exposes durable project/mission workflow tools: create/list projects, create mission, retrieve/list missions, submit for approval, verify and authorize a mission, start, attach evidence, add/clear blockers, request independent review, complete, and close with signed Master approval. Inventory tools persist assets and list assets/evidence/findings; finding tools persist drafts or evidence-validated findings.

These tools operate on the profile-local SQLite database. Worker tools create durable handoff contracts for the primary VANE Hermes profile; the operator-managed Hermes runtime remains responsible for actual worker-session spawning. The MCP server does not spawn workers or perform target requests. Project/mission creation and evidence/finding record writes are local state changes; target-facing actions remain subject to mission approval, exact scope, method allowlists, and separate high-risk action approval.

## Approval boundary
The MCP server performs local state management, deterministic validation/planning, and integrity verification. It does not perform target requests, spawn worker sessions, or submit transactions. Approval verification fails closed until a valid public-only keyring is configured. `vane_scope_check` reports scope coverage, not permission to execute. Its presence does not authorize an assessment. Every assessment action still requires an active envelope, explicit method allowlist, and any additional action-bound approval. The server receives only public verification keys; private signing authority remains external. Mission approval must be verified separately from any high-risk action approval. Neither verification tool grants execution permission by itself.
