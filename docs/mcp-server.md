# VANE MCP Server

VANE ships a local stdio MCP server for deterministic governance utilities. It exposes:
- `vane_status`: reports version and safe capability flags.
- `vane_scope_check`: checks scope coverage only; it does not grant execution authority.
- `vane_verify_mission_approval`: verifies an Ed25519 approval bound to an authorization envelope.
- `vane_verify_action_approval`: verifies an Ed25519 approval bound to one exact asset and method.
- `vane_plan_web2`: classifies supplied assets and creates passive review work items; it performs no requests.
- `vane_plan_web3`: creates read-only smart-contract review tracks for an explicitly scoped address.
- `vane_validate_finding`: validates a finding against supplied evidence.
- `vane_validate_mission_closure`: checks evidence completeness, blockers, references, and mission state.
- `vane_plan_recovery`: recommends a bounded recovery action.
- `vane_lifecycle_decision`: recommends retention/preservation action without deleting data.
- `vane_validate_evidence`: validates evidence record fields and digest shape.
- `vane_verify_event_chain`: verifies a supplied event chain.
- `vane_verify_project_integrity`: verifies the local SQLite event chain and current domain records for a project.

It does not expose live scanners, exploit execution, credential attacks, transaction submission, private-key operations, or target mutation.

## Install
Install the optional MCP extra into the VANE profile's virtual environment:

```bash
python -m pip install -e '.[mcp,crypto]'
```

Hermes connects to the local stdio server using the `mcp_servers.vane_engine` entry in the profile's `config.yaml`. The server is local to that profile. After changing MCP configuration, use `/reload-mcp` or restart the profile session and verify the discovered tools.

## Project and mission operations

The local server also exposes durable project/mission workflow tools: create project/mission, retrieve/list missions, submit for approval, verify and authorize a mission, start, attach evidence, add/clear blockers, request independent review, complete, and close with signed Master approval. Inventory tools persist assets and list assets/evidence/findings; finding tools persist drafts or evidence-validated findings.

These tools operate on the profile-local SQLite database. They do not spawn workers or perform target requests. Project/mission creation and evidence/finding record writes are local state changes; target-facing actions remain subject to mission approval, exact scope, method allowlists, and separate high-risk action approval.

## Approval boundary
The MCP server performs deterministic validation and planning only. Approval verification fails closed until a valid public-only keyring is configured. `vane_scope_check` reports scope coverage, not permission to execute. Its presence does not authorize an assessment. Every assessment action still requires an active envelope, explicit method allowlist, and any additional action-bound approval. The server receives only public verification keys; private signing authority remains external. Mission approval must be verified separately from any high-risk action approval. Neither verification tool grants execution permission by itself.
