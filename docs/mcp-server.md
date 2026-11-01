# VANE MCP Server

VANE ships a local stdio MCP server for deterministic governance utilities. It exposes:
- `vane_status`: reports version and safe capability flags.
- `vane_scope_check`: checks an exact asset/method against a supplied authorization envelope.
- `vane_plan_web2`: classifies supplied assets and creates passive review work items; it performs no requests.
- `vane_plan_web3`: creates read-only smart-contract review tracks for an explicitly scoped address.
- `vane_validate_finding`: validates a finding against supplied evidence.
- `vane_validate_mission_closure`: checks evidence completeness, blockers, references, and mission state.
- `vane_plan_recovery`: recommends a bounded recovery action.
- `vane_lifecycle_decision`: recommends retention/preservation action without deleting data.
- `vane_validate_evidence`: validates evidence record fields and digest shape.
- `vane_verify_event_chain`: verifies a supplied event chain.

It does not expose live scanners, exploit execution, credential attacks, transaction submission, private-key operations, or target mutation.

## Install
Install the optional MCP extra into the VANE profile's virtual environment:

```bash
python -m pip install -e '.[mcp]'
```

Hermes connects to the local stdio server using the `mcp_servers.vane_engine` entry in the profile's `config.yaml`. The server is local to that profile. After changing MCP configuration, use `/reload-mcp` or restart the profile session and verify the discovered tools.

## Approval boundary
The MCP server performs deterministic validation and planning only. Its presence does not authorize an assessment. Every assessment action still requires an active envelope, explicit method allowlist, and any additional action-bound approval. The server currently does not accept signing authority or store credentials.
