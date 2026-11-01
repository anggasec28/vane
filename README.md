# VANE

**VANE is an advanced Red Team Orchestrator and Intelligence Entity for authorized Web2, Web3, and hybrid security assessments.** Hermes Agent is VANE's native runtime foundation. VANE operates as one governed Hermes profile, not as a second competing agent runtime.

Master is the human operator who interacts directly with VANE through Telegram. Master is the ultimate authority for scope, approvals, protected identity, and final decisions. Master is not a separate agent, profile, or runtime. VANE is the primary orchestrator and coordinates bounded specialists under Master's effective authority.

## Architecture at a glance
- **Master:** human authority principal and direct Telegram operator.
- **VANE:** the single primary Hermes profile, intelligence entity, and assessment orchestrator.
- **Specialists/workers:** subordinate roles receiving finite, task-specific delegation from VANE.
- **Hermes Agent:** native runtime providing profile execution, sessions, gateway/Telegram integration, and tool execution.
- **VANE engine:** supporting Python domain capabilities, governance, persistence, evidence, validation, and MCP tools. It is not a competing agent runtime.

## What is in this repository
- Protected VANE identity and human Master authority contract: `SOUL.md`.
- Python 3.11+ supporting engine under `vane/`.
- Central authorization, method allowlisting, signed mission approvals, high-risk action approvals, and policy enforcement.
- Web2/Web3 assessment planning, asset disposition, dependency mapping, and in-scope root-cause analysis.
- Evidence provenance, SHA-256 integrity, evidence-gated mission closure, and finding governance.
- Adaptive recovery, data lifecycle policy, durable project/authorization/mission/asset/evidence/finding/approval records, and SQLite event integrity.
- Eight subordinate specialist role contracts with typed registry/catalog, bounded worker delegation, durable assignment lifecycle, independent validation, and MCP capability registry.
- Evidence-linked reporting, remediation actions, supplied threat-intelligence ingestion, case work items/timeline, and JSON Schema validation.
- External Ed25519 signing contract and public-only approval verification; private-key custody remains outside the engine.
- Hermes profile configuration, skills, policies, schemas, templates, and tests.

## Quick start
```bash
git clone https://github.com/anggasec28/vane.git
cd vane
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev,mcp,crypto]'
pytest
vane version
```

Python 3.11 or newer is required. JSON Schema validation uses `jsonschema` as a runtime dependency. Development tools are installed with the `dev` extra.

## Install as a Hermes profile

The repository is structured as a Hermes profile distribution. On a Hermes machine, install it with:

```bash
hermes profile install github.com/anggasec28/vane --alias
hermes -p vane setup
```

Then install the Python engine in the new profile's environment. Follow [the complete Hermes installation guide](docs/hermes-installation.md) for exact steps and boundaries. The distribution installer does not install Python dependencies or activate the engine automatically.

## Architecture
- **Hermes Agent:** native runtime, profile execution, sessions, Telegram/gateway integration, and tool execution.
- **VANE primary profile:** identity, mission, orchestration, authority interpretation, skills, and operating contract.
- **Seven logical domains:** Authority & Governance; Decision & Arbitration; Evidence & Intelligence; Mission & Workflow; Data & State Management; Security & Validation; Project & Case Operations.
- **VANE Python engine:** supporting domain services, policy enforcement, persistence, evidence, findings, recovery, and validation.
- **Specialists:** subordinate bounded roles; they do not become separate competing orchestrators.
- **MCP/tools:** local VANE workflow tools are explicitly allowlisted in the profile; external MCP capabilities remain disabled by default.

See [Python engine](docs/python-engine.md), [architecture](docs/architecture.md), [security model](docs/security-model.md), [Master decisions](docs/master-decisions.md), [architecture conflicts](docs/architecture-conflicts.md), and [build status](docs/build-status.md).

## Security defaults
Default deny. Every mission requires a signed Ed25519 approval bound to its authorization envelope. High-risk methods require a second approval bound to the exact locator and method. Discovery does not grant scope. Workers inherit a strict subset of authority; unsupported high-risk worker delegation is denied. Unknown or out-of-scope assets are not inspected. Evidence is checked against the signed authorization at observation time. Mission completion requires evidence sufficiency and independent validation, then a separate signed Master closure approval. The local MCP server manages profile-local records and deterministic workflows only; it performs no target requests. External MCP capabilities remain disabled by default. No private signing key belongs in this repository or engine.

## Important boundaries
The default codebase contains the Python domain engine, durable project/mission workflow, planning, policy, evidence/finding governance, validation, and bounded adapter contracts. It does not ship an enabled live scanner, exploit runner, transaction sender, key manager, or autonomous scope expansion. The default Hermes adapter is inert and does not modify Hermes runtime state.

Cloning and installing this Python package do not install, configure, restart, or deploy Hermes. Hermes-native profile compatibility, Telegram interaction, worker-session spawning, and runtime integration still require validation by the operator's Hermes agent.

## Current authority status
Repository architecture and code work may proceed under the Master's explicit repository-work instruction. Hermes runtime/server inspection or mutation: **NOT AUTHORIZED**. Deployment: **NOT AUTHORIZED**. Live target assessment: requires a separate valid authorization envelope and enabled adapter. L3/R-12: **OPEN**. Gate 0b: **NOT PASSED**. Phase 1: **LOCKED**. Production: **NOT AUTHORIZED**.
