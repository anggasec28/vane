# VANE

**VANE is a modular security-assessment agent designed to run inside Hermes Agent.** Hermes remains the runtime; VANE supplies the identity, Python domain engine, policies, skills, orchestration, schemas, and governed capability adapters.

## What is in this repository
- Protected agent identity and Master authority contract: `SOUL.md`.
- Python 3.11+ engine under `vane/`.
- Central authorization, method allowlisting, signed mission approvals, high-risk action approvals, and policy enforcement.
- Web2/Web3 assessment planning, asset disposition, and in-scope root-cause graph.
- Evidence provenance, SHA-256 integrity, evidence-gated mission closure, and finding governance.
- Adaptive recovery, data lifecycle policy, durable project/authorization/mission/asset/evidence/finding/approval records, and SQLite event integrity.
- Eight specialist role contracts with a typed registry/catalog, bounded worker delegation, durable assignment lifecycle, independent validation, and MCP capability registry.
- Evidence-linked report assembly, durable remediation actions, supplied threat-intelligence ingestion, durable case work items/timeline, and optional JSON Schema validation.
- External Ed25519 signing contract and public-only approval verification; private-key custody remains outside the engine.
- Hermes adapter contract, skills, policies, schemas, templates, and tests.

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

Python 3.11 or newer is required. The package has no mandatory third-party runtime dependencies. Development tools are installed with the `dev` extra.

## Install as a Hermes profile

The repository is structured as a Hermes profile distribution. On a Hermes machine, install it with:

```bash
hermes profile install github.com/anggasec28/vane --alias
hermes -p vane setup
```

Then install the Python engine in the new profile's environment. Follow [the complete Hermes installation guide](docs/hermes-installation.md) for the exact steps and boundaries. The distribution installer does not install Python dependencies or activate the engine automatically.

## Architecture
- **Hermes Agent:** runtime, sessions, profile loading, tool execution.
- **VANE profile:** identity, authority, policy, skills, and operating contract.
- **VANE Python engine:** domain models, policy decision point, orchestration, evidence, findings, persistence, validation.
- **MCP/tools:** local VANE workflow tools are explicitly allowlisted in the profile; external MCP capabilities remain disabled by default.

See [Python engine](docs/python-engine.md), [architecture](docs/architecture.md), [security model](docs/security-model.md), [Master decisions](docs/master-decisions.md), and [build status](docs/build-status.md).

## Security defaults
Default deny. Every mission requires a signed Ed25519 approval bound to its authorization envelope. High-risk methods require a second approval bound to the exact locator and method. Discovery does not grant scope. Workers inherit a strict subset of authority; unsupported high-risk worker delegation is denied. Unknown or out-of-scope assets are not inspected. Evidence is checked against the signed authorization at observation time. Mission completion requires evidence sufficiency and independent validation, then a separate signed Master closure approval. The local MCP server manages profile-local records and deterministic workflows only; it performs no target requests. External MCP capabilities remain disabled by default. No private signing key belongs in this repository or engine.

## Important boundaries
The default codebase contains the Python domain engine, durable project/mission workflow, planning, policy, evidence/finding governance, validation, and bounded adapter contracts. It does not ship an enabled live scanner, exploit runner, transaction sender, key manager, or autonomous scope expansion. The default Hermes adapter is inert and does not modify Hermes runtime state.

Cloning and installing this Python package do not install, configure, restart, or deploy Hermes. Hermes-native profile compatibility and runtime integration still require a separate compatibility and approval gate.

## Current authority status
Hermes runtime/server inspection or mutation: **NOT AUTHORIZED**. Deployment: **NOT AUTHORIZED**. Live target assessment: requires a separate valid authorization envelope and enabled adapter. L3/R-12: **OPEN**. Gate 0b: **NOT PASSED**. Phase 1: **LOCKED**. Production: **NOT AUTHORIZED**.
