# Python Engine

## Package boundary
The `vane/` package is the domain engine. Hermes remains the runtime and host for profiles, sessions, tools, and skills. The default Hermes adapter is descriptive/inert: it does not load profiles, call tools, or modify Hermes state. The separate local MCP server exposes deterministic planning and validation tools.

## Core modules
- `models.py`: authorization, mission, asset, evidence, and finding domain types.
- `security/`: authorization checks, approvals, policy decision point, enforcement facade.
- `core/`: mission lifecycle and orchestration.
- `assessment/`: Web2/Web3 planning, asset disposition, dependency graph.
- `evidence/`: SHA-256 integrity and evidence validation.
- `findings/`: evidence-linked finding validation.
- `projects/`: project registry.
- `storage/repository.py`: durable project, signed authorization, mission, asset, evidence, finding, approval, and worker-task repositories.
- `bootstrap.py`: composes SQLite persistence and public-key-only approval verification.
- `recovery/`: bounded evidence-driven recovery planning.
- `lifecycle/`: data retention/disposition decisions.
- `mcp/`: capability allowlist and local stdio MCP server.
- `storage/`: SQLite event persistence.
- `crypto/`: external Ed25519 signing contract.
- `integrations/hermes/`: host adapter contract.
- `validation/`: release readiness gates.

## Safety and authority model
All capability execution is denied unless a valid envelope covers the exact asset and method. Discovery does not expand scope. The repository includes planners and interfaces, not a live scanner. No RPC, HTTP, exploit, transaction, or mutation adapter is enabled by default. Signing private keys are never stored in the engine.

## Install for isolated development
```bash
git clone https://github.com/anggasec28/vane.git
cd vane
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev,mcp,crypto]'
pytest
vane version
vane check --config config/vane.example.json
```

For a profile-backed engine instance, compose the configured public-key verifier and SQLite repository with `from vane.bootstrap import create_engine; engine = create_engine()`. The profile environment variables select the public keyring and database paths. Empty or missing public keys cause approval verification to fail closed.

These steps install the Python package in an isolated environment. They do not install or modify Hermes, deploy services, authorize a target assessment, or enable MCP tools.
