# Install VANE into Hermes Agent

VANE is packaged as a Hermes profile distribution. Hermes remains the runtime. Installing the distribution creates a separate profile named `vane`; it does not replace the default profile or modify the Hermes runtime source.

## Requirements
- Hermes Agent with profile-distribution support (manifest declares Hermes >= 0.12.0).
- Git available to Hermes.
- Python 3.11+ for the VANE Python engine.
- A model/provider configured for the new profile.

## Install the profile
Run this on the machine where Hermes Agent is installed:

```bash
hermes profile install github.com/anggasec28/vane --alias
```

Inspect the profile before starting it:

```bash
hermes profile info vane
hermes -p vane config check
```

Configure the model/provider for the new profile using the Hermes setup flow:

```bash
hermes -p vane setup
```

Do not copy another profile's `.env`, `auth.json`, memories, or sessions into the VANE distribution. Hermes profile distribution installs keep credentials and user state machine-local.

## Install the Python engine in the VANE profile

Hermes profile distribution installs the agent identity, config, and skills. The Python engine is a separate package and must be installed into the profile's own environment:

```bash
cd ~/.hermes/profiles/vane
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[mcp,crypto]'
vane version
vane check --config config/vane.example.json
```

If your Hermes installation stores named profiles in a different home directory, use the path reported by `hermes profile info vane`. Keep the virtual environment and local database out of Git.

## Configure the public approval keyring

Create the local keyring from the example:

```bash
cp config/approval-public-keys.example.json config/approval-public-keys.json
```

Populate `keys` with the key IDs and base64-encoded 32-byte Ed25519 public keys supplied by the separate signing authority. The private key never belongs in this profile or repository. Until a trusted public key is configured, mission/action approval verification fails closed. The local keyring path is ignored by Git.

## Configure Master emergency authority

The Hermes-native bootstrap requires Master emergency suspension control by default. Configure the following variables in the VANE profile's actual gateway/service environment, not merely in an interactive shell:

- `VANE_REQUIRE_EMERGENCY_CONTROL=true`
- `VANE_MASTER_PRINCIPAL`: the canonical Master principal produced by the operator-owned, authenticated Telegram identity binding.
- `VANE_MASTER_KEY_IDS`: comma-separated key IDs for the Master public signing keys already present in the public keyring.

Do not substitute a Telegram display name or username for an authenticated principal. The live Telegram identity binding and external signing authority must be verified by the operator-owned Hermes setup before these values are populated. Until the Master principal and key IDs are configured, the central policy engine intentionally denies target-facing actions. Do not disable the required-control gate to bypass this condition.

The emergency control is global and separate from project authorization. Master-only signed SUSPEND and RELEASE approvals are bound to the operation, expected revision, reason, authority reference, and trigger. The control history is independently checked on every read; invalid or unavailable state blocks actions.

## First-run checks
1. Read `SOUL.md` and `policies/` before using the profile.
2. Confirm `config/vane.example.json` retains default-deny policy, external MCP capabilities disabled by default, the local VANE MCP server limited to profile-local project/mission/evidence/finding state plus deterministic planning/validation, with no target requests, and external signing custody.
3. Run the Python test suite from a development checkout: `python -m pytest`.
4. Keep live assessment capabilities disabled until a project-specific authorization envelope and method allowlist are approved.
5. Keep runtime integration and production status unchanged until their separate approval gates pass.

## Update
Update the profile distribution with:

```bash
hermes profile update vane
```

Hermes preserves local `config.yaml` overrides during updates by default. If the shipped MCP server definition changes, merge the new `mcp_servers.vane_engine` block into the profile config. Use `hermes profile update vane --force-config` only when you intentionally want to reset the profile config to the repository version.

Then, from the VANE profile directory, refresh the editable Python package if dependencies or package metadata changed:

```bash
. .venv/bin/activate
python -m pip install -e '.[mcp,crypto]'
```

## Scope of this installer
The profile distribution installs VANE-owned profile files. It does not install or replace Hermes Agent, start a gateway, create MCP credentials, provision signing keys, activate a live scanner, or authorize any target assessment. Profile configuration and Python engine installation are intentionally separate steps.
