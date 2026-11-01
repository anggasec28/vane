# Validation Plan

## Tracks
- Static structure: required files, YAML/JSON parse, manifest coverage.
- Policy consistency: scope, approval, lifecycle, evidence, and worker rules.
- Schema checks: required fields, enums, references, state transitions.
- Workflow scenarios: blocked observation, out-of-scope discovery, partial evidence, recovery, conflicting evidence, closure.
- Crypto review: signer/verifier separation and external anchor assumptions.
- Integration compatibility: only after explicit runtime inspection/integration authorization.
- Operational tests: only after separate approval and controlled test environment.

## Current execution status
No Hermes runtime integration tests, live target tests, production tests, or deployment tests are claimed. Designed tests are not executed tests.

## Release gate
A release candidate requires complete inventory, decision traceability, schema validation, policy cross-reference, test evidence, unresolved issue register, and explicit Master approval.
